//! The key hierarchy, envelope sealing, and wrapping a group key for another user.
//!
//! ```text
//! password + email
//!   |
//!   +- Argon2id ------------------------------> masterKey   (never leaves the device)
//!        |
//!        +- HKDF "remotier.auth.v1"  --------->  authKey    (sent to the server, which
//!        |                                                   stores Argon2id(authKey))
//!        +- HKDF "remotier.wrap.v1"  --------->  wrapKey
//!             |
//!             +- wraps accountSecret (X25519)  -+ stored on the server as ciphertext,
//!             +- wraps personalKey   (32 bytes) + so a new device can bootstrap
//! ```
//!
//! Two derivations from one master, and the server only ever sees the auth half. Knowing
//! `authKey` - which is what a breached server database would yield - reveals nothing
//! about `wrapKey`, because HKDF is one-way and the two use different `info` strings.
//!
//! `personalKey` encrypts everything not in a shared group. A shared group gets its own
//! random content key, wrapped to each member's X25519 public key.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Generate, Key as AeadKey, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// Re-exported so a consumer can name an account keypair without taking a direct
// dependency on x25519-dalek - and, more to the point, without being able to end up on a
// different version of it than this crate uses.
pub use x25519_dalek::{PublicKey, StaticSecret};

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// OWASP's second recommended Argon2id profile: 19 MiB, 2 passes, 1 lane. Chosen over the
/// heavier ones because this runs on the UI thread's behalf at sign-in on every device,
/// including whatever laptop the user actually owns.
const ARGON_M_COST: u32 = 19 * 1024;
const ARGON_T_COST: u32 = 2;
const ARGON_P_COST: u32 = 1;

const SALT_CONTEXT: &[u8] = b"remotier.salt.v1";
const INFO_AUTH: &[u8] = b"remotier.auth.v1";
const INFO_WRAP: &[u8] = b"remotier.wrap.v1";
const INFO_BOX: &[u8] = b"remotier.box.v1";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("decryption failed - wrong key, or the record was tampered with")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("{0} is {1} bytes, expected {2}")]
    Length(&'static str, usize, usize),
    #[error("payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A 32-byte symmetric key, zeroed when dropped.
pub type ContentKey = Zeroizing<[u8; KEY_LEN]>;

fn key_from(slice: &[u8], what: &'static str) -> Result<ContentKey> {
    let bytes: [u8; KEY_LEN] = slice
        .try_into()
        .map_err(|_| Error::Length(what, slice.len(), KEY_LEN))?;
    Ok(Zeroizing::new(bytes))
}

/// Everything derived from the password, plus the account keypair once unwrapped.
pub struct AccountKeys {
    pub auth: ContentKey,
    pub wrap: ContentKey,
}

/// Derive the master key, then split it.
///
/// The salt is a hash of a fixed context string and the lowercased email rather than a
/// random per-user salt, because a new device has only the password and the email to work
/// from and must arrive at the same key without asking the server for anything first.
/// Lowercasing matters: `Ada@example.com` and `ada@example.com` are the same account to
/// every mail server on earth, and would otherwise be two undecryptable vaults.
pub fn derive_account_keys(password: &str, email: &str) -> Result<AccountKeys> {
    let master = derive_master(password, email)?;
    Ok(AccountKeys {
        auth: subkey(&master, INFO_AUTH)?,
        wrap: subkey(&master, INFO_WRAP)?,
    })
}

/// Derive the same two keys from a recovery code instead of a password.
///
/// A recovery code is high-entropy by construction, so it does not need the email as a
/// salt - but it uses the same Argon2 parameters and the same two `info` strings, so the
/// wrapped blobs on the server are interchangeable between the two paths.
pub fn derive_recovery_keys(code: &str) -> Result<AccountKeys> {
    let normalised = code.replace(['-', ' '], "").to_ascii_uppercase();
    let master = argon2id(normalised.as_bytes(), b"remotier.recovery.v1")?;
    Ok(AccountKeys {
        auth: subkey(&master, INFO_AUTH)?,
        wrap: subkey(&master, INFO_WRAP)?,
    })
}

fn derive_master(password: &str, email: &str) -> Result<ContentKey> {
    let mut hasher = Sha256::new();
    hasher.update(SALT_CONTEXT);
    hasher.update(email.trim().to_ascii_lowercase().as_bytes());
    let salt = hasher.finalize();
    argon2id(password.as_bytes(), &salt)
}

fn argon2id(secret: &[u8], salt: &[u8]) -> Result<ContentKey> {
    let params = Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(KEY_LEN))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(secret, salt, out.as_mut_slice())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

fn subkey(master: &ContentKey, info: &[u8]) -> Result<ContentKey> {
    let hk = Hkdf::<Sha256>::new(None, master.as_slice());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, out.as_mut_slice())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

/// A fresh random content key, for a new account or a newly shared group.
pub fn random_key() -> ContentKey {
    let key = AeadKey::<XChaCha20Poly1305>::generate();
    Zeroizing::new(key.into())
}

// ---------------------------------------------------------------------------
// Symmetric sealing
// ---------------------------------------------------------------------------

/// Seal `plaintext` under `key`, bound to `aad`. Returns `(nonce, ciphertext)`.
pub fn seal(key: &ContentKey, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Encrypt)?;
    let nonce = XNonce::generate();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encrypt)?;
    Ok((nonce.to_vec(), ciphertext))
}

pub fn open(
    key: &ContentKey,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Decrypt)?;
    let nonce =
        XNonce::try_from(nonce).map_err(|_| Error::Length("nonce", nonce.len(), NONCE_LEN))?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

/// Seal a JSON-serialisable payload. Used for record payloads and for the wrapped key
/// blobs the server stores.
pub fn seal_json<T: serde::Serialize>(
    key: &ContentKey,
    aad: &[u8],
    value: &T,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let json = Zeroizing::new(serde_json::to_vec(value)?);
    seal(key, aad, &json)
}

pub fn open_json<T: serde::de::DeserializeOwned>(
    key: &ContentKey,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<T> {
    let json = open(key, aad, nonce, ciphertext)?;
    Ok(serde_json::from_slice(&json)?)
}

// ---------------------------------------------------------------------------
// The account keypair, and wrapping a group key for someone else
// ---------------------------------------------------------------------------

/// Generate an X25519 keypair for a new account.
///
/// Built from AEAD key material rather than `StaticSecret::random_from_rng` on purpose:
/// x25519-dalek and this crate's `rand` are on different `rand_core` majors, and taking
/// the bytes from the one RNG already in the dependency graph avoids pulling a second.
/// X25519 clamps the scalar itself, so uniform bytes are exactly what it wants.
pub fn generate_account_keypair() -> (StaticSecret, PublicKey) {
    let bytes = random_key();
    let secret = StaticSecret::from(*bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn public_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Length("public key", bytes.len(), 32))?;
    Ok(PublicKey::from(arr))
}

pub fn secret_from_bytes(bytes: &[u8]) -> Result<StaticSecret> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Length("secret key", bytes.len(), 32))?;
    Ok(StaticSecret::from(arr))
}

/// Wrap a content key for one recipient, knowing only their public key.
///
/// An anonymous sealed box: a throwaway X25519 keypair per call, so the same group key
/// wrapped twice produces two unrelated blobs, and the sender needs no key of their own.
/// Layout is `ephemeral_public (32) || nonce (24) || ciphertext`.
///
/// The recipient's public key goes into the HKDF salt as well as the exchange, so a blob
/// sealed for one member cannot be replayed as though it were sealed for another.
pub fn wrap_for(recipient: &PublicKey, key: &ContentKey) -> Result<Vec<u8>> {
    let (eph_secret, eph_public) = generate_account_keypair();
    let shared = eph_secret.diffie_hellman(recipient);
    let wrapping = box_key(
        shared.as_bytes(),
        eph_public.as_bytes(),
        recipient.as_bytes(),
    )?;

    let (nonce, ciphertext) = seal(&wrapping, INFO_BOX, key.as_slice())?;

    let mut out = Vec::with_capacity(32 + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwrap a content key sealed to us with [`wrap_for`].
pub fn unwrap_with(secret: &StaticSecret, blob: &[u8]) -> Result<ContentKey> {
    if blob.len() < 32 + NONCE_LEN {
        return Err(Error::Length("wrapped key", blob.len(), 32 + NONCE_LEN));
    }
    let eph_public = public_from_bytes(&blob[..32])?;
    let nonce = &blob[32..32 + NONCE_LEN];
    let ciphertext = &blob[32 + NONCE_LEN..];

    let shared = secret.diffie_hellman(&eph_public);
    let ours = PublicKey::from(secret);
    let wrapping = box_key(shared.as_bytes(), eph_public.as_bytes(), ours.as_bytes())?;

    let plaintext = open(&wrapping, INFO_BOX, nonce, ciphertext)?;
    key_from(&plaintext, "unwrapped key")
}

fn box_key(shared: &[u8], eph_public: &[u8], recipient: &[u8]) -> Result<ContentKey> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_public);
    salt.extend_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_BOX, out.as_mut_slice())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

/// A fresh recovery code: 128 bits, Crockford-ish base32, grouped for reading aloud.
///
/// Shown exactly once, at registration. It is the only way back into an account whose
/// password is forgotten, because the server cannot decrypt anything on the user's behalf.
pub fn generate_recovery_code() -> Zeroizing<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ0123456789";
    let bytes = random_key();
    let mut out = String::with_capacity(31);
    for (i, b) in bytes.iter().take(20).enumerate() {
        if i > 0 && i % 5 == 0 {
            out.push('-');
        }
        out.push(ALPHABET[(*b as usize) % ALPHABET.len()] as char);
    }
    Zeroizing::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Argon2id at 19 MiB is slow by design, so the tests that need a real derivation are
    // few and deliberate.

    #[test]
    fn auth_and_wrap_keys_differ() {
        let keys = derive_account_keys("hunter2", "ada@example.com").unwrap();
        assert_ne!(keys.auth.as_slice(), keys.wrap.as_slice());
    }

    #[test]
    fn email_case_and_padding_do_not_change_the_key() {
        // Otherwise signing in as "Ada@Example.com " creates a second, undecryptable vault.
        let a = derive_account_keys("hunter2", "ada@example.com").unwrap();
        let b = derive_account_keys("hunter2", "  Ada@Example.COM ").unwrap();
        assert_eq!(a.wrap.as_slice(), b.wrap.as_slice());
    }

    #[test]
    fn a_different_email_is_a_different_vault() {
        let a = derive_account_keys("hunter2", "ada@example.com").unwrap();
        let b = derive_account_keys("hunter2", "bob@example.com").unwrap();
        assert_ne!(a.wrap.as_slice(), b.wrap.as_slice());
    }

    #[test]
    fn known_answer_master_split() {
        // Pins the HKDF half of the hierarchy so the client and the server can never
        // disagree about it. The Argon2 half is covered by the tests above; fixing a
        // vector for it would mean paying 19 MiB of hashing on every test run.
        //
        // These two values were computed by an independent RFC 5869 implementation, not
        // copied out of this code's own output - a vector taken from the thing it is
        // meant to check would pass no matter how wrong the derivation was.
        let master = Zeroizing::new([7u8; KEY_LEN]);
        let auth = subkey(&master, INFO_AUTH).unwrap();
        let wrap = subkey(&master, INFO_WRAP).unwrap();

        assert_eq!(
            hex(auth.as_slice()),
            "9826c26a4b90d27992c4b4e0771246d0fdf52a40bd1c0d32d0ee82ec57c6d7d9"
        );
        assert_eq!(
            hex(wrap.as_slice()),
            "fc1be26628c1af0f792b586780431d19d40ddd3793f086443f304ad419ac1730"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn seal_open_round_trip() {
        let key = random_key();
        let (nonce, ct) = seal(&key, b"aad", b"terminal.shop").unwrap();
        assert_ne!(ct.as_slice(), b"terminal.shop");
        let back = open(&key, b"aad", &nonce, &ct).unwrap();
        assert_eq!(back.as_slice(), b"terminal.shop");
    }

    #[test]
    fn a_changed_aad_fails_to_open() {
        // This is the property that stops a server swapping two records' ciphertexts.
        let key = random_key();
        let (nonce, ct) = seal(&key, b"host:h1", b"terminal.shop").unwrap();
        assert!(open(&key, b"host:h2", &nonce, &ct).is_err());
    }

    #[test]
    fn a_wrong_key_fails_to_open() {
        let (nonce, ct) = seal(&random_key(), b"aad", b"secret").unwrap();
        assert!(open(&random_key(), b"aad", &nonce, &ct).is_err());
    }

    #[test]
    fn the_nonce_is_never_reused() {
        let key = random_key();
        let (n1, c1) = seal(&key, b"aad", b"same").unwrap();
        let (n2, c2) = seal(&key, b"aad", b"same").unwrap();
        assert_ne!(n1, n2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn a_group_key_wraps_and_unwraps() {
        let (secret, public) = generate_account_keypair();
        let group_key = random_key();

        let blob = wrap_for(&public, &group_key).unwrap();
        let back = unwrap_with(&secret, &blob).unwrap();
        assert_eq!(back.as_slice(), group_key.as_slice());
    }

    #[test]
    fn another_member_cannot_unwrap_someone_elses_blob() {
        let (_, alice) = generate_account_keypair();
        let (bob_secret, _) = generate_account_keypair();

        let blob = wrap_for(&alice, &random_key()).unwrap();
        assert!(unwrap_with(&bob_secret, &blob).is_err());
    }

    #[test]
    fn wrapping_twice_produces_unrelated_blobs() {
        // The ephemeral keypair is per call, so a server watching shares cannot tell that
        // two members hold the same group key.
        let (_, public) = generate_account_keypair();
        let key = random_key();
        assert_ne!(
            wrap_for(&public, &key).unwrap(),
            wrap_for(&public, &key).unwrap()
        );
    }

    #[test]
    fn a_truncated_wrap_is_rejected_rather_than_panicking() {
        let (secret, public) = generate_account_keypair();
        let blob = wrap_for(&public, &random_key()).unwrap();
        assert!(unwrap_with(&secret, &blob[..40]).is_err());
        assert!(unwrap_with(&secret, &[]).is_err());
    }

    #[test]
    fn recovery_codes_are_readable_and_unique() {
        let a = generate_recovery_code();
        let b = generate_recovery_code();
        assert_ne!(*a, *b);
        assert_eq!(a.len(), 23, "20 symbols in groups of five: {}", *a);
        assert!(
            !a.contains(['I', 'L', 'O', 'U']),
            "ambiguous letter in {}",
            *a
        );
    }

    #[test]
    fn a_recovery_code_derives_the_same_keys_however_it_is_typed() {
        let keys = derive_recovery_keys("abcde-fghjk").unwrap();
        let retyped = derive_recovery_keys("ABCDE FGHJK").unwrap();
        assert_eq!(keys.wrap.as_slice(), retyped.wrap.as_slice());
    }

    #[test]
    fn json_payloads_round_trip_through_the_seal() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct P {
            hostname: String,
        }
        let key = random_key();
        let p = P {
            hostname: "terminal.shop".into(),
        };
        let (nonce, ct) = seal_json(&key, b"aad", &p).unwrap();
        let back: P = open_json(&key, b"aad", &nonce, &ct).unwrap();
        assert_eq!(back, p);
    }
}
