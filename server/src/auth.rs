//! Bearer tokens and password hashing.
//!
//! Opaque random tokens rather than JWTs. Nothing here needs stateless verification, and
//! an opaque token can be revoked the moment a user signs out - which a JWT cannot,
//! without the revocation list that was the reason to avoid state in the first place.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use rand::Rng as _;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::state::AppState;

pub const ACCESS: &str = "access";
pub const REFRESH: &str = "refresh";
/// Refresh tokens outlive access tokens by a long way; the point of the short access
/// token is that it is the one travelling on every request.
pub const REFRESH_TTL_MS: i64 = 90 * 24 * 3600 * 1000;

/// A fresh bearer token, and the hash to store for it.
///
/// Only the hash is persisted. A dump of the `tokens` table therefore yields no live
/// sessions, in the same spirit as not storing the password.
pub fn mint_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Hash the client's `auth_key` for storage.
///
/// The client already ran Argon2id over the password; this is a second, cheaper pass over
/// a value that is already 256 bits of key material. Its job is only to make a stolen
/// database useless directly, not to resist a dictionary attack - there is no dictionary
/// for a uniformly random 32-byte input.
pub fn hash_auth_key(auth_key: &str) -> Result<String> {
    // `SaltString::generate` wants a `rand_core` 0.6 RNG and this crate's `rand` is on a
    // newer major. Encoding our own 16 random bytes is the same salt without a second
    // RNG in the dependency graph.
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| Error::Internal(format!("salt encoding failed: {e}")))?;
    Argon2::default()
        .hash_password(auth_key.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::Internal(format!("hashing failed: {e}")))
}

pub fn verify_auth_key(auth_key: &str, stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    Argon2::default()
        .verify_password(auth_key.as_bytes(), &parsed)
        .is_ok()
}

/// The signed-in account, extracted from the `Authorization: Bearer` header.
///
/// Any handler taking this as an argument is authenticated; there is no way to forget the
/// check, because a handler without it simply has no account id to work with.
pub struct Caller {
    pub account_id: String,
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(Error::Unauthorised)?;

        let row = state
            .store
            .take_token(&hash_token(header.trim()), ACCESS)
            .await?
            .ok_or(Error::Unauthorised)?;

        Ok(Self {
            account_id: row.account_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_never_stored_in_the_clear() {
        let (token, hash) = mint_token();
        assert_ne!(token, hash);
        assert_eq!(hash_token(&token), hash);
    }

    #[test]
    fn two_tokens_are_never_the_same() {
        assert_ne!(mint_token().0, mint_token().0);
    }

    #[test]
    fn an_auth_key_verifies_against_its_own_hash_only() {
        let hash = hash_auth_key("deadbeef").unwrap();
        assert!(verify_auth_key("deadbeef", &hash));
        assert!(!verify_auth_key("deadbeee", &hash));
    }

    #[test]
    fn a_corrupt_stored_hash_is_a_failed_login_not_a_panic() {
        assert!(!verify_auth_key("deadbeef", "not-a-phc-string"));
        assert!(!verify_auth_key("deadbeef", ""));
    }

    #[test]
    fn the_same_key_hashes_differently_each_time() {
        // Per-hash salt: two accounts with the same password must not be visibly equal.
        let a = hash_auth_key("same").unwrap();
        let b = hash_auth_key("same").unwrap();
        assert_ne!(a, b);
        assert!(verify_auth_key("same", &a) && verify_auth_key("same", &b));
    }
}
