//! Registration, sign-in, refresh, and the key-material handoff.
//!
//! Nothing here ever sees a password. The client derives `authKey` from it and sends only
//! that; the `wrapKey` half never leaves the device. So the worst a compromised server can
//! do with a sign-in is learn that one happened.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Query, State};
use axum::Json;
use remotier_sync_proto::api::{
    KeyMaterial, LoginRequest, RecoverRequest, RefreshRequest, RegisterRequest, RewrapRequest,
    SealedBlob, Session, UserLookup,
};

use crate::auth::{self, Caller};
use crate::error::{Error, Result};
use crate::state::AppState;
use crate::store::{Account, NewAccount};

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<Session>> {
    guard(&state, peer)?;
    if !state.config.registration_open {
        return Err(Error::RegistrationClosed);
    }
    validate_email(&body.email)?;

    // The recovery material is not optional. An account registered without it is an
    // account whose owner loses everything to a forgotten password, and the server cannot
    // help - it holds no key. Refusing here is kinder than discovering it later.
    if body
        .recovery_material
        .wrapped_personal_key
        .ciphertext
        .is_empty()
    {
        return Err(Error::BadRequest(
            "recovery material is required - without it a forgotten password is unrecoverable"
                .into(),
        ));
    }

    let account = state
        .store
        .create_account(NewAccount {
            email: body.email.clone(),
            auth_hash: auth::hash_auth_key(&body.auth_key)?,
            recovery_auth_hash: auth::hash_auth_key(&body.recovery_auth_key)?,
            account_public: body.key_material.account_public.clone(),
            wrapped_account_secret: encode(&body.key_material.wrapped_account_secret),
            wrapped_personal_key: encode(&body.key_material.wrapped_personal_key),
            recovery_account_secret: encode(&body.recovery_material.wrapped_account_secret),
            recovery_personal_key: encode(&body.recovery_material.wrapped_personal_key),
        })
        .await?;

    issue_session(&state, account, &body.device_id, &body.device_name).await
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<Session>> {
    guard(&state, peer)?;
    let account = state.store.account_by_email(&body.email).await?;

    // Verify against a dummy hash when the account does not exist, so a request for an
    // unknown address costs the same time as one for a known address. Returning early
    // here would make account enumeration a stopwatch away.
    let Some(account) = account else {
        let _ = auth::verify_auth_key(&body.auth_key, &DUMMY_HASH);
        return Err(Error::BadCredentials);
    };

    if !auth::verify_auth_key(&body.auth_key, &account.auth_hash) {
        return Err(Error::BadCredentials);
    }

    issue_session(&state, account, &body.device_id, &body.device_name).await
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<Session>> {
    // Single use: consumed as it is read, so a stolen refresh token stops working the
    // moment the real client uses its own.
    let row = state
        .store
        .consume_token(&auth::hash_token(&body.refresh_token), auth::REFRESH)
        .await?
        .ok_or(Error::Unauthorised)?;

    let account = state
        .store
        .account_by_id(&row.account_id)
        .await?
        .ok_or(Error::Unauthorised)?;

    issue_session(&state, account, "", "").await
}

pub async fn logout(State(state): State<AppState>, caller: Caller) -> Result<()> {
    // Every token, not just this one. Signing out on a device you are worried about
    // should end the sessions you cannot reach.
    state.store.revoke_account_tokens(&caller.account_id).await
}

/// Re-fetch the wrapped key blobs, for a device that has a session but no keys in memory.
pub async fn keys(State(state): State<AppState>, caller: Caller) -> Result<Json<KeyMaterial>> {
    let account = state
        .store
        .account_by_id(&caller.account_id)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(key_material(&account)))
}

#[derive(serde::Deserialize)]
pub struct LookupQuery {
    email: String,
}

/// Find another user's public key, to share a group with them.
///
/// Authenticated, because it is the one endpoint that reveals whether an address has an
/// account here.
pub async fn lookup(
    State(state): State<AppState>,
    _caller: Caller,
    Query(query): Query<LookupQuery>,
) -> Result<Json<UserLookup>> {
    let account = state
        .store
        .account_by_email(&query.email)
        .await?
        .ok_or(Error::NotFound)?;

    Ok(Json(UserLookup {
        user_id: account.id,
        email: account.email,
        account_public: account.account_public,
    }))
}

/// Sign in with the recovery code.
///
/// Returns the recovery-wrapped blobs rather than the password-wrapped ones - they hold
/// the same two keys, sealed under a different wrapping key. The client opens them with
/// the key derived from the code, then immediately calls `rewrap` with a new password.
pub async fn recover(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<RecoverRequest>,
) -> Result<Json<Session>> {
    guard(&state, peer)?;

    let account = state.store.account_by_email(&body.email).await?;
    let Some(account) = account else {
        let _ = auth::verify_auth_key(&body.recovery_auth_key, &DUMMY_HASH);
        return Err(Error::BadCredentials);
    };
    if !auth::verify_auth_key(&body.recovery_auth_key, &account.recovery_auth_hash) {
        return Err(Error::BadCredentials);
    }

    let recovery_view = Account {
        wrapped_account_secret: account.recovery_account_secret.clone(),
        wrapped_personal_key: account.recovery_personal_key.clone(),
        ..account
    };
    issue_session(&state, recovery_view, &body.device_id, &body.device_name).await
}

/// Replace the password and every wrapped blob.
///
/// The same operation whether it follows a recovery sign-in or an ordinary password
/// change: the account keys themselves never change, only what wraps them. That is why a
/// password change does not have to re-encrypt a single record.
pub async fn rewrap(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<RewrapRequest>,
) -> Result<()> {
    let account = state
        .store
        .account_by_id(&caller.account_id)
        .await?
        .ok_or(Error::NotFound)?;

    state
        .store
        .rewrap_account(
            &account.id,
            NewAccount {
                email: account.email.clone(),
                auth_hash: auth::hash_auth_key(&body.auth_key)?,
                recovery_auth_hash: auth::hash_auth_key(&body.recovery_auth_key)?,
                account_public: account.account_public.clone(),
                wrapped_account_secret: encode(&body.key_material.wrapped_account_secret),
                wrapped_personal_key: encode(&body.key_material.wrapped_personal_key),
                recovery_account_secret: encode(&body.recovery_material.wrapped_account_secret),
                recovery_personal_key: encode(&body.recovery_material.wrapped_personal_key),
            },
        )
        .await?;

    // Every existing session dies with the old password. A password changed because it
    // was exposed has to end the sessions opened with it.
    state.store.revoke_account_tokens(&account.id).await
}

fn guard(state: &AppState, peer: SocketAddr) -> Result<()> {
    if state.auth_limit.check(peer.ip()) {
        Ok(())
    } else {
        Err(Error::RateLimited)
    }
}

async fn issue_session(
    state: &AppState,
    account: Account,
    device_id: &str,
    device_name: &str,
) -> Result<Json<Session>> {
    let now = crate::store::now_ms();

    let (access, access_hash) = auth::mint_token();
    let (refresh_token, refresh_hash) = auth::mint_token();

    state
        .store
        .put_token(
            &access_hash,
            &account.id,
            auth::ACCESS,
            now + state.config.access_ttl_secs * 1000,
        )
        .await?;
    state
        .store
        .put_token(
            &refresh_hash,
            &account.id,
            auth::REFRESH,
            now + auth::REFRESH_TTL_MS,
        )
        .await?;

    if !device_id.is_empty() {
        state
            .store
            .touch_device(&account.id, device_id, device_name)
            .await?;
    }

    let key_material = key_material(&account);
    Ok(Json(Session {
        account_id: account.id,
        email: account.email,
        access_token: access,
        refresh_token,
        expires_in: state.config.access_ttl_secs,
        key_material,
    }))
}

fn key_material(account: &Account) -> KeyMaterial {
    KeyMaterial {
        account_public: account.account_public.clone(),
        wrapped_account_secret: decode(&account.wrapped_account_secret),
        wrapped_personal_key: decode(&account.wrapped_personal_key),
    }
}

/// The blobs are stored as one string so the schema does not need two columns per blob.
fn encode(blob: &SealedBlob) -> String {
    format!("{}.{}", blob.nonce, blob.ciphertext)
}

fn decode(stored: &str) -> SealedBlob {
    let (nonce, ciphertext) = stored.split_once('.').unwrap_or(("", stored));
    SealedBlob {
        nonce: nonce.to_string(),
        ciphertext: ciphertext.to_string(),
    }
}

fn validate_email(email: &str) -> Result<()> {
    let email = email.trim();
    // Deliberately minimal. Anything stricter rejects addresses that work, and this is
    // not the component that decides whether mail can be delivered.
    if email.len() < 3 || email.len() > 254 || !email.contains('@') || email.contains(' ') {
        return Err(Error::BadRequest("that is not an email address".into()));
    }
    Ok(())
}

/// A real Argon2 hash of a value nobody knows, so verifying against it costs what
/// verifying a real one costs.
///
/// Hashed at first use rather than written out as a literal: a hand-written PHC string
/// that fails to parse makes `verify_auth_key` return immediately, which is precisely the
/// timing difference this exists to remove - and it would do so silently.
static DUMMY_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let (throwaway, _) = auth::mint_token();
    auth::hash_auth_key(&throwaway).expect("hashing a random value cannot fail")
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_blob_survives_the_round_trip_through_storage() {
        let blob = SealedBlob {
            nonce: "bm9uY2U".into(),
            ciphertext: "Y2lwaGVy".into(),
        };
        let back = decode(&encode(&blob));
        assert_eq!(back.nonce, blob.nonce);
        assert_eq!(back.ciphertext, blob.ciphertext);
    }

    #[test]
    fn emails_that_are_not_addresses_are_refused() {
        assert!(validate_email("ada@example.com").is_ok());
        assert!(validate_email("  ada@example.com  ").is_ok());
        assert!(validate_email("ada").is_err());
        assert!(validate_email("ada @example.com").is_err());
        assert!(validate_email("").is_err());
    }

    #[test]
    fn the_dummy_hash_never_verifies_but_never_panics() {
        // Its only job is to cost the same as a real verification. If it were malformed
        // the comparison would return early and the timing difference would be back.
        assert!(!crate::auth::verify_auth_key("anything", &DUMMY_HASH));
    }
}
