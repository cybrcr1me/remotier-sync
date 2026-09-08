//! Request and response bodies. One definition, compiled by both sides.

use serde::{Deserialize, Serialize};

use crate::record::Envelope;

/// `GET /v1/instance` - unauthenticated, and the only endpoint a client calls before it
/// trusts an address. The sign-in screen probes this when the instance URL changes, so a
/// typo is reported as "no Remotier instance there" rather than as a failed login.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceInfo {
    pub name: String,
    pub version: String,
    /// Format versions this server accepts. A client whose `FORMAT_VERSION` is absent
    /// says so plainly instead of failing later inside a decryption error.
    pub format_versions: Vec<u16>,
    pub registration_open: bool,
}

/// The blobs a device needs to reconstruct the account keys, all encrypted under a key
/// derived from the password (or the recovery code). The server stores and returns them
/// and can do nothing else with them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyMaterial {
    /// X25519 public key, plaintext - this is how other users wrap a group key for you.
    pub account_public: String,
    /// The X25519 secret, sealed under `wrapKey`.
    pub wrapped_account_secret: SealedBlob,
    /// The personal content key, sealed under `wrapKey`.
    pub wrapped_personal_key: SealedBlob,
}

/// A nonce and ciphertext pair, base64 in JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedBlob {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    /// `authKey`, base64. Never the password. The server hashes this again before storing
    /// it, so a stolen database is not a list of usable credentials.
    pub auth_key: String,
    pub key_material: KeyMaterial,
    /// The same two blobs, sealed under the recovery code's `wrapKey`. Registration
    /// without them would make a forgotten password unrecoverable with no warning.
    pub recovery_material: KeyMaterial,
    /// The recovery code's *auth* half, derived exactly as `auth_key` is. Stored
    /// separately so signing in with the recovery code can be verified the same way as
    /// signing in with the password - the two are interchangeable doors, not one door
    /// and a back way in.
    pub recovery_auth_key: String,
    pub device_id: String,
    pub device_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: String,
    pub device_id: String,
    pub device_name: String,
}

/// Signing in with the recovery code instead of the password.
///
/// Returns the *recovery-wrapped* key material, which the client opens with the key
/// derived from the code. The client is then expected to set a new password and re-wrap,
/// because a recovery code that stays the only way in is a recovery code that will be
/// lost twice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverRequest {
    pub email: String,
    /// Derived from the recovery code by `derive_recovery_keys`.
    pub recovery_auth_key: String,
    pub device_id: String,
    pub device_name: String,
}

/// Replace the password (and its wrapped blobs) after a recovery sign-in, or on request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewrapRequest {
    pub auth_key: String,
    pub key_material: KeyMaterial,
    pub recovery_auth_key: String,
    pub recovery_material: KeyMaterial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub account_id: String,
    pub email: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Seconds until `access_token` expires.
    pub expires_in: i64,
    pub key_material: KeyMaterial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// `GET /v1/sync?cursor=N`. The cursor is a server sequence number, never a timestamp -
/// a pull that depended on clocks would skip records whenever two devices disagreed
/// about the time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullResponse {
    pub envelopes: Vec<Envelope>,
    pub cursor: i64,
    /// True when the server had more than one page. The client pulls again immediately.
    pub more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushRequest {
    pub envelopes: Vec<Envelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushResponse {
    pub accepted: Vec<Accepted>,
    /// Records the server would not take, with a reason. A rejection is not an error for
    /// the push as a whole: one bad clock must not block every other record.
    pub rejected: Vec<Rejected>,
    pub cursor: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Accepted {
    pub id: String,
    pub kind: String,
    pub seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rejected {
    pub id: String,
    pub kind: String,
    pub reason: RejectReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// `updated_at` is further ahead than the server will tolerate. The client should fix
    /// its clock and say so, rather than retrying.
    ImplausibleClock,
    /// The record claims a group the account is not a member of.
    NotAMember,
    /// A newer version already exists. The client pulls and merges.
    Stale,
    TooLarge,
}

/// `GET /v1/users/lookup?email=` - the one place an account's existence is observable to
/// another user, so it is rate limited and requires authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserLookup {
    pub user_id: String,
    pub email: String,
    pub account_public: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareRequest {
    pub group_id: String,
    pub user_id: String,
    /// The group's content key, wrapped to that user's `account_public`. The server never
    /// sees the key itself, only a blob it cannot open.
    pub wrapped_group_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    pub group_id: String,
    /// Whose group this is. Only the owner may share it further or rotate its key.
    pub owner_id: String,
    /// The member. When listing a group's shares this is who it was shared *with*; when
    /// listing your own memberships it is you.
    pub user_id: String,
    /// The other party's address: the member's when the owner lists a group's shares, the
    /// owner's when a member lists what has been shared with them.
    pub email: String,
    pub wrapped_group_key: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub device_id: String,
    pub name: String,
    pub last_seen: i64,
}

/// What the server says when it refuses. `code` is stable and matched on; `message` is
/// shown to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_reasons_are_stable_strings() {
        // Persisted in server logs and matched on by the client; renaming one silently
        // changes behaviour on the other side.
        let json = serde_json::to_string(&RejectReason::ImplausibleClock).unwrap();
        assert_eq!(json, "\"implausible_clock\"");
    }

    #[test]
    fn an_api_error_survives_an_unknown_code() {
        let parsed: ApiError =
            serde_json::from_str(r#"{"code":"something_new","message":"nope"}"#).unwrap();
        assert_eq!(parsed.code, "something_new");
    }
}
