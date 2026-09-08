//! Persistence, behind one trait so the handlers are written once.
//!
//! SQLite is the self-host story: one binary, one file, `docker run` with a volume.
//! Postgres is the hosted instance. The two write their own SQL rather than sharing it
//! through `sqlx::Any`, because the placeholder syntax differs (`?1` against `$1`) and a
//! query string that has to be rewritten at runtime is a query nobody can grep for.

pub mod postgres;
pub mod sqlite;

use async_trait::async_trait;
use remotier_sync_proto::record::Envelope;

use crate::error::Result;

/// An account, as the server knows it. Note what is absent: there is no field here the
/// server could read a hostname out of.
#[derive(Debug, Clone)]
pub struct Account {
    pub id: String,
    pub email: String,
    /// Argon2id over the `auth_key` the client derived. Hashed again on this side so a
    /// stolen database is not a list of usable credentials.
    pub auth_hash: String,
    pub account_public: String,
    pub wrapped_account_secret: String,
    pub wrapped_personal_key: String,
    pub recovery_account_secret: String,
    pub recovery_personal_key: String,
    pub recovery_auth_hash: String,
}

#[derive(Debug, Clone)]
pub struct NewAccount {
    pub email: String,
    pub auth_hash: String,
    pub recovery_auth_hash: String,
    pub account_public: String,
    pub wrapped_account_secret: String,
    pub wrapped_personal_key: String,
    pub recovery_account_secret: String,
    pub recovery_personal_key: String,
}

#[derive(Debug, Clone)]
pub struct TokenRow {
    pub account_id: String,
}

#[derive(Debug, Clone)]
pub struct ShareRow {
    pub group_id: String,
    pub owner_id: String,
    pub user_id: String,
    pub email: String,
    pub wrapped_group_key: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub device_id: String,
    pub name: String,
    pub last_seen: i64,
}

/// Everything the handlers need. Deliberately narrow: no method here takes SQL.
#[async_trait]
pub trait Store: Send + Sync + 'static {
    async fn migrate(&self) -> Result<()>;

    async fn create_account(&self, new: NewAccount) -> Result<Account>;
    async fn account_by_email(&self, email: &str) -> Result<Option<Account>>;
    async fn account_by_id(&self, id: &str) -> Result<Option<Account>>;
    /// Replace every credential and wrapped blob at once. Used after a recovery sign-in
    /// and by an ordinary password change; the two are the same operation.
    async fn rewrap_account(&self, id: &str, new: NewAccount) -> Result<()>;

    async fn put_token(
        &self,
        hash: &str,
        account_id: &str,
        kind: &str,
        expires_at: i64,
    ) -> Result<()>;
    async fn take_token(&self, hash: &str, kind: &str) -> Result<Option<TokenRow>>;
    /// Used on refresh: a refresh token is single-use, so it is deleted as it is read.
    async fn consume_token(&self, hash: &str, kind: &str) -> Result<Option<TokenRow>>;
    async fn revoke_account_tokens(&self, account_id: &str) -> Result<()>;

    /// Store one record and give it the next sequence number for this account.
    ///
    /// Returns `None` when the incoming record is not newer than what is already stored -
    /// the last-write-wins comparison happens here, under whatever locking the backend
    /// gives us, so two devices pushing at once cannot interleave into a lost update.
    async fn put_envelope(&self, account_id: &str, envelope: &Envelope) -> Result<Option<i64>>;

    /// Records with `seq > cursor`, oldest first, at most `limit`. Includes records from
    /// groups shared with this account.
    async fn pull(&self, account_id: &str, cursor: i64, limit: i64) -> Result<Vec<Envelope>>;

    async fn max_seq(&self, account_id: &str) -> Result<i64>;

    async fn put_share(
        &self,
        owner_id: &str,
        group_id: &str,
        user_id: &str,
        wrapped: &str,
    ) -> Result<()>;
    async fn shares_for_group(&self, owner_id: &str, group_id: &str) -> Result<Vec<ShareRow>>;
    async fn delete_share(&self, owner_id: &str, group_id: &str, user_id: &str) -> Result<()>;
    /// Every share this account is a member of, with the key wrapped for them. This is
    /// how a member gets a group key it can actually open.
    async fn shares_for_user(&self, user_id: &str) -> Result<Vec<ShareRow>>;
    /// Who owns a shared group, if anyone has shared it.
    ///
    /// Records in a shared group are stored under the **owner's** account, whoever
    /// pushed them. Storing a member's edit under the member would give one record id two
    /// independent rows, and the owner's pull - which matches on account - would never
    /// see it.
    async fn share_owner(&self, group_id: &str) -> Result<Option<String>>;
    /// May this account write records encrypted under this group's key?
    ///
    /// True when the group has no shares at all (it is the account's own, possibly about
    /// to be shared), or when the account owns it or is a member.
    async fn can_write_group(&self, account_id: &str, group_id: &str) -> Result<bool>;

    async fn touch_device(&self, account_id: &str, device_id: &str, name: &str) -> Result<()>;
    async fn devices(&self, account_id: &str) -> Result<Vec<DeviceRow>>;
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
