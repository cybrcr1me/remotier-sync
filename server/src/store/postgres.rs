//! The hosted-instance backend.
//!
//! Same shape as [`super::sqlite`], different dialect: `$n` placeholders rather than `?n`,
//! and a real sequence rather than a counter row.
//!
//! The SQL is spelled out twice on purpose. A query string rewritten at runtime to suit
//! two dialects is a query nobody can grep for when it misbehaves in production.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use remotier_sync_proto::record::{Envelope, KeyRef, RecordKind};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};

use super::{now_ms, Account, DeviceRow, NewAccount, ShareRow, Store, TokenRow};
use crate::error::{Error, Result};

pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }
}

/// The `created_at` column exists for operators reading the database; nothing in the
/// server reads it back, so it is not in the row struct.
const ACCOUNT_COLUMNS: &str = "id, email, auth_hash, recovery_auth_hash, account_public,
     wrapped_account_secret, wrapped_personal_key, recovery_account_secret,
     recovery_personal_key";

#[async_trait]
impl Store for PostgresStore {
    async fn migrate(&self) -> Result<()> {
        sqlx::raw_sql(include_str!("schema_postgres.sql"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_account(&self, new: NewAccount) -> Result<Account> {
        let id = new_id();
        let result = sqlx::query(
            "INSERT INTO accounts (id, email, auth_hash, recovery_auth_hash, account_public,
                                   wrapped_account_secret, wrapped_personal_key,
                                   recovery_account_secret, recovery_personal_key, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&id)
        .bind(new.email.trim().to_lowercase())
        .bind(&new.auth_hash)
        .bind(&new.recovery_auth_hash)
        .bind(&new.account_public)
        .bind(&new.wrapped_account_secret)
        .bind(&new.wrapped_personal_key)
        .bind(&new.recovery_account_secret)
        .bind(&new.recovery_personal_key)
        .bind(now_ms())
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(Error::EmailTaken)
            }
            Err(e) => return Err(e.into()),
        }

        self.account_by_id(&id)
            .await?
            .ok_or_else(|| Error::Internal("account vanished after insert".into()))
    }

    async fn account_by_email(&self, email: &str) -> Result<Option<Account>> {
        let row = sqlx::query(&format!(
            "SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE email = $1"
        ))
        .bind(email.trim().to_lowercase())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(account_from_row))
    }

    async fn account_by_id(&self, id: &str) -> Result<Option<Account>> {
        let row = sqlx::query(&format!(
            "SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(account_from_row))
    }

    async fn rewrap_account(&self, id: &str, new: NewAccount) -> Result<()> {
        sqlx::query(
            "UPDATE accounts SET auth_hash = $1, recovery_auth_hash = $2,
                    wrapped_account_secret = $3, wrapped_personal_key = $4,
                    recovery_account_secret = $5, recovery_personal_key = $6
             WHERE id = $7",
        )
        .bind(&new.auth_hash)
        .bind(&new.recovery_auth_hash)
        .bind(&new.wrapped_account_secret)
        .bind(&new.wrapped_personal_key)
        .bind(&new.recovery_account_secret)
        .bind(&new.recovery_personal_key)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn put_token(
        &self,
        hash: &str,
        account_id: &str,
        kind: &str,
        expires_at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO tokens (hash, account_id, kind, expires_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT(hash) DO UPDATE SET expires_at = excluded.expires_at",
        )
        .bind(hash)
        .bind(account_id)
        .bind(kind)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_token(&self, hash: &str, kind: &str) -> Result<Option<TokenRow>> {
        let row = sqlx::query(
            "SELECT account_id FROM tokens
             WHERE hash = $1 AND kind = $2 AND expires_at > $3",
        )
        .bind(hash)
        .bind(kind)
        .bind(now_ms())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| TokenRow {
            account_id: r.get("account_id"),
        }))
    }

    async fn consume_token(&self, hash: &str, kind: &str) -> Result<Option<TokenRow>> {
        let row = sqlx::query(
            "DELETE FROM tokens WHERE hash = $1 AND kind = $2 AND expires_at > $3
             RETURNING account_id",
        )
        .bind(hash)
        .bind(kind)
        .bind(now_ms())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| TokenRow {
            account_id: r.get("account_id"),
        }))
    }

    async fn revoke_account_tokens(&self, account_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM tokens WHERE account_id = $1")
            .bind(account_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn put_envelope(&self, account_id: &str, envelope: &Envelope) -> Result<Option<i64>> {
        let key_ref =
            serde_json::to_string(&envelope.key_ref).map_err(|e| Error::Internal(e.to_string()))?;

        let row = sqlx::query(
            "INSERT INTO records (account_id, kind, id, seq, group_id, parent_id, sort,
                                  updated_at, device_id, deleted_at, key_ref, nonce, ciphertext)
             VALUES ($1, $2, $3, nextval('record_seq'), $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT(account_id, kind, id) DO UPDATE SET
                 seq = excluded.seq, group_id = excluded.group_id,
                 parent_id = excluded.parent_id, sort = excluded.sort,
                 updated_at = excluded.updated_at, device_id = excluded.device_id,
                 deleted_at = excluded.deleted_at, key_ref = excluded.key_ref,
                 nonce = excluded.nonce, ciphertext = excluded.ciphertext
             WHERE excluded.updated_at > records.updated_at
                OR (excluded.updated_at = records.updated_at
                    AND excluded.device_id > records.device_id)
             RETURNING seq",
        )
        .bind(account_id)
        .bind(envelope.kind.as_str())
        .bind(&envelope.id)
        .bind(&envelope.group_id)
        .bind(&envelope.parent_id)
        .bind(envelope.sort)
        .bind(envelope.updated_at)
        .bind(&envelope.device_id)
        .bind(envelope.deleted_at)
        .bind(&key_ref)
        .bind(STANDARD.encode(&envelope.nonce))
        .bind(STANDARD.encode(&envelope.ciphertext))
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.get("seq")))
    }

    async fn pull(&self, account_id: &str, cursor: i64, limit: i64) -> Result<Vec<Envelope>> {
        let rows = sqlx::query(
            "SELECT kind, id, seq, group_id, parent_id, sort, updated_at, device_id,
                    deleted_at, key_ref, nonce, ciphertext
             FROM records
             WHERE seq > $1
               AND (account_id = $2
                    OR group_id IN (SELECT group_id FROM shares WHERE user_id = $2))
             ORDER BY seq
             LIMIT $3",
        )
        .bind(cursor)
        .bind(account_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(envelope_from_row).collect()
    }

    async fn max_seq(&self, _account_id: &str) -> Result<i64> {
        let row = sqlx::query("SELECT last_value FROM record_seq")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("last_value"))
    }

    async fn put_share(
        &self,
        owner_id: &str,
        group_id: &str,
        user_id: &str,
        wrapped: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO shares (group_id, owner_id, user_id, wrapped_group_key, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(group_id, user_id) DO UPDATE SET
                 wrapped_group_key = excluded.wrapped_group_key",
        )
        .bind(group_id)
        .bind(owner_id)
        .bind(user_id)
        .bind(wrapped)
        .bind(now_ms())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn shares_for_group(&self, owner_id: &str, group_id: &str) -> Result<Vec<ShareRow>> {
        let rows = sqlx::query(
            "SELECT s.group_id, s.owner_id, s.user_id, a.email, s.wrapped_group_key, s.created_at
             FROM shares s JOIN accounts a ON a.id = s.user_id
             WHERE s.group_id = $1 AND s.owner_id = $2",
        )
        .bind(group_id)
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(share_from_row).collect())
    }

    async fn delete_share(&self, owner_id: &str, group_id: &str, user_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM shares WHERE group_id = $1 AND owner_id = $2 AND user_id = $3")
            .bind(group_id)
            .bind(owner_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn shares_for_user(&self, user_id: &str) -> Result<Vec<ShareRow>> {
        let rows = sqlx::query(
            "SELECT s.group_id, s.owner_id, s.user_id, a.email, s.wrapped_group_key, s.created_at
             FROM shares s JOIN accounts a ON a.id = s.owner_id
             WHERE s.user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(share_from_row).collect())
    }

    async fn share_owner(&self, group_id: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT owner_id FROM shares WHERE group_id = $1 LIMIT 1")
            .bind(group_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get("owner_id")))
    }

    async fn can_write_group(&self, account_id: &str, group_id: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT
               NOT EXISTS(SELECT 1 FROM shares WHERE group_id = $1)
               OR EXISTS(SELECT 1 FROM shares
                         WHERE group_id = $1 AND (owner_id = $2 OR user_id = $2)) AS ok",
        )
        .bind(group_id)
        .bind(account_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<bool, _>("ok"))
    }

    async fn touch_device(&self, account_id: &str, device_id: &str, name: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO devices (account_id, device_id, name, last_seen)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(account_id, device_id) DO UPDATE SET
                 name = excluded.name, last_seen = excluded.last_seen",
        )
        .bind(account_id)
        .bind(device_id)
        .bind(name)
        .bind(now_ms())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn devices(&self, account_id: &str) -> Result<Vec<DeviceRow>> {
        let rows = sqlx::query(
            "SELECT device_id, name, last_seen FROM devices
             WHERE account_id = $1 ORDER BY last_seen DESC",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| DeviceRow {
                device_id: r.get("device_id"),
                name: r.get("name"),
                last_seen: r.get("last_seen"),
            })
            .collect())
    }
}

fn account_from_row(r: PgRow) -> Account {
    Account {
        id: r.get("id"),
        email: r.get("email"),
        auth_hash: r.get("auth_hash"),
        recovery_auth_hash: r.get("recovery_auth_hash"),
        account_public: r.get("account_public"),
        wrapped_account_secret: r.get("wrapped_account_secret"),
        wrapped_personal_key: r.get("wrapped_personal_key"),
        recovery_account_secret: r.get("recovery_account_secret"),
        recovery_personal_key: r.get("recovery_personal_key"),
    }
}

fn envelope_from_row(r: PgRow) -> Result<Envelope> {
    let kind: String = r.get("kind");
    let kind = RecordKind::parse(&kind)
        .ok_or_else(|| Error::Internal(format!("stored record has unknown kind {kind}")))?;
    let key_ref: String = r.get("key_ref");
    let key_ref: KeyRef =
        serde_json::from_str(&key_ref).map_err(|e| Error::Internal(e.to_string()))?;
    let nonce: String = r.get("nonce");
    let ciphertext: String = r.get("ciphertext");

    Ok(Envelope {
        id: r.get("id"),
        kind,
        key_ref,
        group_id: r.get("group_id"),
        parent_id: r.get("parent_id"),
        sort: r.get("sort"),
        updated_at: r.get("updated_at"),
        device_id: r.get("device_id"),
        deleted_at: r.get("deleted_at"),
        nonce: STANDARD
            .decode(nonce)
            .map_err(|e| Error::Internal(e.to_string()))?,
        ciphertext: STANDARD
            .decode(ciphertext)
            .map_err(|e| Error::Internal(e.to_string()))?,
        seq: r.get("seq"),
    })
}

fn new_id() -> String {
    use rand::Rng as _;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn share_from_row(r: PgRow) -> ShareRow {
    ShareRow {
        group_id: r.get("group_id"),
        owner_id: r.get("owner_id"),
        user_id: r.get("user_id"),
        email: r.get("email"),
        wrapped_group_key: r.get("wrapped_group_key"),
        created_at: r.get("created_at"),
    }
}
