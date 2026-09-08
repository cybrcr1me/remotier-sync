//! Configuration, all from the environment so a container needs no config file.

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    /// `sqlite://…` or `postgres://…`. The scheme picks the store.
    pub database_url: String,
    pub instance_name: String,
    pub registration_open: bool,
    /// How long an access token lives. Refresh tokens live until they are used or revoked.
    pub access_ttl_secs: i64,
    /// Largest single record the server will store, in bytes.
    pub max_record_bytes: usize,
    pub max_page: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let bind = var("REMOTIER_BIND", "0.0.0.0:8787")
            .parse()
            .map_err(|e| format!("REMOTIER_BIND is not an address: {e}"))?;

        Ok(Self {
            bind,
            database_url: var("DATABASE_URL", "sqlite://remotier-sync.db?mode=rwc"),
            instance_name: var("REMOTIER_INSTANCE_NAME", "Remotier Sync"),
            // Defaults closed. An instance that accepts registrations the moment it is
            // reachable is a instance someone else's account ends up on.
            registration_open: var("REMOTIER_REGISTRATION_OPEN", "false") == "true",
            access_ttl_secs: 3600,
            max_record_bytes: 256 * 1024,
            max_page: 500,
        })
    }
}

fn var(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}
