use std::sync::Arc;

use crate::config::Config;
use crate::ratelimit::RateLimit;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub config: Arc<Config>,
    /// Guards `/v1/auth/*` only. Everything else is behind a bearer token already.
    pub auth_limit: Arc<RateLimit>,
}
