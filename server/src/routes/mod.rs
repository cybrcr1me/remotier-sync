pub mod auth;
pub mod devices;
pub mod instance;
pub mod shares;
pub mod sync;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/instance", get(instance::info))
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/refresh", post(auth::refresh))
        .route("/v1/auth/recover", post(auth::recover))
        .route("/v1/auth/rewrap", post(auth::rewrap))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/account/keys", get(auth::keys))
        .route("/v1/users/lookup", get(auth::lookup))
        .route("/v1/sync", get(sync::pull).post(sync::push))
        .route("/v1/shares", get(shares::mine).post(shares::create))
        .route("/v1/shares/{group_id}", get(shares::list))
        .route("/v1/shares/{group_id}/{user_id}", delete(shares::remove))
        .route("/v1/devices", get(devices::list))
        .with_state(state)
}
