//! The one endpoint a client calls before it trusts an address.
//!
//! The sign-in screen probes this when the instance URL changes, so a typo is reported as
//! "no Remotier instance there" rather than as a failed login against a stranger's server.

use axum::extract::State;
use axum::Json;
use remotier_sync_proto::api::InstanceInfo;
use remotier_sync_proto::FORMAT_VERSION;

use crate::state::AppState;

pub async fn info(State(state): State<AppState>) -> Json<InstanceInfo> {
    Json(InstanceInfo {
        name: state.config.instance_name.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        format_versions: vec![FORMAT_VERSION],
        registration_open: state.config.registration_open,
    })
}
