use axum::extract::State;
use axum::Json;
use remotier_sync_proto::api::Device;

use crate::auth::Caller;
use crate::error::Result;
use crate::state::AppState;

pub async fn list(State(state): State<AppState>, caller: Caller) -> Result<Json<Vec<Device>>> {
    let devices = state.store.devices(&caller.account_id).await?;
    Ok(Json(
        devices
            .into_iter()
            .map(|d| Device {
                device_id: d.device_id,
                name: d.name,
                last_seen: d.last_seen,
            })
            .collect(),
    ))
}
