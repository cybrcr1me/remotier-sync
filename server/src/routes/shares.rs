//! Sharing a group with another user on this instance.
//!
//! The server routes a wrapped key; it never holds one it can open. Revoking a share
//! removes the row, but the client is responsible for rotating the group key afterwards -
//! the removed member already saw the old one, and no amount of server-side deletion
//! unsees it.

use axum::extract::{Path, State};
use axum::Json;
use remotier_sync_proto::api::{Share, ShareRequest};

use crate::auth::Caller;
use crate::error::{Error, Result};
use crate::state::AppState;

pub async fn create(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<ShareRequest>,
) -> Result<()> {
    if body.user_id == caller.account_id {
        return Err(Error::BadRequest("that group is already yours".into()));
    }
    // Sharing with an account that does not exist would leave a row that can never be
    // resolved to an email, and the owner would see a member they cannot name.
    state
        .store
        .account_by_id(&body.user_id)
        .await?
        .ok_or(Error::NotFound)?;

    state
        .store
        .put_share(
            &caller.account_id,
            &body.group_id,
            &body.user_id,
            &body.wrapped_group_key,
        )
        .await
}

/// Every share this account is a member of, with the group key wrapped for them.
///
/// This is how a member gets a key it can open: the wrap is sealed to their X25519
/// public key, so the server hands over a blob it cannot read itself.
pub async fn mine(State(state): State<AppState>, caller: Caller) -> Result<Json<Vec<Share>>> {
    let rows = state.store.shares_for_user(&caller.account_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Share {
                group_id: r.group_id,
                owner_id: r.owner_id,
                user_id: r.user_id,
                email: r.email,
                wrapped_group_key: r.wrapped_group_key,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

pub async fn list(
    State(state): State<AppState>,
    caller: Caller,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<Share>>> {
    let rows = state
        .store
        .shares_for_group(&caller.account_id, &group_id)
        .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| Share {
                group_id: r.group_id,
                owner_id: r.owner_id,
                user_id: r.user_id,
                email: r.email,
                wrapped_group_key: r.wrapped_group_key,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

pub async fn remove(
    State(state): State<AppState>,
    caller: Caller,
    Path((group_id, user_id)): Path<(String, String)>,
) -> Result<()> {
    // Scoped to the caller as owner, so a member cannot remove other members - or
    // themselves in a way the owner would not see.
    state
        .store
        .delete_share(&caller.account_id, &group_id, &user_id)
        .await
}
