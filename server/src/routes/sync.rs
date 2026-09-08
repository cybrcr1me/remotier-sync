//! Push and pull. The server's whole job, and it does it without reading anything.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::Json;
use remotier_sync_proto::api::{
    Accepted, PullResponse, PushRequest, PushResponse, RejectReason, Rejected,
};
use remotier_sync_proto::merge::clock_is_plausible;
use remotier_sync_proto::record::KeyRef;

use crate::auth::Caller;
use crate::error::{Error, Result};
use crate::state::AppState;
use crate::store::now_ms;

#[derive(serde::Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    cursor: i64,
}

pub async fn pull(
    State(state): State<AppState>,
    caller: Caller,
    Query(query): Query<PullQuery>,
) -> Result<Json<PullResponse>> {
    let limit = state.config.max_page;
    // One over the page size, so "is there more" needs no second query.
    let mut envelopes = state
        .store
        .pull(&caller.account_id, query.cursor, limit + 1)
        .await?;

    let more = envelopes.len() as i64 > limit;
    if more {
        envelopes.truncate(limit as usize);
    }

    // The cursor is the last row actually returned, never the store's high-water mark.
    // Taking the high-water mark would skip everything the page did not fit.
    let cursor = envelopes.last().map_or(query.cursor, |e| e.seq);

    Ok(Json(PullResponse {
        envelopes,
        cursor,
        more,
    }))
}

pub async fn push(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<PushRequest>,
) -> Result<Json<PushResponse>> {
    let now = now_ms();

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    // A batch touches one or two groups in practice, so the answers are cached rather
    // than asked per record.
    let mut writable: HashMap<String, bool> = HashMap::new();
    let mut owners: HashMap<String, Option<String>> = HashMap::new();

    for envelope in &body.envelopes {
        // A rejection is per record, never for the batch. One device with a wrong clock
        // must not stop every other record in the same push from landing.
        if let Some(reason) = refuse(envelope, now, &state) {
            rejected.push(Rejected {
                id: envelope.id.clone(),
                kind: envelope.kind.as_str().to_string(),
                reason,
            });
            continue;
        }

        // Records encrypted under a group key are stored under the group **owner's**
        // account, whoever pushed them. Filing a member's edit under the member would
        // give one record id two independent rows, and the owner's pull - which matches
        // on account - would never see it.
        let mut storage_account = caller.account_id.clone();
        if let KeyRef::Group { group_id } = &envelope.key_ref {
            let allowed = match writable.get(group_id) {
                Some(known) => *known,
                None => {
                    let known = state
                        .store
                        .can_write_group(&caller.account_id, group_id)
                        .await?;
                    writable.insert(group_id.clone(), known);
                    known
                }
            };
            if !allowed {
                rejected.push(Rejected {
                    id: envelope.id.clone(),
                    kind: envelope.kind.as_str().to_string(),
                    reason: RejectReason::NotAMember,
                });
                continue;
            }

            let owner = match owners.get(group_id) {
                Some(known) => known.clone(),
                None => {
                    let known = state.store.share_owner(group_id).await?;
                    owners.insert(group_id.clone(), known.clone());
                    known
                }
            };
            if let Some(owner) = owner {
                storage_account = owner;
            }
        }

        match state.store.put_envelope(&storage_account, envelope).await? {
            Some(seq) => accepted.push(Accepted {
                id: envelope.id.clone(),
                kind: envelope.kind.as_str().to_string(),
                seq,
            }),
            // The stored copy is newer. Not an error: the client pulls and merges.
            None => rejected.push(Rejected {
                id: envelope.id.clone(),
                kind: envelope.kind.as_str().to_string(),
                reason: RejectReason::Stale,
            }),
        }
    }

    let cursor = state.store.max_seq(&caller.account_id).await?;
    Ok(Json(PushResponse {
        accepted,
        rejected,
        cursor,
    }))
}

/// The checks that need no database. Group membership is decided in `push`, where the
/// answers can be cached across a batch.
fn refuse(
    envelope: &remotier_sync_proto::record::Envelope,
    now: i64,
    state: &AppState,
) -> Option<RejectReason> {
    if !clock_is_plausible(envelope.updated_at, now) {
        return Some(RejectReason::ImplausibleClock);
    }
    if envelope.ciphertext.len() > state.config.max_record_bytes {
        return Some(RejectReason::TooLarge);
    }
    None
}

// `Error` is used by the extractors above; naming it keeps the import honest.
const _: fn() -> Option<Error> = || None;
