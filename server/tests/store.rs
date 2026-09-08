// The `#[path]` imports below pull in whole modules, most of which these tests do not
// touch. That is the cost of testing a binary crate's internals without a lib.rs.
#![allow(dead_code)]

//! The store contract, exercised against SQLite.
//!
//! These are the tests that would catch a Postgres backend drifting from the SQLite one:
//! everything here goes through the `Store` trait, so pointing `store()` at a
//! `PostgresStore` runs the same suite unchanged. That is the reason the trait exists.

use remotier_sync_proto::record::{Envelope, KeyRef, RecordKind};

// The server crate is a binary, so its modules are pulled in by path rather than by
// `use remotier_sync_server::…`. A `lib.rs` purely to make tests reachable would be more
// machinery than this costs.
#[path = "../src/config.rs"]
mod config;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/ratelimit.rs"]
mod ratelimit;
#[path = "../src/state.rs"]
mod state;
#[path = "../src/store/mod.rs"]
mod store;

use store::{sqlite::SqliteStore, NewAccount, Store};

async fn fresh() -> SqliteStore {
    // A shared-cache in-memory database, so the pool's several connections all see the
    // same tables. A plain `:memory:` gives each connection its own empty database, which
    // fails as "no such table" on the second query and looks like a migration bug.
    //
    // The name has to be unique per test: cargo runs these in parallel threads of one
    // process, and a shared name makes every test fight over one set of tables.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let store = SqliteStore::connect(&format!(
        "sqlite:file:store-test-{n}?mode=memory&cache=shared"
    ))
    .await
    .unwrap();
    store.migrate().await.unwrap();
    store
}

fn account(email: &str) -> NewAccount {
    NewAccount {
        email: email.into(),
        auth_hash: "hash".into(),
        recovery_auth_hash: "recovery".into(),
        account_public: "pub".into(),
        wrapped_account_secret: "n.c".into(),
        wrapped_personal_key: "n.c".into(),
        recovery_account_secret: "n.c".into(),
        recovery_personal_key: "n.c".into(),
    }
}

fn envelope(id: &str, updated_at: i64, device: &str) -> Envelope {
    Envelope {
        id: id.into(),
        kind: RecordKind::Host,
        key_ref: KeyRef::Personal,
        group_id: None,
        parent_id: None,
        sort: 0,
        updated_at,
        device_id: device.into(),
        deleted_at: None,
        nonce: vec![1; 24],
        ciphertext: vec![9; 32],
        seq: 0,
    }
}

#[tokio::test]
async fn an_email_can_only_be_registered_once() {
    let store = fresh().await;
    store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();

    let again = store.create_account(account("ada@example.com")).await;
    assert!(matches!(again, Err(error::Error::EmailTaken)));

    // And case is not a way around it - otherwise Ada@ and ada@ become two vaults that
    // each think they are hers.
    let cased = store.create_account(account("ADA@example.com")).await;
    assert!(matches!(cased, Err(error::Error::EmailTaken)));
}

#[tokio::test]
async fn a_refresh_token_works_once() {
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    store
        .put_token("hash-1", &a.id, "refresh", i64::MAX)
        .await
        .unwrap();

    assert!(store
        .consume_token("hash-1", "refresh")
        .await
        .unwrap()
        .is_some());
    // A stolen copy replayed after the real client refreshed finds nothing.
    assert!(store
        .consume_token("hash-1", "refresh")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn an_expired_token_is_not_accepted() {
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    store.put_token("old", &a.id, "access", 1).await.unwrap();
    assert!(store.take_token("old", "access").await.unwrap().is_none());
}

#[tokio::test]
async fn a_token_of_the_wrong_kind_is_not_accepted() {
    // Otherwise a refresh token would work as a bearer token, and never expire.
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    store
        .put_token("t", &a.id, "refresh", i64::MAX)
        .await
        .unwrap();
    assert!(store.take_token("t", "access").await.unwrap().is_none());
}

#[tokio::test]
async fn signing_out_ends_every_session() {
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    store
        .put_token("t1", &a.id, "access", i64::MAX)
        .await
        .unwrap();
    store
        .put_token("t2", &a.id, "access", i64::MAX)
        .await
        .unwrap();

    store.revoke_account_tokens(&a.id).await.unwrap();
    assert!(store.take_token("t1", "access").await.unwrap().is_none());
    assert!(store.take_token("t2", "access").await.unwrap().is_none());
}

#[tokio::test]
async fn the_newer_write_wins_and_the_older_one_is_refused() {
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();

    assert!(store
        .put_envelope(&a.id, &envelope("h1", 200, "dev-a"))
        .await
        .unwrap()
        .is_some());

    // An older edit arriving late must not undo the newer one.
    assert!(store
        .put_envelope(&a.id, &envelope("h1", 100, "dev-b"))
        .await
        .unwrap()
        .is_none());

    let pulled = store.pull(&a.id, 0, 10).await.unwrap();
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].updated_at, 200);
}

#[tokio::test]
async fn an_exact_tie_is_broken_by_device_id() {
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();

    store
        .put_envelope(&a.id, &envelope("h1", 100, "dev-a"))
        .await
        .unwrap();
    store
        .put_envelope(&a.id, &envelope("h1", 100, "dev-b"))
        .await
        .unwrap();

    let pulled = store.pull(&a.id, 0, 10).await.unwrap();
    assert_eq!(
        pulled[0].device_id, "dev-b",
        "the higher device id takes the tie"
    );

    // And the same tie resolved the other way round does nothing, so the two devices do
    // not sit swapping versions.
    assert!(store
        .put_envelope(&a.id, &envelope("h1", 100, "dev-a"))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_cursor_walks_forward_and_never_repeats() {
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();

    for i in 0..5 {
        store
            .put_envelope(&a.id, &envelope(&format!("h{i}"), 100 + i, "dev-a"))
            .await
            .unwrap();
    }

    let first = store.pull(&a.id, 0, 2).await.unwrap();
    assert_eq!(first.len(), 2);
    let cursor = first.last().unwrap().seq;

    let second = store.pull(&a.id, cursor, 10).await.unwrap();
    assert_eq!(second.len(), 3);
    assert!(second.iter().all(|e| e.seq > cursor));
}

#[tokio::test]
async fn an_edit_moves_a_record_to_the_end_of_the_log() {
    // A device that has already pulled everything must still see a later edit, so an
    // updated record has to take a new sequence number rather than keeping its old one.
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();

    store
        .put_envelope(&a.id, &envelope("h1", 100, "dev-a"))
        .await
        .unwrap();
    store
        .put_envelope(&a.id, &envelope("h2", 100, "dev-a"))
        .await
        .unwrap();
    let caught_up = store.pull(&a.id, 0, 10).await.unwrap().last().unwrap().seq;

    store
        .put_envelope(&a.id, &envelope("h1", 300, "dev-b"))
        .await
        .unwrap();

    let after = store.pull(&a.id, caught_up, 10).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, "h1");
}

#[tokio::test]
async fn a_tombstone_is_stored_and_pulled_like_any_other_record() {
    let store = fresh().await;
    let a = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();

    store
        .put_envelope(&a.id, &envelope("h1", 100, "dev-a"))
        .await
        .unwrap();

    let mut dead = envelope("h1", 200, "dev-a");
    dead.deleted_at = Some(200);
    dead.ciphertext.clear();
    store.put_envelope(&a.id, &dead).await.unwrap();

    let pulled = store.pull(&a.id, 0, 10).await.unwrap();
    assert_eq!(pulled.len(), 1);
    assert!(pulled[0].deleted_at.is_some());
    assert!(
        pulled[0].ciphertext.is_empty(),
        "a tombstone carries no payload"
    );
}

#[tokio::test]
async fn one_account_cannot_see_anothers_records() {
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();

    store
        .put_envelope(&ada.id, &envelope("h1", 100, "dev-a"))
        .await
        .unwrap();

    assert!(store.pull(&bob.id, 0, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_shared_group_reaches_its_member_and_stops_there() {
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();
    let eve = store
        .create_account(account("eve@example.com"))
        .await
        .unwrap();

    let mut in_group = envelope("h1", 100, "dev-a");
    in_group.group_id = Some("g1".into());
    in_group.key_ref = KeyRef::Group {
        group_id: "g1".into(),
    };
    store.put_envelope(&ada.id, &in_group).await.unwrap();

    let private = envelope("h2", 100, "dev-a");
    store.put_envelope(&ada.id, &private).await.unwrap();

    store
        .put_share(&ada.id, "g1", &bob.id, "wrapped")
        .await
        .unwrap();

    let bobs = store.pull(&bob.id, 0, 10).await.unwrap();
    assert_eq!(bobs.len(), 1, "only the shared group, not Ada's other host");
    assert_eq!(bobs[0].id, "h1");

    assert!(store.pull(&eve.id, 0, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn revoking_a_share_stops_the_records_arriving() {
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();

    let mut in_group = envelope("h1", 100, "dev-a");
    in_group.group_id = Some("g1".into());
    store.put_envelope(&ada.id, &in_group).await.unwrap();
    store
        .put_share(&ada.id, "g1", &bob.id, "wrapped")
        .await
        .unwrap();
    assert_eq!(store.pull(&bob.id, 0, 10).await.unwrap().len(), 1);

    store.delete_share(&ada.id, "g1", &bob.id).await.unwrap();
    assert!(store.pull(&bob.id, 0, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_member_cannot_revoke_a_share_they_do_not_own() {
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();

    let mut in_group = envelope("h1", 100, "dev-a");
    in_group.group_id = Some("g1".into());
    store.put_envelope(&ada.id, &in_group).await.unwrap();
    store
        .put_share(&ada.id, "g1", &bob.id, "wrapped")
        .await
        .unwrap();

    // Bob passing his own id as the owner deletes nothing.
    store.delete_share(&bob.id, "g1", &bob.id).await.unwrap();
    assert_eq!(store.pull(&bob.id, 0, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_password_change_does_not_touch_a_single_record() {
    // The account keys never change; only what wraps them does. This is why a password
    // change is instant rather than a re-encryption of everything the user owns.
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    store
        .put_envelope(&ada.id, &envelope("h1", 100, "dev-a"))
        .await
        .unwrap();
    let before = store.pull(&ada.id, 0, 10).await.unwrap();

    store
        .rewrap_account(
            &ada.id,
            NewAccount {
                auth_hash: "new-hash".into(),
                ..account("ada@example.com")
            },
        )
        .await
        .unwrap();

    let after = store.pull(&ada.id, 0, 10).await.unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before[0].ciphertext, after[0].ciphertext);
    assert_eq!(
        store
            .account_by_id(&ada.id)
            .await
            .unwrap()
            .unwrap()
            .auth_hash,
        "new-hash"
    );
}

#[tokio::test]
async fn devices_are_listed_most_recently_seen_first() {
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();

    store
        .touch_device(&ada.id, "d1", "MacBook Pro")
        .await
        .unwrap();
    store.touch_device(&ada.id, "d2", "Desktop").await.unwrap();
    store
        .touch_device(&ada.id, "d1", "MacBook Pro")
        .await
        .unwrap();

    let devices = store.devices(&ada.id).await.unwrap();
    assert_eq!(
        devices.len(),
        2,
        "touching twice updates rather than duplicates"
    );
    assert_eq!(devices[0].device_id, "d1");
}

#[tokio::test]
async fn the_owner_may_write_to_a_group_they_shared() {
    // The owner is not a member of their own share, so a membership check that only
    // matches `user_id` locks the person who did the sharing out of their own group.
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();
    store
        .put_share(&ada.id, "g1", &bob.id, "wrapped")
        .await
        .unwrap();

    assert!(store.can_write_group(&ada.id, "g1").await.unwrap());
    assert!(store.can_write_group(&bob.id, "g1").await.unwrap());
}

#[tokio::test]
async fn a_stranger_may_not_write_to_someone_elses_shared_group() {
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();
    let eve = store
        .create_account(account("eve@example.com"))
        .await
        .unwrap();
    store
        .put_share(&ada.id, "g1", &bob.id, "wrapped")
        .await
        .unwrap();

    assert!(!store.can_write_group(&eve.id, "g1").await.unwrap());
}

#[tokio::test]
async fn an_unshared_group_is_writable_by_anyone_who_owns_its_records() {
    // A group key is generated before the first share row exists. Refusing here would
    // make the first push of a group about to be shared fail.
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    assert!(store
        .can_write_group(&ada.id, "never-shared")
        .await
        .unwrap());
}

#[tokio::test]
async fn a_members_edit_lands_on_the_owners_copy() {
    // The bug this guards: filing a member's push under the member's own account gives
    // one record id two independent rows, and the owner - who pulls by account - never
    // sees the edit.
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();
    store
        .put_share(&ada.id, "g1", &bob.id, "wrapped")
        .await
        .unwrap();

    let mut owned = envelope("h1", 100, "dev-a");
    owned.group_id = Some("g1".into());
    owned.key_ref = KeyRef::Group {
        group_id: "g1".into(),
    };
    store.put_envelope(&ada.id, &owned).await.unwrap();

    // Bob edits. The route resolves the storage account to the group's owner.
    let owner = store.share_owner("g1").await.unwrap().unwrap();
    assert_eq!(owner, ada.id);

    let mut edited = envelope("h1", 200, "dev-b");
    edited.group_id = Some("g1".into());
    edited.key_ref = KeyRef::Group {
        group_id: "g1".into(),
    };
    store.put_envelope(&owner, &edited).await.unwrap();

    // One row, not two, and the owner sees the newer version.
    let adas = store.pull(&ada.id, 0, 10).await.unwrap();
    assert_eq!(adas.len(), 1);
    assert_eq!(adas[0].updated_at, 200);

    let bobs = store.pull(&bob.id, 0, 10).await.unwrap();
    assert_eq!(bobs.len(), 1);
    assert_eq!(bobs[0].updated_at, 200);
}

#[tokio::test]
async fn an_unshared_group_has_no_owner_so_records_stay_with_their_author() {
    let store = fresh().await;
    store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    assert_eq!(store.share_owner("g1").await.unwrap(), None);
}

#[tokio::test]
async fn a_member_gets_the_key_wrapped_for_them() {
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();
    store
        .put_share(&ada.id, "g1", &bob.id, "sealed-for-bob")
        .await
        .unwrap();

    let mine = store.shares_for_user(&bob.id).await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].wrapped_group_key, "sealed-for-bob");
    assert_eq!(
        mine[0].owner_id, ada.id,
        "the owner is named explicitly, not inferred"
    );
    // The email shown is the owner's - who shared this with me, not my own address.
    assert_eq!(mine[0].email, "ada@example.com");

    assert!(store.shares_for_user(&ada.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn re_sharing_replaces_the_wrap_rather_than_duplicating_it() {
    // Rotation re-wraps the new key for every remaining member.
    let store = fresh().await;
    let ada = store
        .create_account(account("ada@example.com"))
        .await
        .unwrap();
    let bob = store
        .create_account(account("bob@example.com"))
        .await
        .unwrap();

    store
        .put_share(&ada.id, "g1", &bob.id, "old-wrap")
        .await
        .unwrap();
    store
        .put_share(&ada.id, "g1", &bob.id, "new-wrap")
        .await
        .unwrap();

    let mine = store.shares_for_user(&bob.id).await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].wrapped_group_key, "new-wrap");
}
