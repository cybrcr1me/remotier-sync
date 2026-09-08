//! The wire format and envelope crypto shared by the Remotier client and its sync server.
//!
//! Both sides compile this crate, so there is exactly one definition of what travels
//! between them. That is the whole point: an end-to-end encrypted format that drifts
//! between two hand-written implementations fails as "decryption failed", which says
//! nothing about which side is wrong.
//!
//! # What the server can see
//!
//! The design is deliberately *hybrid* rather than fully opaque. An [`Envelope`] carries a
//! plaintext routing header - record id, kind, group, sort order, clock, tombstone - and
//! an encrypted payload holding everything else. The header is what lets the server hand a
//! shared group to the right people without being able to read it.
//!
//! So the server learns: how many records you have, the shape of your group tree, who a
//! group is shared with, and when you edit. It never learns a hostname, username, label,
//! tag, port, placeholder, or note.
//!
//! # Plaintext is a hint, ciphertext is the truth
//!
//! Fields that appear in both places - `group_id`, `sort` - are authoritative *inside* the
//! payload. The plaintext copy exists only so the server can route and order without
//! decrypting. A server that rewrote the plaintext copy could not move a host into another
//! group: the client reads the payload. See [`Envelope::aad`] for the rest of that story.
//!
//! # No secrets travel
//!
//! Passwords, key passphrases and private keys are not in any payload struct here, by
//! construction rather than by filtering. There is nowhere to put them.

pub mod api;
pub mod crypto;
pub mod merge;
pub mod record;

pub use crypto::{AccountKeys, ContentKey, Error as CryptoError};
pub use merge::{resolve, Clock, Resolution};
pub use record::{Envelope, KeyRef, RecordKind};

/// Bumped when a change to the envelope or payload format is not backwards compatible.
/// The server reports the versions it accepts from `GET /v1/instance`, so a client can
/// say "this instance is too old" instead of failing to decrypt.
pub const FORMAT_VERSION: u16 = 1;
