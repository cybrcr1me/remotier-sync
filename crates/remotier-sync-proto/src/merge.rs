//! Which of two versions of a record wins.
//!
//! Per-record last-write-wins. The newest write to a record replaces it whole; a
//! concurrent edit to a *different field* of the same record is lost. That is the accepted
//! trade for SSH config, where two people rarely edit one host in the same minute, and it
//! is about two hundred lines less machinery than per-field timestamps or a CRDT.
//!
//! Deletion is a write like any other, which is why tombstones exist: without one, the
//! device that still has the record simply pushes it back and the deletion undoes itself.

/// One side's claim on a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock<'a> {
    pub updated_at: i64,
    /// Breaks an exact tie. Any deterministic rule would do; what matters is that both
    /// devices reach the *same* answer without talking to each other.
    pub device_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    KeepLocal,
    TakeRemote,
}

/// Resolve two claims on the same record id.
///
/// Ties go to the higher device id rather than to the remote, so a device that pushes and
/// then immediately pulls its own write back does not flap between two equal versions.
pub fn resolve(local: Clock<'_>, remote: Clock<'_>) -> Resolution {
    match remote.updated_at.cmp(&local.updated_at) {
        std::cmp::Ordering::Greater => Resolution::TakeRemote,
        std::cmp::Ordering::Less => Resolution::KeepLocal,
        std::cmp::Ordering::Equal => {
            if remote.device_id > local.device_id {
                Resolution::TakeRemote
            } else {
                Resolution::KeepLocal
            }
        }
    }
}

/// The furthest-in-the-future `updated_at` a server will accept, as milliseconds.
///
/// A device whose clock is set years ahead would otherwise win every conflict forever, and
/// no amount of editing on a correct machine could dislodge it. A day of slack leaves
/// genuine offline edits and ordinary timezone confusion untouched.
pub const MAX_CLOCK_SKEW_MS: i64 = 24 * 60 * 60 * 1000;

pub fn clock_is_plausible(updated_at: i64, server_now: i64) -> bool {
    updated_at <= server_now + MAX_CLOCK_SKEW_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(updated_at: i64, device_id: &str) -> Clock<'_> {
        Clock {
            updated_at,
            device_id,
        }
    }

    #[test]
    fn the_newer_write_wins() {
        assert_eq!(resolve(at(100, "a"), at(200, "b")), Resolution::TakeRemote);
        assert_eq!(resolve(at(200, "a"), at(100, "b")), Resolution::KeepLocal);
    }

    #[test]
    fn an_exact_tie_is_broken_the_same_way_on_both_devices() {
        // Device A comparing itself to B, and device B comparing itself to A, must choose
        // the same winner - otherwise the two sit swapping versions forever.
        let a_sees = resolve(at(100, "a"), at(100, "b"));
        let b_sees = resolve(at(100, "b"), at(100, "a"));
        assert_eq!(a_sees, Resolution::TakeRemote);
        assert_eq!(b_sees, Resolution::KeepLocal);
    }

    #[test]
    fn a_device_does_not_flap_against_its_own_echo() {
        // Pushing a record and pulling it straight back compares a clock against itself.
        assert_eq!(resolve(at(100, "a"), at(100, "a")), Resolution::KeepLocal);
    }

    #[test]
    fn a_newer_delete_beats_an_older_edit() {
        // Tombstones are ordinary writes; nothing here needs to know they are deletions.
        assert_eq!(resolve(at(100, "a"), at(150, "b")), Resolution::TakeRemote);
    }

    #[test]
    fn an_older_edit_does_not_resurrect_a_newer_delete() {
        assert_eq!(resolve(at(150, "a"), at(100, "b")), Resolution::KeepLocal);
    }

    #[test]
    fn a_clock_a_little_ahead_is_accepted() {
        let now = 1_700_000_000_000;
        assert!(clock_is_plausible(now + 60_000, now));
        assert!(clock_is_plausible(now - 999_999_999, now));
    }

    #[test]
    fn a_clock_years_ahead_is_refused() {
        let now = 1_700_000_000_000;
        assert!(!clock_is_plausible(now + 400 * 24 * 3600 * 1000, now));
    }
}
