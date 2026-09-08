//! A small fixed-window limiter for the endpoints that guess.
//!
//! In memory, per process. That is enough for what it defends: `/v1/auth/*` is where an
//! attacker grinds passwords or enumerates addresses, and slowing that to a crawl on each
//! instance is the whole benefit. A shared store across replicas would be better and is
//! not worth a Redis dependency in a binary whose selling point is that it is one file.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimit {
    window: Duration,
    max: usize,
    hits: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl RateLimit {
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            window,
            max,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt. `false` means the caller has had enough.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().expect("rate limit mutex poisoned");

        // Sweep the whole map, not just this key. Otherwise an attacker rotating source
        // addresses grows the map without bound and the limiter becomes the leak.
        hits.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < self.window);
            !times.is_empty()
        });

        let times = hits.entry(ip).or_default();
        if times.len() >= self.max {
            return false;
        }
        times.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, last])
    }

    #[test]
    fn allows_up_to_the_limit_then_refuses() {
        let limit = RateLimit::new(3, Duration::from_secs(60));
        assert!(limit.check(ip(1)));
        assert!(limit.check(ip(1)));
        assert!(limit.check(ip(1)));
        assert!(!limit.check(ip(1)));
    }

    #[test]
    fn one_address_does_not_lock_out_another() {
        let limit = RateLimit::new(1, Duration::from_secs(60));
        assert!(limit.check(ip(1)));
        assert!(!limit.check(ip(1)));
        assert!(limit.check(ip(2)));
    }

    #[test]
    fn the_window_expires() {
        let limit = RateLimit::new(1, Duration::from_millis(20));
        assert!(limit.check(ip(1)));
        assert!(!limit.check(ip(1)));
        std::thread::sleep(Duration::from_millis(30));
        assert!(limit.check(ip(1)));
    }

    #[test]
    fn expired_addresses_are_swept_rather_than_accumulating() {
        // An attacker rotating source addresses must not grow the map without bound.
        let limit = RateLimit::new(1, Duration::from_millis(10));
        for i in 0..50 {
            limit.check(IpAddr::from([10, 0, 0, i]));
        }
        std::thread::sleep(Duration::from_millis(20));
        limit.check(ip(1));
        assert_eq!(limit.hits.lock().unwrap().len(), 1);
    }
}
