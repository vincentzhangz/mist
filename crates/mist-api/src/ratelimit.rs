//! Per-IP sliding-window rate limiter for the login endpoint.
//!
//! Brute-force protection: at most [`DEFAULT_MAX_ATTEMPTS`] login attempts
//! per [`DEFAULT_WINDOW`] per client IP, with `429 + Retry-After` beyond
//! that. Pure in-memory state (a restart clears it); the API is
//! single-replica, so no shared store is needed.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

/// Default login attempts allowed per window per IP.
const DEFAULT_MAX_ATTEMPTS: usize = 10;
/// Default rate-limit window.
const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
/// Cap on distinct IPs tracked; entries pruned oldest-first beyond this.
const MAX_IPS: usize = 10_000;

/// Outcome of a rate-limit check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Under the limit; the attempt was recorded.
    Allow,
    /// Over the limit; retry after this many seconds.
    Deny {
        /// Value for the `Retry-After` header, always `>= 1`.
        retry_after_secs: u64,
    },
}

/// Thread-safe login rate limiter (interior mutability; share by reference).
#[derive(Debug)]
pub struct LoginLimiter {
    max_attempts: usize,
    window: Duration,
    inner: std::sync::Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ATTEMPTS, DEFAULT_WINDOW)
    }
}

impl LoginLimiter {
    /// A limiter allowing `max_attempts` per `window` per IP.
    #[must_use]
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            inner: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Record an attempt from `ip` and return whether it may proceed.
    #[must_use]
    pub fn check(&self, ip: IpAddr) -> Verdict {
        let mut buckets = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        // `unwrap_or(now)`: on machines booted inside the window, treat all
        // prior attempts as expired rather than underflowing.
        let window_start = now.checked_sub(self.window).unwrap_or(now);
        let attempts = buckets.entry(ip).or_default();
        while attempts.front().is_some_and(|seen| *seen < window_start) {
            attempts.pop_front();
        }
        if attempts.len() >= self.max_attempts {
            let oldest = attempts.front().copied().unwrap_or(now);
            let retry_after = self
                .window
                .saturating_sub(now.saturating_duration_since(oldest))
                .as_secs()
                .max(1);
            return Verdict::Deny {
                retry_after_secs: retry_after,
            };
        }
        attempts.push_back(now);
        if buckets.len() > MAX_IPS {
            buckets.retain(|_, seen| seen.back().is_some_and(|last| *last >= window_start));
            if buckets.len() > MAX_IPS
                && let Some(victim) = buckets.keys().next().copied()
            {
                buckets.remove(&victim);
            }
        }
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn allows_up_to_limit_then_denies_with_retry_after() {
        let limiter = LoginLimiter::new(3, Duration::from_secs(60));
        assert_eq!(limiter.check(ip(1)), Verdict::Allow);
        assert_eq!(limiter.check(ip(1)), Verdict::Allow);
        assert_eq!(limiter.check(ip(1)), Verdict::Allow);
        let Verdict::Deny { retry_after_secs } = limiter.check(ip(1)) else {
            panic!("fourth attempt within the window must be denied");
        };
        assert!((1..=60).contains(&retry_after_secs));
    }

    #[test]
    fn buckets_are_per_ip() {
        let limiter = LoginLimiter::new(1, Duration::from_secs(60));
        assert_eq!(limiter.check(ip(1)), Verdict::Allow);
        assert!(matches!(limiter.check(ip(1)), Verdict::Deny { .. }));
        assert_eq!(limiter.check(ip(2)), Verdict::Allow);
    }

    #[test]
    fn window_expiry_readmits() {
        let limiter = LoginLimiter::new(1, Duration::from_millis(20));
        assert_eq!(limiter.check(ip(1)), Verdict::Allow);
        assert!(matches!(limiter.check(ip(1)), Verdict::Deny { .. }));
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(limiter.check(ip(1)), Verdict::Allow);
    }
}
