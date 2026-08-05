//! Per-host rate control and 5xx circuit breaker (SEC-006, SEC-007). Time is
//! injected (monotonic millis) so behaviour is deterministically testable.

use std::collections::BTreeMap;

/// Per-host token bucket + a 5xx-over-window breaker.
pub struct RateControl {
    /// Requests per second permitted per host.
    rps: f64,
    /// Rolling window for the 5xx breaker, in milliseconds.
    window_ms: u64,
    /// Fraction of 5xx over the window that trips the breaker (SEC-007).
    breaker_fraction: f64,
    hosts: BTreeMap<String, HostState>,
}

struct HostState {
    tokens: f64,
    last_refill_ms: u64,
    /// (timestamp_ms, was_5xx) samples within the window.
    outcomes: Vec<(u64, bool)>,
}

/// Outcome of asking to send a request now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permit {
    /// Send now.
    Go,
    /// Wait this many milliseconds before retrying (bucket empty).
    Wait(u64),
    /// The 5xx breaker tripped; abort the scan of this host (SEC-007).
    Abort,
}

impl RateControl {
    /// Rate control for a profile: 5 rps for `quick`, 25 rps otherwise
    /// (SEC-006). The 5xx breaker trips at ≥20% over a 60 s window (SEC-007).
    pub fn for_rps(rps: f64) -> Self {
        Self {
            rps,
            window_ms: 60_000,
            breaker_fraction: 0.20,
            hosts: BTreeMap::new(),
        }
    }

    /// Ask whether a request to `host` may be sent at `now_ms`.
    pub fn poll(&mut self, host: &str, now_ms: u64) -> Permit {
        let rps = self.rps;
        let window = self.window_ms;
        let fraction = self.breaker_fraction;
        let state = self.hosts.entry(host.to_string()).or_insert(HostState {
            tokens: rps,
            last_refill_ms: now_ms,
            outcomes: Vec::new(),
        });

        // Breaker: if enough samples and the 5xx fraction is over the limit,
        // abort. Require a minimum sample count so one early 5xx doesn't trip it.
        state
            .outcomes
            .retain(|(t, _)| now_ms.saturating_sub(*t) <= window);
        let total = state.outcomes.len();
        if total >= 5 {
            let bad = state.outcomes.iter().filter(|(_, is5xx)| *is5xx).count();
            if bad as f64 / total as f64 >= fraction {
                return Permit::Abort;
            }
        }

        // Token bucket refill.
        let elapsed = now_ms.saturating_sub(state.last_refill_ms) as f64;
        state.tokens = (state.tokens + elapsed / 1000.0 * rps).min(rps);
        state.last_refill_ms = now_ms;
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Permit::Go
        } else {
            let needed = 1.0 - state.tokens;
            Permit::Wait((needed / rps * 1000.0).ceil() as u64)
        }
    }

    /// Record a response outcome for the 5xx breaker (SEC-007).
    pub fn record_response(&mut self, host: &str, now_ms: u64, status: u16) {
        if let Some(state) = self.hosts.get_mut(host) {
            state.outcomes.push((now_ms, (500..600).contains(&status)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_limits_then_refills() {
        let mut rc = RateControl::for_rps(5.0);
        // Burst of 5 allowed, 6th must wait.
        for _ in 0..5 {
            assert_eq!(rc.poll("h", 0), Permit::Go);
        }
        assert!(matches!(rc.poll("h", 0), Permit::Wait(_)));
        // After 1s, tokens refill.
        assert_eq!(rc.poll("h", 1000), Permit::Go);
    }

    #[test]
    fn breaker_trips_on_5xx_fraction() {
        let mut rc = RateControl::for_rps(25.0);
        for i in 0..10u64 {
            let _ = rc.poll("h", i);
            // 3 of 10 are 5xx → 30% ≥ 20% → abort.
            rc.record_response("h", i, if i < 3 { 503 } else { 200 });
        }
        assert_eq!(rc.poll("h", 11), Permit::Abort);
    }

    #[test]
    fn breaker_ignores_old_samples() {
        let mut rc = RateControl::for_rps(25.0);
        // Old 5xx outside the 60s window are dropped.
        for i in 0..6u64 {
            let _ = rc.poll("h", i);
            rc.record_response("h", i, 503);
        }
        // Far in the future, the window has cleared.
        assert_ne!(rc.poll("h", 200_000), Permit::Abort);
    }
}
