//! OSV/EPSS/KEV feed cache, snapshot pinning, air-gap bundles (spec 10).
//!
//! The rules this crate embodies:
//! - Feed downloads are the ONLY sanctioned network path outside
//!   `multiscan-scope`, restricted to an allow-list of feed hosts (R-6).
//! - `multiscan db update` is the only command that fetches; a Scan pins one
//!   `FeedSnapshot` for its whole duration and never updates mid-run
//!   (FD-002, FD-003).
//! - Staleness is never silent: too-old feeds warn, and under `--offline`
//!   they are a hard exit-5 (FD-004).

mod bundle;
mod cache;
mod enrich;
mod fetch;
mod signing;
mod update;

pub use bundle::{export as export_bundle, import as import_bundle};
pub use cache::{
    cache_dir, current_snapshot, write_snapshot, FileMeta, Snapshot, SnapshotCounts, SnapshotData,
    SnapshotManifest,
};
pub use enrich::Enrichment;
pub use fetch::{FeedClient, DEFAULT_ALLOWED_HOSTS};
pub use signing::{load_or_create_signing_key, parse_public_key_hex, public_key_bytes, to_hex};
pub use update::{update, FeedSources};

/// Errors from the feed subsystem.
#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    /// Filesystem problem in the cache.
    #[error("feed cache I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Host not on the feed allow-list — refused before any connection (R-6).
    #[error("refusing to fetch from `{0}`: host is not on the feed allow-list")]
    NotAllowed(String),
    /// Malformed URL.
    #[error("invalid feed URL `{0}`")]
    BadUrl(String),
    /// Network or HTTP failure.
    #[error("feed fetch failed: {0}")]
    Fetch(String),
    /// Downloaded or cached data failed validation.
    #[error("corrupt feed data: {0}")]
    Corrupt(String),
    /// A resource exceeded a defensive size/count cap.
    #[error("feed data exceeds cap: {0}")]
    TooLarge(String),
}

/// Result of checking a snapshot's age against `--max-feed-age` (FD-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Within the allowed age.
    Fresh,
    /// Older than the allowed age; warn, or exit 5 under `--offline`.
    Stale {
        /// Age in whole hours (for the warning message).
        age_hours: i64,
    },
}

/// Compare a snapshot `as_of` against the maximum allowed age. `now` is
/// injected by the caller — this crate never reads the clock on the scan path.
pub fn freshness(
    as_of: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    max_age: std::time::Duration,
) -> Freshness {
    let age = now - as_of;
    if age > chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::MAX) {
        Freshness::Stale {
            age_hours: age.num_hours(),
        }
    } else {
        Freshness::Fresh
    }
}

/// Parse a `--max-feed-age` duration: `7d`, `12h`, `30m`, `45s` (spec 4.2).
pub fn parse_max_age(raw: &str) -> Result<std::time::Duration, FeedError> {
    let raw = raw.trim();
    let (number, unit) = raw.split_at(raw.len().saturating_sub(1));
    let value: u64 = number
        .parse()
        .map_err(|_| FeedError::Corrupt(format!("invalid duration `{raw}` (use e.g. 7d, 12h)")))?;
    let seconds = match unit {
        "d" => value.saturating_mul(86_400),
        "h" => value.saturating_mul(3_600),
        "m" => value.saturating_mul(60),
        "s" => value,
        _ => {
            return Err(FeedError::Corrupt(format!(
                "invalid duration `{raw}`: unit must be d, h, m, or s"
            )))
        }
    };
    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn max_age_parses() {
        assert_eq!(parse_max_age("7d").unwrap().as_secs(), 604_800);
        assert_eq!(parse_max_age("12h").unwrap().as_secs(), 43_200);
        assert_eq!(parse_max_age("30m").unwrap().as_secs(), 1_800);
        assert_eq!(parse_max_age("45s").unwrap().as_secs(), 45);
        assert!(parse_max_age("7w").is_err());
        assert!(parse_max_age("").is_err());
        assert!(parse_max_age("d").is_err());
    }

    #[test]
    fn freshness_boundaries() {
        let as_of = chrono::Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        let fresh_now = chrono::Utc.with_ymd_and_hms(2026, 8, 7, 0, 0, 0).unwrap();
        let stale_now = chrono::Utc.with_ymd_and_hms(2026, 8, 9, 0, 0, 0).unwrap();
        let week = std::time::Duration::from_secs(604_800);
        assert_eq!(freshness(as_of, fresh_now, week), Freshness::Fresh);
        assert_eq!(
            freshness(as_of, stale_now, week),
            Freshness::Stale { age_hours: 192 }
        );
    }
}
