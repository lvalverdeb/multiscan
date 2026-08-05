//! Store trait and SQLite implementation: baselines, history, suppressions (spec 11).
//!
//! The [`Store`] trait is the seam for a future server backend (P-8, STO-005):
//! no SQLite type ever appears in its signatures, so swapping the backend is a
//! new impl, not a rewrite. History is event-sourced — status and score
//! changes append, never overwrite (STO-002).

mod memory;
mod sqlite;

use chrono::{DateTime, Utc};
use multiscan_core::{Finding, FindingId};

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;

/// Errors from the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Underlying database error.
    #[error("store backend error: {0}")]
    Backend(String),
    /// The database was written by a newer binary; refusing to open it rather
    /// than risk corruption (STO-004).
    #[error("database schema version {found} is newer than this binary supports ({supported}); upgrade multiscan")]
    SchemaTooNew {
        /// Version found on disk.
        found: u32,
        /// Highest version this binary understands.
        supported: u32,
    },
    /// A stored record could not be (de)serialized.
    #[error("store serialization error: {0}")]
    Serialization(String),
}

/// Counts from an upsert pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpsertStats {
    /// Findings seen for the first time.
    pub new: u64,
    /// Findings whose status or score changed.
    pub updated: u64,
    /// Findings present and unchanged.
    pub unchanged: u64,
}

/// One append-only history event for a Finding (STO-002).
#[derive(Debug, Clone, PartialEq)]
pub struct FindingEvent {
    /// The Finding this event belongs to.
    pub finding_id: String,
    /// When it was recorded (injected via `ScanContext`, never a store clock).
    pub at: DateTime<Utc>,
    /// What changed.
    pub kind: FindingEventKind,
}

/// The kind of a history event.
#[derive(Debug, Clone, PartialEq)]
pub enum FindingEventKind {
    /// First time this Finding was recorded.
    FirstSeen {
        /// Status at first sight.
        status: String,
    },
    /// Lifecycle status changed (e.g. `open` → `fixed`).
    StatusChanged {
        /// Previous status.
        from: String,
        /// New status.
        to: String,
    },
    /// Risk score changed by more than a negligible epsilon.
    ScoreChanged {
        /// Previous score.
        from: f64,
        /// New score.
        to: f64,
    },
}

/// A time-bounded, justified suppression (spec 2, CLI-006).
#[derive(Debug, Clone, PartialEq)]
pub struct Suppression {
    /// The suppressed Finding.
    pub finding_id: String,
    /// Why it is suppressed.
    pub justification: String,
    /// Who approved it.
    pub approver: String,
    /// When it expires; after this the Finding gates normally (FR-014).
    pub expires: DateTime<Utc>,
}

/// Persistent storage for Findings, baselines, history, and suppressions.
///
/// The trait is deliberately backend-agnostic (STO-005). `now` is always
/// passed in, never read from a store-side clock, so behaviour is testable and
/// deterministic (DET-004).
pub trait Store {
    /// Record a scan's Findings, appending history events for anything new or
    /// changed (STO-002). Returns per-category counts.
    fn upsert_findings(
        &mut self,
        findings: &[Finding],
        now: DateTime<Utc>,
    ) -> Result<UpsertStats, StoreError>;

    /// Load a named baseline Finding set (empty if it does not exist).
    fn load_baseline(&self, name: &str) -> Result<Vec<Finding>, StoreError>;

    /// Replace a named baseline with the given Findings.
    fn save_baseline(&mut self, name: &str, findings: &[Finding]) -> Result<(), StoreError>;

    /// Full append-only history for one Finding, oldest first.
    fn history(&self, finding_id: &FindingId) -> Result<Vec<FindingEvent>, StoreError>;

    /// Suppressions still active at `now` (STO-004/FR-014).
    fn active_suppressions(&self, now: DateTime<Utc>) -> Result<Vec<Suppression>, StoreError>;

    /// Add or replace a suppression.
    fn put_suppression(&mut self, suppression: &Suppression) -> Result<(), StoreError>;
}
