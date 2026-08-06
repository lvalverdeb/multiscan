//! Engine trait, EngineManifest, FindingSink, registry (spec 6).
//!
//! Engines are built-in Rust detection modules. They stream `RawFinding`s
//! into a sink, honour cancellation and deadlines, and never touch the store,
//! config, or stdout directly (ENG-003) — everything flows through
//! `ScanContext` and the sink.
//!
//! The `EngineManifest` type is generated from `schemas/engine-manifest.json`
//! (R-4); the spec 6.1 `&'static str` spelling is realised as owned fields
//! constructed once per engine instance.

mod pathfilter;
mod registry;
pub mod testkit;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

pub use multiscan_core::{EngineManifest, Layer, Profile, RawFinding};
pub use pathfilter::{PathFilter, PathFilterError};
pub use registry::{EngineRun, Registry};

/// Immutable inputs to a Scan (spec 2). Time is injected here — pure crates
/// never read a clock (DET-004).
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Scan root; all emitted paths must be made relative to it (DET-005).
    pub root: PathBuf,
    /// Resolved configuration (flags > file > defaults, spec 4.5).
    pub config: multiscan_core::Config,
    /// Exclude globs compiled from `config` (`[scan] exclude` + per-layer,
    /// ADR 0004). Engines MUST consult this during file discovery: skip
    /// matched files, prune matched directories. Compiled at config
    /// resolution so an invalid glob is exit 2, not an engine failure.
    pub excludes: PathFilter,
    /// Active profile.
    pub profile: Profile,
    /// Layers selected for this scan (auto-detected or explicit).
    pub layers: Vec<Layer>,
    /// Pinned feed snapshot id for the whole Scan (FD-002), if feeds exist.
    pub feed_snapshot_id: Option<String>,
    /// Cache directory holding the pinned `FeedSnapshot`. Engines that need
    /// advisory data (SCA) load it from here; `None` when no snapshot is
    /// pinned (secrets/iac need no feeds, FD-007).
    pub feed_cache_dir: Option<PathBuf>,
    /// Authorization for remote probing (spec 9); local scans carry `None`.
    pub authorization: Option<multiscan_core::ScopeAuthorization>,
    /// Cooperative cancellation flag; engines MUST check it between units of
    /// work so Ctrl-C yields partial results, not a hang.
    pub cancel: Arc<AtomicBool>,
    /// Optional deadline; engines MUST stop and return `Partial` once past it.
    pub deadline: Option<Instant>,
    /// Injected wall-clock timestamp of the Scan (RFC 3339), for stamping
    /// only — never identity (spec 7.7.3).
    pub started_at: String,
}

impl ScanContext {
    /// True when the engine should stop now: cancelled or past deadline.
    pub fn should_stop(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
            || self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

/// Result of the cheap applicability check. MUST NOT touch the network or
/// read file contents (spec 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applicability {
    /// The engine has work to do in this context.
    Applicable,
    /// Nothing for this engine here (or the engine is scaffold-only, spec 7.5).
    NotApplicable,
}

/// How a scan invocation of one engine ended (spec 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineOutcome {
    /// Every unit was scanned; only this outcome may close Findings (7.7.4).
    Complete {
        /// Units (files, packages, requests) scanned.
        units_scanned: u64,
    },
    /// Some units were skipped — degraded, not failed. Forces exit ≥ 3 and
    /// never closes Findings (ENG-002).
    Partial {
        /// Units scanned before stopping.
        units_scanned: u64,
        /// Human-readable reason, surfaced on stderr.
        reason: String,
    },
}

/// Typed engine failure (never `Box<dyn Error>`, CLAUDE.md conventions).
/// Recoverable problems degrade to `EngineOutcome::Partial` instead.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The engine could not run at all in this context.
    #[error("engine failed: {0}")]
    Failed(String),
}

/// Sink error: emission was refused (e.g. the scan is shutting down).
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// The sink no longer accepts findings.
    #[error("finding sink closed")]
    Closed,
}

/// Streaming receiver for engine emissions (spec 6.1). Engines never collect
/// whole result sets (NFR-003) — they emit as they go.
pub trait FindingSink {
    /// Emit one raw finding.
    fn emit(&mut self, finding: RawFinding) -> Result<(), SinkError>;
    /// Report progress; goes to stderr rendering, never stdout (CLI-001).
    fn progress(&mut self, done: u64, total: Option<u64>);
}

/// A built-in detection module (spec 6.1).
pub trait Engine: Send + Sync {
    /// Static identity and capabilities.
    fn manifest(&self) -> &EngineManifest;

    /// Cheap static check. MUST NOT touch the network or read file contents.
    fn applicable(&self, ctx: &ScanContext) -> Applicability;

    /// Detection. Streams findings into the sink; MUST honour `ctx.deadline`
    /// and check `ctx.cancel` between units of work.
    fn scan(
        &self,
        ctx: &ScanContext,
        sink: &mut dyn FindingSink,
    ) -> Result<EngineOutcome, EngineError>;
}
