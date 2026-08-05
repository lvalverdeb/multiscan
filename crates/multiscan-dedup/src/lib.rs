//! finding_id construction and Finding merge. Pure — no I/O (spec 7.7).
//!
//! One weakness, one Finding (P-2). This crate owns the two operations that
//! define identity: computing `finding_id` from an identity tuple and merging
//! attributed engine emissions into one deduplicated set. It is deliberately
//! free of I/O, clocks, and randomness (spec 5.2) — enforced by clippy config,
//! the purity gate, and CI.

mod identity;
mod merge;

pub use identity::{finding_id, normalize_origin, normalize_path};
pub use merge::{merge, Attributed, MergedFinding};
