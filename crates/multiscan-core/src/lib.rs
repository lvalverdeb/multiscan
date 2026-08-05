//! Core generated types: Finding, Asset, Severity, Confidence, IDs. Pure — no I/O (spec 5.2).
//!
//! Every type here is generated from `schemas/*.json` by `cargo xtask gen`
//! (R-4). Hand-written behaviour lives in sibling modules as impls on the
//! generated types — never inside `generated.rs`.

// Generated code documents itself from schema descriptions; helper items
// (error module, conversions) are exempt from the docs requirement.
// rustfmt::skip keeps `cargo fmt` from rewriting prettyplease's output,
// which would break the `gen --check` byte-compare drift gate.
#[allow(missing_docs)]
#[rustfmt::skip]
pub mod generated;

pub use generated::*;
