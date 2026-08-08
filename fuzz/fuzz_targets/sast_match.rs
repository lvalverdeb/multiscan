//! Fuzz target for MS-PAT-1 pattern compilation and matching (NFR-010).
//!
//! Two untrusted inputs meet here. Scanned source comes from a repo, and
//! **pattern text comes from a mechanically translated community corpus**
//! (ADR 0014) — a feed-delivered pack is signed but still external data. This
//! target drives both from the same fuzz input.
//!
//! The oracle is the pair of properties matching must hold:
//!
//! 1. **Termination.** Ellipsis matching explores O(n^k) splits in the worst
//!    case. `MAX_ELLIPSES_PER_SEQUENCE` and `MAX_PATTERN_DEPTH` are supposed to
//!    bound that; a hang here means a rule pack could stall a scan.
//! 2. **Determinism.** The same pattern against the same source yields the same
//!    matches, in the same order, with the same bindings (DET-001/DET-002).
//!
//! Run: `cargo +nightly fuzz run sast_match`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use multiscan_sast::lang::python;
use multiscan_sast::matcher::matches;
use multiscan_sast::pattern::PatternExpr;
use multiscan_sast::structural_hash_of;

fuzz_target!(|data: &[u8]| {
    // First byte splits the input into pattern text and source, so the fuzzer
    // can explore the ratio rather than being locked to a fixed one.
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    if rest.is_empty() {
        return;
    }
    let at = (split as usize * rest.len()) / 256;
    let (pattern_bytes, source_bytes) = rest.split_at(at);

    let (Ok(pattern_text), Ok(source)) = (
        std::str::from_utf8(pattern_bytes),
        std::str::from_utf8(source_bytes),
    ) else {
        return;
    };

    // A pattern that does not compile is a pack-load rejection, not a bug.
    let Ok(node) = python::compile_pattern(pattern_text) else {
        return;
    };
    let expr = PatternExpr::Pattern(node);

    // Reject what a pack load would reject, so the target fuzzes the matcher
    // rather than re-testing the validator.
    if expr.validate().is_err() {
        return;
    }

    let Ok(tree) = python::lower_source(source) else {
        return;
    };

    // Termination is asserted by libfuzzer's timeout: if the bounds fail to
    // contain the split explosion, this call never returns.
    let first = matches(&expr, &tree);
    let second = matches(&expr, &tree);

    assert_eq!(
        first.len(),
        second.len(),
        "match count is non-deterministic"
    );
    for (a, b) in first.iter().zip(&second) {
        assert_eq!(
            structural_hash_of(a.node),
            structural_hash_of(b.node),
            "match order or content is non-deterministic (DET-002)"
        );
        assert_eq!(
            a.bindings.keys().collect::<Vec<_>>(),
            b.bindings.keys().collect::<Vec<_>>(),
            "metavariable bindings are non-deterministic (DET-001)"
        );
    }
});
