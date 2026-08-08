//! Fuzz target for the SAST language front-ends (NFR-010, ADR 0015 decision 4).
//!
//! Scanned source is attacker-controllable: a repo can contain anything. Both
//! front-ends carry `unsafe` in their parse path (ruff 2 sites, swc 164), so
//! this target is **release-blocking** — ADR 0015 accepted those parsers on the
//! condition that it exists.
//!
//! The oracle is NOT "didn't panic". libfuzzer already catches crashes; this
//! asserts the two properties identity depends on:
//!
//! 1. **Determinism.** Lowering the same bytes twice yields the same
//!    `structural_hash`. If parsing were order- or address-dependent, every
//!    user's `finding_id` would be unstable (DET-001, SAST-002).
//! 2. **Span containment.** Every emitted span lies inside the source. A span
//!    past the end would mean a Finding pointing at a line that does not exist,
//!    and — for swc, whose positions are SourceMap-global — a rebasing bug.
//!
//! Run: `cargo +nightly fuzz run sast_parse`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use multiscan_sast::lang::{javascript, python};
use multiscan_sast::structural_hash_of;
use multiscan_sast::tree::Node;

/// Assert every span in the tree lies within `len` bytes of source.
fn spans_are_contained(node: &Node, len: usize) {
    assert!(
        node.span.start <= node.span.end,
        "inverted span: {:?}",
        node.span
    );
    assert!(
        node.span.end <= len,
        "span {:?} runs past the {len}-byte source",
        node.span
    );
    for child in &node.children {
        spans_are_contained(child, len);
    }
}

fuzz_target!(|data: &[u8]| {
    // Front-ends take &str; invalid UTF-8 is rejected before parsing, so it is
    // not this target's surface.
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(tree) = python::lower_source(source) {
        let again = python::lower_source(source).expect("parsing is not deterministic");
        assert_eq!(
            structural_hash_of(&tree),
            structural_hash_of(&again),
            "python lowering is non-deterministic — finding_id would be unstable"
        );
        spans_are_contained(&tree, source.len());
    }

    // Both grammars, since TypeScript is a different parser configuration and
    // has its own recovery behaviour.
    for typescript in [false, true] {
        if let Ok(tree) = javascript::lower_source(source, typescript) {
            let again =
                javascript::lower_source(source, typescript).expect("parsing is not deterministic");
            assert_eq!(
                structural_hash_of(&tree),
                structural_hash_of(&again),
                "javascript lowering is non-deterministic (typescript={typescript})"
            );
            spans_are_contained(&tree, source.len());
        }
    }
});
