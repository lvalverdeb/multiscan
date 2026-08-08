//! `T-704` property tests: the fuzz oracles, runnable without nightly.
//!
//! `fuzz/fuzz_targets/sast_parse.rs` and `sast_match.rs` are the release-
//! blocking targets (NFR-010, ADR 0015 decision 4), but they need
//! `cargo +nightly fuzz`. These assert the **same invariants** over
//! proptest-generated input so they run on every `cargo test` — the fuzzer
//! explores far deeper, this catches the regression on the way in.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use multiscan_sast::lang::{javascript, python};
use multiscan_sast::matcher::matches;
use multiscan_sast::pattern::PatternExpr;
use multiscan_sast::structural_hash_of;
use multiscan_sast::tree::Node;
use proptest::prelude::*;

/// Every span must lie inside the source. A span past the end would point a
/// Finding at a line that does not exist — and for swc, whose positions are
/// SourceMap-global, would mean the rebasing is wrong.
fn assert_spans_contained(node: &Node, len: usize) {
    assert!(node.span.start <= node.span.end, "inverted {:?}", node.span);
    assert!(
        node.span.end <= len,
        "span {:?} runs past the {len}-byte source",
        node.span
    );
    for child in &node.children {
        assert_spans_contained(child, len);
    }
}

/// Source-ish text: enough Python/JS punctuation for the parsers to get deep
/// into their state machines, rather than bouncing off byte one.
fn source_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            Just("eval".to_string()),
            Just("def f():".to_string()),
            Just("function g()".to_string()),
            Just("class C".to_string()),
            Just("return".to_string()),
            Just("try:".to_string()),
            Just("except:".to_string()),
            Just("(".to_string()),
            Just(")".to_string()),
            Just("{".to_string()),
            Just("}".to_string()),
            Just("[".to_string()),
            Just("]".to_string()),
            Just(",".to_string()),
            Just(".".to_string()),
            Just("\"s\"".to_string()),
            Just("1".to_string()),
            Just("\n".to_string()),
            Just("    ".to_string()),
            Just("#".to_string()),
            Just("//".to_string()),
            "[a-z_]{1,6}",
        ],
        0..40,
    )
    .prop_map(|parts| parts.join(""))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Lowering is deterministic and span-contained, for anything that parses.
    #[test]
    fn python_lowering_is_deterministic(src in source_text()) {
        if let Ok(tree) = python::lower_source(&src) {
            let again = python::lower_source(&src).expect("parse is not deterministic");
            prop_assert_eq!(
                structural_hash_of(&tree),
                structural_hash_of(&again),
                "non-deterministic lowering makes finding_id unstable"
            );
            assert_spans_contained(&tree, src.len());
        }
    }

    #[test]
    fn javascript_lowering_is_deterministic(src in source_text()) {
        for typescript in [false, true] {
            if let Ok(tree) = javascript::lower_source(&src, typescript) {
                let again = javascript::lower_source(&src, typescript)
                    .expect("parse is not deterministic");
                prop_assert_eq!(
                    structural_hash_of(&tree),
                    structural_hash_of(&again),
                    "non-deterministic lowering (typescript)"
                );
                assert_spans_contained(&tree, src.len());
            }
        }
    }

    /// Arbitrary bytes never panic a front-end — they parse or they error.
    #[test]
    fn arbitrary_text_never_panics(src in ".{0,300}") {
        let _ = python::lower_source(&src);
        let _ = javascript::lower_source(&src, false);
        let _ = javascript::lower_source(&src, true);
    }

    /// Matching terminates and is deterministic. Pattern text is external data
    /// too (a translated community corpus), so it is generated, not fixed.
    #[test]
    fn matching_is_deterministic(
        pattern_text in source_text(),
        src in source_text(),
    ) {
        let Ok(node) = python::compile_pattern(&pattern_text) else { return Ok(()) };
        let expr = PatternExpr::Pattern(node);
        // Skip what a pack load would reject, so this exercises the matcher
        // rather than re-testing the validator.
        if expr.validate().is_err() {
            return Ok(());
        }
        let Ok(tree) = python::lower_source(&src) else { return Ok(()) };

        let first = matches(&expr, &tree);
        let second = matches(&expr, &tree);

        prop_assert_eq!(first.len(), second.len(), "match count is non-deterministic");
        for (a, b) in first.iter().zip(&second) {
            prop_assert_eq!(
                structural_hash_of(a.node),
                structural_hash_of(b.node),
                "match order or content is non-deterministic (DET-002)"
            );
            prop_assert_eq!(
                a.bindings.keys().collect::<Vec<_>>(),
                b.bindings.keys().collect::<Vec<_>>(),
                "bindings are non-deterministic (DET-001)"
            );
        }
    }

    /// A compiled pattern always matches the source it was compiled from.
    ///
    /// The strongest statement of the T-702 design: pattern text and source
    /// traverse identical lowering code, so a hole-free pattern is just its own
    /// source and must match it.
    #[test]
    fn a_hole_free_pattern_matches_its_own_source(src in source_text()) {
        let Ok(node) = python::compile_pattern(&src) else { return Ok(()) };
        let expr = PatternExpr::Pattern(node);
        if expr.validate().is_err() {
            return Ok(());
        }
        let Ok(tree) = python::lower_source(&src) else { return Ok(()) };
        // `src` had no `$`/`...`, so the pattern is literal structure.
        if src.contains('$') || src.contains("...") {
            return Ok(());
        }
        prop_assert!(
            !matches(&expr, &tree).is_empty(),
            "a hole-free pattern must match the source it was compiled from: {:?}",
            src
        );
    }
}
