//! T-101 acceptance tests for the generated types (spec 13, R-4).

use multiscan_core::{Confidence, Finding, NetworkImpact, Severity};

/// Severity ordinal order is load-bearing for gating and factor lookup (spec 2, 8).
#[test]
fn severity_ordinal_order() {
    use Severity::*;
    let expected = [Informational, Low, Medium, High, Critical];
    let mut sorted = expected;
    sorted.sort();
    assert_eq!(sorted, expected);
    assert!(Informational < Low && Low < Medium && Medium < High && High < Critical);
}

/// Confidence ordinal order backs the merge escalation rule (spec 7.7.5, 8).
#[test]
fn confidence_ordinal_order() {
    use Confidence::*;
    assert!(Unconfirmed < Heuristic);
    assert!(Heuristic < Corroborated);
    assert!(Corroborated < Proven);
}

/// ENG-001: NetworkImpact has exactly two variants. This match is exhaustive —
/// adding a `Destructive` variant makes this test fail to compile, which is
/// the point (NG-1 is enforced by the type system).
#[test]
fn network_impact_has_exactly_two_variants() {
    let describe = |n: NetworkImpact| match n {
        NetworkImpact::ReadOnly => "read_only",
        NetworkImpact::ActiveSafe => "active_safe",
    };
    assert_eq!(describe(NetworkImpact::ReadOnly), "read_only");
    assert_eq!(describe(NetworkImpact::ActiveSafe), "active_safe");
}

/// Sample document deserializes, reserializes, and re-parses to the same value.
#[test]
fn finding_sample_round_trips() {
    let raw = include_str!("../../../testdata/samples/finding.json");
    let parsed: Finding = serde_json::from_str(raw).expect("sample must match schema");
    let reserialized = serde_json::to_string_pretty(&parsed).expect("serialize");
    let reparsed: Finding = serde_json::from_str(&reserialized).expect("re-parse");
    assert_eq!(parsed, reparsed);

    // Semantic equality with the original document (field order aside).
    let original: serde_json::Value = serde_json::from_str(raw).unwrap();
    let ours: serde_json::Value = serde_json::from_str(&reserialized).unwrap();
    assert_eq!(original, ours);
}

/// Unknown fields must be rejected — schemas are strict (deny_unknown_fields).
#[test]
fn unknown_fields_rejected() {
    let raw = include_str!("../../../testdata/samples/finding.json");
    let mut doc: serde_json::Value = serde_json::from_str(raw).unwrap();
    doc.as_object_mut()
        .unwrap()
        .insert("bogus_field".into(), serde_json::json!(1));
    assert!(serde_json::from_value::<Finding>(doc).is_err());
}
