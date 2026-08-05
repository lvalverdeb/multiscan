//! T-103 acceptance: merge semantics (spec 7.7.5, FR-004) and proptest
//! shuffle-invariance (determinism at the data layer).

use multiscan_core::{Asset, AssetKind, Confidence, IdentityKey, Location, RawFinding, Severity};
use multiscan_dedup::{finding_id, merge, Attributed};
use proptest::prelude::*;

fn raw(identity: IdentityKey, severity: Severity, confidence: Confidence) -> RawFinding {
    RawFinding {
        identity,
        title: "t".into(),
        description: None,
        severity,
        confidence,
        asset: Asset {
            kind: AssetKind::File,
            identifier: "x".into(),
        },
        location: Location {
            path: "x".into(),
            line: None,
        },
        evidence: vec![],
        rule_id: None,
        remediation: None,
        cwe: vec![],
    }
}

fn dep(purl: &str) -> IdentityKey {
    IdentityKey::VulnerableDependency {
        purl: purl.into(),
        advisory_id: "OSV-1".into(),
        manifest_path: "package-lock.json".into(),
    }
}

/// FR-004: same weakness from two engines → one Finding, two sources,
/// confidence ≥ Corroborated (7.7.5).
#[test]
fn two_engines_merge_and_corroborate() {
    let merged = merge(vec![
        Attributed {
            engine_id: "multiscan.sca".into(),
            raw: raw(dep("pkg:npm/a@1"), Severity::High, Confidence::Heuristic),
        },
        Attributed {
            engine_id: "external:trivy".into(),
            raw: raw(dep("pkg:npm/a@1"), Severity::Medium, Confidence::Heuristic),
        },
    ]);
    assert_eq!(merged.len(), 1);
    let f = &merged[0];
    assert_eq!(f.sources.len(), 2);
    assert!(f.confidence >= Confidence::Corroborated);
    // Severity merges to the maximum.
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.finding_id, finding_id(&dep("pkg:npm/a@1")));
}

/// Same engine twice does NOT corroborate (7.7.5 requires distinct engine_ids).
#[test]
fn same_engine_does_not_corroborate() {
    let merged = merge(vec![
        Attributed {
            engine_id: "multiscan.sca".into(),
            raw: raw(dep("pkg:npm/a@1"), Severity::High, Confidence::Heuristic),
        },
        Attributed {
            engine_id: "multiscan.sca".into(),
            raw: raw(dep("pkg:npm/a@1"), Severity::High, Confidence::Heuristic),
        },
    ]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].confidence, Confidence::Heuristic);
    assert_eq!(merged[0].sources.len(), 1);
}

/// Distinct identities never merge, even when presentation is identical.
#[test]
fn distinct_identities_stay_distinct() {
    let merged = merge(vec![
        Attributed {
            engine_id: "multiscan.sca".into(),
            raw: raw(dep("pkg:npm/a@1"), Severity::High, Confidence::Heuristic),
        },
        Attributed {
            engine_id: "multiscan.sca".into(),
            raw: raw(dep("pkg:npm/b@1"), Severity::High, Confidence::Heuristic),
        },
    ]);
    assert_eq!(merged.len(), 2);
}

/// A higher individual confidence is never lowered by the escalation rule.
#[test]
fn proven_confidence_is_kept() {
    let merged = merge(vec![
        Attributed {
            engine_id: "a".into(),
            raw: raw(dep("pkg:npm/a@1"), Severity::Low, Confidence::Proven),
        },
        Attributed {
            engine_id: "b".into(),
            raw: raw(dep("pkg:npm/a@1"), Severity::Low, Confidence::Unconfirmed),
        },
    ]);
    assert_eq!(merged[0].confidence, Confidence::Proven);
}

fn attributed_strategy() -> impl Strategy<Value = Attributed> {
    let identities = prop::sample::select(vec![
        dep("pkg:npm/a@1"),
        dep("pkg:npm/b@2"),
        dep("pkg:pypi/c@3"),
        IdentityKey::ExposedSecret {
            rule_id: "aws-key".into(),
            path: ".env".into(),
            fingerprint: "ff00".into(),
        },
    ]);
    let severities = prop::sample::select(vec![
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]);
    let confidences = prop::sample::select(vec![
        Confidence::Unconfirmed,
        Confidence::Heuristic,
        Confidence::Corroborated,
        Confidence::Proven,
    ]);
    let engines = prop::sample::select(vec!["e1".to_string(), "e2".into(), "e3".into()]);
    (identities, severities, confidences, engines).prop_map(|(i, s, c, e)| Attributed {
        engine_id: e,
        raw: raw(i, s, c),
    })
}

proptest! {
    /// Shuffle-invariance: engines run in parallel and emit in arbitrary order
    /// (spec 6.2); merge output must not depend on emit order.
    #[test]
    fn merge_is_order_independent(
        inputs in prop::collection::vec(attributed_strategy(), 0..24),
        seed in any::<u64>(),
    ) {
        let mut shuffled = inputs.clone();
        // Deterministic Fisher-Yates from the seed (no RNG state leaks into output).
        let mut state = seed;
        for i in (1..shuffled.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (state % (i as u64 + 1)) as usize;
            shuffled.swap(i, j);
        }
        prop_assert_eq!(merge(inputs), merge(shuffled));
    }
}
