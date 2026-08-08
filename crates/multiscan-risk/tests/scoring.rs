//! T-104 acceptance: golden scoring vectors match to ±0.1 and explanations
//! carry all six factors, the raw product, defaults, and the snapshot id
//! (FR-008, RSK-002/003/005).
//!
//! Factor R (reachability) arrived with T-802 / formula_version 2; a vector
//! that omits `reachability` means `Unknown`, which is the corpus-realistic
//! case ADR 0013 asked these vectors to cover.

// Test-support helpers outside #[test] fns; the in-tests clippy allowance
// does not reach them.
#![allow(clippy::unwrap_used, clippy::panic)]

use multiscan_core::{Confidence, Criticality, DataClassification, Severity};
use multiscan_risk::{
    score, ExploitSignal, ExposureSignal, ReachabilitySignal, RiskContext, Scored, ScoringInputs,
};

fn parse_inputs(v: &serde_json::Value) -> ScoringInputs {
    let severity: Severity = serde_json::from_value(v["severity"].clone()).unwrap();
    let confidence: Confidence = serde_json::from_value(v["confidence"].clone()).unwrap();
    let exposure = match v["exposure"].as_str().unwrap() {
        "internet_reachable" => ExposureSignal::InternetReachable,
        "unknown" => ExposureSignal::Unknown,
        other => panic!("unknown exposure {other}"),
    };
    let exploit = match &v["exploit"] {
        serde_json::Value::String(s) if s == "kev" => ExploitSignal::Kev,
        serde_json::Value::String(s) if s == "no_cve" => ExploitSignal::NoCve,
        serde_json::Value::String(s) if s == "unavailable" => ExploitSignal::Unavailable,
        serde_json::Value::Object(o) => ExploitSignal::Epss(o["epss"].as_f64().unwrap()),
        other => panic!("unknown exploit {other}"),
    };
    let asset_criticality: Option<Criticality> = v
        .get("asset_criticality")
        .map(|c| serde_json::from_value(c.clone()).unwrap());
    let data_classification: Option<DataClassification> = v
        .get("data_classification")
        .map(|c| serde_json::from_value(c.clone()).unwrap());
    let reachability = match v.get("reachability").and_then(serde_json::Value::as_str) {
        Some("referenced") => ReachabilitySignal::Referenced,
        Some("not_referenced") => ReachabilitySignal::NotReferenced,
        // Omitted means Unknown: the overwhelmingly common case in a real
        // corpus, and the one that must leave v1 rankings untouched.
        None | Some("unknown") => ReachabilitySignal::Unknown,
        Some(other) => panic!("unknown reachability {other}"),
    };
    ScoringInputs {
        severity,
        cvss_base: v.get("cvss_base").and_then(serde_json::Value::as_f64),
        confidence,
        exposure,
        exploit,
        reachability,
        context: RiskContext {
            asset_criticality,
            data_classification,
        },
        feed_snapshot_id: v
            .get("feed_snapshot_id")
            .and_then(serde_json::Value::as_str)
            .map(String::from),
    }
}

#[test]
fn golden_vectors_match_within_tolerance() {
    let raw = include_str!("../../../testdata/vectors/scoring.json");
    let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for case in vectors {
        let name = case["name"].as_str().unwrap();
        let inputs = parse_inputs(&case["inputs"]);
        let expected_score = case["expected"]["risk_score"].as_f64().unwrap();
        let expected_defaults: Vec<String> =
            serde_json::from_value(case["expected"]["defaults_applied"].clone()).unwrap();

        let Scored {
            risk_score,
            explanation,
        } = score(&inputs);

        assert!(
            (risk_score - expected_score).abs() <= 0.1,
            "{name}: got {risk_score}, expected {expected_score} ±0.1"
        );
        assert_eq!(
            explanation.defaults_applied, expected_defaults,
            "{name}: defaults_applied mismatch"
        );
        assert_eq!(explanation.formula_version, multiscan_risk::FORMULA_VERSION);
        assert_eq!(
            explanation.feed_snapshot_id, inputs.feed_snapshot_id,
            "{name}: snapshot id must be recorded (RSK-003)"
        );

        // FR-008: the explanation lists exactly five factors, and the raw
        // product is consistent with them.
        let f = &explanation.factors;
        let product = f.severity_base
            * f.exposure
            * f.exploitability
            * f.confidence
            * f.asset_criticality
            * f.reachability;
        assert!((product - explanation.raw_product).abs() < 1e-12, "{name}");
        let factors_json = serde_json::to_value(f).unwrap();
        assert_eq!(factors_json.as_object().unwrap().len(), 6, "{name}");
        assert_eq!(risk_score, 100.0 * explanation.raw_product.clamp(0.0, 1.0));
    }
}

/// Factor ranges hold for every input combination (spec 8 table).
#[test]
fn factor_ranges() {
    for severity in [
        Severity::Informational,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        for exploit in [
            ExploitSignal::Kev,
            ExploitSignal::Epss(0.0),
            ExploitSignal::Epss(0.3),
            ExploitSignal::Epss(0.9),
            ExploitSignal::NoCve,
            ExploitSignal::Unavailable,
        ] {
            let scored = score(&ScoringInputs {
                severity,
                cvss_base: None,
                confidence: Confidence::Heuristic,
                exposure: ExposureSignal::Unknown,
                exploit,
                reachability: ReachabilitySignal::Unknown,
                context: RiskContext::default(),
                feed_snapshot_id: None,
            });
            let f = &scored.explanation.factors;
            assert!((0.05..=1.0).contains(&f.severity_base));
            assert!((0.30..=1.0).contains(&f.exposure));
            assert!((0.20..=1.0).contains(&f.exploitability));
            assert!((0.50..=1.0).contains(&f.confidence));
            assert!((0.50..=1.30).contains(&f.asset_criticality));
            assert!((0.0..=100.0).contains(&scored.risk_score));
        }
    }
}

/// The A factor clamps at 1.30 even for critical + regulated (spec 8).
#[test]
fn asset_criticality_clamps() {
    let scored = score(&ScoringInputs {
        severity: Severity::Critical,
        cvss_base: None,
        confidence: Confidence::Proven,
        exposure: ExposureSignal::InternetReachable,
        exploit: ExploitSignal::Kev,
        reachability: ReachabilitySignal::Referenced,
        context: RiskContext {
            asset_criticality: Some(Criticality::Critical),
            data_classification: Some(DataClassification::Regulated),
        },
        feed_snapshot_id: None,
    });
    assert!(scored.explanation.factors.asset_criticality <= 1.30);
    assert_eq!(scored.risk_score, 100.0);
}

/// `FR-017`: reachability is three-state, and `Unknown` must never behave like
/// `NotReferenced`. Suppressing a real Finding because the parser did not
/// understand a file is a far worse failure than carrying noise.
#[test]
fn unknown_reachability_is_neutral_not_pessimistic() {
    let inputs = |reachability| ScoringInputs {
        severity: Severity::High,
        cvss_base: None,
        confidence: Confidence::Corroborated,
        exposure: ExposureSignal::Unknown,
        exploit: ExploitSignal::NoCve,
        reachability,
        context: RiskContext::default(),
        feed_snapshot_id: None,
    };

    let referenced = score(&inputs(ReachabilitySignal::Referenced));
    let unknown = score(&inputs(ReachabilitySignal::Unknown));
    let not_referenced = score(&inputs(ReachabilitySignal::NotReferenced));

    // Strictly ordered, with Unknown in the middle rather than at the bottom.
    assert!(referenced.risk_score > unknown.risk_score);
    assert!(unknown.risk_score > not_referenced.risk_score);

    // Unknown is exactly neutral: identical to the v1 five-factor product, so
    // the formula_version bump does not reshuffle rankings for users who get
    // no reachability signal (ADR 0013).
    let f = &unknown.explanation.factors;
    let v1_product =
        f.severity_base * f.exposure * f.exploitability * f.confidence * f.asset_criticality;
    assert!((unknown.explanation.raw_product - v1_product).abs() < 1e-12);

    // RSK-002: the default is recorded, never silently applied.
    assert!(unknown
        .explanation
        .defaults_applied
        .contains(&"reachability".to_string()));
    assert!(!referenced
        .explanation
        .defaults_applied
        .contains(&"reachability".to_string()));
}

/// `RSK-006`: reachability changes rank, not existence. A `NotReferenced`
/// Finding is still reported and still gateable — only its score falls.
#[test]
fn not_referenced_still_scores_above_zero() {
    let scored = score(&ScoringInputs {
        severity: Severity::Critical,
        cvss_base: None,
        confidence: Confidence::Proven,
        exposure: ExposureSignal::InternetReachable,
        exploit: ExploitSignal::Kev,
        reachability: ReachabilitySignal::NotReferenced,
        context: RiskContext::default(),
        feed_snapshot_id: None,
    });
    assert!(
        scored.risk_score > 0.0,
        "a NotReferenced finding must still exist and still gate"
    );
    assert!(
        scored.risk_score < 100.0,
        "…but rank below the same finding when referenced"
    );
}
