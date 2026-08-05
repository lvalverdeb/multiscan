//! T-303 acceptance: SARIF export→import round-trip preserves finding_id,
//! severity, location, and sources (FR-013), and foreign SARIF imports with
//! external tool attribution (BRG-001/BRG-003).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use multiscan_bridge::{detect, import, import_sarif, Format};
use multiscan_core::{
    Asset, AssetKind, Confidence, Finding, FindingId, FindingStatus, IdentityKey, Location,
    ScoreExplanation, ScoreFactors, Severity, Source,
};
use multiscan_report::{render, sort_findings, Footer};

fn sample(id: &str, sev: Severity) -> Finding {
    Finding {
        finding_id: FindingId(id.to_string()),
        identity: IdentityKey::VulnerableDependency {
            purl: "pkg:npm/lodash@4.17.20".into(),
            advisory_id: "GHSA-xxxx".into(),
            manifest_path: "package-lock.json".into(),
        },
        title: "lodash vulnerable".into(),
        description: Some("desc".into()),
        severity: sev,
        confidence: Confidence::Corroborated,
        status: FindingStatus::Open,
        risk_score: 82.4,
        score_explanation: ScoreExplanation {
            formula_version: "1".into(),
            feed_snapshot_id: Some("osv-2026".into()),
            factors: ScoreFactors {
                severity_base: 0.75,
                exposure: 0.7,
                exploitability: 1.0,
                confidence: 0.85,
                asset_criticality: 1.0,
            },
            raw_product: 0.44,
            defaults_applied: vec![],
        },
        asset: Asset {
            kind: AssetKind::Package,
            identifier: "pkg:npm/lodash@4.17.20".into(),
        },
        location: Location {
            path: "package-lock.json".into(),
            line: Some(42),
        },
        evidence: vec![],
        sources: vec![Source {
            engine_id: "multiscan.sca".into(),
            rule_id: Some("GHSA-xxxx".into()),
        }],
        remediation: None,
        cwe: vec!["CWE-77".into()],
    }
}

fn export_sarif(findings: &[Finding]) -> String {
    let footer = Footer {
        scanned_at: "2026-01-01T00:00:00Z".into(),
        feed_snapshot_id: None,
    };
    render(multiscan_report::Format::Sarif, findings, &footer)
}

/// FR-013: export then re-import; finding_id/severity/location/sources match.
#[test]
fn sarif_round_trip_preserves_key_fields() {
    let mut original = vec![
        sample("a".repeat(64).as_str(), Severity::High),
        sample("b".repeat(64).as_str(), Severity::Critical),
    ];
    sort_findings(&mut original);

    let sarif = export_sarif(&original);
    assert_eq!(detect(sarif.as_bytes()), Some(Format::Sarif));

    let mut imported = import_sarif(sarif.as_bytes()).unwrap();
    sort_findings(&mut imported);

    assert_eq!(imported.len(), original.len());
    for (a, b) in original.iter().zip(imported.iter()) {
        assert_eq!(a.finding_id, b.finding_id, "finding_id preserved");
        assert_eq!(a.severity, b.severity, "severity preserved");
        assert_eq!(a.location, b.location, "location preserved");
        assert_eq!(a.sources, b.sources, "sources preserved");
    }
    // Our own export is fully lossless.
    assert_eq!(original, imported);
}

/// OUT-001: native fields are correct for external consumers.
#[test]
fn native_fields_for_interop() {
    let original = vec![sample("c".repeat(64).as_str(), Severity::High)];
    let sarif = export_sarif(&original);
    let doc: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let result = &doc["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "GHSA-xxxx");
    assert_eq!(result["level"], "error");
    assert_eq!(
        result["partialFingerprints"]["multiscan/findingId"],
        "c".repeat(64)
    );
}

/// Foreign SARIF (no embedded finding) imports with external attribution.
#[test]
fn foreign_sarif_imports_with_tool_attribution() {
    let foreign = r#"{
      "version": "2.1.0",
      "runs": [{
        "tool": { "driver": { "name": "semgrep" } },
        "results": [{
          "ruleId": "rules.python.sqli",
          "level": "error",
          "message": { "text": "SQL injection" },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": { "uri": "app/db.py" },
              "region": { "startLine": 12 }
            }
          }]
        }]
      }]
    }"#;
    let imported = import(foreign.as_bytes()).unwrap();
    assert_eq!(imported.len(), 1);
    let f = &imported[0];
    // BRG-001: producing tool recorded in sources.
    assert_eq!(f.sources[0].engine_id, "external:semgrep");
    assert_eq!(f.sources[0].rule_id.as_deref(), Some("rules.python.sqli"));
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.location.path, "app/db.py");
    assert_eq!(f.location.line, Some(12));
    // A stable finding_id was synthesized.
    assert_eq!(f.finding_id.0.len(), 64);
}
