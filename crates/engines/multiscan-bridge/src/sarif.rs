//! SARIF 2.1.0 importer (spec 7.6). Two paths:
//!
//! 1. **Our own export** — the result carries `properties["multiscan/finding"]`
//!    with the complete Finding, so import is lossless (FR-013).
//! 2. **Foreign SARIF** — reconstruct a best-effort Finding from the native
//!    fields (`ruleId`, `level`, `locations`, `partialFingerprints`), recording
//!    the producing tool in `sources[].engine_id` (BRG-001) and keeping unknown
//!    rule ids under `external:{tool}:{id}` (BRG-003).

use multiscan_core::{
    Asset, AssetKind, Confidence, Finding, FindingId, FindingStatus, IdentityKey, Location,
    ScoreExplanation, ScoreFactors, Severity, Source,
};
use serde::Deserialize;

use crate::BridgeError;

/// Property-bag key the report crate embeds the full Finding under.
const FINDING_PROPERTY: &str = "multiscan/finding";

#[derive(Deserialize)]
struct SarifDoc {
    #[serde(default)]
    runs: Vec<Run>,
}

#[derive(Deserialize)]
struct Run {
    #[serde(default)]
    tool: Tool,
    #[serde(default)]
    results: Vec<SarifResult>,
}

#[derive(Deserialize, Default)]
struct Tool {
    #[serde(default)]
    driver: Driver,
}

#[derive(Deserialize, Default)]
struct Driver {
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct SarifResult {
    #[serde(default, rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    message: Message,
    #[serde(default)]
    locations: Vec<SarifLocation>,
    #[serde(default, rename = "partialFingerprints")]
    partial_fingerprints: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    properties: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct Message {
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct SarifLocation {
    #[serde(default, rename = "physicalLocation")]
    physical_location: Option<PhysicalLocation>,
}

#[derive(Deserialize)]
struct PhysicalLocation {
    #[serde(default, rename = "artifactLocation")]
    artifact_location: Option<ArtifactLocation>,
    #[serde(default)]
    region: Option<Region>,
}

#[derive(Deserialize)]
struct ArtifactLocation {
    #[serde(default)]
    uri: String,
}

#[derive(Deserialize)]
struct Region {
    #[serde(default, rename = "startLine")]
    start_line: Option<i64>,
}

/// Parse SARIF bytes into Findings.
pub fn import_sarif(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    let doc: SarifDoc =
        serde_json::from_slice(bytes).map_err(|e| BridgeError::Parse(e.to_string()))?;
    let mut findings = Vec::new();
    for run in doc.runs {
        let tool = if run.tool.driver.name.is_empty() {
            "sarif".to_string()
        } else {
            run.tool.driver.name.clone()
        };
        for result in run.results {
            findings.push(reconstruct(&tool, result)?);
        }
    }
    Ok(findings)
}

fn reconstruct(tool: &str, result: SarifResult) -> Result<Finding, BridgeError> {
    // Lossless path: our own export embeds the complete Finding.
    if let Some(embedded) = result.properties.get(FINDING_PROPERTY) {
        return serde_json::from_value(embedded.clone())
            .map_err(|e| BridgeError::Parse(format!("embedded finding: {e}")));
    }

    // Foreign SARIF: reconstruct from native fields.
    let (path, line) = result
        .locations
        .first()
        .and_then(|l| l.physical_location.as_ref())
        .map(|p| {
            let path = p
                .artifact_location
                .as_ref()
                .map(|a| a.uri.clone())
                .unwrap_or_default();
            let line = p.region.as_ref().and_then(|r| r.start_line);
            (path, line)
        })
        .unwrap_or_default();

    let rule = result
        .rule_id
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let severity = level_to_severity(result.level.as_deref());
    let title = if result.message.text.is_empty() {
        rule.clone()
    } else {
        result.message.text.clone()
    };

    // Identity: foreign findings are treated as structural patterns keyed by
    // rule + path + a stable hash of the rule id (never a raw line number).
    let structural_hash = format!("sarif:{}", blake3::hash(rule.as_bytes()).to_hex());
    let identity = IdentityKey::StructuralPattern {
        rule_id: rule.clone(),
        path: normalize_path(&path),
        structural_hash,
    };
    let finding_id = result
        .partial_fingerprints
        .get("multiscan/findingId")
        .cloned()
        .unwrap_or_else(|| multiscan_dedup::finding_id(&identity));

    // BRG-001 / BRG-003: record the producing tool; unknown ids namespaced.
    let source = Source {
        engine_id: format!("external:{tool}"),
        rule_id: Some(rule),
    };

    Ok(Finding {
        finding_id: FindingId(finding_id),
        identity,
        title,
        description: None,
        severity,
        confidence: Confidence::Heuristic,
        status: FindingStatus::Open,
        // Imported findings are not re-scored in v1; the score is recorded as
        // 0 with the default explanation. Re-scoring imports is future work.
        risk_score: 0.0,
        score_explanation: ScoreExplanation {
            formula_version: "1".to_string(),
            feed_snapshot_id: None,
            factors: ScoreFactors {
                severity_base: 0.05,
                exposure: 0.7,
                exploitability: 0.5,
                confidence: 0.7,
                asset_criticality: 1.0,
            },
            raw_product: 0.0,
            defaults_applied: vec!["imported".to_string()],
        },
        asset: Asset {
            kind: AssetKind::File,
            identifier: normalize_path(&path),
        },
        location: Location {
            path: normalize_path(&path),
            line,
        },
        evidence: vec![],
        sources: vec![source],
        remediation: None,
        cwe: vec![],
    })
}

fn level_to_severity(level: Option<&str>) -> Severity {
    match level {
        Some("error") => Severity::High,
        Some("warning") => Severity::Medium,
        Some("note") => Severity::Low,
        _ => Severity::Informational,
    }
}

fn normalize_path(path: &str) -> String {
    multiscan_dedup::normalize_path(path)
}
