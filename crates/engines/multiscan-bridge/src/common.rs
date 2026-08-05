//! Shared helpers for reconstructing a `Finding` from an external tool's
//! record. Imported findings are not re-scored in v1 (risk_score 0 with a
//! default explanation); native scoring/enrichment applies if they merge into
//! a scan (BRG-001).

use multiscan_core::{
    Asset, AssetKind, Confidence, Evidence, Finding, FindingId, FindingStatus, IdentityKey,
    Location, Remediation, ScoreExplanation, ScoreFactors, Severity, Source,
};

/// Everything an importer needs to specify to build one Finding.
pub struct Imported {
    /// Class-discriminated identity (drives cross-tool dedup, spec 7.7).
    pub identity: IdentityKey,
    /// One-line title.
    pub title: String,
    /// Longer description, if any.
    pub description: Option<String>,
    /// Mapped severity (BRG-002 — every importer declares its own map).
    pub severity: Severity,
    /// Display path (root-relative POSIX).
    pub path: String,
    /// Line, if the tool reports one.
    pub line: Option<i64>,
    /// External tool name, recorded as `external:{tool}` in sources (BRG-001).
    pub tool: String,
    /// Native rule/advisory id from the tool.
    pub rule_id: String,
    /// Fixed version, for dependency findings (SCA-004 shape).
    pub fixed_version: Option<String>,
    /// CWE ids, if the tool provides them.
    pub cwe: Vec<String>,
}

/// Default score explanation for an unscored import.
fn imported_explanation() -> ScoreExplanation {
    ScoreExplanation {
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
    }
}

/// Build a Finding from an imported record. `finding_id` is derived from the
/// identity so an import can merge with a native finding of the same identity
/// (FR-004).
pub fn build(imported: Imported) -> Finding {
    let finding_id = multiscan_dedup::finding_id(&imported.identity);
    let remediation = imported.fixed_version.as_ref().map(|v| Remediation {
        fix_available: true,
        fixed_version: Some(v.clone()),
        summary: Some(format!("Upgrade to {v}.")),
    });
    Finding {
        finding_id: FindingId(finding_id),
        identity: imported.identity,
        title: imported.title,
        description: imported.description,
        severity: imported.severity,
        // Imported findings are heuristic until corroborated by a native
        // engine in the dedup pass (7.7.5).
        confidence: Confidence::Heuristic,
        status: FindingStatus::Open,
        risk_score: 0.0,
        score_explanation: imported_explanation(),
        asset: Asset {
            kind: AssetKind::File,
            identifier: imported.path.clone(),
        },
        location: Location {
            path: imported.path,
            line: imported.line,
        },
        evidence: vec![Evidence {
            kind: "imported".to_string(),
            summary: format!("Imported from {}", imported.tool),
            detail: serde_json::Map::new(),
            dependency_path: vec![],
        }],
        // BRG-001: the producing tool is recorded in sources.
        sources: vec![Source {
            engine_id: format!("external:{}", imported.tool),
            rule_id: Some(imported.rule_id),
        }],
        remediation,
        cwe: imported.cwe,
    }
}

/// Normalize a path to the identity form (DET-005).
pub fn norm(path: &str) -> String {
    multiscan_dedup::normalize_path(path)
}
