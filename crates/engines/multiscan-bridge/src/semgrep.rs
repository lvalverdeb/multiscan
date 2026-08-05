//! Semgrep JSON importer (spec 7.6). Semgrep reports code findings; each maps
//! to a `StructuralPattern` keyed by check id, path, and a stable hash.

use multiscan_core::{Finding, IdentityKey, Severity};
use serde::Deserialize;

use crate::common::{build, norm, Imported};
use crate::BridgeError;

#[derive(Deserialize)]
struct SemgrepReport {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(Deserialize)]
struct SemgrepResult {
    #[serde(default)]
    check_id: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    start: Position,
    #[serde(default)]
    extra: Extra,
}

#[derive(Deserialize, Default)]
struct Position {
    #[serde(default)]
    line: Option<i64>,
}

#[derive(Deserialize, Default)]
struct Extra {
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    metadata: Metadata,
}

#[derive(Deserialize, Default)]
struct Metadata {
    #[serde(default)]
    cwe: Vec<String>,
}

/// BRG-002: Semgrep severity → Severity.
fn severity(label: Option<&str>) -> Severity {
    match label.map(str::to_ascii_uppercase).as_deref() {
        Some("ERROR") => Severity::High,
        Some("WARNING") => Severity::Medium,
        Some("INFO") => Severity::Low,
        _ => Severity::Informational,
    }
}

/// Parse a Semgrep JSON report into Findings.
pub fn import(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    let report: SemgrepReport =
        serde_json::from_slice(bytes).map_err(|e| BridgeError::Parse(e.to_string()))?;
    let mut findings = Vec::new();
    for result in report.results {
        let path = norm(&result.path);
        let structural_hash = format!(
            "semgrep:{}",
            blake3::hash(result.check_id.as_bytes()).to_hex()
        );
        let identity = IdentityKey::StructuralPattern {
            rule_id: result.check_id.clone(),
            path: path.clone(),
            structural_hash,
        };
        findings.push(build(Imported {
            identity,
            title: result
                .extra
                .message
                .clone()
                .unwrap_or_else(|| result.check_id.clone()),
            description: result.extra.message.clone(),
            severity: severity(result.extra.severity.as_deref()),
            path,
            line: result.start.line,
            tool: "semgrep".to_string(),
            rule_id: result.check_id.clone(),
            fixed_version: None,
            cwe: result.extra.metadata.cwe.clone(),
        }));
    }
    Ok(findings)
}
