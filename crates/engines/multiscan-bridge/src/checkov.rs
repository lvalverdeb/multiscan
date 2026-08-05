//! Checkov JSON importer (spec 7.6). Checkov reports IaC misconfigurations;
//! each failed check maps to an `IacMisconfiguration` — the same identity
//! shape a native IaC finding uses.

use multiscan_core::{Finding, IdentityKey, Severity};
use serde::Deserialize;

use crate::common::{build, norm, Imported};
use crate::BridgeError;

#[derive(Deserialize)]
struct CheckovReport {
    #[serde(default)]
    results: CheckovResults,
}

#[derive(Deserialize, Default)]
struct CheckovResults {
    #[serde(default)]
    failed_checks: Vec<FailedCheck>,
}

#[derive(Deserialize)]
struct FailedCheck {
    #[serde(default)]
    check_id: String,
    #[serde(default)]
    check_name: Option<String>,
    #[serde(default)]
    file_path: String,
    #[serde(default)]
    resource: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    guideline: Option<String>,
}

/// BRG-002: Checkov severity → Severity. Checkov often omits severity; the
/// documented default is Medium.
fn severity(label: Option<&str>) -> Severity {
    match label.map(str::to_ascii_uppercase).as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        Some("INFO") => Severity::Informational,
        _ => Severity::Medium,
    }
}

/// Parse a Checkov JSON report into Findings.
pub fn import(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    let report: CheckovReport =
        serde_json::from_slice(bytes).map_err(|e| BridgeError::Parse(e.to_string()))?;
    let mut findings = Vec::new();
    for check in report.results.failed_checks {
        let path = norm(&check.file_path);
        let identity = IdentityKey::IacMisconfiguration {
            policy_id: check.check_id.clone(),
            path: path.clone(),
            resource_address: check.resource.clone(),
        };
        findings.push(build(Imported {
            identity,
            title: check
                .check_name
                .clone()
                .unwrap_or_else(|| check.check_id.clone()),
            description: check.guideline.clone(),
            severity: severity(check.severity.as_deref()),
            path,
            line: None,
            tool: "checkov".to_string(),
            rule_id: check.check_id.clone(),
            fixed_version: None,
            cwe: vec![],
        }));
    }
    Ok(findings)
}
