//! Trivy JSON importer (spec 7.6). Trivy reports vulnerable OS/library
//! packages; each maps to a `VulnerableDependency` with the same identity a
//! native SCA finding would have, so the two merge in dedup (FR-004).

use multiscan_core::{IdentityKey, Severity};
use serde::Deserialize;

use crate::common::{build, norm, Imported};
use crate::BridgeError;
use multiscan_core::Finding;

#[derive(Deserialize)]
struct TrivyReport {
    #[serde(rename = "SchemaVersion", default)]
    _schema_version: Option<i64>,
    #[serde(rename = "Results", default)]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target", default)]
    target: String,
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(rename = "Vulnerabilities", default)]
    vulnerabilities: Vec<TrivyVuln>,
}

#[derive(Deserialize)]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID", default)]
    id: String,
    #[serde(rename = "PkgName", default)]
    pkg_name: String,
    #[serde(rename = "InstalledVersion", default)]
    installed_version: String,
    #[serde(rename = "FixedVersion", default)]
    fixed_version: Option<String>,
    #[serde(rename = "Severity", default)]
    severity: Option<String>,
    #[serde(rename = "PkgIdentifier", default)]
    pkg_identifier: Option<PkgIdentifier>,
    #[serde(rename = "Title", default)]
    title: Option<String>,
}

#[derive(Deserialize, Default)]
struct PkgIdentifier {
    #[serde(rename = "PURL", default)]
    purl: Option<String>,
}

/// BRG-002: explicit Trivy severity → Severity map.
fn severity(label: Option<&str>) -> Severity {
    match label.map(str::to_ascii_uppercase).as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => Severity::Informational,
    }
}

/// Trivy ecosystem `Type` → purl type, for constructing a purl when Trivy does
/// not include `PkgIdentifier.PURL`.
fn purl_type(kind: &str) -> &str {
    match kind {
        "npm" | "node-pkg" | "yarn" | "pnpm" => "npm",
        "gomod" | "golang" => "golang",
        "pip" | "python-pkg" | "poetry" => "pypi",
        "cargo" | "rust-binary" => "cargo",
        "gemspec" | "bundler" => "gem",
        "jar" | "pom" | "gradle" => "maven",
        "composer" => "composer",
        "nuget" | "dotnet-core" => "nuget",
        "debian" | "ubuntu" => "deb",
        "alpine" => "apk",
        "redhat" | "centos" | "amazon" => "rpm",
        other => other,
    }
}

/// Parse a Trivy JSON report into Findings.
pub fn import(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    let report: TrivyReport =
        serde_json::from_slice(bytes).map_err(|e| BridgeError::Parse(e.to_string()))?;
    let mut findings = Vec::new();
    for result in report.results {
        let manifest_path = norm(&result.target);
        for vuln in result.vulnerabilities {
            let purl = vuln
                .pkg_identifier
                .as_ref()
                .and_then(|p| p.purl.clone())
                .unwrap_or_else(|| {
                    format!(
                        "pkg:{}/{}@{}",
                        purl_type(&result.kind),
                        vuln.pkg_name,
                        vuln.installed_version
                    )
                });
            let identity = IdentityKey::VulnerableDependency {
                purl,
                advisory_id: vuln.id.clone(),
                manifest_path: manifest_path.clone(),
            };
            findings.push(build(Imported {
                identity,
                title: vuln
                    .title
                    .clone()
                    .unwrap_or_else(|| format!("{} affected by {}", vuln.pkg_name, vuln.id)),
                description: vuln.title.clone(),
                severity: severity(vuln.severity.as_deref()),
                path: manifest_path.clone(),
                line: None,
                tool: "trivy".to_string(),
                rule_id: vuln.id.clone(),
                fixed_version: vuln.fixed_version.clone(),
                cwe: vec![],
            }));
        }
    }
    Ok(findings)
}
