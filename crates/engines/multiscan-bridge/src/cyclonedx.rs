//! CycloneDX importer (spec 7.6).
//!
//! CycloneDX is primarily an SBOM format, but 1.4+ carries an optional
//! `vulnerabilities[]` array — the VEX section — and that is the part a
//! security tool can import as Findings. Each entry maps to a
//! `VulnerableDependency` with the same identity a native SCA finding would
//! have, so the two merge in dedup (`FR-004`).
//!
//! **An SBOM with no `vulnerabilities[]` yields no Findings**, which is
//! correct rather than a failure: the file records what is present, not what
//! is wrong with it. Resolving an SBOM's components against the pinned
//! snapshot would be a genuinely useful feature, but it is an Engine's job
//! (producing findings from evidence) rather than a Bridge's (normalizing
//! findings another tool already produced). Recorded as phase-2 Q-14.

use multiscan_core::{Finding, IdentityKey, Severity};
use serde::Deserialize;

use crate::common::{build, norm, Imported};
use crate::BridgeError;

#[derive(Deserialize)]
struct Bom {
    #[serde(rename = "bomFormat", default)]
    _bom_format: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<Vulnerability>,
    #[serde(default)]
    metadata: Option<Metadata>,
}

#[derive(Deserialize, Default)]
struct Metadata {
    #[serde(default)]
    component: Option<Component>,
}

#[derive(Deserialize, Default)]
struct Component {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct Vulnerability {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    ratings: Vec<Rating>,
    #[serde(default)]
    affects: Vec<Affects>,
}

#[derive(Deserialize)]
struct Rating {
    #[serde(default)]
    severity: Option<String>,
}

#[derive(Deserialize)]
struct Affects {
    /// A `bom-ref`, which by convention is the component's purl.
    #[serde(rename = "ref", default)]
    reference: Option<String>,
}

/// `BRG-002`: explicit CycloneDX severity → `Severity`. No passthrough.
fn severity(label: Option<&str>) -> Severity {
    match label.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        // `none`, `info`, `unknown` and anything unrecognized land here rather
        // than being guessed upward.
        _ => Severity::Informational,
    }
}

/// Parse a CycloneDX BOM into Findings.
pub fn import(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    let bom: Bom = serde_json::from_slice(bytes).map_err(|e| BridgeError::Parse(e.to_string()))?;

    // The BOM subject, used as the manifest path so imported findings key
    // consistently. Falls back to the format name when metadata is absent.
    let subject = bom
        .metadata
        .as_ref()
        .and_then(|m| m.component.as_ref())
        .and_then(|c| c.name.clone())
        .unwrap_or_else(|| "cyclonedx".to_string());
    let manifest_path = norm(&subject);

    let mut findings = Vec::new();
    for vuln in bom.vulnerabilities {
        let Some(advisory_id) = vuln.id.filter(|s| !s.is_empty()) else {
            // BRG-003 posture: a record with no identifier cannot be given a
            // stable identity, so it is skipped rather than assigned one.
            continue;
        };
        let sev = severity(vuln.ratings.first().and_then(|r| r.severity.as_deref()));

        // One Finding per affected component: a CVE against three packages is
        // three weaknesses to fix, not one.
        for affect in &vuln.affects {
            let Some(purl) = affect.reference.clone().filter(|s| s.starts_with("pkg:")) else {
                continue;
            };
            findings.push(build(Imported {
                identity: IdentityKey::VulnerableDependency {
                    purl: purl.clone(),
                    advisory_id: advisory_id.clone(),
                    manifest_path: manifest_path.clone(),
                },
                title: format!("{purl} affected by {advisory_id}"),
                description: vuln.description.clone(),
                severity: sev,
                path: manifest_path.clone(),
                line: None,
                tool: "cyclonedx".to_string(),
                rule_id: advisory_id.clone(),
                // CycloneDX VEX carries neither a fix version nor a CWE in the
                // shape we rely on; inventing either would be passthrough.
                fixed_version: None,
                cwe: vec![],
            }));
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_the_vex_section() {
        let bom = br#"{
          "bomFormat": "CycloneDX",
          "specVersion": "1.5",
          "metadata": {"component": {"name": "my-app"}},
          "vulnerabilities": [{
            "id": "CVE-2021-23337",
            "description": "Command injection in lodash",
            "ratings": [{"severity": "high"}],
            "affects": [{"ref": "pkg:npm/lodash@4.17.20"}]
          }]
        }"#;
        let findings = import(bom).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        match &findings[0].identity {
            IdentityKey::VulnerableDependency {
                purl, advisory_id, ..
            } => {
                assert_eq!(purl, "pkg:npm/lodash@4.17.20");
                assert_eq!(advisory_id, "CVE-2021-23337");
            }
            other => panic!("wrong identity: {other:?}"),
        }
    }

    #[test]
    fn one_finding_per_affected_component() {
        // A CVE against three packages is three things to fix.
        let bom = br#"{
          "bomFormat": "CycloneDX",
          "vulnerabilities": [{
            "id": "CVE-1",
            "ratings": [{"severity": "low"}],
            "affects": [
              {"ref": "pkg:npm/a@1"},
              {"ref": "pkg:npm/b@2"},
              {"ref": "pkg:npm/c@3"}
            ]
          }]
        }"#;
        assert_eq!(import(bom).unwrap().len(), 3);
    }

    #[test]
    fn an_sbom_without_vulnerabilities_yields_nothing() {
        // Correct, not a failure: the file records what is present, not what
        // is wrong with it.
        let bom = br#"{
          "bomFormat": "CycloneDX",
          "specVersion": "1.5",
          "components": [{"type": "library", "name": "lodash", "version": "4.17.20"}]
        }"#;
        assert!(import(bom).unwrap().is_empty());
    }

    #[test]
    fn unrecognized_severity_never_rounds_up() {
        // BRG-002 / ENG-004: no passthrough, no guessing upward.
        for label in [None, Some("none"), Some("unknown"), Some("wat")] {
            assert_eq!(severity(label), Severity::Informational);
        }
        assert_eq!(severity(Some("CRITICAL")), Severity::Critical);
    }

    #[test]
    fn records_without_an_id_or_a_purl_are_skipped() {
        // Neither can be given a stable identity, so neither is invented.
        let bom = br#"{
          "vulnerabilities": [
            {"ratings": [{"severity": "high"}], "affects": [{"ref": "pkg:npm/a@1"}]},
            {"id": "CVE-2", "affects": [{"ref": "not-a-purl"}]}
          ]
        }"#;
        assert!(import(bom).unwrap().is_empty());
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert!(import(b"{not json").is_err());
    }
}
