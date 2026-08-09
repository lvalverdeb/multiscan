//! SPDX importer (spec 7.6).
//!
//! SPDX 2.x has **no vulnerability model**. What it does carry, per package, is
//! `externalRefs` — and one of those categories is `SECURITY`, whose `advisory`
//! type points at a specific advisory for that package. That is the only part
//! of an SPDX document that describes a weakness, so it is the part imported.
//!
//! Most SPDX files in the wild carry none, and yield no Findings. That is
//! correct rather than a failure: an SBOM records what is present, not what is
//! wrong with it. Resolving components against the pinned snapshot is an
//! Engine's job, not a Bridge's — see phase-2 Q-14 and the note in
//! [`crate::cyclonedx`].

use multiscan_core::{Finding, IdentityKey, Severity};
use serde::Deserialize;

use crate::common::{build, norm, Imported};
use crate::BridgeError;

#[derive(Deserialize)]
struct SpdxDocument {
    #[serde(rename = "spdxVersion", default)]
    _version: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "versionInfo", default)]
    version: Option<String>,
    #[serde(rename = "externalRefs", default)]
    external_refs: Vec<ExternalRef>,
}

#[derive(Deserialize)]
struct ExternalRef {
    #[serde(rename = "referenceCategory", default)]
    category: Option<String>,
    #[serde(rename = "referenceType", default)]
    kind: Option<String>,
    #[serde(rename = "referenceLocator", default)]
    locator: Option<String>,
}

/// The advisory id a locator names.
///
/// SPDX locators are URLs; the advisory id is the last meaningful path segment
/// (`https://.../CVE-2021-23337` → `CVE-2021-23337`). A bare id is taken as-is.
fn advisory_id(locator: &str) -> Option<String> {
    let trimmed = locator.trim().trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    (!last.is_empty()).then(|| last.to_string())
}

/// The purl for a package, preferring an explicit `PACKAGE-MANAGER` ref.
fn package_purl(package: &Package) -> Option<String> {
    if let Some(purl) = package.external_refs.iter().find_map(|r| {
        let locator = r.locator.as_deref()?;
        locator.starts_with("pkg:").then(|| locator.to_string())
    }) {
        return Some(purl);
    }
    // No purl ref: a name and version alone cannot be given a purl type
    // without guessing the ecosystem, and a wrong purl would key the Finding
    // to a package that does not exist (BRG-003 posture).
    let _ = (&package.name, &package.version);
    None
}

/// Parse an SPDX document into Findings.
pub fn import(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    let doc: SpdxDocument =
        serde_json::from_slice(bytes).map_err(|e| BridgeError::Parse(e.to_string()))?;
    let manifest_path = norm(doc.name.as_deref().unwrap_or("spdx"));

    let mut findings = Vec::new();
    for package in &doc.packages {
        let Some(purl) = package_purl(package) else {
            continue;
        };
        for reference in &package.external_refs {
            let is_security = reference
                .category
                .as_deref()
                .is_some_and(|c| c.eq_ignore_ascii_case("SECURITY"));
            let is_advisory = reference
                .kind
                .as_deref()
                .is_some_and(|k| k.eq_ignore_ascii_case("advisory"));
            if !is_security || !is_advisory {
                continue;
            }
            let Some(id) = reference.locator.as_deref().and_then(advisory_id) else {
                continue;
            };
            findings.push(build(Imported {
                identity: IdentityKey::VulnerableDependency {
                    purl: purl.clone(),
                    advisory_id: id.clone(),
                    manifest_path: manifest_path.clone(),
                },
                title: format!("{purl} affected by {id}"),
                description: None,
                // SPDX carries no severity. Rather than guess one, imports land
                // at Informational and are ranked by enrichment downstream
                // (BRG-002: explicit map, never passthrough or invention).
                severity: Severity::Informational,
                path: manifest_path.clone(),
                line: None,
                tool: "spdx".to_string(),
                rule_id: id,
                // SPDX advisory refs carry no fix version or CWE.
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
    fn imports_security_advisory_refs() {
        let doc = br#"{
          "spdxVersion": "SPDX-2.3",
          "name": "my-app",
          "packages": [{
            "name": "lodash",
            "versionInfo": "4.17.20",
            "externalRefs": [
              {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
               "referenceLocator": "pkg:npm/lodash@4.17.20"},
              {"referenceCategory": "SECURITY", "referenceType": "advisory",
               "referenceLocator": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}
            ]
          }]
        }"#;
        let findings = import(doc).unwrap();
        assert_eq!(findings.len(), 1);
        match &findings[0].identity {
            IdentityKey::VulnerableDependency {
                purl, advisory_id, ..
            } => {
                assert_eq!(purl, "pkg:npm/lodash@4.17.20");
                assert_eq!(advisory_id, "CVE-2021-23337", "id taken from the URL tail");
            }
            other => panic!("wrong identity: {other:?}"),
        }
    }

    #[test]
    fn an_sbom_without_security_refs_yields_nothing() {
        // The common case, and correct: SPDX records what is present.
        let doc = br#"{
          "name": "my-app",
          "packages": [{
            "name": "lodash", "versionInfo": "4.17.20",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                              "referenceType": "purl",
                              "referenceLocator": "pkg:npm/lodash@4.17.20"}]
          }]
        }"#;
        assert!(import(doc).unwrap().is_empty());
    }

    #[test]
    fn a_package_without_a_purl_is_skipped() {
        // Guessing the ecosystem would key the Finding to a package that does
        // not exist (BRG-003 posture).
        let doc = br#"{
          "packages": [{
            "name": "lodash", "versionInfo": "4.17.20",
            "externalRefs": [{"referenceCategory": "SECURITY",
                              "referenceType": "advisory",
                              "referenceLocator": "CVE-2021-23337"}]
          }]
        }"#;
        assert!(import(doc).unwrap().is_empty());
    }

    #[test]
    fn non_advisory_security_refs_are_ignored() {
        // `cpe23Type` and `fix` are SECURITY refs too, but neither names an
        // advisory affecting the package.
        let doc = br#"{
          "packages": [{
            "externalRefs": [
              {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
               "referenceLocator": "pkg:npm/a@1"},
              {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
               "referenceLocator": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}
            ]
          }]
        }"#;
        assert!(import(doc).unwrap().is_empty());
    }

    #[test]
    fn advisory_id_extraction_handles_urls_and_bare_ids() {
        assert_eq!(
            advisory_id("https://nvd.nist.gov/vuln/detail/CVE-1"),
            Some("CVE-1".into())
        );
        assert_eq!(
            advisory_id("https://example.test/GHSA-x/"),
            Some("GHSA-x".into())
        );
        assert_eq!(advisory_id("CVE-2"), Some("CVE-2".into()));
        assert_eq!(advisory_id("  "), None);
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert!(import(b"{not json").is_err());
    }
}
