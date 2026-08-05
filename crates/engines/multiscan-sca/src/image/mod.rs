//! Container image support (spec 7.1): OCI pull + hardened layer extraction.
//! Package-database parsing → OSV resolution lands in T-402; this module
//! delivers the pull and the security-critical extraction.

mod extract;
mod oci;
mod ospkg;
mod rpmdb;

pub use extract::{extract_layer, ExtractError, Limits, Stats};
pub use oci::{OciClient, OciError, PulledImage, Reference};
pub use ospkg::{OsPackage, OsRelease};

use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;

use multiscan_core::{
    Asset, AssetKind, Confidence, Evidence, IdentityKey, Location, RawFinding, Remediation,
    Severity,
};

/// Result of scanning an extracted image's OS packages.
pub struct ImageScan {
    /// Detected OS release, if any.
    pub os: Option<OsRelease>,
    /// Number of installed OS packages found.
    pub package_count: usize,
    /// Emitted `ContainerVulnerability` raw findings.
    pub findings: Vec<RawFinding>,
    /// Set when a package database was found but could not be parsed (e.g. an
    /// rpm binary DB): the scan is Partial, not Complete (spec 7.7.4).
    pub partial: Option<String>,
}

/// Scan an extracted image root for vulnerable OS packages, resolving against
/// the OSV snapshot pinned in `feed_cache`. Reads are confined beneath `dest`.
pub fn scan_os_packages(dest: &Path, image_digest: &str, feed_cache: Option<&Path>) -> ImageScan {
    let root = match Dir::open_ambient_dir(dest, ambient_authority()) {
        Ok(dir) => dir,
        Err(_) => {
            return ImageScan {
                os: None,
                package_count: 0,
                findings: vec![],
                partial: Some("could not open extracted image root".to_string()),
            }
        }
    };

    let os = ospkg::detect_os(&root);
    let (packages, unsupported_db) = ospkg::read_packages(&root);
    let mut partial = if unsupported_db {
        Some("rpm database format not yet supported".to_string())
    } else {
        None
    };

    let mut findings = Vec::new();
    let index = feed_cache.and_then(crate::OsvIndex::from_cache);

    if let (Some(os), Some(index)) = (&os, &index) {
        if let (Some(ecosystem), namespace, purl_type) =
            (os.osv_ecosystem(), os.purl_namespace(), os.purl_type())
        {
            for pkg in &packages {
                let purl = format!("pkg:{purl_type}/{namespace}/{}@{}", pkg.name, pkg.version);
                for advisory in index.advisories_for(&ecosystem, &pkg.name) {
                    let Some(m) = advisory.matches(&ecosystem, &pkg.name, &pkg.version) else {
                        continue;
                    };
                    findings.push(container_finding(
                        &purl,
                        image_digest,
                        advisory,
                        &m,
                        pkg,
                        &ecosystem,
                    ));
                }
            }
        }
    } else if os.is_some() && index.is_none() && partial.is_none() {
        partial = Some("no feed snapshot; OS package enrichment unavailable".to_string());
    }

    ImageScan {
        os,
        package_count: packages.len(),
        findings,
        partial,
    }
}

fn container_finding(
    purl: &str,
    image_digest: &str,
    advisory: &crate::Advisory,
    m: &crate::osv::Match,
    pkg: &OsPackage,
    ecosystem: &str,
) -> RawFinding {
    let mut detail = serde_json::Map::new();
    let cves = advisory.cve_aliases();
    if !cves.is_empty() {
        detail.insert(
            "cve_aliases".to_string(),
            serde_json::Value::Array(cves.into_iter().map(serde_json::Value::String).collect()),
        );
    }
    RawFinding {
        identity: IdentityKey::ContainerVulnerability {
            purl: purl.to_string(),
            advisory_id: advisory.id.clone(),
            image_digest: image_digest.to_string(),
        },
        title: advisory
            .summary
            .clone()
            .unwrap_or_else(|| format!("{} affected by {}", pkg.name, advisory.id)),
        description: advisory.summary.clone(),
        severity: advisory
            .severity_label()
            .and_then(map_severity)
            .unwrap_or(Severity::Medium),
        confidence: Confidence::Corroborated,
        asset: Asset {
            kind: AssetKind::Image,
            identifier: image_digest.to_string(),
        },
        location: Location {
            path: format!("{ecosystem} package {}", pkg.name),
            line: None,
        },
        evidence: vec![Evidence {
            kind: "os_package".to_string(),
            summary: format!("{}@{} in {ecosystem}", pkg.name, pkg.version),
            detail,
            dependency_path: vec![purl.to_string()],
        }],
        rule_id: Some(advisory.id.clone()),
        remediation: Some(Remediation {
            fix_available: m.fixed_version.is_some(),
            fixed_version: m.fixed_version.clone(),
            summary: m
                .fixed_version
                .as_ref()
                .map(|v| format!("Upgrade {} to {v}.", pkg.name)),
        }),
        cwe: advisory.cwe_ids(),
    }
}

fn map_severity(label: &str) -> Option<Severity> {
    match label.to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MODERATE" | "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

/// Extract all of an image's layers, in order (base first, whiteouts applied),
/// into `dest`. `dest` must already exist. Returns cumulative stats.
///
/// The whole extraction is confined beneath `dest` via a cap-std `Dir`, so no
/// entry — however malicious — can affect anything outside it (SCA-005).
pub fn extract_image(layers: &[Vec<u8>], dest: &Path) -> Result<Stats, ExtractError> {
    let root = Dir::open_ambient_dir(dest, ambient_authority())
        .map_err(|e| ExtractError::Io(e.to_string()))?;
    let limits = Limits::default();
    let mut stats = Stats::default();
    for layer in layers {
        extract_layer(layer.as_slice(), &root, &limits, &mut stats)?;
    }
    Ok(stats)
}
