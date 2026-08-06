//! IaC engine: HCL/YAML/JSON normalization and policy evaluation (spec 7.3).
//!
//! Parse Terraform HCL and Kubernetes YAML/JSON into one normalized resource
//! tree, then evaluate the bundled CIS-mapped policy pack against it. Policies
//! are data, not code (IAC-001); unresolved interpolations degrade to
//! `Heuristic` rather than a silent pass (IAC-003).

mod dockerfile;
mod hcl_parse;
mod k8s_parse;
mod policy;
mod resource;

use std::path::{Path, PathBuf};

use multiscan_core::{
    Asset, AssetKind, Confidence, EngineManifest, Evidence, FindingClass, IdentityKey, Layer,
    Location, NetworkImpact, RawFinding, Severity,
};
use multiscan_engine::{
    Applicability, Engine, EngineError, EngineOutcome, FindingSink, PathFilter, ScanContext,
};

pub use policy::{Condition, Policy};
pub use resource::{Resource, Value};

/// The bundled CIS-mapped policy pack, content-addressed for provenance
/// (FD-006). Embedded so the iac layer needs zero network access (FD-007).
const CIS_PACK: &str = include_str!("../rules/cis-core.json");

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES_VISITED: usize = 1_000_000;

#[derive(serde::Deserialize)]
struct Pack {
    pack_id: String,
    version: String,
    policies: Vec<Policy>,
}

/// The IaC engine.
pub struct IacEngine {
    manifest: EngineManifest,
    policies: Vec<Policy>,
    pack_digest: String,
    /// Policies with no compliance mapping (IAC-004 `mapping_gaps` counter).
    mapping_gaps: usize,
}

impl IacEngine {
    /// Construct the engine with the embedded CIS policy pack.
    pub fn new() -> Self {
        // The embedded pack is validated in tests, so parse failure is a bug;
        // fall back to an empty pack rather than panic in library code.
        Self::from_pack_bytes(CIS_PACK.as_bytes()).unwrap_or_else(|_| {
            Self::build(
                Pack {
                    pack_id: "cis-core".to_string(),
                    version: "0".to_string(),
                    policies: Vec::new(),
                },
                String::new(),
            )
        })
    }

    /// Construct from a policy pack distributed through the feed channel
    /// (ADR 0010): `rules/iac.json` bytes, digest-verified upstream. Returns
    /// an error if the JSON does not parse; the caller falls back to the
    /// embedded pack.
    pub fn from_pack_bytes(bytes: &[u8]) -> Result<Self, String> {
        let pack: Pack = serde_json::from_slice(bytes).map_err(|e| format!("iac pack: {e}"))?;
        let digest = format!("blake3:{}", blake3::hash(bytes).to_hex());
        Ok(Self::build(pack, digest))
    }

    /// The pack this engine loaded, as `id@version` — for pin checks.
    pub fn pack_ref(&self) -> String {
        match &self.manifest.rule_set {
            Some(rs) => format!("{}@{}", rs.id, rs.version),
            None => String::new(),
        }
    }

    fn build(pack: Pack, pack_digest: String) -> Self {
        let mapping_gaps = pack
            .policies
            .iter()
            .filter(|p| p.compliance_controls.is_empty())
            .count();

        // Build the severity map from the pack's own severities (ENG-004).
        let mut severity_map = std::collections::BTreeMap::new();
        for p in &pack.policies {
            severity_map.insert(p.id.clone(), parse_severity(&p.severity));
        }

        Self {
            manifest: EngineManifest {
                id: "multiscan.iac".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                finding_classes: vec![FindingClass::IacMisconfiguration],
                layers: vec![Layer::Iac],
                network_impact: NetworkImpact::ReadOnly,
                requires_authorization: false,
                rule_set: Some(multiscan_core::RuleSetRef {
                    id: pack.pack_id.clone(),
                    version: pack.version.clone(),
                    digest: pack_digest.clone(),
                }),
                severity_map,
            },
            policies: pack.policies,
            pack_digest,
            mapping_gaps,
        }
    }

    /// Number of policies lacking a compliance mapping (IAC-004).
    pub fn mapping_gaps(&self) -> usize {
        self.mapping_gaps
    }
}

impl Default for IacEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

/// A parseable IaC file: its parser and whether it is HCL, K8s, or Dockerfile.
enum Kind {
    Hcl,
    K8s,
    Dockerfile,
}

fn classify(file_name: &str) -> Option<Kind> {
    if file_name.ends_with(".tf") {
        Some(Kind::Hcl)
    } else if file_name.ends_with(".yaml") || file_name.ends_with(".yml") {
        Some(Kind::K8s)
    } else if dockerfile::is_dockerfile(file_name) {
        Some(Kind::Dockerfile)
    } else {
        None
    }
}

/// IaC files under `root`, skipping VCS/vendor dirs and configured excludes
/// (`[scan] exclude` plus `[scan.iac] exclude`, ADR 0004).
fn find_files(root: &Path, excludes: &PathFilter) -> Vec<(PathBuf, String, Kind)> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_FILES_VISITED {
                found.sort_by(|a: &(PathBuf, String, Kind), b| a.1.cmp(&b.1));
                return found;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if excludes.is_excluded(Layer::Iac, &rel) || excludes.is_ignored(&rel, is_dir) {
                continue; // matched dirs prune the walk, matched files skip
            }
            if is_dir {
                if matches!(name.as_str(), ".git" | "node_modules" | "target" | ".venv") {
                    continue;
                }
                stack.push(path);
            } else if let Some(kind) = classify(&name) {
                found.push((path, rel, kind));
            }
        }
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

impl Engine for IacEngine {
    fn manifest(&self) -> &EngineManifest {
        &self.manifest
    }

    fn applicable(&self, ctx: &ScanContext) -> Applicability {
        if find_files(&ctx.root, &ctx.excludes).is_empty() {
            Applicability::NotApplicable
        } else {
            Applicability::Applicable
        }
    }

    fn scan(
        &self,
        ctx: &ScanContext,
        sink: &mut dyn FindingSink,
    ) -> Result<EngineOutcome, EngineError> {
        let files = find_files(&ctx.root, &ctx.excludes);
        let total = files.len() as u64;
        let mut scanned = 0u64;
        let mut degraded: Option<String> = None;

        for (abs, rel, kind) in files {
            if ctx.should_stop() {
                return Ok(EngineOutcome::Partial {
                    units_scanned: scanned,
                    reason: "cancelled or past deadline".to_string(),
                });
            }
            scanned += 1;
            sink.progress(scanned, Some(total));

            if std::fs::metadata(&abs).map(|m| m.len()).unwrap_or(0) > MAX_FILE_BYTES {
                degraded = Some(format!("{rel}: exceeds size cap"));
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&abs) else {
                continue;
            };
            let parsed = match kind {
                Kind::Hcl => hcl_parse::parse(&text, &rel),
                Kind::K8s => k8s_parse::parse(&text, &rel),
                Kind::Dockerfile => dockerfile::parse(&text, &rel),
            };
            let resources = match parsed {
                Ok(resources) => resources,
                Err(reason) => {
                    // Malformed IaC file degrades to Partial (spec 7.1).
                    degraded = Some(reason);
                    continue;
                }
            };
            for resource in &resources {
                self.evaluate(resource, sink)
                    .map_err(|e| EngineError::Failed(e.to_string()))?;
            }
        }

        match degraded {
            Some(reason) => Ok(EngineOutcome::Partial {
                units_scanned: scanned,
                reason,
            }),
            None => Ok(EngineOutcome::Complete {
                units_scanned: scanned,
            }),
        }
    }
}

impl IacEngine {
    fn evaluate(
        &self,
        resource: &Resource,
        sink: &mut dyn FindingSink,
    ) -> Result<(), multiscan_engine::SinkError> {
        for p in &self.policies {
            if !p.resource_kinds.iter().any(|k| k == &resource.kind) {
                continue;
            }
            let (confidence, is_violation) = match p.condition.eval(resource) {
                policy::Eval::Violation => (Confidence::Corroborated, true),
                // IAC-003: unresolved input is a Heuristic finding, not a pass.
                policy::Eval::Unresolved => (Confidence::Heuristic, true),
                policy::Eval::Pass => (Confidence::Corroborated, false),
            };
            if !is_violation {
                continue;
            }

            let mut detail = serde_json::Map::new();
            detail.insert(
                "compliance_controls".to_string(),
                serde_json::Value::Array(
                    p.compliance_controls
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
            detail.insert(
                "rule_pack".to_string(),
                serde_json::Value::String(self.pack_digest.clone()),
            );

            sink.emit(RawFinding {
                identity: IdentityKey::IacMisconfiguration {
                    policy_id: p.id.clone(),
                    path: resource.source_path.clone(),
                    resource_address: resource.address.clone(),
                },
                title: p.title.clone(),
                description: Some(p.remediation.clone()),
                severity: parse_severity(&p.severity),
                confidence,
                asset: Asset {
                    kind: AssetKind::File,
                    identifier: resource.source_path.clone(),
                },
                location: Location {
                    path: resource.source_path.clone(),
                    line: None,
                },
                evidence: vec![Evidence {
                    kind: "policy_violation".to_string(),
                    summary: format!("{} violates {}", resource.address, p.id),
                    detail,
                    dependency_path: vec![],
                }],
                rule_id: Some(p.id.clone()),
                remediation: Some(multiscan_core::Remediation {
                    fix_available: false,
                    fixed_version: None,
                    summary: Some(p.remediation.clone()),
                }),
                cwe: p.cwe.clone(),
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_loads_and_every_policy_is_mapped() {
        let engine = IacEngine::new();
        assert!(!engine.policies.is_empty());
        // IAC-004: the bundled pack has no mapping gaps.
        assert_eq!(engine.mapping_gaps(), 0);
        for p in &engine.policies {
            assert!(
                !p.compliance_controls.is_empty(),
                "policy {} has no compliance control",
                p.id
            );
        }
    }
}
