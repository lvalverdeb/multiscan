//! SCA engine: lockfiles and OS packages to purl to OSV resolution (spec 7.1).
//!
//! Detection model: parse manifests/lockfiles → construct purls → resolve
//! against the pinned OSV snapshot → emit `VulnerableDependency`. Version
//! matching uses each ecosystem's own ordering (SCA-002); a malformed file
//! degrades to `Partial`, never aborts the scan.

pub mod image;
mod lockfile;
pub(crate) mod osv;
mod version;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use multiscan_core::{
    Asset, AssetKind, Confidence, EngineManifest, Evidence, FindingClass, IdentityKey, Layer,
    Location, NetworkImpact, RawFinding, Remediation, Severity,
};
use multiscan_engine::{
    Applicability, Engine, EngineError, EngineOutcome, FindingSink, PathFilter, ScanContext,
};

pub use lockfile::ResolvedPackage;
pub use osv::Advisory;
pub use version::Scheme;

/// Defensive caps for the tree walk and per-file reads (untrusted input).
const MAX_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILES_VISITED: usize = 1_000_000;

/// The SCA engine.
pub struct ScaEngine {
    manifest: EngineManifest,
}

impl ScaEngine {
    /// Construct the engine with its manifest.
    pub fn new() -> Self {
        Self {
            manifest: EngineManifest {
                id: "multiscan.sca".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                finding_classes: vec![
                    FindingClass::VulnerableDependency,
                    FindingClass::ContainerVulnerability,
                ],
                layers: vec![Layer::Sca],
                network_impact: NetworkImpact::ReadOnly,
                requires_authorization: false,
                rule_set: None,
                // OSV coarse severity label → our ordinal. Unknown labels
                // default to Medium; nothing is inferred past the map (ENG-004).
                severity_map: [
                    ("CRITICAL", Severity::Critical),
                    ("HIGH", Severity::High),
                    ("MODERATE", Severity::Medium),
                    ("MEDIUM", Severity::Medium),
                    ("LOW", Severity::Low),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            },
        }
    }

    /// Map an advisory's coarse label to Severity; absent/unknown → Medium.
    fn severity_for(&self, label: Option<&str>) -> Severity {
        label
            .and_then(|l| self.manifest.severity_map.get(&l.to_ascii_uppercase()))
            .copied()
            .unwrap_or(Severity::Medium)
    }
}

impl Default for ScaEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve the full package inventory under `root` — every package in every
/// recognized lockfile, deduplicated by purl and sorted. This is the source
/// for the CycloneDX SBOM (spec 12); it needs no OSV snapshot. Unparseable
/// lockfiles are skipped rather than failing the inventory. `excludes` is the
/// same filter the scan ran with, so the SBOM never inventories what the
/// scan was told not to look at.
pub fn resolve_inventory(root: &Path, excludes: &PathFilter) -> Vec<ResolvedPackage> {
    let mut by_purl: std::collections::BTreeMap<String, ResolvedPackage> =
        std::collections::BTreeMap::new();
    for (abs, _rel, name) in find_lockfiles(root, excludes) {
        let Some(parse) = lockfile::parser_for(&name) else {
            continue;
        };
        if std::fs::metadata(&abs).map(|m| m.len()).unwrap_or(0) > MAX_LOCKFILE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&abs) else {
            continue;
        };
        if let Ok(packages) = parse(&text) {
            for package in packages {
                by_purl.insert(package.purl(), package);
            }
        }
    }
    by_purl.into_values().collect()
}

/// The parent directory of a root-relative POSIX path (`""` at the root).
fn rel_parent(rel: &str) -> &str {
    rel.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("")
}

/// Sort discoveries and drop shadowed manifests: a manifest is a fallback,
/// so if one of its lockfiles exists in the same directory or an ancestor
/// (workspace roots hold the lock for member manifests — Cargo, Go), the
/// lockfile's exact resolutions win and the manifest is skipped. A repo is
/// never double-reported.
fn finish_discovery(mut found: Vec<(PathBuf, String, String)>) -> Vec<(PathBuf, String, String)> {
    let locks: std::collections::BTreeSet<(String, String)> = found
        .iter()
        .filter(|(_, _, name)| !lockfile::is_manifest(name))
        .map(|(_, rel, name)| (rel_parent(rel).to_string(), name.clone()))
        .collect();
    found.retain(|(_, rel, name)| {
        if !lockfile::is_manifest(name) {
            return true;
        }
        let shadows = lockfile::shadowing_lockfiles(name);
        let mut dir = rel_parent(rel);
        loop {
            if shadows
                .iter()
                .any(|lock| locks.contains(&(dir.to_string(), (*lock).to_string())))
            {
                return false;
            }
            if dir.is_empty() {
                return true;
            }
            dir = rel_parent(dir);
        }
    });
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

/// Find lockfiles and unshadowed manifests under `root`, bounded and skipping
/// heavy vendor dirs and configured excludes (`[scan] exclude` plus
/// `[scan.sca] exclude`, ADR 0004).
/// Returns (absolute path, root-relative POSIX path, file name), sorted.
fn find_lockfiles(root: &Path, excludes: &PathFilter) -> Vec<(PathBuf, String, String)> {
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
                return finish_discovery(found);
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if excludes.is_excluded(Layer::Sca, &rel) || excludes.is_ignored(&rel, is_dir) {
                continue; // matched dirs prune the walk, matched files skip
            }
            if is_dir {
                if matches!(name.as_str(), ".git" | "node_modules" | "target" | ".venv") {
                    continue;
                }
                stack.push(path);
            } else if lockfile::SUPPORTED_FILES.contains(&name.as_str()) {
                found.push((path, rel, name));
            }
        }
    }
    finish_discovery(found)
}

/// OSV advisories indexed by lowercased package name, per ecosystem.
pub(crate) struct OsvIndex {
    by_name: BTreeMap<String, BTreeMap<String, Vec<Advisory>>>,
}

impl OsvIndex {
    fn load(ctx: &ScanContext) -> Option<Self> {
        Self::from_cache(ctx.feed_cache_dir.as_deref()?)
    }

    /// Load the OSV index from the snapshot pinned in `cache`.
    pub(crate) fn from_cache(cache: &Path) -> Option<Self> {
        let snapshot = multiscan_feeds::current_snapshot(cache).ok()??;
        let mut by_name: BTreeMap<String, BTreeMap<String, Vec<Advisory>>> = BTreeMap::new();
        for name in snapshot.manifest.files.keys() {
            let Some(ecosystem) = name
                .strip_prefix("osv/")
                .and_then(|n| n.strip_suffix(".jsonl"))
            else {
                continue;
            };
            let Ok(bytes) = snapshot.read_file(name) else {
                continue;
            };
            let index = by_name.entry(ecosystem.to_string()).or_default();
            for line in bytes.split(|b| *b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Ok(advisory) = serde_json::from_slice::<Advisory>(line) {
                    for affected in &advisory.affected {
                        if let Some(pkg) = &affected.package {
                            index
                                .entry(pkg.name.to_ascii_lowercase())
                                .or_default()
                                .push(advisory.clone());
                        }
                    }
                }
            }
        }
        Some(Self { by_name })
    }

    pub(crate) fn advisories_for(&self, ecosystem: &str, name: &str) -> &[Advisory] {
        self.by_name
            .get(ecosystem)
            .and_then(|m| m.get(&name.to_ascii_lowercase()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

impl Engine for ScaEngine {
    fn manifest(&self) -> &EngineManifest {
        &self.manifest
    }

    fn applicable(&self, ctx: &ScanContext) -> Applicability {
        // Cheap: bounded existence check for any supported lockfile name.
        if find_lockfiles(&ctx.root, &ctx.excludes).is_empty() {
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
        let index = OsvIndex::load(ctx);
        let lockfiles = find_lockfiles(&ctx.root, &ctx.excludes);
        let total = lockfiles.len() as u64;
        let mut scanned = 0u64;
        let mut degraded: Option<String> = None;

        for (abs, rel, name) in lockfiles {
            if ctx.should_stop() {
                return Ok(EngineOutcome::Partial {
                    units_scanned: scanned,
                    reason: "cancelled or past deadline".to_string(),
                });
            }
            scanned += 1;
            sink.progress(scanned, Some(total));

            let Some(parse) = lockfile::parser_for(&name) else {
                continue;
            };
            if std::fs::metadata(&abs).map(|m| m.len()).unwrap_or(0) > MAX_LOCKFILE_BYTES {
                degraded = Some(format!("{rel}: exceeds size cap"));
                continue;
            }
            let text = match std::fs::read_to_string(&abs) {
                Ok(text) => text,
                Err(e) => {
                    degraded = Some(format!("{rel}: {e}"));
                    continue;
                }
            };
            let packages = match parse(&text) {
                Ok(packages) => packages,
                Err(reason) => {
                    // SCA: a malformed lockfile degrades to Partial (spec 7.1).
                    degraded = Some(reason);
                    continue;
                }
            };

            for package in packages {
                self.emit_for_package(index.as_ref(), &rel, &package, sink)
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

impl ScaEngine {
    fn emit_for_package(
        &self,
        index: Option<&OsvIndex>,
        manifest_path: &str,
        package: &ResolvedPackage,
        sink: &mut dyn FindingSink,
    ) -> Result<(), multiscan_engine::SinkError> {
        let asset = Asset {
            kind: AssetKind::Package,
            identifier: package.purl(),
        };

        // SCA-001: unpinned declarations are Informational/Unconfirmed, never
        // silently skipped.
        let Some(version) = &package.version else {
            sink.emit(RawFinding {
                identity: IdentityKey::VulnerableDependency {
                    purl: package.purl(),
                    advisory_id: "native:sca:unpinned".to_string(),
                    manifest_path: manifest_path.to_string(),
                },
                title: format!("Unpinned dependency `{}`", package.name),
                description: Some(
                    "Version is not pinned; it cannot be resolved against advisories.".to_string(),
                ),
                severity: Severity::Informational,
                confidence: Confidence::Unconfirmed,
                asset,
                location: Location {
                    path: manifest_path.to_string(),
                    line: None,
                },
                evidence: vec![],
                rule_id: Some("native:sca:unpinned".to_string()),
                remediation: Some(Remediation {
                    fix_available: false,
                    fixed_version: None,
                    summary: Some("Pin the dependency to an exact version.".to_string()),
                }),
                cwe: vec![],
            })?;
            return Ok(());
        };

        let Some(index) = index else {
            // No snapshot ⇒ no advisory data; the scan-side staleness policy
            // (FD-004/FD-007) already warned.
            return Ok(());
        };

        for advisory in index.advisories_for(&package.ecosystem, &package.name) {
            let Some(m) = advisory.matches(&package.ecosystem, &package.name, version) else {
                continue;
            };
            // Carry the advisory's CVE aliases so the post-dedup enrichment
            // stage can look them up in KEV/EPSS for factor X (spec 8), without
            // putting enrichment data into identity.
            let mut detail = serde_json::Map::new();
            let cves = advisory.cve_aliases();
            if !cves.is_empty() {
                detail.insert(
                    "cve_aliases".to_string(),
                    serde_json::Value::Array(
                        cves.into_iter().map(serde_json::Value::String).collect(),
                    ),
                );
            }
            let mut evidence = vec![Evidence {
                kind: "lockfile_entry".to_string(),
                summary: format!("{}@{} in {manifest_path}", package.name, version),
                detail,
                // SCA-003: attribute transitive deps. A fuller dependency graph
                // lands with per-ecosystem tree parsing; for now the package's
                // own purl anchors the path.
                dependency_path: vec![package.purl()],
            }];
            if let Some(summary) = &advisory.summary {
                evidence.push(Evidence {
                    kind: "advisory".to_string(),
                    summary: summary.clone(),
                    detail: serde_json::Map::new(),
                    dependency_path: vec![],
                });
            }

            sink.emit(RawFinding {
                // ADR 0012: identity is keyed on the canonical vulnerability id
                // (CVE when present), so a GHSA and a PYSEC of one CVE share a
                // finding_id and the dedup pass merges them into one finding
                // (max severity, both records as sources). `rule_id` keeps the
                // actual OSV record so each still appears as a distinct source.
                identity: IdentityKey::VulnerableDependency {
                    purl: package.purl(),
                    advisory_id: advisory.canonical_vuln_id(),
                    manifest_path: manifest_path.to_string(),
                },
                title: advisory
                    .summary
                    .clone()
                    .unwrap_or_else(|| format!("{} affected by {}", package.name, advisory.id)),
                description: advisory.summary.clone(),
                severity: self.severity_for(advisory.severity_label()),
                confidence: Confidence::Corroborated,
                asset: asset.clone(),
                location: Location {
                    path: manifest_path.to_string(),
                    line: None,
                },
                evidence,
                rule_id: Some(advisory.id.clone()),
                remediation: Some(Remediation {
                    fix_available: m.fixed_version.is_some(),
                    fixed_version: m.fixed_version.clone(),
                    summary: m
                        .fixed_version
                        .as_ref()
                        .map(|v| format!("Upgrade {} to {v}.", package.name)),
                }),
                cwe: advisory.cwe_ids(),
            })?;
        }
        Ok(())
    }
}
