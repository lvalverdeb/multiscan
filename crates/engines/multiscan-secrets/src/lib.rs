//! Secrets engine: regex, entropy, truncated fingerprints (spec 7.2).
//!
//! SEC-101 is the load-bearing invariant: a detected secret **value** never
//! leaves [`fingerprint`] — Findings carry only the rule id, location, a
//! truncated keyed fingerprint, and a heavily-masked preview. Entropy-only
//! detections are capped at Medium/Heuristic (SEC-103).

mod entropy;
mod fingerprint;
mod noise;
mod rules;

use std::path::{Path, PathBuf};

use multiscan_core::{
    Asset, AssetKind, Confidence, EngineManifest, Evidence, FindingClass, IdentityKey, Layer,
    Location, NetworkImpact, RawFinding, Severity,
};
use multiscan_engine::{
    Applicability, Engine, EngineError, EngineOutcome, FindingSink, PathFilter, ScanContext,
};

pub use entropy::shannon_bits;
pub use fingerprint::{fingerprint, mask};

/// Files larger than this are skipped (untrusted input; secrets live in source
/// and config, not multi-GB blobs).
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FILES_VISITED: usize = 1_000_000;
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Minimum length and entropy for the generic high-entropy detector.
const ENTROPY_MIN_LEN: usize = 20;
const ENTROPY_MIN_BITS: f64 = 4.0;

/// The secrets engine.
pub struct SecretsEngine {
    manifest: EngineManifest,
    rules: Vec<rules::Rule>,
    token: Option<regex::Regex>,
}

impl SecretsEngine {
    /// Construct the engine with the bundled rule pack.
    pub fn new() -> Self {
        let severity_map = [
            ("aws-access-key-id", Severity::High),
            ("aws-secret-access-key", Severity::Critical),
            ("github-token", Severity::High),
            ("slack-token", Severity::High),
            ("google-api-key", Severity::High),
            ("private-key-block", Severity::Critical),
            ("jwt", Severity::Medium),
            ("high-entropy-string", Severity::Medium),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        Self {
            manifest: EngineManifest {
                id: "multiscan.secrets".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                finding_classes: vec![FindingClass::ExposedSecret],
                layers: vec![Layer::Secrets],
                network_impact: NetworkImpact::ReadOnly,
                requires_authorization: false,
                rule_set: None,
                severity_map,
            },
            rules: rules::builtin_rules(),
            // Candidate tokens for the entropy detector: long unbroken runs of
            // secret-ish characters. Built fallibly (no panic in library code);
            // if it somehow failed to compile, entropy detection is simply off.
            token: regex::Regex::new(r"[A-Za-z0-9+/_\-]{20,}").ok(),
        }
    }
}

impl Default for SecretsEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Files under `root` (bounded; skips VCS/vendor dirs and configured
/// excludes — `[scan] exclude` plus `[scan.secrets] exclude`, ADR 0004).
fn find_files(root: &Path, excludes: &PathFilter) -> Vec<(PathBuf, String)> {
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
                found.sort();
                return found;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if excludes.is_excluded(Layer::Secrets, &rel) {
                continue; // matched dirs prune the walk, matched files skip
            }
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if matches!(name.as_str(), ".git" | "node_modules" | "target" | ".venv") {
                    continue;
                }
                stack.push(path);
            } else {
                found.push((path, rel));
            }
        }
    }
    found.sort();
    found
}

impl Engine for SecretsEngine {
    fn manifest(&self) -> &EngineManifest {
        &self.manifest
    }

    fn applicable(&self, _ctx: &ScanContext) -> Applicability {
        // Secrets can appear in any repo; cheap unconditional applicability.
        Applicability::Applicable
    }

    fn scan(
        &self,
        ctx: &ScanContext,
        sink: &mut dyn FindingSink,
    ) -> Result<EngineOutcome, EngineError> {
        let files = find_files(&ctx.root, &ctx.excludes);
        let total = files.len() as u64;
        let mut scanned = 0u64;

        for (abs, rel) in files {
            if ctx.should_stop() {
                return Ok(EngineOutcome::Partial {
                    units_scanned: scanned,
                    reason: "cancelled or past deadline".to_string(),
                });
            }
            scanned += 1;
            sink.progress(scanned, Some(total));

            if std::fs::metadata(&abs).map(|m| m.len()).unwrap_or(0) > MAX_FILE_BYTES {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&abs) else {
                continue; // binary or unreadable — skip, not an error
            };
            // ADR 0005: known-noise files (built-in list + configured
            // entropy_exclude) keep the precise rules but lose the entropy
            // fallback — their high-entropy content is checksums, not secrets.
            let entropy_enabled = !noise::entropy_noise_path(&rel)
                && !ctx.excludes.is_entropy_excluded(&rel);
            self.scan_text(&text, &rel, entropy_enabled, sink)
                .map_err(|e| EngineError::Failed(e.to_string()))?;
        }

        Ok(EngineOutcome::Complete {
            units_scanned: scanned,
        })
    }
}

impl SecretsEngine {
    fn scan_text(
        &self,
        text: &str,
        path: &str,
        entropy_enabled: bool,
        sink: &mut dyn FindingSink,
    ) -> Result<(), multiscan_engine::SinkError> {
        for (idx, line) in text.lines().enumerate() {
            if line.len() > MAX_LINE_BYTES {
                continue;
            }
            let line_number = (idx + 1) as i64;

            // High-precision provider rules first.
            let mut matched_here = false;
            for rule in &self.rules {
                for caps in rule.pattern.captures_iter(line) {
                    let value = rule.extract(&caps);
                    if value.is_empty() {
                        continue;
                    }
                    matched_here = true;
                    self.emit(
                        sink,
                        rule.id,
                        rule.description,
                        rule.severity,
                        rule.confidence,
                        value,
                        path,
                        line_number,
                    )?;
                }
            }

            // Entropy fallback: only when no precise rule already fired on this
            // line, to avoid double-reporting the same secret. Capped at
            // Medium/Heuristic (SEC-103). Skipped entirely on known-noise
            // files, and per-token for content-address shapes — digests,
            // UUIDs, URL-embedded runs (ADR 0005).
            if !matched_here && entropy_enabled {
                let Some(token) = &self.token else { continue };
                for m in token.find_iter(line) {
                    let candidate = m.as_str();
                    if noise::digest_shaped(candidate)
                        || noise::uuid_shaped(candidate)
                        || noise::in_url_context(line, m.start())
                    {
                        continue;
                    }
                    if candidate.len() >= ENTROPY_MIN_LEN
                        && shannon_bits(candidate.as_bytes()) >= ENTROPY_MIN_BITS
                    {
                        self.emit(
                            sink,
                            "high-entropy-string",
                            "High-entropy string (possible secret)",
                            Severity::Medium,
                            Confidence::Heuristic,
                            candidate,
                            path,
                            line_number,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Emit one ExposedSecret. This is the ONLY place a detected value is
    /// touched, and it is immediately reduced to a fingerprint + mask; the raw
    /// value never enters any Finding field (SEC-101).
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        sink: &mut dyn FindingSink,
        rule_id: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
        value: &str,
        path: &str,
        line: i64,
    ) -> Result<(), multiscan_engine::SinkError> {
        let fingerprint = fingerprint(value);
        let masked = mask(value);
        sink.emit(RawFinding {
            identity: IdentityKey::ExposedSecret {
                rule_id: rule_id.to_string(),
                path: path.to_string(),
                fingerprint: fingerprint.clone(),
            },
            title: format!("{description} exposed"),
            description: Some(format!(
                "A {description} was detected. Rotate it and remove it from source."
            )),
            severity,
            confidence,
            asset: Asset {
                kind: AssetKind::File,
                identifier: path.to_string(),
            },
            location: Location {
                path: path.to_string(),
                line: Some(line),
            },
            evidence: vec![Evidence {
                kind: "secret_fingerprint".to_string(),
                // Only the masked preview + fingerprint — never the value.
                summary: format!("{description} `{masked}` (fingerprint {fingerprint})"),
                detail: serde_json::Map::new(),
                dependency_path: vec![],
            }],
            rule_id: Some(rule_id.to_string()),
            remediation: None,
            cwe: vec!["CWE-798".to_string()],
        })
    }
}
