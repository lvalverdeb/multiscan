//! Structural pattern matching over source code (spec 7.5).
//!
//! v1 shipped the scaffold and [`structural_hash`] only (`T-604`). `T-701` adds
//! the language-independent core: the [`tree`] both front-ends lower into, the
//! MS-PAT-1 [`pattern`] representation, the [`matcher`], and [`rules`] pack
//! loading. Language front-ends — the parsers that turn real source and leaf
//! pattern text into these types — arrive with `T-702` (ADR 0015).
//!
//! **NG-2 stands permanently: structural matching only, no taint or dataflow
//! analysis.** [`pattern::PatternExpr`] has no variant that could express it.
//!
//! The contract this implements is `docs/ms-pat-1.md`.

pub mod compile;
pub mod imports;
pub mod lang;
pub mod matcher;
pub mod pattern;
pub mod rules;
pub mod tree;

use std::path::{Path, PathBuf};

use multiscan_core::{
    Asset, AssetKind, EngineManifest, Evidence, FindingClass, IdentityKey, Layer, Location,
    NetworkImpact, RawFinding, Severity,
};
use multiscan_engine::{
    Applicability, Engine, EngineError, EngineOutcome, FindingSink, PathFilter, ScanContext,
};

use crate::compile::CompiledRule;
use crate::rules::Language;
use crate::tree::Node;

/// Files larger than this are skipped. Source, not blobs; untrusted input.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Directory-walk bound, mirroring the other file-walking engines.
const MAX_FILES_VISITED: usize = 1_000_000;

/// Domain separator for the structural hash. Bumping it changes every
/// `StructuralPattern` finding_id, so it is frozen (cf. dedup's identity
/// encoding).
const STRUCTURAL_DOMAIN: &[u8] = b"multiscan:structural_hash:v1";

/// Hash the *shape* of a code fragment: its canonical node kinds plus its
/// normalized identifiers — never raw line numbers or literal text (spec
/// 7.7.2, amended by ADR 0016). Two fragments that differ only in whitespace,
/// line position, or (with normalization) identifier spelling produce the same
/// hash, so a `StructuralPattern` finding is stable across cosmetic edits.
///
/// Kinds come from [`tree::Kind`] — MultiScan's own closed vocabulary, not a
/// parser's — so identity survives a parser upgrade or replacement
/// (ADR 0015). Prefer [`structural_hash_of`], which derives both arguments
/// from a matched subtree in the frozen pre-order form.
pub fn structural_hash(node_kinds: &[&str], normalized_identifiers: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STRUCTURAL_DOMAIN);
    hasher.update(&(node_kinds.len() as u64).to_le_bytes());
    for kind in node_kinds {
        hasher.update(&(kind.len() as u64).to_le_bytes());
        hasher.update(kind.as_bytes());
    }
    hasher.update(&(normalized_identifiers.len() as u64).to_le_bytes());
    for id in normalized_identifiers {
        hasher.update(&(id.len() as u64).to_le_bytes());
        hasher.update(id.as_bytes());
    }
    format!("b3:{}", &hasher.finalize().to_hex()[..24])
}

/// Hash a matched subtree in the frozen form: pre-order canonical kinds plus
/// normalized identifiers, spans excluded (`docs/ms-pat-1.md` §5).
///
/// This is the `structural_hash` component of the `StructuralPattern` identity
/// tuple, so **reformatting a file does not change the resulting
/// `finding_id`** (`SAST-002`). Changing what this function feeds the hash
/// invalidates every user's baselines and suppressions — a stop-and-ask change.
pub fn structural_hash_of(node: &Node) -> String {
    let (kinds, names) = node.structural_parts();
    structural_hash(&kinds, &names)
}

/// Which front-end handles a file extension, or `None` if the language is
/// unsupported (`SAST-003`).
///
/// Extension-only by construction: no file is opened to decide this, which is
/// what keeps `applicable()` cheap.
pub fn language_for_extension(extension: &str) -> Option<Language> {
    let ext = extension.to_ascii_lowercase();
    if lang::python::EXTENSIONS.contains(&ext.as_str()) {
        Some(Language::Python)
    } else if lang::javascript::EXTENSIONS.contains(&ext.as_str()) {
        if lang::javascript::is_typescript(&ext) {
            Some(Language::Typescript)
        } else {
            Some(Language::Javascript)
        }
    } else {
        None
    }
}

/// Discover source files a front-end can handle: `(absolute, relative, language)`.
///
/// Extension-only, exclude-aware, and bounded. Results are sorted by relative
/// path so emission order does not depend on the filesystem (`DET-002`).
///
/// Public because reachability (`T-802`) walks the same file set to extract
/// imports, and the two must agree on what counts as scanned source.
pub fn discover(root: &Path, excludes: &PathFilter) -> Vec<(PathBuf, String, Language)> {
    find_files(root, excludes)
}

fn find_files(root: &Path, excludes: &PathFilter) -> Vec<(PathBuf, String, Language)> {
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
                found.sort_by(|a: &(PathBuf, String, Language), b| a.1.cmp(&b.1));
                return found;
            }
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if excludes.is_excluded(Layer::Sast, &rel) || excludes.is_ignored(&rel, is_dir) {
                continue; // matched dirs prune the walk, matched files skip
            }
            if is_dir {
                stack.push(path);
                continue;
            }
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if let Some(language) = language_for_extension(ext) {
                found.push((path, rel, language));
            }
        }
    }
    found.sort_by(|a, b| a.1.cmp(&b.1));
    found
}

/// The SAST engine: MS-PAT-1 rules matched structurally over parsed source.
///
/// Rules are injected rather than embedded. `multiscan-sast` authors no
/// vulnerability knowledge (§1.2) — the corpus is a mechanically translated
/// pack delivered over the feed channel (ADR 0014, `T-705`). With no rules the
/// engine is `NotApplicable`, which also means it can never report `Complete`
/// over zero rules and wrongly close findings (§7.7.4).
pub struct SastEngine {
    manifest: EngineManifest,
    rules: Vec<CompiledRule>,
    /// Rules the pack carried that could not be loaded or compiled.
    ///
    /// Nonzero means this scan ran with **fewer rules than the pack declares**,
    /// so `Complete` would be a lie: a rule that fired yesterday and is broken
    /// today would have its findings closed as `Fixed` while the code is
    /// unchanged (§7.7.4). The outcome degrades to `Partial` instead.
    rejected_rules: usize,
}

impl SastEngine {
    /// Construct the engine with no rules. Inert until a pack is supplied.
    pub fn new() -> Self {
        Self::with_rules(Vec::new())
    }

    /// Construct the engine with a compiled rule set and no pack provenance.
    /// Convenience for tests; production goes through [`SastEngine::with_pack`].
    pub fn with_rules(rules: Vec<CompiledRule>) -> Self {
        Self::with_pack(rules, None, 0)
    }

    /// Construct the engine from a loaded pack.
    ///
    /// `rule_set` records *which corpus ran* in the manifest (`FD-006`), the
    /// same way the IaC engine does — without it a Finding's provenance chain
    /// cannot name the pack that produced it. `rejected` is the count of rules
    /// the pack declared but that failed to load or compile.
    pub fn with_pack(
        rules: Vec<CompiledRule>,
        rule_set: Option<multiscan_core::RuleSetRef>,
        rejected: usize,
    ) -> Self {
        Self {
            manifest: EngineManifest {
                id: "multiscan.sast".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                finding_classes: vec![FindingClass::StructuralPattern],
                layers: vec![Layer::Sast],
                network_impact: NetworkImpact::ReadOnly,
                requires_authorization: false,
                rule_set,
                // Every rule carries its own explicit severity (SAST-004); this
                // map remains the manifest-level declaration ENG-004 requires.
                severity_map: [("structural", Severity::Medium)]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            },
            rules,
            rejected_rules: rejected,
        }
    }

    /// Match every applicable rule against one parsed file, emitting Findings.
    fn match_file(
        &self,
        tree: &Node,
        rel_path: &str,
        language: Language,
        sink: &mut dyn FindingSink,
    ) -> Result<Option<String>, multiscan_engine::SinkError> {
        let mut degraded = None;

        for rule in &self.rules {
            let Some(expr) = rule.per_language.get(&language) else {
                continue;
            };
            // Buffered per rule per file — bounded by one file's match count,
            // never the whole scan (NFR-003) — because the matcher's callback
            // cannot propagate a SinkError out of the walk.
            let mut emitted = Vec::new();
            let stats = matcher::for_each_match(expr, tree, |m| {
                emitted.push((structural_hash_of(m.node), m.node.span.line));
            });
            if stats.budget_exhausted {
                // Matching gave up, so this rule's results are incomplete.
                // Surfacing it degrades the scan to Partial; swallowing it
                // would be a silent false negative that lets Complete close
                // findings (§7.7.4).
                degraded = Some(format!(
                    "{rel_path}: rule {} exhausted the match budget",
                    rule.id
                ));
            }
            for (structural_hash, line) in emitted {
                sink.emit(RawFinding {
                    identity: IdentityKey::StructuralPattern {
                        rule_id: rule.id.clone(),
                        path: rel_path.to_string(),
                        structural_hash: structural_hash.clone(),
                    },
                    title: rule.message.clone(),
                    description: None,
                    severity: rule.severity,
                    confidence: rule.confidence,
                    asset: Asset {
                        kind: AssetKind::File,
                        identifier: rel_path.to_string(),
                    },
                    location: Location {
                        path: rel_path.to_string(),
                        line: Some(line as i64),
                    },
                    evidence: vec![Evidence {
                        kind: "structural_match".to_string(),
                        summary: format!(
                            "rule {} matched structurally ({structural_hash})",
                            rule.id
                        ),
                        detail: serde_json::Map::new(),
                        dependency_path: vec![],
                    }],
                    rule_id: Some(rule.id.clone()),
                    remediation: None,
                    cwe: vec![],
                })?;
            }
        }
        Ok(degraded)
    }
}

impl Default for SastEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine for SastEngine {
    fn manifest(&self) -> &EngineManifest {
        &self.manifest
    }

    fn applicable(&self, ctx: &ScanContext) -> Applicability {
        // No rules means nothing to match — and, critically, means we must not
        // run and report Complete, which would close previously-reported
        // findings (§7.7.4).
        if self.rules.is_empty() {
            return Applicability::NotApplicable;
        }
        // Extension-only: the walk reads directory entries, never file
        // contents (SAST-003, ENG contract).
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
        // A pack that only partly compiled means this run cannot close
        // anything: rules the pack declares were not applied, so their absence
        // from the output is not evidence they no longer match (§7.7.4).
        let mut degraded: Option<String> = (self.rejected_rules > 0).then(|| {
            format!(
                "{} pack rule(s) rejected at load; scanned with fewer rules than the pack declares",
                self.rejected_rules
            )
        });

        for (abs, rel, language) in files {
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

            let parsed = match language {
                Language::Python => lang::python::lower_source(&text),
                Language::Javascript => lang::javascript::lower_source(&text, false),
                Language::Typescript => lang::javascript::lower_source(&text, true),
            };
            let tree = match parsed {
                Ok(tree) => tree,
                Err(e) => {
                    // A file that does not parse degrades the scan to Partial
                    // rather than aborting it — and Partial cannot close
                    // findings, so a syntax error never marks anything fixed.
                    degraded = Some(format!("{rel}: {e}"));
                    continue;
                }
            };

            if let Some(reason) = self
                .match_file(&tree, &rel, language, sink)
                .map_err(|e| EngineError::Failed(e.to_string()))?
            {
                degraded = Some(reason);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_hash_ignores_line_positions() {
        // Same node kinds + identifiers ⇒ same hash regardless of anything the
        // caller might have wanted to include (line numbers are never passed).
        let a = structural_hash(&["call", "identifier"], &["unwrap"]);
        let b = structural_hash(&["call", "identifier"], &["unwrap"]);
        assert_eq!(a, b);
        assert!(a.starts_with("b3:"));
    }

    #[test]
    fn different_shapes_differ() {
        assert_ne!(
            structural_hash(&["call"], &["a"]),
            structural_hash(&["call"], &["b"])
        );
        assert_ne!(
            structural_hash(&["call", "arg"], &["a"]),
            structural_hash(&["call"], &["a", "arg"])
        );
    }

    #[test]
    fn engine_without_rules_is_not_applicable() {
        // No corpus, no run — and so no Complete that could close findings.
        let engine = SastEngine::new();
        let ctx = multiscan_engine::testkit::test_context(vec![Layer::Sast]);
        assert_eq!(engine.applicable(&ctx), Applicability::NotApplicable);
    }

    #[test]
    fn extension_routing_covers_both_front_ends() {
        assert_eq!(language_for_extension("py"), Some(Language::Python));
        assert_eq!(language_for_extension("pyi"), Some(Language::Python));
        assert_eq!(language_for_extension("js"), Some(Language::Javascript));
        assert_eq!(language_for_extension("mjs"), Some(Language::Javascript));
        assert_eq!(language_for_extension("ts"), Some(Language::Typescript));
        assert_eq!(language_for_extension("tsx"), Some(Language::Typescript));
        // SAST-003: unhandled languages are simply not claimed.
        assert_eq!(language_for_extension("rs"), None);
        assert_eq!(language_for_extension("go"), None);
        assert_eq!(language_for_extension("java"), None);
        // Case-insensitive, so a .PY file is not silently skipped.
        assert_eq!(language_for_extension("PY"), Some(Language::Python));
    }
}

#[cfg(test)]
mod engine_tests {
    use super::*;
    use crate::rules::parse_pack;
    use multiscan_engine::{testkit, SinkError};

    /// Collects emissions; the registry's own sink is private to that crate.
    #[derive(Default)]
    struct CollectingSink {
        findings: Vec<RawFinding>,
    }

    impl FindingSink for CollectingSink {
        fn emit(&mut self, finding: RawFinding) -> Result<(), SinkError> {
            self.findings.push(finding);
            Ok(())
        }
        fn progress(&mut self, _done: u64, _total: Option<u64>) {}
    }

    fn eval_engine() -> SastEngine {
        let pack = parse_pack(
            br#"{"pack_id":"t","version":"1.0.0","rules":[{
                "id": "eval-call",
                "message": "eval on non-literal input",
                "languages": ["python", "javascript", "typescript"],
                "severity": "high",
                "confidence": "heuristic",
                "pattern": "eval($X)"
            }]}"#,
        )
        .unwrap();
        let (rules, rejected) = compile::compile_pack(&pack);
        assert!(rejected.is_empty(), "rejected: {rejected:?}");
        SastEngine::with_rules(rules)
    }

    fn write(dir: &std::path::Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn unsupported_languages_degrade_and_the_scan_completes() {
        // SAST-003, in full: a repo mixing handled and unhandled languages
        // yields findings for what we parse and Complete overall — the
        // unhandled files are simply not claimed, never an error.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "eval(user_input)\n");
        write(dir.path(), "main.rs", "fn main() { eval(x); }\n");
        write(
            dir.path(),
            "Server.java",
            "class S { void f(){ eval(x); } }\n",
        );
        write(dir.path(), "notes.txt", "eval(everything)\n");

        let mut ctx = testkit::test_context(vec![Layer::Sast]);
        ctx.root = dir.path().to_path_buf();

        let engine = eval_engine();
        assert_eq!(engine.applicable(&ctx), Applicability::Applicable);

        let mut sink = CollectingSink::default();
        let outcome = engine.scan(&ctx, &mut sink).unwrap();

        assert_eq!(
            outcome,
            EngineOutcome::Complete { units_scanned: 1 },
            "only the Python file is a unit; the rest are not this engine's"
        );
        assert_eq!(sink.findings.len(), 1);
        assert_eq!(sink.findings[0].location.path, "app.py");
    }

    #[test]
    fn a_syntax_error_degrades_to_partial_and_cannot_close_findings() {
        // §7.7.4: only Complete may close. A malformed file in someone's repo
        // must not silently mark every other SAST finding fixed.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "good.py", "eval(a)\n");
        write(dir.path(), "broken.py", "def (:\n");

        let mut ctx = testkit::test_context(vec![Layer::Sast]);
        ctx.root = dir.path().to_path_buf();

        let mut sink = CollectingSink::default();
        let outcome = eval_engine().scan(&ctx, &mut sink).unwrap();

        assert!(
            matches!(outcome, EngineOutcome::Partial { .. }),
            "got {outcome:?}"
        );
        // The healthy file still reported.
        assert_eq!(sink.findings.len(), 1);
    }

    #[test]
    fn findings_carry_structural_identity_and_a_line() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "import os\n\neval(danger)\n");

        let mut ctx = testkit::test_context(vec![Layer::Sast]);
        ctx.root = dir.path().to_path_buf();

        let mut sink = CollectingSink::default();
        eval_engine().scan(&ctx, &mut sink).unwrap();

        let finding = &sink.findings[0];
        assert_eq!(finding.location.line, Some(3), "line is 1-based");
        match &finding.identity {
            IdentityKey::StructuralPattern {
                rule_id,
                path,
                structural_hash,
            } => {
                assert_eq!(rule_id, "eval-call");
                assert_eq!(path, "app.py");
                assert!(structural_hash.starts_with("b3:"));
            }
            other => panic!("wrong identity: {other:?}"),
        }
    }

    #[test]
    fn reformatting_a_file_preserves_finding_identity() {
        // SAST-002 end to end, through the Engine: the same code reformatted
        // produces the same identity tuple, so a user's baseline survives a
        // `black`/`prettier` run.
        let identity_of = |body: &str| {
            let dir = tempfile::tempdir().unwrap();
            write(dir.path(), "app.py", body);
            let mut ctx = testkit::test_context(vec![Layer::Sast]);
            ctx.root = dir.path().to_path_buf();
            let mut sink = CollectingSink::default();
            eval_engine().scan(&ctx, &mut sink).unwrap();
            sink.findings[0].identity.clone()
        };

        assert_eq!(
            identity_of("def f(a):\n    return eval(a)\n"),
            identity_of("\n# reformatted\ndef f( a ):\n\n    return eval( a )\n"),
        );
    }

    #[test]
    fn typescript_files_route_to_the_typescript_grammar() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.ts", "const x: string = eval(y as any);\n");

        let mut ctx = testkit::test_context(vec![Layer::Sast]);
        ctx.root = dir.path().to_path_buf();

        let mut sink = CollectingSink::default();
        let outcome = eval_engine().scan(&ctx, &mut sink).unwrap();

        assert_eq!(outcome, EngineOutcome::Complete { units_scanned: 1 });
        assert_eq!(sink.findings.len(), 1);
    }

    #[test]
    fn emission_order_is_stable_across_runs() {
        // DET-002: sorted discovery, pre-order matching. Same repo, same order.
        let dir = tempfile::tempdir().unwrap();
        for name in ["c.py", "a.py", "b.js"] {
            write(dir.path(), name, "eval(x)\n");
        }
        let mut ctx = testkit::test_context(vec![Layer::Sast]);
        ctx.root = dir.path().to_path_buf();

        let paths = || {
            let mut sink = CollectingSink::default();
            eval_engine().scan(&ctx, &mut sink).unwrap();
            sink.findings
                .iter()
                .map(|f| f.location.path.clone())
                .collect::<Vec<_>>()
        };

        let first = paths();
        assert_eq!(first, vec!["a.py", "b.js", "c.py"]);
        for _ in 0..20 {
            assert_eq!(first, paths());
        }
    }
}
