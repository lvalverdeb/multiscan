//! Module-level reachability for the risk factor (`T-802`, `FR-017`).
//!
//! Extraction lives in `multiscan-sast` (`T-801`); this is the policy layer that
//! turns "which modules does this repo import" into a per-Finding signal. The
//! split is deliberate: which modules a file imports is a parsing question,
//! whether a *package* counts as referenced is ecosystem policy.
//!
//! # The asymmetry that matters
//!
//! `Referenced` and `NotReferenced` are not equally safe to get wrong.
//! Wrongly reporting `Referenced` carries noise. Wrongly reporting
//! `NotReferenced` **suppresses a real Finding**. So this module emits
//! `NotReferenced` only where the package→module mapping is reliable, and
//! `Unknown` everywhere else (`FR-017`, `RSK-002`).

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use multiscan_core::IdentityKey;
use multiscan_engine::PathFilter;
use multiscan_risk::ReachabilitySignal;
use multiscan_sast::imports::{self, Imports};
use multiscan_sast::lang::MAX_SOURCE_BYTES as MAX_SOURCE_BYTES_USIZE;
use multiscan_sast::rules::Language;

/// Size cap, mirroring the front-ends' own limit so this pass rejects exactly
/// what they would.
const MAX_SOURCE_BYTES: u64 = MAX_SOURCE_BYTES_USIZE as u64;

/// Modules imported anywhere in the scanned tree, plus whether extraction was
/// complete enough to draw a negative conclusion.
#[derive(Debug, Default)]
pub struct Index {
    imports: Imports,
    /// Ecosystems whose sources were parsed cleanly enough that "no import
    /// found" is trustworthy.
    trustworthy: BTreeSet<&'static str>,
}

impl Index {
    /// An index that knows nothing: every Finding scores `Unknown`.
    ///
    /// Used when the SAST layer did not run — no source scanned means no
    /// evidence, which is emphatically not evidence of absence.
    pub fn empty() -> Self {
        Index::default()
    }

    /// Build by parsing every supported source file under `root`.
    ///
    /// **Anything not read cleanly marks its ecosystem untrustworthy** — a
    /// parse failure, an unreadable file, or one over the size cap. If some of
    /// the repo's Python went unread, we are not entitled to conclude that a
    /// Python package is unused.
    ///
    /// Honours `cancel` between files: Ctrl-C mid-scan yields an index that
    /// concludes nothing rather than one that concludes wrongly from a partial
    /// read.
    pub fn build(root: &Path, excludes: &PathFilter, cancel: &AtomicBool) -> Self {
        let mut imports = Imports::new();
        // An ecosystem is trustworthy only once at least one of its files has
        // been parsed. Starting these at `true` would make a repo with no
        // Python — or no source at all — report every PyPI package as
        // NotReferenced, concluding absence from zero evidence. That is the
        // exact failure FR-017's three-state design exists to prevent.
        let mut python_seen = false;
        let mut js_seen = false;
        let mut python_ok = true;
        let mut js_ok = true;

        for (abs, _rel, language) in multiscan_sast::discover(root, excludes) {
            match language {
                Language::Python => python_seen = true,
                _ => js_seen = true,
            }
            if cancel.load(Ordering::Relaxed) {
                // Stop, and trust nothing: the remaining files were never read.
                return Index {
                    imports,
                    trustworthy: BTreeSet::new(),
                };
            }

            let mark_untrusted = |python_ok: &mut bool, js_ok: &mut bool| match language {
                Language::Python => *python_ok = false,
                _ => *js_ok = false,
            };

            // Bound allocation by input size *before* reading (NFR-003): a
            // multi-GB blob must not be pulled into memory just to be rejected.
            let too_big = std::fs::metadata(&abs)
                .map(|m| m.len() > MAX_SOURCE_BYTES)
                .unwrap_or(true);
            if too_big {
                mark_untrusted(&mut python_ok, &mut js_ok);
                continue;
            }

            let Ok(text) = std::fs::read_to_string(&abs) else {
                mark_untrusted(&mut python_ok, &mut js_ok);
                continue;
            };
            let parsed = match language {
                Language::Python => multiscan_sast::lang::python::lower_source(&text),
                Language::Javascript => {
                    multiscan_sast::lang::javascript::lower_source(&text, false)
                }
                Language::Typescript => multiscan_sast::lang::javascript::lower_source(&text, true),
            };
            match parsed {
                Ok(tree) => imports.extend(imports::extract(&tree, language)),
                Err(_) => mark_untrusted(&mut python_ok, &mut js_ok),
            }
        }

        let mut trustworthy = BTreeSet::new();
        if python_seen && python_ok {
            trustworthy.insert("pypi");
        }
        if js_seen && js_ok {
            trustworthy.insert("npm");
        }
        Index {
            imports,
            trustworthy,
        }
    }

    /// The reachability signal for one Finding.
    ///
    /// Only dependency findings carry a package to resolve; everything else is
    /// `Unknown` because the question does not apply.
    pub fn signal_for(&self, identity: &IdentityKey) -> ReachabilitySignal {
        let purl = match identity {
            IdentityKey::VulnerableDependency { purl, .. } => purl,
            // A container package is not imported by first-party source.
            _ => return ReachabilitySignal::Unknown,
        };
        let Some((ecosystem, package)) = parse_purl(purl) else {
            return ReachabilitySignal::Unknown;
        };

        for module in module_candidates(ecosystem, &package) {
            if imports::references(&self.imports, &module) {
                return ReachabilitySignal::Referenced;
            }
        }

        // Nothing matched. Only call that NotReferenced where the mapping is
        // reliable and the sources parsed cleanly.
        if self.trustworthy.contains(ecosystem) && mapping_is_reliable(ecosystem, &package) {
            ReachabilitySignal::NotReferenced
        } else {
            ReachabilitySignal::Unknown
        }
    }
}

/// `pkg:npm/@scope/name@1.2.3` → `("npm", "@scope/name")`.
fn parse_purl(purl: &str) -> Option<(&'static str, String)> {
    let rest = purl.strip_prefix("pkg:")?;
    let (kind, rest) = rest.split_once('/')?;
    let ecosystem = match kind {
        "npm" => "npm",
        "pypi" => "pypi",
        _ => return None,
    };
    // Strip the version, keeping any `@scope/` prefix intact.
    let name = match rest.rfind('@') {
        Some(at) if at > 0 => &rest[..at],
        _ => rest,
    };
    Some((ecosystem, name.to_string()))
}

/// Module names a package plausibly presents as an import.
fn module_candidates(ecosystem: &str, package: &str) -> Vec<String> {
    match ecosystem {
        // npm module specifiers are the package name verbatim.
        "npm" => vec![package.to_string()],
        // PyPI distribution names are normalized (PEP 503) and frequently
        // differ from the import name in case and separator.
        "pypi" => {
            let lower = package.to_ascii_lowercase();
            let underscored = lower.replace('-', "_");
            let mut out = vec![lower.clone()];
            if underscored != lower {
                out.push(underscored);
            }
            out
        }
        _ => vec![],
    }
}

/// Whether "no matching import" is strong enough to mean `NotReferenced`.
///
/// npm is reliable: the specifier *is* the package name. PyPI is not — a
/// distribution routinely imports under a different name (`PyYAML` → `yaml`,
/// `Pillow` → `PIL`, `beautifulsoup4` → `bs4`), and there is no mapping in the
/// lockfile to consult. Authoring one would be authoring ecosystem knowledge
/// (§1.2), so PyPI negatives stay `Unknown` rather than risk suppressing a real
/// Finding.
fn mapping_is_reliable(ecosystem: &str, _package: &str) -> bool {
    ecosystem == "npm"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(modules: &[&str], trustworthy: &[&'static str]) -> Index {
        Index {
            imports: modules.iter().map(|m| m.to_string()).collect(),
            trustworthy: trustworthy.iter().copied().collect(),
        }
    }

    fn dep(purl: &str) -> IdentityKey {
        IdentityKey::VulnerableDependency {
            purl: purl.into(),
            advisory_id: "OSV-1".into(),
            manifest_path: "package-lock.json".into(),
        }
    }

    #[test]
    fn an_imported_npm_package_is_referenced() {
        let idx = index(&["lodash"], &["npm"]);
        assert_eq!(
            idx.signal_for(&dep("pkg:npm/lodash@4.17.20")),
            ReachabilitySignal::Referenced
        );
    }

    #[test]
    fn scoped_npm_names_compare_whole() {
        let idx = index(&["@scope/pkg"], &["npm"]);
        assert_eq!(
            idx.signal_for(&dep("pkg:npm/@scope/pkg@1.0.0")),
            ReachabilitySignal::Referenced
        );
    }

    #[test]
    fn an_unimported_npm_package_is_not_referenced() {
        let idx = index(&["react"], &["npm"]);
        assert_eq!(
            idx.signal_for(&dep("pkg:npm/lodash@4.17.20")),
            ReachabilitySignal::NotReferenced
        );
    }

    #[test]
    fn an_unimported_pypi_package_stays_unknown() {
        // PyYAML imports as `yaml`; concluding NotReferenced from the
        // distribution name would suppress a real Finding.
        let idx = index(&["os"], &["pypi", "npm"]);
        assert_eq!(
            idx.signal_for(&dep("pkg:pypi/PyYAML@5.1")),
            ReachabilitySignal::Unknown,
            "PyPI negatives are never trusted"
        );
    }

    #[test]
    fn a_pypi_package_matching_its_import_name_is_referenced() {
        let idx = index(&["requests"], &["pypi"]);
        assert_eq!(
            idx.signal_for(&dep("pkg:pypi/requests@2.0.0")),
            ReachabilitySignal::Referenced
        );
        // Distribution names normalize: `zope-interface` imports as
        // `zope_interface`.
        let idx = index(&["zope_interface"], &["pypi"]);
        assert_eq!(
            idx.signal_for(&dep("pkg:pypi/zope-interface@5.0")),
            ReachabilitySignal::Referenced
        );
    }

    #[test]
    fn a_parse_failure_makes_negatives_untrustworthy() {
        // Some of the repo's JS could not be read, so "not imported" is not a
        // conclusion we are entitled to draw.
        let idx = index(&["react"], &[]);
        assert_eq!(
            idx.signal_for(&dep("pkg:npm/lodash@4.17.20")),
            ReachabilitySignal::Unknown
        );
    }

    #[test]
    fn an_empty_index_knows_nothing() {
        // No SAST layer ran: no evidence is not evidence of absence.
        assert_eq!(
            Index::empty().signal_for(&dep("pkg:npm/lodash@4.17.20")),
            ReachabilitySignal::Unknown
        );
    }

    #[test]
    fn non_dependency_findings_are_unknown() {
        let idx = index(&["lodash"], &["npm"]);
        for identity in [
            IdentityKey::ExposedSecret {
                rule_id: "aws".into(),
                path: ".env".into(),
                fingerprint: "x".into(),
            },
            IdentityKey::ContainerVulnerability {
                purl: "pkg:npm/lodash@4.17.20".into(),
                advisory_id: "OSV-1".into(),
                image_digest: "sha256:x".into(),
            },
        ] {
            assert_eq!(
                idx.signal_for(&identity),
                ReachabilitySignal::Unknown,
                "reachability does not apply to {identity:?}"
            );
        }
    }

    #[test]
    fn an_oversize_file_is_never_read_and_poisons_negatives() {
        // NFR-003: bound allocation by input size before reading. And an
        // unread file must not let us conclude a package is unused.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.js"), "import x from 'react';\n").unwrap();

        let huge = dir.path().join("bundle.js");
        let f = std::fs::File::create(&huge).unwrap();
        f.set_len(MAX_SOURCE_BYTES + 1).unwrap();
        drop(f);

        let idx = Index::build(dir.path(), &PathFilter::empty(), &AtomicBool::new(false));

        // The readable file still contributed.
        assert_eq!(
            idx.signal_for(&dep("pkg:npm/react@18.0.0")),
            ReachabilitySignal::Referenced
        );
        // But the skipped blob makes "not imported" unsafe to assert.
        assert_eq!(
            idx.signal_for(&dep("pkg:npm/lodash@4.17.20")),
            ReachabilitySignal::Unknown,
            "an unread file must poison negative conclusions"
        );
    }

    #[test]
    fn cancellation_yields_an_index_that_concludes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "import x from 'react';\n").unwrap();

        let cancelled = AtomicBool::new(true);
        let idx = Index::build(dir.path(), &PathFilter::empty(), &cancelled);

        assert_eq!(
            idx.signal_for(&dep("pkg:npm/lodash@4.17.20")),
            ReachabilitySignal::Unknown,
            "a cancelled pass must not produce NotReferenced"
        );
    }

    #[test]
    fn build_reads_both_ecosystems() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "const _ = require('lodash');\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "import requests\n").unwrap();

        let idx = Index::build(dir.path(), &PathFilter::empty(), &AtomicBool::new(false));

        assert_eq!(
            idx.signal_for(&dep("pkg:npm/lodash@4.17.20")),
            ReachabilitySignal::Referenced
        );
        assert_eq!(
            idx.signal_for(&dep("pkg:pypi/requests@2.0.0")),
            ReachabilitySignal::Referenced
        );
        // npm negatives are trustworthy here; both files parsed.
        assert_eq!(
            idx.signal_for(&dep("pkg:npm/react@18.0.0")),
            ReachabilitySignal::NotReferenced
        );
    }

    #[test]
    fn a_syntax_error_poisons_only_its_own_ecosystem() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ok.js"), "import x from 'react';\n").unwrap();
        std::fs::write(dir.path().join("broken.py"), "def (:\n").unwrap();

        let idx = Index::build(dir.path(), &PathFilter::empty(), &AtomicBool::new(false));

        // JS parsed cleanly, so a JS negative still stands.
        assert_eq!(
            idx.signal_for(&dep("pkg:npm/lodash@4.17.20")),
            ReachabilitySignal::NotReferenced
        );
        // Python did not, so a Python negative does not.
        assert_eq!(
            idx.signal_for(&dep("pkg:pypi/requests@2.0.0")),
            ReachabilitySignal::Unknown
        );
    }

    #[test]
    fn unsupported_ecosystems_are_unknown() {
        let idx = index(&["serde"], &["npm", "pypi"]);
        assert_eq!(
            idx.signal_for(&dep("pkg:cargo/serde@1.0")),
            ReachabilitySignal::Unknown
        );
    }

    #[test]
    fn purl_parsing_keeps_scopes_and_drops_versions() {
        assert_eq!(
            parse_purl("pkg:npm/@scope/pkg@1.0.0"),
            Some(("npm", "@scope/pkg".to_string()))
        );
        assert_eq!(
            parse_purl("pkg:pypi/requests@2.0.0"),
            Some(("pypi", "requests".to_string()))
        );
        assert_eq!(parse_purl("pkg:cargo/serde@1.0"), None);
    }
}
