//! OSV advisory model and range matching (spec 7.1). Only the fields we need;
//! unknown fields are ignored so the model tolerates OSV schema growth.

use serde::Deserialize;

use crate::version::Scheme;

/// One OSV advisory record (a line of `osv/<ecosystem>.jsonl`).
#[derive(Debug, Clone, Deserialize)]
pub struct Advisory {
    /// Canonical advisory id (e.g. `GHSA-…`, `RUSTSEC-…`).
    pub id: String,
    /// Short summary, if present.
    #[serde(default)]
    pub summary: Option<String>,
    /// Aliases (often the CVE id) — used for KEV/EPSS enrichment.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Affected package/version records.
    #[serde(default)]
    pub affected: Vec<Affected>,
    /// Severity/CWE references, if present.
    #[serde(default)]
    pub database_specific: Option<DatabaseSpecific>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseSpecific {
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    /// GHSA-style coarse severity label (e.g. `HIGH`), when present.
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Affected {
    #[serde(default)]
    pub package: Option<Package>,
    #[serde(default)]
    pub ranges: Vec<Range>,
    /// Explicit affected version list (some ecosystems use this instead of
    /// ranges).
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
}

/// Outcome of matching one advisory against a concrete package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Lowest fixed version strictly greater than the current version, if the
    /// advisory names one (SCA-004). `None` ⇒ report `fix_available: false`.
    pub fixed_version: Option<String>,
}

impl Advisory {
    /// The canonical vulnerability id for identity and dedup (ADR 0012): the
    /// smallest CVE alias when the advisory carries one, else the advisory's
    /// own id. Records that share a CVE — typically a GHSA and a PYSEC — thus
    /// share one identity and merge downstream into a single finding (max
    /// severity, both records as sources), instead of duplicating.
    pub fn canonical_vuln_id(&self) -> String {
        self.cve_aliases()
            .into_iter()
            .min()
            .unwrap_or_else(|| self.id.clone())
    }

    /// The CVE alias, if any, for KEV/EPSS enrichment.
    pub fn cve_aliases(&self) -> Vec<String> {
        self.aliases
            .iter()
            .filter(|a| a.starts_with("CVE-"))
            .cloned()
            .collect()
    }

    /// CWE ids, if the advisory carries them.
    pub fn cwe_ids(&self) -> Vec<String> {
        self.database_specific
            .as_ref()
            .map(|d| d.cwe_ids.clone())
            .unwrap_or_default()
    }

    /// Coarse severity label (e.g. `HIGH`) if the advisory records one.
    pub fn severity_label(&self) -> Option<&str> {
        self.database_specific
            .as_ref()
            .and_then(|d| d.severity.as_deref())
    }

    /// Does this advisory affect `name`@`version` in `ecosystem`? Returns the
    /// match (with computed `fixed_version`) or `None`.
    pub fn matches(&self, ecosystem: &str, name: &str, version: &str) -> Option<Match> {
        let scheme = Scheme::for_osv_ecosystem(ecosystem);
        for affected in &self.affected {
            let Some(package) = &affected.package else {
                continue;
            };
            if package.ecosystem != ecosystem || !name_matches(ecosystem, &package.name, name) {
                continue;
            }
            // Explicit version list.
            if affected.versions.iter().any(|v| v == version) {
                return Some(Match {
                    fixed_version: lowest_fix(affected, version, scheme),
                });
            }
            // Range events. An *unbounded* range (an `introduced` with no
            // `fixed`/`last_affected` upper bound) marks every later version
            // affected. When the advisory ALSO enumerates explicit `versions`,
            // that enumeration is authoritative: a version absent from it
            // (already checked above) is not affected, and the unbounded range
            // is treated as a degenerate shadow — commonly the ECOSYSTEM
            // projection of a GIT-commit fix OSV could not map to a version.
            // This prevents a fixed package from matching an old advisory
            // forever (FR-003/SCA-001 intent). A range with any upper bound
            // always applies, and an unbounded range with no `versions` list
            // still matches (a genuinely unfixed vulnerability stays caught).
            for range in &affected.ranges {
                if range.range_type == "GIT" {
                    continue; // commit ranges are not version-comparable here
                }
                if !affected.versions.is_empty() && range_is_unbounded(range) {
                    continue;
                }
                if in_range(range, version, scheme) {
                    return Some(Match {
                        fixed_version: lowest_fix(affected, version, scheme),
                    });
                }
            }
        }
        None
    }
}

/// Package-name equality, ecosystem-aware. PyPI normalizes case and `-`/`_`/`.`;
/// npm names are lowercase; others compare exactly.
fn name_matches(ecosystem: &str, a: &str, b: &str) -> bool {
    match ecosystem {
        "PyPI" => normalize_pypi(a) == normalize_pypi(b),
        "npm" => a.eq_ignore_ascii_case(b),
        _ => a == b,
    }
}

fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !last_sep {
                out.push('-');
                last_sep = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            last_sep = false;
        }
    }
    out
}

/// A range with no upper bound: it has `introduced` events but no `fixed` and
/// no `last_affected`, so it marks every version at or after `introduced`
/// affected with no termination. Such a range is deferred to an explicit
/// `versions` enumeration when the advisory provides one.
fn range_is_unbounded(range: &Range) -> bool {
    range
        .events
        .iter()
        .all(|e| e.fixed.is_none() && e.last_affected.is_none())
}

/// Evaluate one range against a version using OSV interval semantics: sort
/// events by version; the version is affected if it sits at or after an
/// `introduced` and before the following `fixed` (or at/before `last_affected`).
fn in_range(range: &Range, version: &str, scheme: Scheme) -> bool {
    use std::cmp::Ordering;

    // Build (kind, bound) pairs. "0" introduced = from the beginning.
    #[derive(PartialEq)]
    enum Kind {
        Introduced,
        Fixed,
        LastAffected,
    }
    let mut bounds: Vec<(Kind, String)> = Vec::new();
    for event in &range.events {
        if let Some(v) = &event.introduced {
            bounds.push((Kind::Introduced, v.clone()));
        }
        if let Some(v) = &event.fixed {
            bounds.push((Kind::Fixed, v.clone()));
        }
        if let Some(v) = &event.last_affected {
            bounds.push((Kind::LastAffected, v.clone()));
        }
    }
    // Sort by version bound; "0" (introduced-from-start) sorts first.
    bounds.sort_by(|(_, a), (_, b)| {
        if a == "0" {
            return Ordering::Less;
        }
        if b == "0" {
            return Ordering::Greater;
        }
        scheme.compare(a, b)
    });

    let mut vulnerable = false;
    for (kind, bound) in &bounds {
        // "0" is negative infinity: the version is always strictly above it.
        let cmp = if bound == "0" {
            Ordering::Greater
        } else {
            scheme.compare(version, bound)
        };
        match kind {
            Kind::Introduced => {
                if cmp != Ordering::Less {
                    vulnerable = true; // version >= introduced
                }
            }
            Kind::Fixed => {
                if cmp != Ordering::Less {
                    vulnerable = false; // version >= fixed ⇒ patched
                }
            }
            Kind::LastAffected => {
                if cmp == Ordering::Greater {
                    vulnerable = false; // version > last_affected ⇒ patched
                }
            }
        }
    }
    vulnerable
}

/// Lowest `fixed` version strictly greater than `version` across the affected
/// entry's ranges (SCA-004).
fn lowest_fix(affected: &Affected, version: &str, scheme: Scheme) -> Option<String> {
    use std::cmp::Ordering;
    let mut best: Option<String> = None;
    for range in &affected.ranges {
        for event in &range.events {
            if let Some(fixed) = &event.fixed {
                if scheme.compare(fixed, version) == Ordering::Greater {
                    best = match best {
                        Some(current) if scheme.compare(fixed, &current) != Ordering::Less => {
                            Some(current)
                        }
                        _ => Some(fixed.clone()),
                    };
                }
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advisory(json: &str) -> Advisory {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn semver_range_match_and_fix() {
        let adv = advisory(
            r#"{"id":"GHSA-x","affected":[{"package":{"ecosystem":"npm","name":"lodash"},
            "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#,
        );
        let m = adv.matches("npm", "lodash", "4.17.20").unwrap();
        assert_eq!(m.fixed_version.as_deref(), Some("4.17.21"));
        // Patched version is not matched.
        assert!(adv.matches("npm", "lodash", "4.17.21").is_none());
        // Double-digit patch below the fix still matches (not a string compare).
        assert!(adv.matches("npm", "lodash", "4.17.9").is_some());
    }

    #[test]
    fn unbounded_range_defers_to_versions_enumeration() {
        // The redis PYSEC-2022-43162 shape: an ECOSYSTEM range `introduced: 0`
        // with no upper bound, plus an explicit `versions` list. A version
        // absent from the list must NOT match (the false positive), while a
        // version in the list still matches.
        let adv = advisory(
            r#"{"id":"PYSEC-x","affected":[{"package":{"ecosystem":"PyPI","name":"redis"},
            "versions":["4.3.4","4.4.0","6.4.0"],
            "ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc123"}]},
                      {"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}"#,
        );
        assert!(adv.matches("PyPI", "redis", "8.0.1").is_none(), "unbounded range must defer to the versions list");
        assert!(adv.matches("PyPI", "redis", "6.4.0").is_some(), "an enumerated version still matches");
    }

    #[test]
    fn unbounded_range_still_matches_without_versions_list() {
        // No `versions` enumeration: a genuinely unfixed vulnerability with an
        // open-ended range must still be caught (recall preserved).
        let adv = advisory(
            r#"{"id":"PYSEC-y","affected":[{"package":{"ecosystem":"PyPI","name":"foo"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"}]}]}]}"#,
        );
        assert!(adv.matches("PyPI", "foo", "9.9.9").is_some());
        assert!(adv.matches("PyPI", "foo", "0.9.0").is_none());
    }

    #[test]
    fn bounded_range_matches_version_not_in_enumeration() {
        // The deep-translator counter-case: a version in a *bounded* range but
        // not enumerated must still match (no false negative).
        let adv = advisory(
            r#"{"id":"PYSEC-z","affected":[{"package":{"ecosystem":"PyPI","name":"bar"},
            "versions":["1.0","1.1"],
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.3"}]}]}]}"#,
        );
        assert!(adv.matches("PyPI", "bar", "1.2.5").is_some(), "bounded range covers a non-enumerated in-range version");
        assert!(adv.matches("PyPI", "bar", "1.3").is_none());
    }

    #[test]
    fn pypi_normalized_name_and_prerelease() {
        let adv = advisory(
            r#"{"id":"PYSEC-1","affected":[{"package":{"ecosystem":"PyPI","name":"Django"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0"},{"fixed":"3.2.15"}]}]}]}"#,
        );
        // Name normalization: dist name spelled differently still matches.
        assert!(adv.matches("PyPI", "django", "3.1.0").is_some());
        let m = adv.matches("PyPI", "DJANGO", "3.2.14").unwrap();
        assert_eq!(m.fixed_version.as_deref(), Some("3.2.15"));
        assert!(adv.matches("PyPI", "django", "3.2.15").is_none());
        // Below the introduced bound: not affected.
        assert!(adv.matches("PyPI", "django", "2.2.0").is_none());
    }

    #[test]
    fn last_affected_semantics() {
        let adv = advisory(
            r#"{"id":"OSV-1","affected":[{"package":{"ecosystem":"crates.io","name":"foo"},
            "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"1.4.0"}]}]}]}"#,
        );
        assert!(adv.matches("crates.io", "foo", "1.4.0").is_some());
        assert!(adv.matches("crates.io", "foo", "1.4.1").is_none());
        // No fixed event ⇒ no fixed_version (fix_available: false).
        assert_eq!(
            adv.matches("crates.io", "foo", "1.2.0")
                .unwrap()
                .fixed_version,
            None
        );
    }

    #[test]
    fn wrong_ecosystem_or_name_no_match() {
        let adv = advisory(
            r#"{"id":"GHSA-x","affected":[{"package":{"ecosystem":"npm","name":"lodash"},
            "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#,
        );
        assert!(adv.matches("crates.io", "lodash", "4.17.20").is_none());
        assert!(adv.matches("npm", "underscore", "4.17.20").is_none());
    }
}
