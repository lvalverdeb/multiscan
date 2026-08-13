//! OSV advisory model and range matching (spec 7.1). Only the fields we need;
//! unknown fields are ignored so the model tolerates OSV schema growth.

use serde::Deserialize;

use crate::distro::{self, DistroKey};
use crate::version::Scheme;

/// How a lookup names the ecosystem it wants advisories for.
///
/// Lockfile ecosystems are exact strings — `npm` is `npm`. OS package
/// ecosystems are a normalized [`DistroKey`], because OSV and `os-release`
/// spell the same release differently (ADR 0022 §5).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EcoKey {
    /// An ecosystem matched by exact string equality.
    Exact(String),
    /// A distro release matched on its normalized identity.
    Distro(DistroKey),
}

impl EcoKey {
    /// The key an OSV record's own `package.ecosystem` indexes under.
    pub(crate) fn for_record(ecosystem: &str) -> Self {
        match distro::from_osv_ecosystem(ecosystem) {
            Some(key) => EcoKey::Distro(key),
            None => EcoKey::Exact(ecosystem.to_string()),
        }
    }
}

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
    /// Ids OSV records as connected to this one. Distro advisories put their
    /// CVE here rather than in `aliases` (ADR 0023).
    #[serde(default)]
    pub related: Vec<String>,
    /// Ids this advisory derives from — the upstream CVE for a distro
    /// backport. The stronger of the two connections (ADR 0023).
    #[serde(default)]
    pub upstream: Vec<String>,
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
    /// The canonical vulnerability id for identity and dedup (ADR 0012, as
    /// ratified by ADR 0023): the smallest CVE the advisory names, else the
    /// advisory's own id. Records that share a CVE — a GHSA and a PYSEC, a DSA
    /// and an openSUSE-SU — thus share one identity and merge downstream into
    /// a single finding (max severity, both records as sources), instead of
    /// duplicating.
    ///
    /// The three CVE-bearing fields are consulted in precedence order, not
    /// unioned: `aliases` is OSV's equivalence claim, `upstream` names the CVE
    /// a distro backport derives from, and `related` is only "connected to".
    /// Taking the minimum across all three would let a loosely-related CVE
    /// outrank the record's own alias — measured against the mirrored
    /// ecosystems, that would re-key 26 records to a CVE that is not the one
    /// they claim to be.
    pub fn canonical_vuln_id(&self) -> String {
        fn smallest_cve<'a>(ids: impl Iterator<Item = &'a String>) -> Option<String> {
            ids.filter(|a| a.starts_with("CVE-")).min().cloned()
        }
        smallest_cve(self.aliases.iter())
            .or_else(|| smallest_cve(self.upstream.iter()))
            .or_else(|| smallest_cve(self.related.iter()))
            .unwrap_or_else(|| self.id.clone())
    }

    /// Every CVE this advisory names, for KEV/EPSS enrichment and evidence
    /// detail — sorted and deduplicated (`DET-001`).
    ///
    /// Distro advisories overwhelmingly carry their CVE in `related` or
    /// `upstream` rather than `aliases` (ADR 0023): of 695 sampled openSUSE
    /// records, 674 name a CVE in `related` and none in `aliases`. Reading
    /// only `aliases` would leave every OS package finding unenriched, so
    /// factor X would fall back to its default (`RSK-002`) even for a
    /// KEV-listed weakness.
    pub fn cve_aliases(&self) -> Vec<String> {
        let mut cves: Vec<String> = self
            .aliases
            .iter()
            .chain(&self.related)
            .chain(&self.upstream)
            .filter(|a| a.starts_with("CVE-"))
            .cloned()
            .collect();
        cves.sort();
        cves.dedup();
        cves
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
    ///
    /// `ecosystem` is an OSV ecosystem string. For OS packages, prefer
    /// [`Advisory::matches_key`]: an image reports `Ubuntu 22.04`, which is
    /// spelled `Ubuntu:22.04:LTS` here, and only the normalized key knows they
    /// are the same release.
    pub fn matches(&self, ecosystem: &str, name: &str, version: &str) -> Option<Match> {
        self.matches_key(&EcoKey::for_record(ecosystem), name, version)
    }

    /// As [`Advisory::matches`], against a normalized ecosystem key.
    pub(crate) fn matches_key(&self, key: &EcoKey, name: &str, version: &str) -> Option<Match> {
        for affected in &self.affected {
            let Some(package) = &affected.package else {
                continue;
            };
            // The scheme comes from the record's own ecosystem, which is the
            // one whose ordering the version bounds were written in.
            let scheme = Scheme::for_osv_ecosystem(&package.ecosystem);
            if EcoKey::for_record(&package.ecosystem) != *key
                || !name_matches(&package.ecosystem, &package.name, name)
            {
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
        assert!(
            adv.matches("PyPI", "redis", "8.0.1").is_none(),
            "unbounded range must defer to the versions list"
        );
        assert!(
            adv.matches("PyPI", "redis", "6.4.0").is_some(),
            "an enumerated version still matches"
        );
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
        assert!(
            adv.matches("PyPI", "bar", "1.2.5").is_some(),
            "bounded range covers a non-enumerated in-range version"
        );
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

    /// ADR 0022 §5: an image reports `ID=ubuntu VERSION_ID=22.04`, OSV writes
    /// `Ubuntu:22.04:LTS`, and only the normalized key knows they are one
    /// release. Before ADR 0022 this comparison was string equality and
    /// matched nothing on Ubuntu or RHEL.
    fn os_key(id: &str, version: Option<&str>) -> EcoKey {
        EcoKey::Distro(crate::distro::from_os_release(id, version).expect("resolvable distro"))
    }

    #[test]
    fn os_release_matches_the_osv_spelling_of_its_ecosystem() {
        let ubuntu = advisory(
            r#"{"id":"USN-1","affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"openssl"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.2-0ubuntu1.15"}]}]}]}"#,
        );
        let m = ubuntu
            .matches_key(
                &os_key("ubuntu", Some("22.04")),
                "openssl",
                "3.0.2-0ubuntu1.10",
            )
            .expect("Ubuntu:22.04:LTS matches a 22.04 image");
        assert_eq!(m.fixed_version.as_deref(), Some("3.0.2-0ubuntu1.15"));
        // A different release must not match.
        assert!(ubuntu
            .matches_key(
                &os_key("ubuntu", Some("24.04")),
                "openssl",
                "3.0.2-0ubuntu1.10"
            )
            .is_none());

        let rhel = advisory(
            r#"{"id":"RHSA-1","affected":[{"package":{"ecosystem":"Red Hat:enterprise_linux:9::appstream","name":"openssl"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-25.el9_3"}]}]}]}"#,
        );
        assert!(rhel
            .matches_key(&os_key("rhel", Some("9.3")), "openssl", "1:3.0.7-24.el9")
            .is_some());
        assert!(rhel
            .matches_key(&os_key("rhel", Some("8.9")), "openssl", "1:3.0.7-24.el9")
            .is_none());
    }

    #[test]
    fn ubuntu_pro_advisory_does_not_match_a_plain_release() {
        // Its fix ships only to Pro subscribers; reporting it against a plain
        // 22.04 image would advertise a version the user cannot install
        // (ADR 0022 §6).
        let pro = advisory(
            r#"{"id":"USN-2","affected":[{"package":{"ecosystem":"Ubuntu:Pro:22.04:LTS","name":"libtiff"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.3.0-6ubuntu0.9"}]}]}]}"#,
        );
        assert!(pro
            .matches_key(
                &os_key("ubuntu", Some("22.04")),
                "libtiff",
                "4.3.0-6ubuntu0.1"
            )
            .is_none());
    }

    /// ADR 0023 precedence: `aliases` is an equivalence claim and outranks the
    /// looser `related`. Unioning the fields and taking the minimum would
    /// re-key this record to a CVE it never claimed to be.
    #[test]
    fn an_alias_cve_outranks_a_smaller_related_cve() {
        let adv = advisory(
            r#"{"id":"GHSA-q","aliases":["CVE-2024-9999"],"related":["CVE-2024-1111"],
            "affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.0.0"]}]}"#,
        );
        assert_eq!(adv.canonical_vuln_id(), "CVE-2024-9999");
        // Enrichment still sees both — that is a lookup, not an identity.
        assert_eq!(
            adv.cve_aliases(),
            vec!["CVE-2024-1111".to_string(), "CVE-2024-9999".to_string()]
        );
    }

    #[test]
    fn distro_advisory_cve_comes_from_related_and_upstream() {
        // ADR 0023: distro records put the CVE here, not in `aliases`.
        let adv = advisory(
            r#"{"id":"openSUSE-SU-2024:14017-1","related":["CVE-2024-3094"],"upstream":["CVE-2024-3094"],
            "affected":[{"package":{"ecosystem":"openSUSE:Tumbleweed","name":"xz"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.6.2-1.1"}]}]}]}"#,
        );
        assert_eq!(adv.cve_aliases(), vec!["CVE-2024-3094".to_string()]);
        // ADR 0023, ratified: identity keys on the CVE, so this record merges
        // with any other distro's advisory for the same weakness.
        assert_eq!(adv.canonical_vuln_id(), "CVE-2024-3094");

        // Tumbleweed is rolling: its os-release datestamp is not a release.
        let m = adv
            .matches_key(
                &os_key("opensuse-tumbleweed", Some("20240328")),
                "xz",
                "5.6.1-1.1",
            )
            .expect("the backdoored version is affected");
        assert_eq!(m.fixed_version.as_deref(), Some("5.6.2-1.1"));
        // The fixed rebuild is not.
        assert!(adv
            .matches_key(
                &os_key("opensuse-tumbleweed", Some("20240501")),
                "xz",
                "5.6.2-1.1"
            )
            .is_none());
        // Leap is a different distro entirely.
        assert!(adv
            .matches_key(&os_key("opensuse-leap", Some("15.6")), "xz", "5.6.1-1.1")
            .is_none());
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
