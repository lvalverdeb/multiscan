//! Ecosystem-correct version comparison (SCA-002, FR-003).
//!
//! A shared naive string comparator is a defect: `"1.10.0" < "1.9.0"` is true
//! as strings but false as versions, and PEP 440 pre-releases order below
//! their release. Each ecosystem's OSV ranges are compared with that
//! ecosystem's own ordering.

use std::cmp::Ordering;

/// The version-ordering scheme for an ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Cargo, npm, Go — SemVer 2.0 precedence.
    Semver,
    /// PyPI — PEP 440.
    Pep440,
    /// Debian/Ubuntu — dpkg version ordering (epoch:upstream-revision).
    Debian,
    /// Alpine — apk version ordering.
    Apk,
    /// RPM (RHEL/Fedora/SUSE) — EVR ordering.
    Rpm,
    /// RubyGems — `Gem::Version` ordering: alphanumeric segments, string
    /// segments are pre-releases sorting below numeric ones.
    RubyGems,
    /// Packagist — Composer normalization: optional `v`, stability suffixes
    /// dev < alpha < beta < RC < stable < patch.
    Composer,
    /// Maven — a subset of ComparableVersion: numeric segments compared
    /// numerically, known qualifiers ranked (alpha < beta < milestone < rc <
    /// snapshot < release < sp), SNAPSHOT below its release.
    Maven,
    /// Fallback: dotted numeric segments, then lexical. Used where a precise
    /// scheme is not yet wired. Never a silent naive string compare.
    Generic,
}

impl Scheme {
    /// The OSV ecosystem string this scheme applies to. OS ecosystems are
    /// release-qualified in OSV (`Debian:11`, `Ubuntu:22.04`, `Alpine:v3.20`,
    /// `Red Hat`, `Rocky Linux:9`, …), so we match on a prefix.
    pub fn for_osv_ecosystem(ecosystem: &str) -> Scheme {
        let base = ecosystem.split(':').next().unwrap_or(ecosystem);
        match base {
            "crates.io" | "npm" | "Go" => Scheme::Semver,
            "PyPI" => Scheme::Pep440,
            "Debian" | "Ubuntu" => Scheme::Debian,
            "Alpine" => Scheme::Apk,
            "Red Hat" | "Rocky Linux" | "AlmaLinux" | "openSUSE" | "SUSE" | "Fedora" => Scheme::Rpm,
            "RubyGems" => Scheme::RubyGems,
            "Packagist" => Scheme::Composer,
            "Maven" => Scheme::Maven,
            _ => Scheme::Generic,
        }
    }

    /// Compare two version strings under this scheme. Unparseable versions
    /// sort *below* parseable ones and compare lexically among themselves, so
    /// a malformed version never spuriously matches a range bound.
    pub fn compare(self, a: &str, b: &str) -> Ordering {
        match self {
            Scheme::Semver => cmp_with(a, b, parse_semver),
            Scheme::Pep440 => cmp_with(a, b, parse_pep440),
            Scheme::Debian => cmp_with(a, b, parse_debian),
            Scheme::Apk => cmp_apk(a, b),
            Scheme::Rpm => cmp_rpm(a, b),
            Scheme::RubyGems => cmp_rubygems(a, b),
            Scheme::Composer => cmp_composer(a, b),
            Scheme::Maven => cmp_maven(a, b),
            Scheme::Generic => cmp_generic(a, b),
        }
    }
}

/// Maven ComparableVersion (subset). Tokenize on `.` / `-` and on
/// digit↔letter boundaries; numeric tokens compare numerically, qualifier
/// tokens by a known ranking. When one side runs out, the missing token is
/// the release baseline (numeric 0 against a number, empty qualifier against
/// a qualifier) — so `1.0 == 1.0.0` and `1.0 > 1.0-alpha`. A subset, but
/// faithful for the release-grade bounds OSV Maven advisories use.
fn cmp_maven(a: &str, b: &str) -> Ordering {
    /// alpha < beta < milestone < rc < snapshot < "" (release) < sp <
    /// unknown. Unknown qualifiers sort after all known ones, then lexically.
    fn qual_rank(q: &str) -> i32 {
        match q {
            "alpha" | "a" => 1,
            "beta" | "b" => 2,
            "milestone" | "m" => 3,
            "rc" | "cr" => 4,
            "snapshot" => 5,
            "" | "ga" | "final" | "release" => 6,
            "sp" => 7,
            _ => 8,
        }
    }
    enum Item {
        Num(u64),
        Qual(String),
    }
    fn tokenize(v: &str) -> Vec<Item> {
        let lower = v.trim().to_ascii_lowercase();
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut cur_digit = false;
        let flush = |cur: &mut String, digit: bool, out: &mut Vec<Item>| {
            if cur.is_empty() {
                return;
            }
            if digit {
                out.push(Item::Num(cur.parse().unwrap_or(0)));
            } else if matches!(cur.as_str(), "ga" | "final" | "release") {
                // Release synonyms are the null qualifier: drop them so
                // `1.0-ga` == `1.0` == `1.0.0` (Maven null-value trimming).
                cur.clear();
            } else {
                out.push(Item::Qual(std::mem::take(cur)));
            }
            cur.clear();
        };
        for c in lower.chars() {
            if c == '.' || c == '-' || c == '_' || c == '+' {
                flush(&mut cur, cur_digit, &mut out);
                continue;
            }
            let is_digit = c.is_ascii_digit();
            if !cur.is_empty() && is_digit != cur_digit {
                flush(&mut cur, cur_digit, &mut out);
            }
            cur_digit = is_digit;
            cur.push(c);
        }
        flush(&mut cur, cur_digit, &mut out);
        out
    }
    fn cmp_item(x: Option<&Item>, y: Option<&Item>) -> Ordering {
        match (x, y) {
            (Some(Item::Num(a)), Some(Item::Num(b))) => a.cmp(b),
            (Some(Item::Qual(a)), Some(Item::Qual(b))) => {
                qual_rank(a).cmp(&qual_rank(b)).then_with(|| a.cmp(b))
            }
            // A numeric item always outranks a qualifier item.
            (Some(Item::Num(_)), Some(Item::Qual(_))) => Ordering::Greater,
            (Some(Item::Qual(_)), Some(Item::Num(_))) => Ordering::Less,
            // Missing side takes the release baseline for the present kind.
            (None, Some(Item::Num(b))) => 0u64.cmp(b),
            (Some(Item::Num(a)), None) => a.cmp(&0),
            (None, Some(Item::Qual(b))) => qual_rank("").cmp(&qual_rank(b)),
            (Some(Item::Qual(a)), None) => qual_rank(a).cmp(&qual_rank("")),
            (None, None) => Ordering::Equal,
        }
    }
    let (ta, tb) = (tokenize(a), tokenize(b));
    for i in 0..ta.len().max(tb.len()) {
        match cmp_item(ta.get(i), tb.get(i)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// `Gem::Version` ordering. A version is a sequence of segments — numeric
/// runs and letter runs (`-` reads as `.pre.`, per RubyGems). Comparison is
/// segment-wise: numbers numerically, strings lexically, a string sorts
/// below any number, and a missing segment is numeric zero — which makes
/// `1.0.beta1 < 1.0 == 1.0.0` come out right.
fn cmp_rubygems(a: &str, b: &str) -> Ordering {
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    enum Seg {
        // Variant order is the ordering: pre-release strings below numbers.
        Str(String),
        Num(u64),
    }
    fn segments(v: &str) -> Vec<Seg> {
        let lower = v.trim().to_ascii_lowercase().replace('-', ".pre.");
        let mut out = Vec::new();
        for run in lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|s| !s.is_empty())
        {
            // Split mixed runs like "beta1" into "beta", 1.
            let mut rest = run;
            while !rest.is_empty() {
                let cut = rest
                    .char_indices()
                    .find(|(_, c)| {
                        c.is_ascii_digit() != rest.starts_with(|r: char| r.is_ascii_digit())
                    })
                    .map(|(i, _)| i)
                    .unwrap_or(rest.len());
                let (head, tail) = rest.split_at(cut);
                out.push(match head.parse::<u64>() {
                    Ok(n) => Seg::Num(n),
                    Err(_) => Seg::Str(head.to_string()),
                });
                rest = tail;
            }
        }
        out
    }
    let (sa, sb) = (segments(a), segments(b));
    for i in 0..sa.len().max(sb.len()) {
        let zero = Seg::Num(0);
        let x = sa.get(i).unwrap_or(&zero);
        let y = sb.get(i).unwrap_or(&zero);
        match x.cmp(y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// Composer/Packagist ordering: optional leading `v`, dotted numerics, then
/// a stability suffix ranking dev < alpha < beta < RC < stable < patch, each
/// with an optional number (`1.0.0-RC2`). Mirrors Composer's normalized
/// comparison closely enough for OSV range bounds, which are release-grade.
fn cmp_composer(a: &str, b: &str) -> Ordering {
    fn stability_rank(s: &str) -> i32 {
        match s {
            "dev" => 0,
            "a" | "alpha" => 1,
            "b" | "beta" => 2,
            "rc" => 3,
            "p" | "pl" | "patch" => 5,
            _ => 4, // unknown suffixes treated as stable-adjacent
        }
    }
    fn parts(v: &str) -> (Vec<u64>, i32, u64) {
        let lower = v.trim().to_ascii_lowercase();
        let lower = lower.strip_prefix('v').unwrap_or(&lower);
        // `dev-master`-style branch versions: no numeric part, rank dev.
        if lower.starts_with("dev-") {
            return (vec![], 0, 0);
        }
        let (head, suffix) = match lower.split_once(['-', '_', '+']) {
            Some((h, s)) => (h, s),
            None => (lower, ""),
        };
        let nums = head
            .split('.')
            .map(|n| n.parse::<u64>().unwrap_or(0))
            .collect();
        if suffix.is_empty() {
            return (nums, 4, 0);
        }
        let digits_at = suffix
            .char_indices()
            .find(|(_, c)| c.is_ascii_digit())
            .map(|(i, _)| i)
            .unwrap_or(suffix.len());
        let (word, num) = suffix.split_at(digits_at);
        (
            nums,
            stability_rank(word.trim_matches(['-', '_', '.'])),
            num.parse::<u64>().unwrap_or(0),
        )
    }
    let (an, ar, anum) = parts(a);
    let (bn, br, bnum) = parts(b);
    for i in 0..an.len().max(bn.len()) {
        let x = an.get(i).copied().unwrap_or(0);
        let y = bn.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    ar.cmp(&br).then(anum.cmp(&bnum))
}

fn parse_debian(v: &str) -> Option<debversion::Version> {
    v.parse::<debversion::Version>().ok()
}

/// RPM EVR comparison via the `rpm` crate's label ordering (`epoch:version-release`).
fn cmp_rpm(a: &str, b: &str) -> Ordering {
    rpm::rpm_evr_compare(a, b)
}

/// Alpine apk version comparison. apk versions are dot-separated numeric
/// components, then an optional letter, then optional `_suffixN` pre/post
/// tags, then an optional `-rN` build revision. This implements the ordering
/// apk-tools uses (hand-rolled: no maintained crate, cf. plan). Suffixes rank:
/// alpha < beta < pre < rc < (release) < cvs < svn < git < hg < p.
fn cmp_apk(a: &str, b: &str) -> Ordering {
    fn suffix_rank(s: &str) -> i32 {
        match s {
            "alpha" => 0,
            "beta" => 1,
            "pre" => 2,
            "rc" => 3,
            "cvs" => 5,
            "svn" => 6,
            "git" => 7,
            "hg" => 8,
            "p" => 9,
            _ => 4, // plain release sits between rc and post tags
        }
    }
    // Split off the -rN build revision.
    let (a_main, a_rev) = a.rsplit_once("-r").unwrap_or((a, "0"));
    let (b_main, b_rev) = b.rsplit_once("-r").unwrap_or((b, "0"));

    // Split main into numeric-dotted part, trailing letter, and _suffix.
    fn parts(main: &str) -> (Vec<u64>, Option<char>, Vec<(i32, u64)>) {
        let (head, suffixes) = match main.split_once('_') {
            Some((h, s)) => (h, s),
            None => (main, ""),
        };
        // Trailing single letter (e.g. `1.2.3a`).
        let (num_str, letter) = if head
            .chars()
            .last()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
        {
            let mut chars = head.chars();
            let last = chars.next_back();
            (chars.as_str().to_string(), last)
        } else {
            (head.to_string(), None)
        };
        let nums: Vec<u64> = num_str
            .split('.')
            .map(|n| n.parse::<u64>().unwrap_or(0))
            .collect();
        // Parse `_suffixN_suffixM...`.
        let mut sfx = Vec::new();
        for token in suffixes.split('_').filter(|t| !t.is_empty()) {
            let split = token
                .char_indices()
                .find(|(_, c)| c.is_ascii_digit())
                .map(|(i, _)| i)
                .unwrap_or(token.len());
            let (word, num) = token.split_at(split);
            sfx.push((suffix_rank(word), num.parse::<u64>().unwrap_or(0)));
        }
        (nums, letter, sfx)
    }

    // A missing suffix is "release": rank 4, between rc (3) and post tags (5+).
    // So `1.0_alpha1` < `1.0` < `1.0_p1`. Compare element-wise, padding the
    // shorter side with the release baseline.
    fn cmp_suffixes(a: &[(i32, u64)], b: &[(i32, u64)]) -> Ordering {
        let release = (4i32, 0u64);
        for i in 0..a.len().max(b.len()) {
            let x = a.get(i).copied().unwrap_or(release);
            let y = b.get(i).copied().unwrap_or(release);
            match x.cmp(&y) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }

    let (an, al, asfx) = parts(a_main);
    let (bn, bl, bsfx) = parts(b_main);
    an.iter()
        .zip(bn.iter())
        .find_map(|(x, y)| match x.cmp(y) {
            Ordering::Equal => None,
            other => Some(other),
        })
        .unwrap_or_else(|| an.len().cmp(&bn.len()))
        .then_with(|| al.cmp(&bl))
        .then_with(|| cmp_suffixes(&asfx, &bsfx))
        .then_with(|| {
            a_rev
                .parse::<u64>()
                .unwrap_or(0)
                .cmp(&b_rev.parse::<u64>().unwrap_or(0))
        })
}

fn cmp_with<T: Ord>(a: &str, b: &str, parse: fn(&str) -> Option<T>) -> Ordering {
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => a.cmp(b),
    }
}

fn parse_semver(v: &str) -> Option<semver::Version> {
    let trimmed = v.strip_prefix('v').unwrap_or(v);
    semver::Version::parse(trimmed).ok()
}

fn parse_pep440(v: &str) -> Option<pep440_rs::Version> {
    v.parse::<pep440_rs::Version>().ok()
}

/// Dotted-segment comparison: numeric segments compared numerically, mixed
/// segments lexically. Deterministic and total, unlike a raw string compare.
fn cmp_generic(a: &str, b: &str) -> Ordering {
    let split = |s: &str| -> Vec<String> {
        s.split(['.', '-', '+', '_', '~'])
            .map(str::to_string)
            .collect()
    };
    let (sa, sb) = (split(a), split(b));
    for i in 0..sa.len().max(sb.len()) {
        let x = sa.get(i).map(String::as_str).unwrap_or("0");
        let y = sb.get(i).map(String::as_str).unwrap_or("0");
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(nx), Ok(ny)) => nx.cmp(&ny),
            _ => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    #[test]
    fn semver_double_digit_beats_naive_string() {
        // The canonical trap: "1.10.0" < "1.9.0" as strings, > as versions.
        assert_eq!(Scheme::Semver.compare("1.10.0", "1.9.0"), Greater);
        assert_eq!(Scheme::Generic.compare("1.10.0", "1.9.0"), Greater);
        // A naive string compare would disagree — guard against regressing to it.
        assert_ne!("1.10.0".cmp("1.9.0"), Greater);
    }

    #[test]
    fn semver_prerelease_orders_below_release() {
        assert_eq!(Scheme::Semver.compare("1.0.0-rc.1", "1.0.0"), Less);
        assert_eq!(Scheme::Semver.compare("1.0.0-alpha", "1.0.0-beta"), Less);
        assert_eq!(Scheme::Semver.compare("v1.2.3", "1.2.3"), Equal);
    }

    #[test]
    fn pep440_prerelease_and_epoch() {
        assert_eq!(Scheme::Pep440.compare("1.0.0rc1", "1.0.0"), Less);
        assert_eq!(Scheme::Pep440.compare("1.0", "1.0.0"), Equal);
        assert_eq!(Scheme::Pep440.compare("1.10", "1.9"), Greater);
        // Epoch dominates.
        assert_eq!(Scheme::Pep440.compare("1!1.0", "2.0"), Greater);
        // Post-release beats the plain release.
        assert_eq!(Scheme::Pep440.compare("1.0.post1", "1.0"), Greater);
    }

    #[test]
    fn rubygems_ordering() {
        // Pre-release segments sort below the release.
        assert_eq!(Scheme::RubyGems.compare("1.0.0.beta1", "1.0.0"), Less);
        assert_eq!(Scheme::RubyGems.compare("1.0.0.beta1", "1.0.0.beta2"), Less);
        assert_eq!(
            Scheme::RubyGems.compare("1.0.0.rc1", "1.0.0.beta9"),
            Greater
        );
        // `-` reads as `.pre.`.
        assert_eq!(Scheme::RubyGems.compare("1.0.0-alpha", "1.0.0"), Less);
        // Numeric, not string.
        assert_eq!(Scheme::RubyGems.compare("7.0.10", "7.0.9"), Greater);
        // Trailing zeros are insignificant.
        assert_eq!(Scheme::RubyGems.compare("1.0", "1.0.0"), Equal);
    }

    #[test]
    fn composer_ordering() {
        assert_eq!(Scheme::Composer.compare("v1.2.3", "1.2.3"), Equal);
        assert_eq!(Scheme::Composer.compare("1.0.0-RC1", "1.0.0"), Less);
        assert_eq!(Scheme::Composer.compare("1.0.0-rc1", "1.0.0-rc2"), Less);
        assert_eq!(
            Scheme::Composer.compare("1.0.0-alpha1", "1.0.0-beta1"),
            Less
        );
        assert_eq!(Scheme::Composer.compare("1.10.0", "1.9.9"), Greater);
        // Branch versions rank as dev, below any numbered release.
        assert_eq!(Scheme::Composer.compare("dev-master", "0.0.1"), Less);
        // Patch releases order above the plain release.
        assert_eq!(Scheme::Composer.compare("1.0.0-p1", "1.0.0"), Greater);
    }

    #[test]
    fn maven_ordering() {
        // Double-digit numeric, not string.
        assert_eq!(Scheme::Maven.compare("1.10", "1.9"), Greater);
        // Qualifier ranking and SNAPSHOT below release.
        assert_eq!(Scheme::Maven.compare("1.0-alpha", "1.0-beta"), Less);
        assert_eq!(Scheme::Maven.compare("1.0-milestone", "1.0-rc"), Less);
        assert_eq!(Scheme::Maven.compare("1.0-SNAPSHOT", "1.0"), Less);
        assert_eq!(Scheme::Maven.compare("1.0", "1.0-sp"), Less);
        // final/ga == release.
        assert_eq!(Scheme::Maven.compare("1.0-Final", "1.0"), Equal);
        assert_eq!(Scheme::Maven.compare("1.0-ga", "1.0.0"), Equal);
        // digit↔letter boundary split: 1.0alpha1 == 1.0-alpha-1.
        assert_eq!(Scheme::Maven.compare("1.0alpha1", "1.0-alpha-1"), Equal);
        assert_eq!(Scheme::Maven.compare("1.0-alpha1", "1.0-alpha2"), Less);
        // Trailing zeros are insignificant.
        assert_eq!(Scheme::Maven.compare("1.2", "1.2.0"), Equal);
    }

    #[test]
    fn ecosystem_routing() {
        assert_eq!(Scheme::for_osv_ecosystem("crates.io"), Scheme::Semver);
        assert_eq!(Scheme::for_osv_ecosystem("PyPI"), Scheme::Pep440);
        assert_eq!(Scheme::for_osv_ecosystem("Maven"), Scheme::Maven);
        assert_eq!(Scheme::for_osv_ecosystem("RubyGems"), Scheme::RubyGems);
        assert_eq!(Scheme::for_osv_ecosystem("Packagist"), Scheme::Composer);
        assert_eq!(Scheme::for_osv_ecosystem("Go"), Scheme::Semver);
        // OS ecosystems are release-qualified in OSV.
        assert_eq!(Scheme::for_osv_ecosystem("Debian:11"), Scheme::Debian);
        assert_eq!(Scheme::for_osv_ecosystem("Ubuntu:22.04"), Scheme::Debian);
        assert_eq!(Scheme::for_osv_ecosystem("Alpine:v3.20"), Scheme::Apk);
        assert_eq!(Scheme::for_osv_ecosystem("Red Hat"), Scheme::Rpm);
    }

    #[test]
    fn debian_dpkg_ordering() {
        // Debian revisions and epochs order correctly (not as strings).
        assert_eq!(
            Scheme::Debian.compare("1.1.1n-0+deb11u1", "1.1.1n-0+deb11u3"),
            Less
        );
        assert_eq!(Scheme::Debian.compare("2:1.0", "1:9.9"), Greater); // epoch wins
        assert_eq!(Scheme::Debian.compare("1.10", "1.9"), Greater);
    }

    #[test]
    fn apk_ordering() {
        // Build revision.
        assert_eq!(Scheme::Apk.compare("3.1.4-r5", "3.1.4-r10"), Less);
        // Numeric components, not string.
        assert_eq!(Scheme::Apk.compare("1.10.0-r0", "1.9.0-r0"), Greater);
        // Pre-release suffix orders below release.
        assert_eq!(Scheme::Apk.compare("1.0.0_alpha1-r0", "1.0.0-r0"), Less);
        assert_eq!(
            Scheme::Apk.compare("1.0.0_rc1-r0", "1.0.0_beta1-r0"),
            Greater
        );
    }

    #[test]
    fn rpm_evr_ordering() {
        assert_eq!(Scheme::Rpm.compare("1.0-1", "1.0-2"), Less);
        assert_eq!(Scheme::Rpm.compare("1.10-1", "1.9-1"), Greater);
        assert_eq!(Scheme::Rpm.compare("2:1.0-1", "1:2.0-1"), Greater); // epoch wins
    }
}
