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
    /// Fallback: dotted numeric segments, then lexical. Used where a precise
    /// scheme is not yet wired (Maven/RubyGems/etc. get dedicated schemes as
    /// their fixtures land). Never a silent naive string compare.
    Generic,
}

impl Scheme {
    /// The OSV ecosystem string this scheme applies to.
    pub fn for_osv_ecosystem(ecosystem: &str) -> Scheme {
        match ecosystem {
            "crates.io" | "npm" | "Go" => Scheme::Semver,
            "PyPI" => Scheme::Pep440,
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
            Scheme::Generic => cmp_generic(a, b),
        }
    }
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
    fn ecosystem_routing() {
        assert_eq!(Scheme::for_osv_ecosystem("crates.io"), Scheme::Semver);
        assert_eq!(Scheme::for_osv_ecosystem("PyPI"), Scheme::Pep440);
        assert_eq!(Scheme::for_osv_ecosystem("Maven"), Scheme::Generic);
    }
}
