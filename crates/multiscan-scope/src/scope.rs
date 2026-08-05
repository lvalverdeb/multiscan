//! Host/method scope matching (SEC-002, SEC-003, PRB-003). Pure and lexical —
//! part of the static gate, so it runs with zero network I/O.

use crate::decision::{Decision, Denied};

/// A validated scope: include/exclude patterns and permitted methods. Wildcard
/// patterns spanning a public suffix are rejected at construction (SEC-003), so
/// a `Scope` value is always safe to match against.
pub struct Scope {
    include: Vec<String>,
    exclude: Vec<String>,
    permitted_methods: Vec<String>,
}

impl Scope {
    /// Build from raw patterns, rejecting public-suffix-spanning wildcards
    /// (SEC-003, fail closed).
    pub fn new(
        include: Vec<String>,
        exclude: Vec<String>,
        permitted_methods: Vec<String>,
    ) -> Result<Self, Denied> {
        for pattern in include.iter().chain(exclude.iter()) {
            if let Some(bad) = unsafe_wildcard(pattern) {
                return Err(Denied::UnsafeWildcard(bad));
            }
        }
        Ok(Self {
            include,
            exclude,
            permitted_methods: permitted_methods
                .into_iter()
                .map(|m| m.to_ascii_uppercase())
                .collect(),
        })
    }

    /// Decide whether `host` is in scope. `exclude` always beats `include`
    /// (SEC-002).
    pub fn decide_host(&self, host: &str) -> Decision {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        // Exclude first, and it wins.
        for pattern in &self.exclude {
            if matches_pattern(pattern, &host) {
                return Decision::Denied(Denied::ExcludedBy(pattern.clone()));
            }
        }
        for pattern in &self.include {
            if matches_pattern(pattern, &host) {
                return Decision::Allowed {
                    matched_pattern: pattern.clone(),
                };
            }
        }
        Decision::Denied(Denied::NotIncluded(host))
    }

    /// Whether `method` is permitted by the authorization (case-insensitive).
    /// Profile restrictions (PRB-003) are applied by the caller *before* this.
    pub fn method_permitted(&self, method: &str) -> bool {
        self.permitted_methods
            .iter()
            .any(|m| m == &method.to_ascii_uppercase())
    }
}

/// If `pattern`'s wildcard spans a public suffix, return the offending pattern.
/// `*.staging.acme.com` is fine; `*.com` / `*.co.uk` are not — the rule is that
/// a wildcard must leave at least one label beyond the registrable suffix.
fn unsafe_wildcard(pattern: &str) -> Option<String> {
    let pattern = pattern.trim().to_ascii_lowercase();
    let Some(rest) = pattern.strip_prefix("*.") else {
        return None; // not a wildcard pattern
    };
    // The bytes after `*.` must themselves be more specific than a public
    // suffix. `psl::suffix` returns the public suffix of a domain; if `rest`
    // *is* a public suffix (or shorter), the wildcard is too broad.
    let is_registrable = psl::domain(rest.as_bytes()).is_some_and(|d| {
        // A registrable domain has a suffix strictly shorter than the whole
        // (i.e. there is at least one label before the public suffix).
        d.suffix().as_bytes().len() < rest.len()
    });
    if is_registrable {
        None
    } else {
        Some(pattern)
    }
}

/// Match a host against a scope pattern. Supports a leading `*.` wildcard that
/// matches exactly one-or-more leading labels; otherwise an exact match.
fn matches_pattern(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `*.staging.acme.com` matches `a.staging.acme.com` and
        // `a.b.staging.acme.com`, but not `staging.acme.com` itself.
        host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(include: &[&str], exclude: &[&str]) -> Scope {
        Scope::new(
            include.iter().map(|s| s.to_string()).collect(),
            exclude.iter().map(|s| s.to_string()).collect(),
            vec!["GET".into(), "HEAD".into()],
        )
        .unwrap()
    }

    #[test]
    fn exact_and_wildcard_matching() {
        let s = scope(&["staging.acme.com", "*.staging.acme.internal"], &[]);
        assert!(s.decide_host("staging.acme.com").is_allowed());
        assert!(s.decide_host("api.staging.acme.internal").is_allowed());
        assert!(s.decide_host("a.b.staging.acme.internal").is_allowed());
        // Wildcard does not match the bare suffix.
        assert!(!s.decide_host("staging.acme.internal").is_allowed());
        assert!(!s.decide_host("evil.com").is_allowed());
    }

    #[test]
    fn exclude_beats_include() {
        let s = scope(&["*.staging.acme.com"], &["payments.staging.acme.com"]);
        assert!(s.decide_host("api.staging.acme.com").is_allowed());
        // Excluded even though it matches the include wildcard (SEC-002).
        match s.decide_host("payments.staging.acme.com") {
            Decision::Denied(Denied::ExcludedBy(_)) => {}
            other => panic!("expected ExcludedBy, got {other:?}"),
        }
    }

    #[test]
    fn public_suffix_wildcards_rejected() {
        // SEC-003: these must fail construction.
        assert!(Scope::new(vec!["*.com".into()], vec![], vec![]).is_err());
        assert!(Scope::new(vec!["*.co.uk".into()], vec![], vec![]).is_err());
        // A registrable-domain wildcard is fine.
        assert!(Scope::new(vec!["*.acme.com".into()], vec![], vec![]).is_ok());
        assert!(Scope::new(vec!["*.staging.acme.com".into()], vec![], vec![]).is_ok());
    }

    #[test]
    fn method_permitted_is_case_insensitive() {
        let s = scope(&["a.com"], &[]);
        assert!(s.method_permitted("get"));
        assert!(s.method_permitted("HEAD"));
        assert!(!s.method_permitted("POST"));
    }
}
