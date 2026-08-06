//! Config-file suppression matching (CLI-006, ADR 0008).
//!
//! A `[[suppress]]` entry carries a mandatory justification/approver/expires
//! (CLI-006) plus one or more *selectors*: an exact `finding_id`, an engine
//! `rule_id`, and/or a `path` glob. An entry with no selector is a config
//! error — it would suppress everything. When several selectors are present
//! they are ANDed, so `rule_id = "high-entropy-string"` + `path = "uv.lock"`
//! silences exactly that class in exactly that file and nothing else.
//!
//! Store-backed suppressions (`multiscan suppress add`) remain `finding_id`
//! only; the scoped selectors live in the committed, diff-friendly config
//! (CLI-007) where a reviewer can see and approve them.

use globset::{Glob, GlobMatcher};
use multiscan_core::{Finding, SuppressEntry};

/// A compiled `[[suppress]]` entry: selectors plus its expiry.
#[derive(Debug)]
pub struct CompiledSuppression {
    finding_id: Option<String>,
    rule_id: Option<String>,
    path: Option<GlobMatcher>,
    expires: String,
}

impl CompiledSuppression {
    /// Whether this suppression is active at `now` and matches `finding`.
    /// All present selectors must match (AND); presence of ≥1 is guaranteed
    /// at compile time.
    pub fn active_match(&self, finding: &Finding, now: chrono::DateTime<chrono::Utc>) -> bool {
        if !suppression_active(&self.expires, now) {
            return false;
        }
        let rule_ids: Vec<&str> = finding
            .sources
            .iter()
            .filter_map(|s| s.rule_id.as_deref())
            .collect();
        self.matches_facts(&finding.finding_id.0, &rule_ids, &finding.location.path)
    }

    /// Pure selector match against a finding's identifying facts (ignores
    /// expiry). All present selectors must hold.
    fn matches_facts(&self, finding_id: &str, source_rule_ids: &[&str], path: &str) -> bool {
        if let Some(id) = &self.finding_id {
            if finding_id != id {
                return false;
            }
        }
        if let Some(rule_id) = &self.rule_id {
            if !source_rule_ids.contains(&rule_id.as_str()) {
                return false;
            }
        }
        if let Some(glob) = &self.path {
            if !glob.is_match(path) {
                return false;
            }
        }
        true
    }
}

/// Compile and validate every config `[[suppress]]` entry. Structural errors
/// (no selector, or a bad `path` glob) are reported regardless of expiry, so
/// a malformed suppression is a config error (exit 2) even if already expired.
/// The mandatory CLI-006 fields are enforced upstream by the schema.
pub fn compile(entries: &[SuppressEntry]) -> Result<Vec<CompiledSuppression>, String> {
    let mut out = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        if e.finding_id.is_none() && e.rule_id.is_none() && e.path.is_none() {
            return Err(format!(
                "[[suppress]] #{}: at least one selector (finding_id, rule_id, or path) is required",
                i + 1
            ));
        }
        let path = match &e.path {
            Some(pattern) => Some(
                Glob::new(pattern)
                    .map_err(|err| {
                        format!("[[suppress]] #{}: invalid path glob `{pattern}`: {err}", i + 1)
                    })?
                    .compile_matcher(),
            ),
            None => None,
        };
        out.push(CompiledSuppression {
            finding_id: e.finding_id.as_ref().map(|f| f.0.clone()),
            rule_id: e.rule_id.clone(),
            path,
            expires: e.expires.clone(),
        });
    }
    Ok(out)
}

/// Whether an `expires` string (RFC 3339 datetime or bare `YYYY-MM-DD`) is
/// still in the future relative to `now`. A bare date is active through the
/// end of the stated day (UTC).
pub fn suppression_active(expires: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(expires) {
        return dt.with_timezone(&chrono::Utc) > now;
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(expires, "%Y-%m-%d") {
        if let Some(end) = date.and_hms_opt(23, 59, 59) {
            return end.and_utc() > now;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-08-06T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn entry(toml: &str) -> Vec<SuppressEntry> {
        #[derive(serde::Deserialize)]
        struct W {
            suppress: Vec<SuppressEntry>,
        }
        toml::from_str::<W>(toml).unwrap().suppress
    }

    #[test]
    fn rule_and_path_scopes_precisely() {
        let s = compile(&entry(
            "[[suppress]]\nrule_id = \"high-entropy-string\"\npath = \"uv.lock\"\njustification = \"checksums\"\napprover = \"sec\"\nexpires = \"2027-01-01\"\n",
        ))
        .unwrap();
        assert!(s[0].matches_facts("a", &["high-entropy-string"], "uv.lock"));
        // Right rule, wrong path.
        assert!(!s[0].matches_facts("b", &["high-entropy-string"], "src/main.py"));
        // Right path, wrong rule.
        assert!(!s[0].matches_facts("c", &["aws-access-key-id"], "uv.lock"));
    }

    #[test]
    fn path_glob_matches_subtree() {
        let s = compile(&entry(
            "[[suppress]]\nrule_id = \"high-entropy-string\"\npath = \"vendor/**\"\njustification = \"x\"\napprover = \"y\"\nexpires = \"2027-01-01\"\n",
        ))
        .unwrap();
        assert!(s[0].matches_facts("a", &["high-entropy-string"], "vendor/lib/x.js"));
        assert!(!s[0].matches_facts("b", &["high-entropy-string"], "app/x.js"));
    }

    #[test]
    fn expiry_gates_the_match() {
        let expired = compile(&entry(
            "[[suppress]]\npath = \"uv.lock\"\njustification = \"x\"\napprover = \"y\"\nexpires = \"2020-01-01\"\n",
        ))
        .unwrap();
        // Selector matches, but the entry is expired at `now`.
        assert!(expired[0].matches_facts("a", &["r"], "uv.lock"));
        assert!(!suppression_active(&expired[0].expires, now()));
    }

    #[test]
    fn empty_selector_is_an_error() {
        let err = compile(&entry(
            "[[suppress]]\njustification = \"x\"\napprover = \"y\"\nexpires = \"2027-01-01\"\n",
        ))
        .unwrap_err();
        assert!(err.contains("at least one selector"), "{err}");
    }

    #[test]
    fn bad_glob_is_an_error() {
        let err = compile(&entry(
            "[[suppress]]\npath = \"a{b\"\njustification = \"x\"\napprover = \"y\"\nexpires = \"2027-01-01\"\n",
        ))
        .unwrap_err();
        assert!(err.contains("invalid path glob"), "{err}");
    }

    #[test]
    fn finding_id_only_still_works() {
        let s = compile(&entry(
            "[[suppress]]\nfinding_id = \"deadbeef\"\njustification = \"x\"\napprover = \"y\"\nexpires = \"2027-01-01\"\n",
        ))
        .unwrap();
        assert!(s[0].matches_facts("deadbeef", &["r"], "p"));
        assert!(!s[0].matches_facts("other", &["r"], "p"));
    }
}
