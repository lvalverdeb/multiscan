//! Built-in secret detection rules (spec 7.2). Rules are patterns, not code.
//!
//! Each rule has an explicit severity and confidence (ENG-004); high-precision
//! provider patterns are `Proven`/`High`, while the entropy fallback is capped
//! at `Medium`/`Heuristic` (SEC-103, handled in the engine).

use multiscan_core::{Confidence, Severity};
use regex::Regex;

/// One pattern-based secret rule.
pub struct Rule {
    /// Stable rule id (identity input, spec 7.7.2).
    pub id: &'static str,
    /// Human-readable secret type.
    pub description: &'static str,
    /// Compiled detection pattern; capture group 1, if present, is the secret
    /// value, else the whole match.
    pub pattern: Regex,
    /// Severity for a match.
    pub severity: Severity,
    /// Confidence for a match.
    pub confidence: Confidence,
}

impl Rule {
    /// Extract the secret substring from a regex match.
    pub fn extract<'a>(&self, caps: &regex::Captures<'a>) -> &'a str {
        caps.get(1)
            .or_else(|| caps.get(0))
            .map(|m| m.as_str())
            .unwrap_or("")
    }
}

/// Build the bundled rule set. Compiled once per engine instance.
pub fn builtin_rules() -> Vec<Rule> {
    // Patterns kept deliberately tight to limit false positives; breadth
    // parity with dedicated secret scanners is not a v1 goal.
    let specs: &[(&str, &str, &str, Severity, Confidence)] = &[
        (
            "aws-access-key-id",
            "AWS access key id",
            r"\b(AKIA[0-9A-Z]{16})\b",
            Severity::High,
            Confidence::Proven,
        ),
        (
            "aws-secret-access-key",
            "AWS secret access key",
            r#"(?i)aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+]{40})["']?"#,
            Severity::Critical,
            Confidence::Proven,
        ),
        (
            "github-token",
            "GitHub personal access / app token",
            r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b",
            Severity::High,
            Confidence::Proven,
        ),
        (
            "slack-token",
            "Slack token",
            r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b",
            Severity::High,
            Confidence::Proven,
        ),
        (
            "google-api-key",
            "Google API key",
            r"\b(AIza[0-9A-Za-z_\-]{35})\b",
            Severity::High,
            Confidence::Proven,
        ),
        (
            "private-key-block",
            "Private key material",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            Severity::Critical,
            Confidence::Proven,
        ),
        (
            "jwt",
            "JSON Web Token",
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
            Severity::Medium,
            Confidence::Corroborated,
        ),
    ];

    specs
        .iter()
        .filter_map(|(id, description, pattern, severity, confidence)| {
            // A malformed built-in pattern is a bug, not user input; skip it
            // rather than panic so one bad rule never aborts a scan.
            Regex::new(pattern).ok().map(|pattern| Rule {
                id,
                description,
                pattern,
                severity: *severity,
                confidence: *confidence,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtins_compile() {
        // 7 specs above; all patterns must compile.
        assert_eq!(builtin_rules().len(), 7);
    }

    #[test]
    fn aws_key_matches_and_extracts() {
        let rules = builtin_rules();
        let rule = rules.iter().find(|r| r.id == "aws-access-key-id").unwrap();
        let caps = rule.pattern.captures("key = AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(rule.extract(&caps), "AKIAIOSFODNN7EXAMPLE");
    }
}
