//! Built-in secret detection rules (spec 7.2). Rules are patterns, not code —
//! they live in the embedded, versioned `rules/builtin.json` pack (same
//! data-not-code shape as the IaC CIS pack), so growing the corpus is a pack
//! edit, and a future external pack channel ships detectors as data.
//!
//! Each rule has an explicit severity and confidence (ENG-004); provider
//! patterns carry an attributable prefix or structural marker and stay
//! `Proven`, while the entropy fallback is capped at `Medium`/`Heuristic`
//! (SEC-103, handled in the engine).

use multiscan_core::{Confidence, Severity};
use regex::Regex;
use serde::Deserialize;

/// The embedded rule pack, content-addressed for provenance like the IaC
/// CIS pack (FD-006). Zero network access needed (FD-007).
const BUILTIN_PACK: &str = include_str!("../rules/builtin.json");

/// One pattern-based secret rule.
pub struct Rule {
    /// Stable rule id (identity input, spec 7.7.2).
    pub id: String,
    /// Human-readable secret type.
    pub description: String,
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

/// A loaded rule pack: identity for the manifest's `rule_set` plus the
/// compiled rules.
pub struct RulePack {
    /// Pack id (`builtin` for the embedded pack; `[rules] secrets_pack` pins
    /// against this).
    pub id: String,
    /// Pack version.
    pub version: String,
    /// blake3 digest of the pack bytes.
    pub digest: String,
    /// Compiled rules.
    pub rules: Vec<Rule>,
}

#[derive(Deserialize)]
struct PackFile {
    pack_id: String,
    version: String,
    #[serde(default)]
    rules: Vec<RuleSpec>,
}

#[derive(Deserialize)]
struct RuleSpec {
    id: String,
    description: String,
    pattern: String,
    severity: Severity,
    confidence: Confidence,
}

/// Load the embedded pack. A malformed built-in pattern is a bug, not user
/// input; the rule is skipped rather than panicking so one bad rule never
/// aborts a scan (the pack-integrity test fails the build instead).
pub fn builtin_pack() -> RulePack {
    let digest = format!("blake3:{}", blake3::hash(BUILTIN_PACK.as_bytes()).to_hex());
    let parsed: PackFile = serde_json::from_str(BUILTIN_PACK).unwrap_or(PackFile {
        pack_id: "builtin".to_string(),
        version: "0".to_string(),
        rules: Vec::new(),
    });
    let rules = parsed
        .rules
        .into_iter()
        .filter_map(|spec| {
            Regex::new(&spec.pattern).ok().map(|pattern| Rule {
                id: spec.id,
                description: spec.description,
                pattern,
                severity: spec.severity,
                confidence: spec.confidence,
            })
        })
        .collect();
    RulePack {
        id: parsed.pack_id,
        version: parsed.version,
        digest,
        rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pack integrity: every rule in the JSON must survive compilation — a
    /// silently skipped rule is a detection regression.
    #[test]
    fn every_pack_rule_compiles() {
        let raw: serde_json::Value = serde_json::from_str(BUILTIN_PACK).unwrap();
        let declared = raw["rules"].as_array().unwrap().len();
        let pack = builtin_pack();
        assert_eq!(pack.rules.len(), declared, "a pack rule failed to compile");
        assert!(declared >= 21, "corpus shrank: {declared} rules");
        assert_eq!(pack.id, "builtin");
        assert!(pack.digest.starts_with("blake3:"));
    }

    #[test]
    fn rule_ids_are_unique() {
        let pack = builtin_pack();
        let mut ids: Vec<&str> = pack.rules.iter().map(|r| r.id.as_str()).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "duplicate rule id in pack");
    }

    fn rule(id: &str) -> Rule {
        builtin_pack()
            .rules
            .into_iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("rule {id} missing"))
    }

    #[test]
    fn aws_key_matches_and_extracts() {
        let r = rule("aws-access-key-id");
        let caps = r.pattern.captures("key = AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(r.extract(&caps), "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn new_provider_rules_match_their_shapes() {
        // (rule id, sample that must match)
        let positives = [
            (
                "github-fine-grained-pat",
                format!("github_pat_{}_{}", "A".repeat(22), "B".repeat(59)),
            ),
            ("gitlab-pat", format!("glpat-{}", "x1".repeat(13))),
            ("npm-token", format!("npm_{}", "a1B2".repeat(9))),
            (
                "pypi-token",
                format!("pypi-AgEIcHlwaS5vcmc{}", "Ab-C".repeat(15)),
            ),
            (
                "stripe-secret-key",
                format!("sk_live_{}", "4eC9".repeat(7)),
            ),
            (
                "sendgrid-api-key",
                format!("SG.{}.{}", "aB-9zK4mPq1XwE8rT5uY0s", "C".repeat(43)),
            ),
            ("twilio-api-key", format!("SK{}", "0af9".repeat(8))),
            (
                "openai-api-key",
                format!("sk-{}T3BlbkFJ{}", "Ab12".repeat(5), "Cd34".repeat(5)),
            ),
            (
                "anthropic-api-key",
                format!("sk-ant-api03-{}", "Xy-9".repeat(12)),
            ),
            // Assembled at runtime so no webhook-shaped literal sits in
            // source — GitHub push protection (rightly) flags those.
            (
                "slack-webhook",
                format!(
                    "https://hooks.slack.com/services/T{}/B{}/{}",
                    "0000TEST0",
                    "0000TEST0",
                    "X".repeat(24)
                ),
            ),
            (
                "discord-webhook",
                format!(
                    "https://discord.com/api/webhooks/123456789012345678/{}",
                    "aZ-_".repeat(16)
                ),
            ),
            (
                "azure-storage-key",
                format!("AccountKey={}{}==", "Ab+/".repeat(21), "Zx"),
            ),
            (
                "database-url-credentials",
                "postgres://svc:S3cr3tPassw0rd@db.internal:5432/app".to_string(),
            ),
            (
                "keyword-context-secret",
                "API_KEY = \"f8Zk2mQ9vX4nR7wL\"".to_string(),
            ),
        ];
        for (id, sample) in positives {
            let r = rule(id);
            assert!(
                r.pattern.is_match(&sample),
                "{id} failed to match its own shape: {sample}"
            );
        }
    }

    #[test]
    fn database_url_extracts_password_only() {
        let r = rule("database-url-credentials");
        let line = "url = postgres://svc:S3cr3tPassw0rd@db.internal:5432/app";
        let caps = r.pattern.captures(line).unwrap();
        assert_eq!(r.extract(&caps), "S3cr3tPassw0rd");
    }

    #[test]
    fn tight_patterns_reject_near_misses() {
        // (rule id, sample that must NOT match)
        let negatives = [
            ("stripe-secret-key", "sk_live_short"),
            ("twilio-api-key", "SKINCARE0000000000000000000000000"), // not hex
            ("anthropic-api-key", "sk-ant-short"),
            ("gitlab-pat", "glpat-short"),
            // Unquoted value: keyword rule requires quotes to bound the value.
            ("keyword-context-secret", "password = hunter2limited"),
            // URL without a password component.
            ("database-url-credentials", "postgres://db.internal:5432/app"),
        ];
        for (id, sample) in negatives {
            let r = rule(id);
            assert!(!r.pattern.is_match(sample), "{id} over-matched: {sample}");
        }
    }
}
