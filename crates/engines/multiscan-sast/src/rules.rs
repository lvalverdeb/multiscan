//! SAST rule packs: MS-PAT-1 rules as data, in the same shape as the secrets
//! and IaC packs (ADR 0010), delivered over the feed channel.
//!
//! The operator layer deserializes here; leaf *pattern text* stays a `String`
//! until a language front-end (`T-702`) compiles it with that language's real
//! parser, per the substitution convention in `docs/ms-pat-1.md` §3.
//!
//! Rejection is total: a rule that uses an operator outside MS-PAT-1, or omits
//! its severity, fails pack load rather than being silently downgraded
//! (`SAST-004`, `ENG-004`).

use std::collections::{BTreeMap, BTreeSet};

use multiscan_core::{Confidence, Severity};
use serde::Deserialize;

use crate::pattern::{PatternError, MAX_ELLIPSES_PER_SEQUENCE, MAX_PATTERN_DEPTH};

/// Defensive caps for feed-delivered packs. Signed and digest-verified
/// upstream, but still external data (ADR 0010).
const MAX_PACK_RULES: usize = 10_000;
const MAX_PATTERN_BYTES: usize = 8_192;

/// Languages a rule can target. Fixed by ADR 0013 — Python and JS/TS.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// Python.
    Python,
    /// JavaScript.
    Javascript,
    /// TypeScript — same front-end as JavaScript (ADR 0013).
    Typescript,
}

/// A pattern expression as it appears in a pack, with leaf patterns still
/// uncompiled text.
///
/// The variants are exactly MS-PAT-1's operators. `deny_unknown_fields` plus
/// the absence of any taint variant is what makes an out-of-subset rule a load
/// error: there is nothing to deserialize `pattern-sources` *into*.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum RawPatternExpr {
    /// `pattern` — leaf pattern text, compiled by the front-end.
    Pattern(String),
    /// `patterns` — conjunction.
    Patterns(Vec<RawPatternExpr>),
    /// `pattern-either` — disjunction.
    PatternEither(Vec<RawPatternExpr>),
    /// `pattern-not` — negation.
    PatternNot(Box<RawPatternExpr>),
    /// `pattern-inside` — context.
    PatternInside(Box<RawPatternExpr>),
    /// `pattern-not-inside` — negative context.
    PatternNotInside(Box<RawPatternExpr>),
}

impl RawPatternExpr {
    /// Nesting depth, counting operators only (leaf text is not yet parsed).
    pub fn depth(&self) -> usize {
        match self {
            RawPatternExpr::Pattern(_) => 1,
            RawPatternExpr::Patterns(list) | RawPatternExpr::PatternEither(list) => {
                1 + list.iter().map(RawPatternExpr::depth).max().unwrap_or(0)
            }
            RawPatternExpr::PatternNot(inner)
            | RawPatternExpr::PatternInside(inner)
            | RawPatternExpr::PatternNotInside(inner) => 1 + inner.depth(),
        }
    }

    /// Structural checks that do not need a parser.
    fn validate(&self) -> Result<(), PatternError> {
        match self {
            RawPatternExpr::Pattern(text) => {
                if text.trim() == "..." {
                    return Err(PatternError::BareEllipsis);
                }
                Ok(())
            }
            RawPatternExpr::Patterns(list) | RawPatternExpr::PatternEither(list) => {
                if list.is_empty() {
                    return Err(PatternError::EmptyOperandList);
                }
                list.iter().try_for_each(RawPatternExpr::validate)
            }
            RawPatternExpr::PatternNot(inner)
            | RawPatternExpr::PatternInside(inner)
            | RawPatternExpr::PatternNotInside(inner) => inner.validate(),
        }
    }

    /// Every leaf pattern text in the expression, for the front-end to compile.
    pub fn leaf_texts(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.collect_leaves(&mut out);
        out
    }

    fn collect_leaves<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            RawPatternExpr::Pattern(text) => out.push(text.as_str()),
            RawPatternExpr::Patterns(list) | RawPatternExpr::PatternEither(list) => {
                for e in list {
                    e.collect_leaves(out);
                }
            }
            RawPatternExpr::PatternNot(inner)
            | RawPatternExpr::PatternInside(inner)
            | RawPatternExpr::PatternNotInside(inner) => inner.collect_leaves(out),
        }
    }
}

/// Where a pack, or one rule in it, came from.
///
/// ADR 0014 decision 3 requires the translator to stamp this, and decision 4
/// requires the licence audit result to ride along with the content. Carried
/// as free-form data because it is provenance, not behaviour: nothing here
/// affects matching.
pub type Provenance = serde_json::Map<String, serde_json::Value>;

/// One MS-PAT-1 rule.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SastRule {
    /// Stable rule id — an identity input (§7.7.2).
    pub id: String,
    /// Upstream source, licence and translation date, when translated.
    #[serde(default)]
    pub provenance: Option<Provenance>,
    /// Human-readable finding message.
    pub message: String,
    /// Languages this rule applies to.
    pub languages: Vec<Language>,
    /// Explicit severity. Required: inferred or passthrough severity is
    /// forbidden (`ENG-004`, `SAST-004`).
    pub severity: Severity,
    /// Explicit confidence.
    pub confidence: Confidence,
    /// The rule's pattern expression.
    #[serde(flatten)]
    pub pattern: RawPatternExpr,
}

/// A loaded SAST rule pack.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SastPack {
    /// Pack id; `[rules] sast_pack` pins against this.
    pub id: String,
    /// Pack version.
    pub version: String,
    /// blake3 digest of the pack bytes, for `RuleSetRef` provenance.
    pub digest: String,
    /// Corpus source, licence audit result and translation date, when the pack
    /// was mechanically translated (ADR 0014 decisions 3 and 4).
    pub provenance: Option<Provenance>,
    /// Rules, in pack order — iteration order is the pack's, never the
    /// filesystem's (`DET-001`).
    pub rules: Vec<SastRule>,
    /// Rules rejected at load, by rule id and reason.
    ///
    /// Surfaced rather than swallowed: a silently shrinking corpus reads as
    /// coverage (ADR 0014 decision 3).
    pub rejected: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    pack_id: String,
    version: String,
    #[serde(default)]
    provenance: Option<Provenance>,
    #[serde(default)]
    rules: Vec<SastRule>,
}

/// Why a pack could not be loaded at all.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    /// The pack bytes are not valid JSON in the pack shape. A rule using an
    /// operator outside MS-PAT-1 lands here — there is no variant for it.
    #[error("sast rule pack: {0}")]
    Malformed(String),
}

/// Load and validate a pack.
///
/// Whole-pack problems are an error. Individual bad rules are recorded in
/// [`SastPack::rejected`] and skipped, so one malformed rule never aborts a
/// scan — the same posture as the secrets pack.
pub fn parse_pack(bytes: &[u8]) -> Result<SastPack, PackError> {
    let digest = format!("blake3:{}", blake3::hash(bytes).to_hex());
    let parsed: PackFile =
        serde_json::from_slice(bytes).map_err(|e| PackError::Malformed(e.to_string()))?;

    let mut rules: Vec<SastRule> = Vec::new();
    let mut rejected: BTreeMap<String, String> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for rule in parsed.rules.into_iter().take(MAX_PACK_RULES) {
        // Rule id is an identity input (§7.7.2): two rules sharing one would
        // collide in the `finding_id` namespace, so the duplicate is rejected
        // rather than shadowing.
        let outcome = if !seen.insert(rule.id.clone()) {
            Err("duplicate rule id".to_string())
        } else {
            check_rule(&rule)
        };

        if let Err(reason) = outcome {
            // Keyed by id, so a repeated id would overwrite an earlier
            // rejection; disambiguate rather than lose the record.
            let mut key = rule.id.clone();
            let mut nth = 2;
            while rejected.contains_key(&key) {
                key = format!("{} #{nth}", rule.id);
                nth += 1;
            }
            rejected.insert(key, reason);
            continue;
        }
        rules.push(rule);
    }

    Ok(SastPack {
        id: parsed.pack_id,
        version: parsed.version,
        digest,
        provenance: parsed.provenance,
        rules,
        rejected,
    })
}

fn check_rule(rule: &SastRule) -> Result<(), String> {
    if rule.languages.is_empty() {
        return Err("rule targets no language".to_string());
    }
    if rule.pattern.depth() > MAX_PATTERN_DEPTH {
        return Err(format!(
            "pattern nests {} deep, exceeding the maximum of {MAX_PATTERN_DEPTH}",
            rule.pattern.depth()
        ));
    }
    if let Some(text) = rule
        .pattern
        .leaf_texts()
        .into_iter()
        .find(|t| t.len() > MAX_PATTERN_BYTES)
    {
        return Err(format!(
            "leaf pattern is {} bytes, exceeding the maximum of {MAX_PATTERN_BYTES}",
            text.len()
        ));
    }
    // Cheap textual pre-filter for the O(n^k) ellipsis case. The authoritative
    // per-sequence check is `PatternNode::validate`, which needs the compiled
    // pattern and so runs in the front-end (T-702); this bounds the leaf before
    // a parser ever sees it.
    if let Some(text) = rule
        .pattern
        .leaf_texts()
        .into_iter()
        .find(|t| t.matches("...").count() > MAX_ELLIPSES_PER_SEQUENCE)
    {
        return Err(format!(
            "leaf pattern has {} `...` items, exceeding the maximum of {MAX_ELLIPSES_PER_SEQUENCE}",
            text.matches("...").count()
        ));
    }
    rule.pattern.validate().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_json(rules: &str) -> Vec<u8> {
        format!(r#"{{"pack_id":"t","version":"1.0.0","rules":[{rules}]}}"#).into_bytes()
    }

    const EVAL_RULE: &str = r#"{
        "id": "py.eval",
        "message": "eval on non-literal input",
        "languages": ["python"],
        "severity": "high",
        "confidence": "heuristic",
        "pattern": "eval($X)"
    }"#;

    #[test]
    fn loads_a_well_formed_rule() {
        let pack = parse_pack(&pack_json(EVAL_RULE)).unwrap();
        assert_eq!(pack.id, "t");
        assert_eq!(pack.rules.len(), 1);
        assert_eq!(pack.rules[0].id, "py.eval");
        assert_eq!(pack.rules[0].languages, vec![Language::Python]);
        assert!(pack.rejected.is_empty());
        assert!(pack.digest.starts_with("blake3:"));
    }

    #[test]
    fn taint_mode_cannot_be_expressed() {
        // NG-2 is permanent, and it is enforced by there being no variant to
        // deserialize taint operators into — not by a blocklist.
        let taint = r#"{
            "id": "py.taint",
            "message": "taint",
            "languages": ["python"],
            "severity": "high",
            "confidence": "heuristic",
            "pattern-sources": ["input()"],
            "pattern-sinks": ["eval($X)"]
        }"#;
        let err = parse_pack(&pack_json(taint)).unwrap_err();
        assert!(matches!(err, PackError::Malformed(_)));
    }

    #[test]
    fn out_of_subset_operators_are_rejected() {
        for operator in [
            r#""metavariable-pattern": {"metavariable": "$X"}"#,
            r#""metavariable-comparison": {"comparison": "$X > 1"}"#,
            r#""pattern-regex": "eval\\(""#,
            r#""fix": "safe_eval($X)""#,
        ] {
            let rule = format!(
                r#"{{"id":"r","message":"m","languages":["python"],
                     "severity":"high","confidence":"heuristic",{operator}}}"#
            );
            assert!(
                parse_pack(&pack_json(&rule)).is_err(),
                "{operator} must be rejected at pack load"
            );
        }
    }

    #[test]
    fn missing_severity_is_rejected() {
        // SAST-004 / ENG-004: severity is never inferred.
        let rule = r#"{
            "id": "py.nosev",
            "message": "m",
            "languages": ["python"],
            "confidence": "heuristic",
            "pattern": "eval($X)"
        }"#;
        assert!(parse_pack(&pack_json(rule)).is_err());
    }

    #[test]
    fn bad_rules_are_recorded_not_swallowed() {
        // A rule with no language is skipped, the rest of the pack still
        // loads, and the rejection is visible.
        let bad = r#"{
            "id": "py.nolang",
            "message": "m",
            "languages": [],
            "severity": "high",
            "confidence": "heuristic",
            "pattern": "eval($X)"
        }"#;
        let pack = parse_pack(&pack_json(&format!("{EVAL_RULE},{bad}"))).unwrap();
        assert_eq!(pack.rules.len(), 1);
        assert_eq!(pack.rejected.len(), 1);
        assert!(pack.rejected.contains_key("py.nolang"));
    }

    #[test]
    fn bare_ellipsis_is_rejected() {
        let rule = r#"{
            "id": "py.bare",
            "message": "m",
            "languages": ["python"],
            "severity": "high",
            "confidence": "heuristic",
            "pattern": "..."
        }"#;
        let pack = parse_pack(&pack_json(rule)).unwrap();
        assert!(pack.rules.is_empty());
        assert!(pack.rejected["py.bare"].contains("sequence operator"));
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        // Rule id is an identity input (§7.7.2): duplicates would collide in
        // the finding_id namespace.
        let pack = parse_pack(&pack_json(&format!("{EVAL_RULE},{EVAL_RULE}"))).unwrap();
        assert_eq!(pack.rules.len(), 1);
        assert_eq!(pack.rejected.len(), 1);
        assert!(pack.rejected.values().any(|r| r.contains("duplicate")));
    }

    #[test]
    fn repeated_bad_ids_keep_separate_rejection_records() {
        // `rejected` is keyed by id, so two bad rules sharing one must not
        // overwrite each other — a silently shrinking record reads as coverage.
        let bad = r#"{
            "id": "py.dup",
            "message": "m",
            "languages": [],
            "severity": "high",
            "confidence": "heuristic",
            "pattern": "eval($X)"
        }"#;
        let pack = parse_pack(&pack_json(&format!("{bad},{bad}"))).unwrap();
        assert!(pack.rules.is_empty());
        assert_eq!(pack.rejected.len(), 2, "both rejections recorded");
    }

    #[test]
    fn out_of_subset_operator_alongside_a_valid_one_is_rejected() {
        // The existing rejection tests present the bad operator alone. Serde's
        // `flatten` disables deny_unknown_fields, so the coexisting case is
        // guarded only by the flattened enum's single-key semantics — pin it,
        // or a later refactor could start silently ignoring `fix`.
        let rule = r#"{
            "id": "py.fix",
            "message": "m",
            "languages": ["python"],
            "severity": "high",
            "confidence": "heuristic",
            "pattern": "eval($X)",
            "fix": "safe_eval($X)"
        }"#;
        assert!(
            parse_pack(&pack_json(rule)).is_err(),
            "autofix beside a valid pattern must still be rejected"
        );
    }

    #[test]
    fn ellipsis_heavy_leaf_text_is_rejected() {
        // Textual pre-filter for the O(n^k) case, before a parser sees it.
        let dots = ["..."; MAX_ELLIPSES_PER_SEQUENCE + 1].join(", ");
        let rule = format!(
            r#"{{"id":"py.dots","message":"m","languages":["python"],
                 "severity":"high","confidence":"heuristic","pattern":"f({dots})"}}"#
        );
        let pack = parse_pack(&pack_json(&rule)).unwrap();
        assert!(pack.rules.is_empty());
        assert!(pack.rejected["py.dots"].contains("exceeding"));
    }

    #[test]
    fn nested_operators_round_trip() {
        let rule = r#"{
            "id": "py.nested",
            "message": "m",
            "languages": ["python", "javascript"],
            "severity": "critical",
            "confidence": "proven",
            "patterns": [
                {"pattern": "eval($X)"},
                {"pattern-not-inside": {"pattern": "try_block($Y)"}}
            ]
        }"#;
        let pack = parse_pack(&pack_json(rule)).unwrap();
        assert_eq!(pack.rules.len(), 1);
        assert_eq!(pack.rules[0].pattern.depth(), 3);
        assert_eq!(
            pack.rules[0].pattern.leaf_texts(),
            vec!["eval($X)", "try_block($Y)"]
        );
    }

    #[test]
    fn oversized_leaf_pattern_is_rejected() {
        let huge = "e".repeat(MAX_PATTERN_BYTES + 1);
        let rule = format!(
            r#"{{"id":"py.huge","message":"m","languages":["python"],
                 "severity":"high","confidence":"heuristic","pattern":"{huge}"}}"#
        );
        let pack = parse_pack(&pack_json(&rule)).unwrap();
        assert!(pack.rules.is_empty());
        assert!(pack.rejected["py.huge"].contains("exceeding"));
    }
}
