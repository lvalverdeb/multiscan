//! Compiling a [`SastPack`] into matchable rules.
//!
//! The operator layer is language-independent (`T-701`); leaf pattern text is
//! not, so a rule is compiled once **per language it targets**, each through
//! that language's front-end. `eval($X)` means different trees in Python and
//! JavaScript, and the compiled forms must not be shared.

use std::collections::BTreeMap;

use multiscan_core::{Confidence, Severity};

use crate::lang::{javascript, python, LowerError};
use crate::pattern::PatternExpr;
use crate::rules::{Language, RawPatternExpr, SastPack, SastRule};

/// A rule compiled and ready to match.
pub struct CompiledRule {
    /// Stable rule id — an identity input (§7.7.2).
    pub id: String,
    /// Finding message.
    pub message: String,
    /// Explicit severity (`ENG-004`).
    pub severity: Severity,
    /// Explicit confidence.
    pub confidence: Confidence,
    /// The compiled expression for each targeted language.
    ///
    /// `BTreeMap` so iteration order is fixed (`DET-001`).
    pub per_language: BTreeMap<Language, PatternExpr>,
}

/// Compile every rule in a pack.
///
/// Returns the compiled rules plus the rules that could not be compiled, keyed
/// by id. A rule whose pattern text does not parse is **rejected, not skipped
/// silently** — a shrinking corpus that reads as coverage is the failure mode
/// ADR 0014 decision 3 exists to prevent.
pub fn compile_pack(pack: &SastPack) -> (Vec<CompiledRule>, BTreeMap<String, String>) {
    let mut compiled = Vec::new();
    let mut rejected = pack.rejected.clone();

    for rule in &pack.rules {
        match compile_rule(rule) {
            Ok(c) => compiled.push(c),
            Err(reason) => {
                rejected.insert(rule.id.clone(), reason);
            }
        }
    }
    (compiled, rejected)
}

/// Compile one rule for every language it targets.
pub fn compile_rule(rule: &SastRule) -> Result<CompiledRule, String> {
    let mut per_language = BTreeMap::new();

    for language in &rule.languages {
        let expr =
            compile_expr(&rule.pattern, *language).map_err(|e| format!("{language:?}: {e}"))?;
        // Structural validity (ellipsis bounds, depth) is checked on the
        // compiled form, where a sequence is actually visible.
        expr.validate().map_err(|e| format!("{language:?}: {e}"))?;
        per_language.insert(*language, expr);
    }

    Ok(CompiledRule {
        id: rule.id.clone(),
        message: rule.message.clone(),
        severity: rule.severity,
        confidence: rule.confidence,
        per_language,
    })
}

fn compile_expr(raw: &RawPatternExpr, language: Language) -> Result<PatternExpr, LowerError> {
    Ok(match raw {
        RawPatternExpr::Pattern(text) => PatternExpr::Pattern(compile_leaf(text, language)?),
        RawPatternExpr::Patterns(list) => PatternExpr::All(
            list.iter()
                .map(|e| compile_expr(e, language))
                .collect::<Result<_, _>>()?,
        ),
        RawPatternExpr::PatternEither(list) => PatternExpr::Either(
            list.iter()
                .map(|e| compile_expr(e, language))
                .collect::<Result<_, _>>()?,
        ),
        RawPatternExpr::PatternNot(inner) => {
            PatternExpr::Not(Box::new(compile_expr(inner, language)?))
        }
        RawPatternExpr::PatternInside(inner) => {
            PatternExpr::Inside(Box::new(compile_expr(inner, language)?))
        }
        RawPatternExpr::PatternNotInside(inner) => {
            PatternExpr::NotInside(Box::new(compile_expr(inner, language)?))
        }
    })
}

fn compile_leaf(text: &str, language: Language) -> Result<crate::pattern::PatternNode, LowerError> {
    match language {
        Language::Python => python::compile_pattern(text),
        Language::Javascript => javascript::compile_pattern(text, false),
        Language::Typescript => javascript::compile_pattern(text, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::matches;
    use crate::rules::parse_pack;

    fn pack(rules: &str) -> SastPack {
        parse_pack(format!(r#"{{"pack_id":"t","version":"1.0.0","rules":[{rules}]}}"#).as_bytes())
            .unwrap()
    }

    #[test]
    fn compiles_one_rule_per_targeted_language() {
        let p = pack(
            r#"{
                "id": "eval",
                "message": "eval on user input",
                "languages": ["python", "javascript"],
                "severity": "high",
                "confidence": "heuristic",
                "pattern": "eval($X)"
            }"#,
        );
        let (compiled, rejected) = compile_pack(&p);
        assert!(rejected.is_empty());
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].per_language.len(), 2);

        // Each compiled form matches its own language's source.
        let py = python::lower_source("eval(x)\n").unwrap();
        let js = javascript::lower_source("eval(x);\n", false).unwrap();
        assert_eq!(
            matches(&compiled[0].per_language[&Language::Python], &py).len(),
            1
        );
        assert_eq!(
            matches(&compiled[0].per_language[&Language::Javascript], &js).len(),
            1
        );
    }

    #[test]
    fn unparseable_pattern_text_is_rejected_not_skipped() {
        let p = pack(
            r#"{
                "id": "broken",
                "message": "m",
                "languages": ["python"],
                "severity": "high",
                "confidence": "heuristic",
                "pattern": "def ((("
            }"#,
        );
        let (compiled, rejected) = compile_pack(&p);
        assert!(compiled.is_empty());
        assert!(rejected.contains_key("broken"));
    }

    #[test]
    fn load_time_rejections_are_carried_through() {
        // A rule rejected by parse_pack must still appear after compilation.
        let p = pack(
            r#"{
                "id": "nolang",
                "message": "m",
                "languages": [],
                "severity": "high",
                "confidence": "heuristic",
                "pattern": "eval($X)"
            }"#,
        );
        let (_, rejected) = compile_pack(&p);
        assert!(rejected.contains_key("nolang"));
    }

    #[test]
    fn nested_operators_compile() {
        let p = pack(
            r#"{
                "id": "guarded",
                "message": "unguarded eval",
                "languages": ["python"],
                "severity": "critical",
                "confidence": "proven",
                "patterns": [
                    {"pattern": "eval($X)"},
                    {"pattern-not-inside": {"pattern": "try:\n    ...\nexcept:\n    ..."}}
                ]
            }"#,
        );
        let (compiled, rejected) = compile_pack(&p);
        assert!(rejected.is_empty(), "rejected: {rejected:?}");
        assert_eq!(compiled.len(), 1);

        let expr = &compiled[0].per_language[&Language::Python];
        let bare = python::lower_source("eval(x)\n").unwrap();
        let guarded = python::lower_source("try:\n    eval(x)\nexcept:\n    pass\n").unwrap();

        assert_eq!(matches(expr, &bare).len(), 1);
        assert!(
            matches(expr, &guarded).is_empty(),
            "pattern-not-inside must exclude the guarded call"
        );
    }
}
