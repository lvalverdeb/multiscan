//! `cargo xtask translate-rules` — mechanically translate a community Semgrep
//! corpus into an `MS-PAT-1` rule pack (ADR 0014 decision 3).
//!
//! **This is dev tooling, never a shipped Engine capability.** MultiScan does
//! not author vulnerability knowledge (§1.2); it consumes a community corpus
//! and keeps only the part that fits the documented subset. Everything else is
//! dropped, counted, and recorded — a corpus that shrinks quietly would read as
//! coverage.
//!
//! ```text
//! cargo xtask translate-rules \
//!     --from path/to/semgrep-rules \
//!     --source https://github.com/example/rules \
//!     --license MIT \
//!     --out rules/sast.json
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Licences whose terms permit redistributing derived rule content through the
/// feed channel.
///
/// ADR 0014 decision 4 makes this a **blocking check in the translator**, not a
/// review-time convention. The Semgrep community registry's Commons Clause is
/// the known landmine: it restricts selling, which is why no `Commons-Clause`
/// variant appears here and cannot be added without its own review.
const REDISTRIBUTABLE: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "CC0-1.0",
    "Unlicense",
    "LGPL-2.1-or-later",
];

/// Languages the front-ends handle (ADR 0013). A rule targeting anything else
/// is out of scope, not a failure.
const IN_SCOPE: &[&str] = &["python", "py", "javascript", "js", "typescript", "ts"];

/// MS-PAT-1's operator set (`docs/ms-pat-1.md` §2). A rule using anything else
/// is dropped.
const IN_SUBSET: &[&str] = &[
    "pattern",
    "patterns",
    "pattern-either",
    "pattern-not",
    "pattern-inside",
    "pattern-not-inside",
];

/// Keys that mark a rule as definitively out of subset, for a precise reason.
fn out_of_subset_reason(key: &str) -> Option<&'static str> {
    match key {
        "mode" => Some("taint mode is forbidden permanently (NG-2)"),
        "pattern-sources" | "pattern-sinks" | "pattern-sanitizers" | "pattern-propagators" => {
            Some("taint operator is forbidden permanently (NG-2)")
        }
        "fix" | "fix-regex" => Some("autofix is out of subset"),
        "pattern-regex" | "pattern-not-regex" => Some("regex operators are out of subset"),
        "metavariable-pattern" | "metavariable-comparison" | "metavariable-regex" => {
            Some("metavariable operators are out of subset")
        }
        "join" => Some("join mode is out of subset"),
        _ => None,
    }
}

/// Explicit severity mapping. `ENG-004` forbids passthrough: an unrecognized
/// upstream severity is a dropped rule, never a guess.
fn map_severity(upstream: &str) -> Option<&'static str> {
    match upstream.to_ascii_uppercase().as_str() {
        "ERROR" => Some("high"),
        "WARNING" => Some("medium"),
        "INFO" => Some("low"),
        _ => None,
    }
}

/// Every translated rule is `heuristic`: a community pattern tuned for another
/// engine has not been validated under our matcher, and confidence is earned by
/// the FP gate, not inherited from upstream reputation.
const TRANSLATED_CONFIDENCE: &str = "heuristic";

pub fn run(
    from: PathBuf,
    source: String,
    license: String,
    out: PathBuf,
    now: String,
) -> Result<()> {
    if !REDISTRIBUTABLE.contains(&license.as_str()) {
        bail!(
            "licence `{license}` is not on the redistributable list, so this corpus cannot ship \
             through the feed channel (ADR 0014 decision 4).\n\
             Admissible: {}\n\
             This is a blocking check: widening it needs its own review, and the Semgrep registry's \
             Commons Clause restriction is exactly what it exists to catch.",
            REDISTRIBUTABLE.join(", ")
        );
    }

    let mut kept: Vec<serde_json::Value> = Vec::new();
    let mut dropped: BTreeMap<String, u64> = BTreeMap::new();
    let mut files = 0u64;

    let mut stack = vec![from.clone()];
    let mut yaml_paths = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("reading corpus dir {}", dir.display()))?
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yaml") | Some("yml")
            ) {
                yaml_paths.push(path);
            }
        }
    }
    // Sorted so a re-run over the same corpus produces a byte-identical pack
    // (DET-001/DET-002 apply to dev tooling that emits shipped data).
    yaml_paths.sort();

    for path in &yaml_paths {
        files += 1;
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let doc: serde_json::Value = match serde_yaml_ng::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                *dropped.entry("unparseable yaml".into()).or_default() += 1;
                continue;
            }
        };
        let Some(rules) = doc.get("rules").and_then(|r| r.as_array()) else {
            continue;
        };
        for rule in rules {
            match translate_rule(rule, &source, &license, &now) {
                Ok(v) => kept.push(v),
                Err(reason) => *dropped.entry(reason).or_default() += 1,
            }
        }
    }

    // Deterministic pack order, and a stable identity for the same corpus.
    kept.sort_by(|a, b| {
        a["id"]
            .as_str()
            .unwrap_or("")
            .cmp(b["id"].as_str().unwrap_or(""))
    });

    let dropped_total: u64 = dropped.values().sum();
    let pack = serde_json::json!({
        "pack_id": "community-translated",
        "version": now.clone(),
        "provenance": {
            "source": source,
            "license": license,
            "translated_at": now,
            "files_read": files,
            "rules_kept": kept.len(),
            // Visible in the manifest, per ADR 0014 decision 3: silent
            // truncation would read as coverage.
            "rules_dropped": dropped_total,
            "dropped_by_reason": dropped,
        },
        "rules": kept,
    });

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&out, serde_json::to_string_pretty(&pack)? + "\n")
        .with_context(|| format!("writing {}", out.display()))?;

    println!(
        "xtask translate-rules: {} kept, {} dropped from {} file(s) → {}",
        kept.len(),
        dropped_total,
        files,
        out.display()
    );
    for (reason, count) in &pack["provenance"]["dropped_by_reason"]
        .as_object()
        .cloned()
        .unwrap_or_default()
    {
        println!("  dropped {count}: {reason}");
    }
    if kept.is_empty() {
        bail!("no rules survived translation — the pack would be empty");
    }
    Ok(())
}

/// Translate one Semgrep rule, or explain why it was dropped.
fn translate_rule(
    rule: &serde_json::Value,
    source: &str,
    license: &str,
    now: &str,
) -> Result<serde_json::Value, String> {
    let obj = rule.as_object().ok_or("rule is not a mapping")?;

    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("rule has no id")?;
    let message = obj
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or("rule has no message")?;

    // Out-of-subset operators are checked first so the reason is precise
    // rather than a generic "no usable pattern".
    for key in obj.keys() {
        if let Some(reason) = out_of_subset_reason(key) {
            return Err(reason.to_string());
        }
    }

    let languages: Vec<String> = obj
        .get("languages")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|l| l.as_str())
                .map(|l| l.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    if languages.is_empty() {
        return Err("rule targets no language".into());
    }

    let mut out_languages: Vec<&str> = Vec::new();
    for lang in &languages {
        match lang.as_str() {
            "python" | "py" => out_languages.push("python"),
            "javascript" | "js" => out_languages.push("javascript"),
            "typescript" | "ts" => out_languages.push("typescript"),
            _ => {}
        }
    }
    out_languages.sort_unstable();
    out_languages.dedup();
    if out_languages.is_empty() {
        return Err(format!(
            "language out of scope (ADR 0013 covers {})",
            IN_SCOPE.join("/")
        ));
    }

    let severity = obj
        .get("severity")
        .and_then(|v| v.as_str())
        .ok_or("rule has no severity")?;
    let severity = map_severity(severity)
        .ok_or_else(|| format!("unmapped upstream severity `{severity}` (ENG-004)"))?;

    let pattern = translate_expr(rule)?;

    let mut translated = serde_json::Map::new();
    translated.insert("id".into(), id.into());
    translated.insert("message".into(), message.into());
    translated.insert("languages".into(), out_languages.into());
    translated.insert("severity".into(), severity.into());
    translated.insert("confidence".into(), TRANSLATED_CONFIDENCE.into());
    // Provenance rides on the rule as well as the pack, so a Finding can be
    // traced to its upstream source (ADR 0014 decision 3).
    translated.insert(
        "provenance".into(),
        serde_json::json!({
            "upstream_id": id,
            "source": source,
            "license": license,
            "translated_at": now,
        }),
    );

    if let serde_json::Value::Object(expr) = pattern {
        for (k, v) in expr {
            translated.insert(k, v);
        }
    }
    Ok(serde_json::Value::Object(translated))
}

/// Translate the pattern expression, recursively. Any operator outside
/// MS-PAT-1 drops the whole rule — a partially applied rule would silently
/// mean something other than what its author wrote.
fn translate_expr(node: &serde_json::Value) -> Result<serde_json::Value, String> {
    let obj = node.as_object().ok_or("pattern node is not a mapping")?;

    for key in obj.keys() {
        if let Some(reason) = out_of_subset_reason(key) {
            return Err(reason.to_string());
        }
    }

    // Exactly one operator per node, which is what the MS-PAT-1 enum accepts.
    let present: Vec<&String> = obj
        .keys()
        .filter(|k| IN_SUBSET.contains(&k.as_str()))
        .collect();
    let Some(op) = present.first() else {
        return Err("no MS-PAT-1 operator present".into());
    };
    if present.len() > 1 {
        return Err("multiple operators on one node".into());
    }
    let op = op.as_str();
    let value = &obj[op];

    let translated = match op {
        "pattern" => {
            let text = value.as_str().ok_or("pattern is not a string")?;
            serde_json::json!({ "pattern": text })
        }
        "patterns" | "pattern-either" => {
            let items = value.as_array().ok_or("operator takes a list")?;
            if items.is_empty() {
                return Err("operator has an empty operand list".into());
            }
            let translated: Result<Vec<_>, String> = items.iter().map(translate_expr).collect();
            serde_json::json!({ op: translated? })
        }
        "pattern-not" | "pattern-inside" | "pattern-not-inside" => {
            // Semgrep allows the shorthand `pattern-inside: <text>`; normalize
            // it into the nested form our loader expects.
            let inner = match value {
                serde_json::Value::String(text) => serde_json::json!({ "pattern": text }),
                other => translate_expr(other)?,
            };
            serde_json::json!({ op: inner })
        }
        _ => return Err(format!("`{op}` is not an MS-PAT-1 operator")),
    };
    Ok(translated)
}

/// Where a translated pack is written by default.
pub fn default_out() -> PathBuf {
    Path::new("rules").join("sast.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_never_passes_through() {
        assert_eq!(map_severity("ERROR"), Some("high"));
        assert_eq!(map_severity("warning"), Some("medium"));
        assert_eq!(map_severity("INFO"), Some("low"));
        // ENG-004: an unrecognized severity is a drop, never a guess.
        assert_eq!(map_severity("CRITICAL"), None);
        assert_eq!(map_severity(""), None);
    }

    #[test]
    fn taint_operators_are_rejected_by_name() {
        for key in [
            "mode",
            "pattern-sources",
            "pattern-sinks",
            "pattern-sanitizers",
        ] {
            assert!(
                out_of_subset_reason(key).unwrap().contains("NG-2"),
                "{key} must cite NG-2"
            );
        }
    }

    #[test]
    fn a_simple_rule_translates() {
        let rule = serde_json::json!({
            "id": "python.lang.eval",
            "message": "eval on user input",
            "languages": ["python"],
            "severity": "ERROR",
            "pattern": "eval($X)",
        });
        let out = translate_rule(&rule, "src", "MIT", "2026-08-08").unwrap();
        assert_eq!(out["id"], "python.lang.eval");
        assert_eq!(out["severity"], "high");
        assert_eq!(out["confidence"], "heuristic");
        assert_eq!(out["pattern"], "eval($X)");
        assert_eq!(out["languages"], serde_json::json!(["python"]));
        assert_eq!(out["provenance"]["license"], "MIT");
        assert_eq!(out["provenance"]["upstream_id"], "python.lang.eval");
    }

    #[test]
    fn language_aliases_normalize_and_dedup() {
        let rule = serde_json::json!({
            "id": "r", "message": "m", "severity": "INFO",
            "languages": ["js", "javascript", "ts", "go"],
            "pattern": "eval($X)",
        });
        let out = translate_rule(&rule, "s", "MIT", "t").unwrap();
        assert_eq!(
            out["languages"],
            serde_json::json!(["javascript", "typescript"]),
            "aliases collapse and out-of-scope languages are simply absent"
        );
    }

    #[test]
    fn an_entirely_out_of_scope_language_drops_the_rule() {
        let rule = serde_json::json!({
            "id": "r", "message": "m", "severity": "ERROR",
            "languages": ["go"], "pattern": "eval($X)",
        });
        let err = translate_rule(&rule, "s", "MIT", "t").unwrap_err();
        assert!(err.contains("out of scope"));
    }

    #[test]
    fn taint_rules_drop_with_the_ng2_reason() {
        let rule = serde_json::json!({
            "id": "r", "message": "m", "severity": "ERROR", "languages": ["python"],
            "mode": "taint",
            "pattern-sources": [{"pattern": "input()"}],
            "pattern-sinks": [{"pattern": "eval($X)"}],
        });
        let err = translate_rule(&rule, "s", "MIT", "t").unwrap_err();
        assert!(err.contains("NG-2"), "got: {err}");
    }

    #[test]
    fn nested_operators_translate_and_shorthand_normalizes() {
        let rule = serde_json::json!({
            "id": "r", "message": "m", "severity": "ERROR", "languages": ["python"],
            "patterns": [
                {"pattern": "eval($X)"},
                {"pattern-not-inside": "try: ..."}
            ],
        });
        let out = translate_rule(&rule, "s", "MIT", "t").unwrap();
        let patterns = out["patterns"].as_array().unwrap();
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0]["pattern"], "eval($X)");
        // The string shorthand became the nested form our loader expects.
        assert_eq!(patterns[1]["pattern-not-inside"]["pattern"], "try: ...");
    }

    #[test]
    fn an_out_of_subset_operator_nested_deep_drops_the_whole_rule() {
        // A partially applied rule would silently mean something other than
        // what its author wrote.
        let rule = serde_json::json!({
            "id": "r", "message": "m", "severity": "ERROR", "languages": ["python"],
            "patterns": [
                {"pattern": "eval($X)"},
                {"metavariable-regex": {"metavariable": "$X"}}
            ],
        });
        assert!(translate_rule(&rule, "s", "MIT", "t").is_err());
    }

    #[test]
    fn a_non_redistributable_licence_is_a_blocking_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = run(
            dir.path().to_path_buf(),
            "src".into(),
            "Commons-Clause".into(),
            dir.path().join("out.json"),
            "2026-08-08".into(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not on the redistributable list"));
        assert!(msg.contains("Commons Clause"), "names the known landmine");
    }

    #[test]
    fn translation_is_deterministic_and_records_drops() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rules.yaml"),
            r#"
rules:
  - id: b.rule
    message: second
    languages: [python]
    severity: ERROR
    pattern: eval($X)
  - id: a.rule
    message: first
    languages: [python]
    severity: WARNING
    pattern: exec($X)
  - id: c.taint
    message: taint
    languages: [python]
    severity: ERROR
    mode: taint
    pattern-sinks:
      - pattern: eval($X)
  - id: d.golang
    message: other language
    languages: [go]
    severity: ERROR
    pattern: eval($X)
"#,
        )
        .unwrap();

        let out = dir.path().join("pack.json");
        run(
            dir.path().to_path_buf(),
            "https://example.test/rules".into(),
            "MIT".into(),
            out.clone(),
            "2026-08-08".into(),
        )
        .unwrap();

        let pack: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let rules = pack["rules"].as_array().unwrap();

        assert_eq!(rules.len(), 2, "two in-subset, in-scope rules survive");
        // Sorted by id, so the same corpus yields a byte-identical pack.
        assert_eq!(rules[0]["id"], "a.rule");
        assert_eq!(rules[1]["id"], "b.rule");
        assert_eq!(rules[0]["severity"], "medium");

        // Drops are visible, per-reason — never a silent shrink.
        assert_eq!(pack["provenance"]["rules_dropped"], 2);
        let reasons = pack["provenance"]["dropped_by_reason"].as_object().unwrap();
        assert!(reasons.keys().any(|k| k.contains("NG-2")));
        assert!(reasons.keys().any(|k| k.contains("out of scope")));
    }

    #[test]
    fn an_empty_result_is_an_error_not_an_empty_pack() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("r.yaml"),
            "rules:\n  - id: x\n    message: m\n    languages: [go]\n    severity: ERROR\n    pattern: f()\n",
        )
        .unwrap();
        assert!(run(
            dir.path().to_path_buf(),
            "s".into(),
            "MIT".into(),
            dir.path().join("out.json"),
            "t".into(),
        )
        .is_err());
    }
}

/// The seam: a pack this translator emits must load in the real engine.
/// Testing the two halves separately would leave exactly the gap where a
/// format drift hides.
#[cfg(test)]
mod round_trip {
    use super::*;

    #[test]
    fn a_translated_pack_loads_and_compiles_in_the_engine() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rules.yaml"),
            r#"
rules:
  - id: py.eval
    message: eval on user input
    languages: [python, javascript]
    severity: ERROR
    pattern: eval($X)
  - id: py.guarded
    message: unguarded exec
    languages: [python]
    severity: WARNING
    patterns:
      - pattern: exec($X)
      - pattern-not-inside: "def safe_wrapper(): ..."
"#,
        )
        .unwrap();

        let out = dir.path().join("pack.json");
        run(
            dir.path().to_path_buf(),
            "https://example.test/rules".into(),
            "MIT".into(),
            out.clone(),
            "2026-08-08".into(),
        )
        .unwrap();

        let bytes = std::fs::read(&out).unwrap();

        // Loads under the engine's own parser, with nothing rejected.
        let pack = multiscan_sast::rules::parse_pack(&bytes)
            .expect("translated pack must parse in the engine");
        assert!(
            pack.rejected.is_empty(),
            "translated rules must not be rejected at load: {:?}",
            pack.rejected
        );
        assert_eq!(pack.rules.len(), 2);

        // …and compiles: leaf pattern text goes through the real front-ends.
        let (compiled, rejected) = multiscan_sast::compile::compile_pack(&pack);
        assert!(rejected.is_empty(), "compile rejected: {rejected:?}");
        assert_eq!(compiled.len(), 2);

        // The multi-language rule really did compile once per language.
        let eval = compiled.iter().find(|r| r.id == "py.eval").unwrap();
        assert_eq!(eval.per_language.len(), 2);

        // And it matches real source end to end.
        let tree = multiscan_sast::lang::python::lower_source("eval(user_input)\n").unwrap();
        let expr = &eval.per_language[&multiscan_sast::rules::Language::Python];
        assert_eq!(multiscan_sast::matcher::matches(expr, &tree).len(), 1);
    }
}
