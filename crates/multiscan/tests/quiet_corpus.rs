//! SDD §13.3 FP-006: the "quiet corpus". Realistic benign inputs that
//! historically tripped the secrets heuristics — lockfile checksums, IDE
//! state, hex digests, UUIDs, content-address URLs, minified bundles, and
//! secret-named config placeholders — MUST produce zero findings. A change
//! that makes any of them fire is a build failure, guarding the exact
//! regression that once produced 1,586 false positives.
//!
//! This is the false-positive counterpart to the golden true-positive corpus;
//! add a fixture here for every new benign shape a heuristic detector learns
//! to ignore.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

fn quiet_dir() -> PathBuf {
    // repo-root/testdata/corpus/quiet, from crates/multiscan.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/corpus/quiet")
        .canonicalize()
        .expect("quiet corpus directory exists")
}

/// The whole quiet corpus scans clean on the secrets layer.
#[test]
fn quiet_corpus_produces_no_secrets_findings() {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .args([
            "scan",
            quiet_dir().join("secrets").to_str().unwrap(),
            "--layers",
            "secrets",
            "--offline",
            "--no-store",
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");

    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().expect("json array");
    if !arr.is_empty() {
        let detail: Vec<String> = arr
            .iter()
            .map(|f| {
                format!(
                    "{} @ {}",
                    f["identity"]["rule_id"].as_str().unwrap_or("?"),
                    f["location"]["path"].as_str().unwrap_or("?")
                )
            })
            .collect();
        panic!(
            "quiet corpus fired {} finding(s) — a false-positive regression (FP-006):\n  {}",
            arr.len(),
            detail.join("\n  ")
        );
    }
}

/// FP-006 for the SAST layer (`T-704`).
///
/// The fixtures in `quiet/sast/` are the near-misses a **textual** matcher gets
/// wrong: `eval` inside a string, inside a comment, as part of a longer
/// identifier, as a method name, and as a member call. A structural matcher
/// must fire on none of them — which is the whole claim of `SAST-002`, tested
/// against real files rather than hand-built trees.
///
/// The test carries its own **positive control**. Without one, a pack that
/// silently failed to load would produce zero findings and pass, and the gate
/// would be quietly measuring nothing.
#[test]
fn quiet_corpus_produces_no_sast_findings() {
    let cache = tempfile::tempdir().unwrap();
    seed_sast_pack(cache.path());

    // Control: the same pack, same binary, against a file that genuinely calls
    // eval. If this does not fire, the gate below is vacuous.
    let control = tempfile::tempdir().unwrap();
    std::fs::write(control.path().join("real.py"), "eval(user_input)\n").unwrap();
    let fired = sast_scan(cache.path(), control.path());
    assert_eq!(
        fired.len(),
        1,
        "positive control must fire, or the quiet gate proves nothing"
    );

    // The gate itself.
    let arr = sast_scan(cache.path(), &quiet_dir());
    if !arr.is_empty() {
        let detail: Vec<String> = arr
            .iter()
            .map(|f| {
                format!(
                    "{} @ {}:{}",
                    f["identity"]["rule_id"].as_str().unwrap_or("?"),
                    f["location"]["path"].as_str().unwrap_or("?"),
                    f["location"]["line"].as_i64().unwrap_or(-1),
                )
            })
            .collect();
        panic!(
            "sast quiet corpus fired {} finding(s) — a structural matcher must \
             not be fooled by text (FP-006, SAST-002):\n  {}",
            arr.len(),
            detail.join("\n  ")
        );
    }
}

/// Seed a one-rule fixture pack (not a corpus) matching a bare `eval($X)`.
fn seed_sast_pack(cache: &std::path::Path) {
    use std::collections::BTreeMap;
    let pack = br#"{
      "pack_id": "quiet-fixture",
      "version": "1.0.0",
      "rules": [{
        "id": "fp.eval",
        "message": "eval on non-literal input",
        "languages": ["python", "javascript", "typescript"],
        "severity": "high",
        "confidence": "heuristic",
        "pattern": "eval($X)"
      }]
    }"#
    .to_vec();
    let mut rule_packs = BTreeMap::new();
    rule_packs.insert("sast".to_string(), pack);
    multiscan_feeds::write_snapshot(
        cache,
        &multiscan_feeds::SnapshotData {
            kev_json: br#"{"vulnerabilities":[]}"#.to_vec(),
            epss_csv: b"cve,epss,percentile\n".to_vec(),
            osv_jsonl: BTreeMap::new(),
            rule_packs,
            counts: multiscan_feeds::SnapshotCounts {
                kev: 0,
                epss: 0,
                osv: BTreeMap::new(),
            },
            sources: BTreeMap::new(),
        },
        chrono::Utc::now(),
    )
    .unwrap();
}

fn sast_scan(cache: &std::path::Path, target: &std::path::Path) -> Vec<serde_json::Value> {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .args([
            "scan",
            target.to_str().unwrap(),
            "--layers",
            "sast",
            "--no-store",
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");
    serde_json::from_slice::<serde_json::Value>(&out.stdout)
        .unwrap_or(serde_json::Value::Null)
        .as_array()
        .cloned()
        .unwrap_or_default()
}
