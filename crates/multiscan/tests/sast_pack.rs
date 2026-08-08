//! `T-705` (plumbing half): a SAST rule pack delivered over the feed channel
//! produces Findings, and a refresh changes detections with no rebuild — the
//! phase-2 exit criterion for workstream A.
//!
//! The pack here is a **test fixture**, not a shipped corpus. §1.2 forbids
//! authoring vulnerability knowledge, so the real corpus must be mechanically
//! translated from a community source (ADR 0014) — that half stays gated on a
//! licence audit. This proves the channel works once one exists.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use chrono::Utc;
use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};

/// A pack whose single rule flags `eval($X)` in Python and JS.
fn pack_json(version: &str, rule_id: &str, pattern: &str) -> Vec<u8> {
    format!(
        r#"{{
          "pack_id": "test-fixture",
          "version": "{version}",
          "rules": [{{
            "id": "{rule_id}",
            "message": "eval on non-literal input",
            "languages": ["python", "javascript"],
            "severity": "high",
            "confidence": "heuristic",
            "pattern": "{pattern}"
          }}]
        }}"#
    )
    .into_bytes()
}

fn seed(cache: &Path, pack: Option<Vec<u8>>) {
    let mut rule_packs = BTreeMap::new();
    if let Some(bytes) = pack {
        rule_packs.insert("sast".to_string(), bytes);
    }
    let data = SnapshotData {
        kev_json: br#"{"vulnerabilities":[]}"#.to_vec(),
        epss_csv: b"cve,epss,percentile\n".to_vec(),
        osv_jsonl: BTreeMap::new(),
        rule_packs,
        counts: SnapshotCounts {
            kev: 0,
            epss: 0,
            osv: BTreeMap::new(),
        },
        sources: BTreeMap::new(),
    };
    write_snapshot(cache, &data, Utc::now()).unwrap();
}

fn project(source: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.py"), source).unwrap();
    dir
}

fn scan(cache: &Path, dir: &Path, extra: &[&str]) -> (std::process::Output, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(dir)
        .args(["scan", ".", "--layers", "sast", "--format", "json"])
        .args(extra)
        .output()
        .expect("binary runs");
    let value = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    (out, value)
}

fn structural_findings(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|f| f["identity"]["finding_class"] == "structural_pattern")
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_feed_delivered_pack_produces_findings() {
    let cache = tempfile::tempdir().unwrap();
    seed(
        cache.path(),
        Some(pack_json("1.0.0", "py.eval", "eval($X)")),
    );
    let dir = project("eval(user_input)\n");

    let (_, value) = scan(cache.path(), dir.path(), &[]);
    let findings = structural_findings(&value);

    assert_eq!(findings.len(), 1, "the pack's rule matched");
    assert_eq!(findings[0]["identity"]["rule_id"], "py.eval");
    assert_eq!(findings[0]["severity"], "high");
    assert_eq!(findings[0]["location"]["path"], "app.py");
}

#[test]
fn a_pack_refresh_changes_detections_with_no_rebuild() {
    // The phase-2 exit criterion: detection content is data, not code.
    let dir = project("exec(user_input)\n");

    let cache_a = tempfile::tempdir().unwrap();
    seed(
        cache_a.path(),
        Some(pack_json("1.0.0", "py.eval", "eval($X)")),
    );
    let (_, before) = scan(cache_a.path(), dir.path(), &[]);
    assert!(
        structural_findings(&before).is_empty(),
        "the v1 pack does not know about exec"
    );

    // Same binary, same source — only the pack changed.
    let cache_b = tempfile::tempdir().unwrap();
    seed(
        cache_b.path(),
        Some(pack_json("2.0.0", "py.exec", "exec($X)")),
    );
    let (_, after) = scan(cache_b.path(), dir.path(), &[]);
    let findings = structural_findings(&after);

    assert_eq!(findings.len(), 1, "the refreshed pack detects it");
    assert_eq!(findings[0]["identity"]["rule_id"], "py.exec");
}

#[test]
fn no_pack_means_an_inert_engine() {
    // §1.2: there is no embedded fallback corpus. No pack, no rules, and
    // critically no Complete-over-zero-rules that could close findings.
    let cache = tempfile::tempdir().unwrap();
    seed(cache.path(), None);
    let dir = project("eval(user_input)\n");

    let (out, value) = scan(cache.path(), dir.path(), &[]);
    assert!(structural_findings(&value).is_empty());
    assert_eq!(out.status.code(), Some(0), "an inert layer is not an error");
}

#[test]
fn a_pin_that_matches_nothing_leaves_the_layer_inactive() {
    // Better to scan with no corpus than silently with the wrong one.
    let cache = tempfile::tempdir().unwrap();
    seed(
        cache.path(),
        Some(pack_json("1.0.0", "py.eval", "eval($X)")),
    );
    let dir = project("eval(user_input)\n");
    std::fs::write(
        dir.path().join("multiscan.toml"),
        "[rules]\nsast_pack = \"test-fixture@9.9.9\"\n",
    )
    .unwrap();

    let (out, value) = scan(cache.path(), dir.path(), &[]);
    assert!(structural_findings(&value).is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no sast pack matches pin"),
        "the unhonored pin is reported, not silent"
    );
}

#[test]
fn a_matching_pin_activates_the_pack() {
    let cache = tempfile::tempdir().unwrap();
    seed(
        cache.path(),
        Some(pack_json("1.0.0", "py.eval", "eval($X)")),
    );
    let dir = project("eval(user_input)\n");
    std::fs::write(
        dir.path().join("multiscan.toml"),
        "[rules]\nsast_pack = \"test-fixture@1.0.0\"\n",
    )
    .unwrap();

    let (_, value) = scan(cache.path(), dir.path(), &[]);
    assert_eq!(structural_findings(&value).len(), 1);
}

#[test]
fn rejected_rules_are_reported_not_swallowed() {
    // A shrinking corpus that reads as coverage is the failure ADR 0014
    // decision 3 exists to prevent.
    let cache = tempfile::tempdir().unwrap();
    let pack = br#"{
      "pack_id": "test-fixture",
      "version": "1.0.0",
      "rules": [
        {"id":"good","message":"m","languages":["python"],"severity":"high",
         "confidence":"heuristic","pattern":"eval($X)"},
        {"id":"broken","message":"m","languages":["python"],"severity":"high",
         "confidence":"heuristic","pattern":"def ((("}
      ]
    }"#
    .to_vec();
    seed(cache.path(), Some(pack));
    let dir = project("eval(user_input)\n");

    let (out, value) = scan(cache.path(), dir.path(), &["--verbose"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        structural_findings(&value).len(),
        1,
        "the good rule still runs"
    );
    assert!(stderr.contains("1 rule(s) rejected"), "count is surfaced");
    assert!(stderr.contains("rejected broken"), "--verbose names it");
}

#[test]
fn findings_are_deterministic_across_runs() {
    // DET-002 through the whole pipeline, with a real pack.
    let cache = tempfile::tempdir().unwrap();
    seed(
        cache.path(),
        Some(pack_json("1.0.0", "py.eval", "eval($X)")),
    );
    let dir = project("eval(a)\nprint(1)\neval(b)\n");

    let (_, first) = scan(cache.path(), dir.path(), &[]);
    let ids: Vec<_> = structural_findings(&first)
        .iter()
        .map(|f| f["finding_id"].clone())
        .collect();
    assert_eq!(ids.len(), 2);

    for _ in 0..3 {
        let (_, again) = scan(cache.path(), dir.path(), &[]);
        let repeat: Vec<_> = structural_findings(&again)
            .iter()
            .map(|f| f["finding_id"].clone())
            .collect();
        assert_eq!(
            ids, repeat,
            "same inputs, same finding_ids in the same order"
        );
    }
}

/// Q-12 / ADR 0018 at the CLI boundary: a repo containing the pathological
/// TypeScript file must still finish.
///
/// Before the parse bound this scan did not terminate — a 203-byte file
/// committed to a repository hung any scan of it.
#[test]
fn a_repo_containing_the_pathological_file_still_terminates() {
    let cache = tempfile::tempdir().unwrap();
    seed(
        cache.path(),
        Some(pack_json("1.0.0", "py.eval", "eval($X)")),
    );

    let dir = tempfile::tempdir().unwrap();
    let reproducer = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/corpus/sast-pathological/ts-backtrack-4-unbounded.ts");
    std::fs::copy(&reproducer, dir.path().join("evil.ts")).unwrap();
    // A healthy file alongside it, so we can prove the scan kept working.
    std::fs::write(dir.path().join("app.py"), "eval(user_input)\n").unwrap();

    let start = std::time::Instant::now();
    let (out, value) = scan(cache.path(), dir.path(), &[]);
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "scan took {elapsed:?} — the parse bound did not hold end to end"
    );

    // The healthy file was still scanned and still reported.
    let findings = structural_findings(&value);
    assert_eq!(findings.len(), 1, "the Python file must still be scanned");
    assert_eq!(findings[0]["location"]["path"], "app.py");

    // And the scan says so: a file it could not read degrades the outcome,
    // so nothing gets closed on the strength of an incomplete run (§7.7.4).
    assert_eq!(
        out.status.code(),
        Some(3),
        "an abandoned parse must degrade the scan, not pass silently"
    );
}
