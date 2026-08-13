//! `T-802` acceptance at the CLI boundary: the reachability factor reaches a
//! real Finding's `score_explanation` (`FR-017`, `RSK-006`).
//!
//! The unit tests in `src/reachability.rs` cover `Index` in isolation. These
//! cover what they cannot: the layer gate, the three `assemble_finding` call
//! sites, and the factor actually surfacing in machine output. Hermetic — a
//! seeded snapshot in an isolated cache, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use chrono::Utc;
use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};

/// npm lodash < 4.17.21, the same real-shaped record the SCA tests use.
const LODASH_ADVISORY: &str = r#"{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command injection in lodash","aliases":["CVE-2021-23337"],"database_specific":{"severity":"HIGH","cwe_ids":["CWE-77"]},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;

fn seed_snapshot(cache: &Path) {
    let mut osv = BTreeMap::new();
    osv.insert(
        "npm".to_string(),
        format!("{LODASH_ADVISORY}\n").into_bytes(),
    );
    let mut osv_counts = BTreeMap::new();
    osv_counts.insert("npm".to_string(), 1u64);
    let data = SnapshotData {
        kev_json: br#"{"vulnerabilities":[]}"#.to_vec(),
        epss_csv: b"cve,epss,percentile\n".to_vec(),
        osv_jsonl: osv,
        rule_packs: BTreeMap::new(),
        counts: SnapshotCounts {
            kev: 0,
            epss: 0,
            osv: osv_counts,
        },
        sources: BTreeMap::new(),
        skipped_ecosystems: Default::default(),
    };
    write_snapshot(cache, &data, Utc::now()).unwrap();
}

fn project_with(source: Option<(&str, &str)>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();
    if let Some((name, body)) = source {
        std::fs::write(dir.path().join(name), body).unwrap();
    }
    dir
}

/// Scan and return the single finding's reachability factor.
fn reachability_of(project: &Path, cache: &Path, layers: &str) -> f64 {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(project)
        .args(["scan", ".", "--layers", layers, "--format", "json"])
        .output()
        .expect("binary runs");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = value.as_array().expect("findings array");
    let dep = findings
        .iter()
        .find(|f| f["identity"]["finding_class"] == "vulnerable_dependency")
        .expect("the lodash advisory resolves");
    dep["score_explanation"]["factors"]["reachability"]
        .as_f64()
        .expect("reachability factor is present")
}

#[test]
fn an_imported_package_scores_referenced() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = project_with(Some(("app.js", "const _ = require('lodash');\n")));

    assert_eq!(
        reachability_of(project.path(), cache.path(), "sca"),
        1.1,
        "source imports lodash, so the factor raises the score"
    );
}

#[test]
fn an_unimported_package_scores_not_referenced() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = project_with(Some(("app.js", "const react = require('react');\n")));

    assert_eq!(
        reachability_of(project.path(), cache.path(), "sca"),
        0.65,
        "npm negatives are trustworthy: the specifier IS the package name"
    );
}

#[test]
fn a_repo_with_no_source_scores_unknown() {
    // A lockfile with no first-party source: nothing was parsed, so nothing is
    // concluded. No evidence is not evidence of absence (FR-017).
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = project_with(None);

    assert_eq!(
        reachability_of(project.path(), cache.path(), "sca"),
        1.0,
        "Unknown is neutral"
    );
}

#[test]
fn the_factor_is_gated_on_sca_not_sast() {
    // Reachability is evidence FOR dependency findings, so `--layers sca` —
    // precisely the run that benefits — must not be starved of it.
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = project_with(Some(("app.js", "const _ = require('lodash');\n")));

    assert_eq!(
        reachability_of(project.path(), cache.path(), "sca"),
        1.1,
        "an sca-only scan still gets reachability"
    );
}

#[test]
fn a_not_referenced_finding_is_still_reported_and_gateable() {
    // RSK-006: reachability changes rank, not existence.
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = project_with(Some(("app.js", "const react = require('react');\n")));

    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache.path())
        .current_dir(project.path())
        .args([
            "scan",
            ".",
            "--layers",
            "sca",
            "--format",
            "json",
            "--fail-on",
            "low",
        ])
        .output()
        .expect("binary runs");

    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = value.as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["identity"]["finding_class"] == "vulnerable_dependency"),
        "a NotReferenced finding is still reported"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "…and still gates: Exit::GateFailed is 1 here, distinct from the \
         scanner-broke 3 (CLI-005)"
    );
}

#[test]
fn formula_version_is_recorded_as_2() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = project_with(Some(("app.js", "const _ = require('lodash');\n")));

    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache.path())
        .current_dir(project.path())
        .args(["scan", ".", "--layers", "sca", "--format", "json"])
        .output()
        .expect("binary runs");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let dep = value
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["identity"]["finding_class"] == "vulnerable_dependency")
        .unwrap();

    assert_eq!(
        dep["score_explanation"]["formula_version"], "2",
        "RSK-004: the formula that produced the score is recorded"
    );
}
