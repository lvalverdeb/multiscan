//! T-202 acceptance at the CLI boundary: FR-002 (resolve a known-vulnerable
//! lockfile against a pinned snapshot, offline, with fixed_version populated)
//! and FR-003 (ecosystem-correct version matching — no naive-string false
//! positives). All hermetic: a snapshot is seeded into an isolated cache; no
//! network, no real host.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use chrono::Utc;
use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};

/// One OSV advisory: npm lodash < 4.17.21 (a real-shaped GHSA record).
const LODASH_ADVISORY: &str = r#"{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command injection in lodash","aliases":["CVE-2021-23337"],"database_specific":{"severity":"HIGH","cwe_ids":["CWE-77"]},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;

fn seed_snapshot(cache: &Path) -> String {
    let mut osv = BTreeMap::new();
    osv.insert(
        "npm".to_string(),
        format!("{LODASH_ADVISORY}\n").into_bytes(),
    );
    let mut osv_counts = BTreeMap::new();
    osv_counts.insert("npm".to_string(), 1u64);
    let data = SnapshotData {
        kev_json: br#"{"vulnerabilities":[{"cveID":"CVE-2021-23337"}]}"#.to_vec(),
        epss_csv: b"cve,epss,percentile\nCVE-2021-23337,0.6,0.97\n".to_vec(),
        osv_jsonl: osv,
        counts: SnapshotCounts {
            kev: 1,
            epss: 1,
            osv: osv_counts,
        },
        sources: BTreeMap::new(),
    };
    write_snapshot(cache, &data, Utc::now())
        .unwrap()
        .manifest
        .snapshot_id
}

fn write_package_lock(dir: &Path, version: &str) {
    let content = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{"name":"app"}},"node_modules/lodash":{{"version":"{version}"}}}}}}"#
    );
    std::fs::write(dir.join("package-lock.json"), content).unwrap();
}

fn scan_json(cache: &Path, project: &Path, extra: &[&str]) -> (Output, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(project)
        .args(["scan", ".", "--layers", "sca", "--format", "json"])
        .args(extra)
        .output()
        .expect("binary runs");
    let value = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    (out, value)
}

/// FR-002: a vulnerable version resolves to the advisory with fixed_version.
#[test]
fn vulnerable_lockfile_resolves_offline() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_package_lock(project.path(), "4.17.20");

    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    let findings = findings.as_array().unwrap();
    assert_eq!(findings.len(), 1, "expected one advisory match");
    let f = &findings[0];
    assert_eq!(f["identity"]["advisory_id"], "GHSA-35jh-r3h4-6jhm");
    assert_eq!(f["remediation"]["fixed_version"], "4.17.21");
    assert_eq!(f["remediation"]["fix_available"], true);
    assert_eq!(f["severity"], "high");
    // Enrichment: CVE is in KEV → factor X = 1.00 recorded in the explanation.
    assert!(
        (f["score_explanation"]["factors"]["exploitability"]
            .as_f64()
            .unwrap()
            - 1.0)
            .abs()
            < 1e-9
    );
}

/// FR-003: 4.17.21 is patched — a naive string compare ("4.17.21" vs "4.17.9")
/// would misjudge neighbours, but the fixed version must produce no finding.
#[test]
fn patched_version_produces_no_finding() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_package_lock(project.path(), "4.17.21");

    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(findings.as_array().unwrap().is_empty());
}

/// FR-003 again: 4.17.9 < 4.17.21 as versions (a string compare says the
/// opposite), so it MUST still be flagged.
#[test]
fn double_digit_patch_below_fix_is_flagged() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_package_lock(project.path(), "4.17.9");

    let (_out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(findings.as_array().unwrap().len(), 1);
}

/// SCA runs offline against the pinned snapshot with no network (the offline
/// harness proves no syscall; here we assert exit 0 and a real result).
#[test]
fn sca_offline_exit_zero_with_snapshot() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_package_lock(project.path(), "4.17.20");
    // High severity + KEV enrichment scores ~44.6; a threshold below it fires
    // the gate (exit 1), proving both resolution and enrichment ran.
    let (out, _f) = scan_json(
        cache.path(),
        project.path(),
        &["--offline", "--fail-on", "40"],
    );
    assert_eq!(out.status.code(), Some(1));
    // And a threshold above it does not.
    let (clean, _f) = scan_json(
        cache.path(),
        project.path(),
        &["--offline", "--fail-on", "90"],
    );
    assert_eq!(clean.status.code(), Some(0));
}

/// A directory with no lockfile → SCA not applicable → clean empty scan.
#[test]
fn no_lockfile_no_findings() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("README.md"), "hi").unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(findings.as_array().unwrap().is_empty());
}
