//! T-201 acceptance at the CLI boundary: db status/path, and the scan-side
//! staleness matrix (FD-002..004, FD-007). A snapshot is seeded directly into
//! an isolated cache via MULTISCAN_CACHE_DIR — no network, no real host.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use chrono::{Duration, Utc};
use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};

fn seed_snapshot(cache: &Path, age: Duration) -> String {
    let data = SnapshotData {
        kev_json: br#"{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}"#.to_vec(),
        epss_csv: b"cve,epss,percentile\nCVE-2021-44228,0.9,0.99\n".to_vec(),
        osv_jsonl: BTreeMap::new(),
        counts: SnapshotCounts {
            kev: 1,
            epss: 1,
            osv: BTreeMap::new(),
        },
        sources: BTreeMap::new(),
    };
    let snapshot = write_snapshot(cache, &data, Utc::now() - age).unwrap();
    snapshot.manifest.snapshot_id
}

fn scan(cache: &Path, scan_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(scan_dir)
        .arg("scan")
        .arg(".")
        .args(args)
        .output()
        .expect("binary runs")
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

#[test]
fn db_path_and_status_reflect_cache() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path(), Duration::hours(1));

    let path_out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache.path())
        .args(["db", "path"])
        .output()
        .unwrap();
    assert_eq!(code(&path_out), 0);
    assert_eq!(
        String::from_utf8_lossy(&path_out.stdout).trim(),
        cache.path().to_string_lossy()
    );

    let status_out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache.path())
        .args(["db", "status"])
        .output()
        .unwrap();
    assert_eq!(code(&status_out), 0);
    let stdout = String::from_utf8_lossy(&status_out.stdout);
    assert!(stdout.contains("kev        1 entries"));
    // A-3: OSV attribution appears in status.
    assert!(stdout.contains("OSV"));
}

/// A fresh snapshot pins silently; the scan proceeds clean.
#[test]
fn fresh_snapshot_no_warning() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path(), Duration::hours(1));
    let scan_dir = tempfile::tempdir().unwrap();
    let out = scan(cache.path(), scan_dir.path(), &["--layers", "sca"]);
    assert_eq!(code(&out), 0);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("stale") && !stderr.contains("old"));
}

/// FD-004: stale online → warning, exit still 0.
#[test]
fn stale_snapshot_online_warns_but_succeeds() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path(), Duration::days(30));
    let scan_dir = tempfile::tempdir().unwrap();
    let out = scan(cache.path(), scan_dir.path(), &["--layers", "sca"]);
    assert_eq!(code(&out), 0);
    assert!(String::from_utf8_lossy(&out.stderr).contains("old"));
}

/// FD-004: stale under --offline → exit 5.
#[test]
fn stale_snapshot_offline_exits_five() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path(), Duration::days(30));
    let scan_dir = tempfile::tempdir().unwrap();
    let out = scan(
        cache.path(),
        scan_dir.path(),
        &["--layers", "sca", "--offline"],
    );
    assert_eq!(code(&out), 5);
}

/// A generous --max-feed-age rescues an otherwise-stale snapshot under offline.
#[test]
fn max_feed_age_override_allows_old_snapshot() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path(), Duration::days(30));
    let scan_dir = tempfile::tempdir().unwrap();
    let out = scan(
        cache.path(),
        scan_dir.path(),
        &["--layers", "sca", "--offline", "--max-feed-age", "60d"],
    );
    assert_eq!(code(&out), 0);
}

/// FD-007: secrets and iac work with zero prior network access — no snapshot,
/// offline, exit 0.
#[test]
fn offline_secrets_without_snapshot_succeeds() {
    let cache = tempfile::tempdir().unwrap();
    let scan_dir = tempfile::tempdir().unwrap();
    let out = scan(
        cache.path(),
        scan_dir.path(),
        &["--layers", "secrets", "--offline"],
    );
    assert_eq!(code(&out), 0);
}

/// FD-003/FD-007: offline + explicit sca + no snapshot → exit 5, and no
/// network was needed to decide that.
#[test]
fn offline_sca_without_snapshot_exits_five() {
    let cache = tempfile::tempdir().unwrap();
    let scan_dir = tempfile::tempdir().unwrap();
    let out = scan(
        cache.path(),
        scan_dir.path(),
        &["--layers", "sca", "--offline"],
    );
    assert_eq!(code(&out), 5);
}
