//! `FR-018` at the CLI boundary: freshness is opt-in and offline is absolute.
//!
//! No real host is contacted — the default path makes no request at all, which
//! is the property under test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();
    dir
}

fn run(cache: &Path, dir: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(dir)
        .args(["scan", ".", "--layers", "sca", "--format", "json"])
        .args(extra)
        .output()
        .expect("binary runs")
}

#[test]
fn freshness_and_offline_are_rejected_together() {
    // A flag that silently no-ops would let a user believe they had checked
    // for fresh advisories when they had not (ADR 0020 decision 2).
    let cache = tempfile::tempdir().unwrap();
    let dir = project();
    let out = run(cache.path(), dir.path(), &["--offline", "--freshness"]);

    assert_eq!(out.status.code(), Some(2), "usage error, not a silent win");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--freshness"),
        "names the conflict: {stderr}"
    );
    assert!(stderr.contains("--offline"));
}

#[test]
fn the_default_path_makes_no_request() {
    // FR-018: without the flag, only the pinned snapshot is consulted. There is
    // no snapshot here and no network available to these tests, so a scan that
    // completes cleanly is the evidence that nothing was fetched.
    let cache = tempfile::tempdir().unwrap();
    let dir = project();
    let out = run(cache.path(), dir.path(), &[]);

    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("osv.dev"),
        "the default path must not mention the API: {stderr}"
    );
}

#[test]
fn offline_alone_still_works() {
    // The conflict check must not have broken plain --offline.
    let cache = tempfile::tempdir().unwrap();
    let dir = project();
    let out = run(cache.path(), dir.path(), &["--offline"]);
    assert_ne!(
        out.status.code(),
        Some(2),
        "--offline on its own is not a usage error"
    );
}
