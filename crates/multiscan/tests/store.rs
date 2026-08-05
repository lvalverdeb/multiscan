//! T-301 acceptance at the CLI boundary: persistence across scans (STO-001,
//! STO-002) and `--no-store` statelessness (STO-003).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

fn scan(project: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(project)
        .args(["scan", ".", "--layers", "iac", "--offline"])
        .args(extra)
        .output()
        .expect("binary runs")
}

fn public_bucket(project: &Path) {
    std::fs::write(
        project.join("main.tf"),
        "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}\n",
    )
    .unwrap();
}

/// A default scan creates the findings database under the scan root (STO-001).
#[test]
fn scan_creates_database() {
    let project = tempfile::tempdir().unwrap();
    public_bucket(project.path());
    let out = scan(project.path(), &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        project.path().join(".multiscan/multiscan.db").exists(),
        "the findings DB should be created by default"
    );
    // The persistence summary is on stderr, never stdout (CLI-001).
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("store:"));
}

/// STO-003: --no-store writes no database.
#[test]
fn no_store_is_stateless() {
    let project = tempfile::tempdir().unwrap();
    public_bucket(project.path());
    let out = scan(project.path(), &["--no-store"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        !project.path().join(".multiscan/multiscan.db").exists(),
        "--no-store must not create a database"
    );
}

/// STO-002: two scans record the finding once as new, then unchanged — the
/// history is event-sourced and does not double-count.
#[test]
fn second_scan_reports_unchanged() {
    let project = tempfile::tempdir().unwrap();
    public_bucket(project.path());

    let first = scan(project.path(), &[]);
    assert!(String::from_utf8_lossy(&first.stderr).contains("new"));

    let second = scan(project.path(), &[]);
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("unchanged"),
        "second scan should see the finding as unchanged: {stderr}"
    );
}
