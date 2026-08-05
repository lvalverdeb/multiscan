//! Acceptance: `multiscan report` re-renders stored findings without a scan.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("binary runs")
}

#[test]
fn report_rerenders_stored_findings() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.tf"),
        "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}\n",
    )
    .unwrap();
    // Scan persists to the store.
    let scan = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--format",
            "json",
        ],
    );
    let scanned: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();

    // report --format json re-renders the same set without re-scanning.
    let report = run(project.path(), &["report", "--format", "json"]);
    assert_eq!(report.status.code(), Some(0));
    let reported: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();

    let scan_ids: Vec<&str> = scanned
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["finding_id"].as_str().unwrap())
        .collect();
    let report_ids: Vec<&str> = reported
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["finding_id"].as_str().unwrap())
        .collect();
    assert_eq!(scan_ids, report_ids);
    assert!(!report_ids.is_empty());
}
