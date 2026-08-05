//! T-603 acceptance: FR-016 — `multiscan explain <id>` prints the five score
//! factors, defaults, evidence, and remediation; `--history` shows events.

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

/// Scan an IaC project (persisting to the store), then explain a finding.
#[test]
fn explain_prints_factors_evidence_remediation() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.tf"),
        "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}\n",
    )
    .unwrap();

    // Scan populates the store and emits json we can read the id from.
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
    let findings: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let id = findings[0]["finding_id"].as_str().unwrap();

    // explain by 12-char prefix (as printed in the table).
    let out = run(project.path(), &["explain", &id[..12]]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);

    // FR-016 / RSK-005: all five factors named.
    for factor in [
        "severity_base",
        "exposure",
        "exploitability",
        "confidence",
        "asset_criticality",
    ] {
        assert!(text.contains(factor), "missing factor {factor}");
    }
    assert!(text.contains("raw product"));
    assert!(text.contains("defaults applied"));
    assert!(text.contains("Evidence"));
    assert!(text.contains("Remediation"));
    assert!(text.contains("Score (formula 1)"));
}

/// --history prints the event log (at least the FirstSeen event).
#[test]
fn explain_history_shows_events() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.tf"),
        "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}\n",
    )
    .unwrap();
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
    let findings: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let id = findings[0]["finding_id"].as_str().unwrap().to_string();

    let out = run(project.path(), &["explain", &id, "--history"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("History"));
    assert!(text.contains("first seen"));
}

/// An unknown id is a usage error.
#[test]
fn explain_unknown_id_errors() {
    let project = tempfile::tempdir().unwrap();
    // No store yet.
    let out = run(project.path(), &["explain", "deadbeef"]);
    assert_eq!(out.status.code(), Some(2));
}
