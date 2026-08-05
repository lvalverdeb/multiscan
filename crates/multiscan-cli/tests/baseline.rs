//! T-302 acceptance: baseline delta gating (FR-010), suppression expiry
//! (FR-014), and the suppress/diff lifecycle. Hermetic temp dirs, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

fn public_bucket(project: &Path) {
    // A public S3 bucket scores High (~24.5) — enough to trip a gate.
    std::fs::write(
        project.join("main.tf"),
        "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}\n",
    )
    .unwrap();
}

fn run(project: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(project)
        .args(args)
        .output()
        .expect("binary runs")
}

fn scan_json(project: &Path, args: &[&str]) -> serde_json::Value {
    let mut full = vec![
        "scan",
        ".",
        "--layers",
        "iac",
        "--offline",
        "--format",
        "json",
    ];
    full.extend_from_slice(args);
    let out = run(project, &full);
    serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
}

/// FR-010: a baseline containing the only high Finding → --baseline → exit 0.
#[test]
fn baseline_suppresses_known_finding_from_gate() {
    let project = tempfile::tempdir().unwrap();
    public_bucket(project.path());

    // Without a baseline, the finding trips the gate.
    let bare = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--fail-on",
            "20",
            "--no-store",
        ],
    );
    assert_eq!(bare.status.code(), Some(1), "high finding should gate");

    // Capture the current findings as the baseline.
    let baseline = scan_json(project.path(), &["--no-store"]);
    let baseline_path = project.path().join("baseline.json");
    std::fs::write(&baseline_path, serde_json::to_vec(&baseline).unwrap()).unwrap();

    // With the baseline, the same finding is not new → exit 0 (FR-010).
    let gated = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--fail-on",
            "20",
            "--no-store",
            "--baseline",
            "baseline.json",
        ],
    );
    assert_eq!(
        gated.status.code(),
        Some(0),
        "baseline-known finding must not gate"
    );
}

/// A NEW finding not in the baseline still gates (baseline is delta-only).
#[test]
fn new_finding_still_gates_against_baseline() {
    let project = tempfile::tempdir().unwrap();
    public_bucket(project.path());
    // Baseline captured while only the bucket exists.
    let baseline = scan_json(project.path(), &["--no-store"]);
    std::fs::write(
        project.path().join("baseline.json"),
        serde_json::to_vec(&baseline).unwrap(),
    )
    .unwrap();

    // Add a second violation (unencrypted volume) → new id, must gate.
    std::fs::write(
        project.path().join("vol.tf"),
        "resource \"aws_ebs_volume\" \"v\" {\n  encrypted = false\n}\n",
    )
    .unwrap();
    let out = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--fail-on",
            "10",
            "--no-store",
            "--baseline",
            "baseline.json",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "a new finding must still gate");
}

/// FR-014: an expired suppression means the Finding appears and gates normally.
#[test]
fn expired_suppression_does_not_hide_finding() {
    let project = tempfile::tempdir().unwrap();
    public_bucket(project.path());

    // Find the finding id.
    let findings = scan_json(project.path(), &["--no-store"]);
    let id = findings[0]["finding_id"].as_str().unwrap().to_string();

    // A suppression that expired yesterday.
    std::fs::write(
        project.path().join("multiscan.toml"),
        format!(
            "[[suppress]]\nfinding_id = \"{id}\"\njustification = \"old\"\napprover = \"sec\"\nexpires = \"2020-01-01\"\n"
        ),
    )
    .unwrap();
    let out = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--fail-on",
            "20",
            "--no-store",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "expired suppression must not hide the finding"
    );
}

/// An active suppression hides the Finding from the gate and human output.
#[test]
fn active_suppression_hides_finding() {
    let project = tempfile::tempdir().unwrap();
    // Encrypted so only the public-ACL policy fires — a single finding, so the
    // human table is empty once it is suppressed.
    std::fs::write(
        project.path().join("main.tf"),
        "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n  \
         server_side_encryption_configuration {\n    rule {}\n  }\n}\n",
    )
    .unwrap();
    let findings = scan_json(project.path(), &["--no-store"]);
    assert_eq!(
        findings.as_array().unwrap().len(),
        1,
        "expected a single finding"
    );
    let id = findings[0]["finding_id"].as_str().unwrap().to_string();

    std::fs::write(
        project.path().join("multiscan.toml"),
        format!(
            "[[suppress]]\nfinding_id = \"{id}\"\njustification = \"accepted risk\"\napprover = \"sec\"\nexpires = \"2099-01-01\"\n"
        ),
    )
    .unwrap();

    // Gate: suppressed finding does not block.
    let gated = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--fail-on",
            "20",
            "--no-store",
        ],
    );
    assert_eq!(
        gated.status.code(),
        Some(0),
        "active suppression must not gate"
    );

    // Human output hides it; machine output keeps it with status suppressed.
    let table = run(
        project.path(),
        &["scan", ".", "--layers", "iac", "--offline", "--no-store"],
    );
    assert!(String::from_utf8_lossy(&table.stdout).contains("No findings."));
    let json = scan_json(project.path(), &["--no-store"]);
    assert_eq!(json[0]["status"], "suppressed");
}

/// suppress add → list → expire lifecycle against the store.
#[test]
fn suppress_add_list_expire_lifecycle() {
    let project = tempfile::tempdir().unwrap();
    // A scan first, so the DB and a finding exist.
    public_bucket(project.path());
    let findings = scan_json(project.path(), &[]);
    let id = findings[0]["finding_id"].as_str().unwrap().to_string();

    let add = run(
        project.path(),
        &[
            "suppress",
            "add",
            &id,
            "--justification",
            "vendored",
            "--approver",
            "sec",
            "--expires",
            "2099-01-01",
        ],
    );
    assert_eq!(add.status.code(), Some(0));

    let list = run(project.path(), &["suppress", "list"]);
    let list_out = String::from_utf8_lossy(&list.stdout);
    assert!(list_out.contains("active"));
    assert!(list_out.contains(&id));

    // Now the scan's gate ignores it.
    let gated = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--fail-on",
            "20",
        ],
    );
    assert_eq!(gated.status.code(), Some(0));

    // Expire it → it becomes inactive → the finding gates again.
    let expire = run(project.path(), &["suppress", "expire", &id]);
    assert_eq!(expire.status.code(), Some(0));
    let regated = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--fail-on",
            "20",
        ],
    );
    assert_eq!(
        regated.status.code(),
        Some(1),
        "expired suppression must gate again"
    );
}

/// diff reports added/resolved against a baseline.
#[test]
fn diff_reports_added_and_resolved() {
    let project = tempfile::tempdir().unwrap();
    public_bucket(project.path());
    // Baseline = empty finding set; current scan has the bucket finding.
    std::fs::write(project.path().join("baseline.json"), "[]").unwrap();
    // Populate the store.
    run(
        project.path(),
        &["scan", ".", "--layers", "iac", "--offline"],
    );

    let out = run(project.path(), &["diff", "baseline.json"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("new"),
        "diff should report new findings: {stdout}"
    );
    assert!(stdout.contains("+ "));
}
