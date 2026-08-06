//! ADR 0008 acceptance: scoped `[[suppress]]` entries (rule_id + path) at the
//! CLI boundary. Suppressed findings are excluded from the gate but still
//! reported (status suppressed); a malformed entry is a config error (exit 2).
//! Hermetic: isolated dirs, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

const AWS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";

fn scan(project: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(project)
        .args(["scan", ".", "--layers", "secrets", "--offline", "--no-store"])
        .args(extra)
        .output()
        .expect("binary runs")
}

fn write_config(dir: &Path, body: &str) {
    std::fs::write(dir.join("multiscan.toml"), body).unwrap();
}

/// Two files each leak an AWS key. A rule+path suppression silences only the
/// vendored one: the gate still fails on the other, but passes once both are
/// covered — proving the selector scopes precisely.
#[test]
fn rule_and_path_suppression_scopes_the_gate() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("vendor")).unwrap();
    std::fs::write(
        project.path().join("vendor/keys.txt"),
        format!("KEY={AWS_KEY_ID}\n"),
    )
    .unwrap();
    std::fs::write(project.path().join("app.env"), format!("KEY={AWS_KEY_ID}\n")).unwrap();

    // No suppression: the AWS key is high → gate fails.
    let out = scan(project.path(), &["--fail-on", "high"]);
    assert_eq!(out.status.code(), Some(1));

    // Suppress the rule in vendor/ only: app.env still fails the gate.
    write_config(
        project.path(),
        "[[suppress]]\nrule_id = \"aws-access-key-id\"\npath = \"vendor/**\"\n\
         justification = \"vendored sample keys\"\napprover = \"sec-team\"\nexpires = \"2099-01-01\"\n",
    );
    let out = scan(project.path(), &["--fail-on", "high"]);
    assert_eq!(out.status.code(), Some(1), "app.env key must still gate");

    // The vendored finding is present but marked suppressed.
    let out = scan(project.path(), &["--format", "json"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();
    let vendored = arr
        .iter()
        .find(|f| f["location"]["path"] == "vendor/keys.txt")
        .expect("vendored finding present");
    assert_eq!(vendored["status"], "suppressed");
    let app = arr
        .iter()
        .find(|f| f["location"]["path"] == "app.env")
        .expect("app finding present");
    assert_eq!(app["status"], "open");

    // Widen the path to cover both → gate passes.
    write_config(
        project.path(),
        "[[suppress]]\nrule_id = \"aws-access-key-id\"\npath = \"**\"\n\
         justification = \"test fixtures\"\napprover = \"sec-team\"\nexpires = \"2099-01-01\"\n",
    );
    let out = scan(project.path(), &["--fail-on", "high"]);
    assert_eq!(out.status.code(), Some(0), "both keys suppressed → clean gate");
}

/// An expired scoped suppression does not apply — the finding gates normally
/// again (FR-014).
#[test]
fn expired_scoped_suppression_reappears() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.env"), format!("KEY={AWS_KEY_ID}\n")).unwrap();
    write_config(
        project.path(),
        "[[suppress]]\nrule_id = \"aws-access-key-id\"\npath = \"**\"\n\
         justification = \"temporary\"\napprover = \"sec\"\nexpires = \"2000-01-01\"\n",
    );
    let out = scan(project.path(), &["--fail-on", "high"]);
    assert_eq!(out.status.code(), Some(1), "expired suppression must not apply");
}

/// A `[[suppress]]` entry with no selector is a config error (exit 2).
#[test]
fn empty_selector_is_config_error() {
    let project = tempfile::tempdir().unwrap();
    write_config(
        project.path(),
        "[[suppress]]\njustification = \"x\"\napprover = \"y\"\nexpires = \"2099-01-01\"\n",
    );
    let out = scan(project.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("selector"), "reason missing: {stderr}");
}

/// A bad path glob is a config error (exit 2).
#[test]
fn bad_path_glob_is_config_error() {
    let project = tempfile::tempdir().unwrap();
    write_config(
        project.path(),
        "[[suppress]]\npath = \"a{b\"\njustification = \"x\"\napprover = \"y\"\nexpires = \"2099-01-01\"\n",
    );
    let out = scan(project.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
}

/// CLI-006 stays intact: missing approver is still a parse error (exit 2),
/// selectors or not.
#[test]
fn missing_mandatory_field_still_errors() {
    let project = tempfile::tempdir().unwrap();
    write_config(
        project.path(),
        "[[suppress]]\nrule_id = \"aws-access-key-id\"\njustification = \"x\"\nexpires = \"2099-01-01\"\n",
    );
    let out = scan(project.path(), &[]);
    assert_eq!(out.status.code(), Some(2), "approver is mandatory (CLI-006)");
}
