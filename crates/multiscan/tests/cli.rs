//! T-105 acceptance: exit codes (spec 4.4), stdout/stderr discipline
//! (CLI-001), config precedence (spec 4.5), CLI-006, FR-009, FR-015, and the
//! SEC-001 refusal path — all against the real binary.

// Test-support helpers outside #[test] fns; the in-tests clippy allowance
// does not reach them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

fn multiscan(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("binary runs")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("exit code")
}

#[test]
fn empty_scan_exits_clean() {
    let dir = tempfile::tempdir().unwrap();
    let out = multiscan(dir.path(), &["scan", "."]);
    assert_eq!(code(&out), 0);
    // Body says no findings; a footer line carries the scan timestamp (OUT-002).
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("No findings.\n"));
    assert!(stdout.contains("scanned at"));
}

#[test]
fn unknown_flag_is_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = multiscan(dir.path(), &["scan", ".", "--bogus"]);
    assert_eq!(code(&out), 2);
}

/// CLI-006: a [[suppress]] entry without justification/approver/expires is a
/// config error, exit 2.
#[test]
fn incomplete_suppression_is_config_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("multiscan.toml"),
        "[[suppress]]\nfinding_id = \"abc\"\njustification = \"x\"\n",
    )
    .unwrap();
    let out = multiscan(dir.path(), &["scan", "."]);
    assert_eq!(code(&out), 2);
    assert!(!out.stderr.is_empty());
}

/// CLI-001: with --format json, stdout is pure JSON even with warnings and
/// verbose diagnostics present on stderr.
#[test]
fn machine_stdout_is_pure_json() {
    let dir = tempfile::tempdir().unwrap();
    let out = multiscan(
        dir.path(),
        &[
            "scan",
            ".",
            "--format",
            "json",
            "--verbose",
            "--testkit-fixture",
            "3",
            "--testkit-partial",
        ],
    );
    // Partial outcome → exit 3, but stdout still carries the findings (FR-015).
    assert_eq!(code(&out), 3);
    assert!(!out.stderr.is_empty(), "diagnostics must go to stderr");
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be pure JSON");
    assert_eq!(parsed.as_array().unwrap().len(), 3);
}

/// FR-009: gate met → exit 1 and the blocking id on stderr.
#[test]
fn gate_prints_blocking_id_to_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let out = multiscan(
        dir.path(),
        &["scan", ".", "--testkit-fixture", "2", "--fail-on", "15"],
    );
    assert_eq!(code(&out), 1);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("gate:"), "blocking id missing: {stderr}");
    // The full 64-hex id is printed so it can be copy-pasted into explain.
    assert!(stderr
        .split_whitespace()
        .any(|token| token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())));
}

/// Severity-name thresholds gate too (spec 4.2 --fail-on).
#[test]
fn severity_fail_on_gates() {
    let dir = tempfile::tempdir().unwrap();
    let out = multiscan(
        dir.path(),
        &["scan", ".", "--testkit-fixture", "2", "--fail-on", "high"],
    );
    assert_eq!(code(&out), 1);
    let out = multiscan(
        dir.path(),
        &[
            "scan",
            ".",
            "--testkit-fixture",
            "2",
            "--fail-on",
            "critical",
        ],
    );
    assert_eq!(code(&out), 0);
}

/// Flags override file values (spec 4.5): the config gates at 15, the flag
/// raises the threshold and wins.
#[test]
fn flag_overrides_config_gate() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("multiscan.toml"),
        "[gate]\nfail_on = 15.0\n",
    )
    .unwrap();
    let from_config = multiscan(dir.path(), &["scan", ".", "--testkit-fixture", "2"]);
    assert_eq!(code(&from_config), 1, "config threshold must gate");
    let flag_wins = multiscan(
        dir.path(),
        &["scan", ".", "--testkit-fixture", "2", "--fail-on", "99"],
    );
    assert_eq!(code(&flag_wins), 0, "flag must override config");
}

/// Config is discovered upward from the scan root (spec 4.5).
#[test]
fn config_discovered_upward() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("multiscan.toml"),
        "[gate]\nfail_on = 15.0\n",
    )
    .unwrap();
    let child = dir.path().join("nested/deeper");
    std::fs::create_dir_all(&child).unwrap();
    let out = multiscan(&child, &["scan", ".", "--testkit-fixture", "2"]);
    assert_eq!(code(&out), 1, "parent config must be discovered and gate");
}

/// FR-015 + ENG-002: partial completion is exit 3, distinct from gate exit 1,
/// even when the gate also fires (scan error wins).
#[test]
fn partial_beats_gate_in_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let out = multiscan(
        dir.path(),
        &[
            "scan",
            ".",
            "--testkit-fixture",
            "2",
            "--testkit-partial",
            "--fail-on",
            "5",
        ],
    );
    assert_eq!(code(&out), 3);
}

/// SEC-001 / FR-007 (refusal half): scan web without authorization exits 4.
#[test]
fn web_scan_without_authorization_denied() {
    let dir = tempfile::tempdir().unwrap();
    let out = multiscan(dir.path(), &["scan", "web", "https://staging.example"]);
    assert_eq!(code(&out), 4);
    assert!(String::from_utf8_lossy(&out.stderr).contains("SEC-001"));
}

/// --min-severity filters display, not the gate (spec 4.2).
#[test]
fn min_severity_filters_display_not_gate() {
    let dir = tempfile::tempdir().unwrap();
    let out = multiscan(
        dir.path(),
        &[
            "scan",
            ".",
            "--testkit-fixture",
            "2",
            "--min-severity",
            "high",
            "--fail-on",
            "10",
        ],
    );
    // Medium finding hidden from the table, but the gate still saw it.
    assert_eq!(code(&out), 1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("HIGH"));
    assert!(!stdout.contains("MEDIUM"));
}
