//! ADR 0006 acceptance: the opt-in git-history pass finds
//! committed-then-removed secrets, keeps SEC-101, and degrades honestly.
//! Hermetic: temp repos built with the git CLI, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

const AWS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        // Hermetic identity/config; no host or global config leakage.
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repo whose HEAD is clean but whose history contains a leaked key.
fn repo_with_rotated_secret() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    std::fs::write(
        dir.path().join("config.py"),
        format!("AWS_KEY = \"{AWS_KEY_ID}\"\n"),
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "add config"]);
    // "Remove" the secret — it lives on in the object store.
    std::fs::write(dir.path().join("config.py"), "AWS_KEY = None  # rotated\n").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "rotate"]);
    dir
}

fn scan(project: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(project)
        .args(["scan", ".", "--layers", "secrets", "--offline", "--no-store", "--format", "json"])
        .args(extra)
        .output()
        .expect("binary runs")
}

/// Without --history the rotated secret is invisible; with it, found — and
/// the value itself never appears in output (SEC-101).
#[test]
fn history_finds_rotated_secret() {
    let repo = repo_with_rotated_secret();

    let out = scan(repo.path(), &[]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        findings.as_array().unwrap().is_empty(),
        "tree scan must be clean: {findings:?}"
    );

    let out = scan(repo.path(), &["--history"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains(AWS_KEY_ID), "secret value leaked (SEC-101)");
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();
    let hit = arr
        .iter()
        .find(|f| f["identity"]["rule_id"] == "aws-access-key-id")
        .expect("historical key found");
    assert_eq!(hit["location"]["path"], "config.py");
    // Provenance is in evidence, identity is the normal secret identity.
    let evidence = hit["evidence"][0]["summary"].as_str().unwrap();
    assert!(evidence.contains("git history"), "{evidence}");
}

/// A secret still in the tree yields ONE finding with --history, not two:
/// identical identity merges the sightings.
#[test]
fn live_secret_not_duplicated_by_history() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    std::fs::write(
        dir.path().join("config.py"),
        format!("AWS_KEY = \"{AWS_KEY_ID}\"\n"),
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "add"]);

    let out = scan(dir.path(), &["--history"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let aws: Vec<_> = findings
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["identity"]["rule_id"] == "aws-access-key-id")
        .collect();
    assert_eq!(aws.len(), 1, "history sighting must merge, not duplicate");
}

/// ADR 0005 noise rules apply to historical paths too: an old lockfile's
/// checksums do not resurface as entropy findings.
#[test]
fn history_respects_entropy_noise_rules() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    std::fs::write(
        dir.path().join("uv.lock"),
        "hash = \"sha256:c64d871ed5491a6571948dd48eabd185b46c6c23b64e3afd0c059fc7593ada30\"\nblob = \"Zx9Qw3Vb7Nk2Rt5Yu8Pm1Lo4Hf6Gd0Sa\"\n",
    )
    .unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "lock"]);
    std::fs::remove_file(dir.path().join("uv.lock")).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "drop lock"]);

    let out = scan(dir.path(), &["--history"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        findings.as_array().unwrap().is_empty(),
        "historical lockfile noise resurfaced: {findings:?}"
    );
}

/// --history on a non-repo is degraded coverage: exit 3, reason on stderr,
/// never a clean exit 0.
#[test]
fn history_on_non_repo_degrades() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
    let out = scan(dir.path(), &["--history"]);
    assert_eq!(out.status.code(), Some(3), "must be Partial, not clean");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("history"), "reason missing: {stderr}");
}
