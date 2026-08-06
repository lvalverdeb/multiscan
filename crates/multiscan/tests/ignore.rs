//! ADR 0009 acceptance: `.multiscanignore` is always honored; `.gitignore` is
//! opt-in so a secrets scan never skips a gitignored file by default. Hermetic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

const AWS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";

fn paths_scanned(project: &Path) -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(project)
        .args(["scan", ".", "--layers", "secrets", "--offline", "--no-store", "--format", "json"])
        .output()
        .expect("binary runs");
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    findings
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["location"]["path"].as_str().unwrap().to_string())
        .collect()
}

/// `.multiscanignore` skips matched paths with no other config.
#[test]
fn multiscanignore_skips_paths() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("generated")).unwrap();
    std::fs::write(
        project.path().join("generated/keys.txt"),
        format!("K={AWS_KEY_ID}\n"),
    )
    .unwrap();
    std::fs::write(project.path().join("app.env"), format!("K={AWS_KEY_ID}\n")).unwrap();
    std::fs::write(project.path().join(".multiscanignore"), "generated/\n").unwrap();

    let paths = paths_scanned(project.path());
    assert!(paths.contains(&"app.env".to_string()));
    assert!(
        !paths.iter().any(|p| p.starts_with("generated/")),
        "ignored dir leaked: {paths:?}"
    );
}

/// A gitignored secret file is STILL scanned by default — the security-safe
/// default (ADR 0009). Opting in with respect_gitignore skips it.
#[test]
fn gitignore_is_off_by_default_and_opt_in() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".gitignore"), ".env\n").unwrap();
    std::fs::write(project.path().join(".env"), format!("K={AWS_KEY_ID}\n")).unwrap();

    // Default: the gitignored .env is scanned, so the key is found.
    let paths = paths_scanned(project.path());
    assert!(
        paths.contains(&".env".to_string()),
        "gitignored .env must be scanned by default: {paths:?}"
    );

    // Opt in: now .gitignore is honored and .env is skipped.
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan]\nrespect_gitignore = true\n",
    )
    .unwrap();
    let paths = paths_scanned(project.path());
    assert!(
        !paths.contains(&".env".to_string()),
        "respect_gitignore should skip .env: {paths:?}"
    );
}

/// `.multiscanignore` negation can re-include a path `.gitignore` excluded
/// (it is applied last).
#[test]
fn multiscanignore_negation_reincludes_over_gitignore() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".gitignore"), "*.env\n").unwrap();
    std::fs::write(project.path().join("secret.env"), format!("K={AWS_KEY_ID}\n")).unwrap();
    std::fs::write(project.path().join(".multiscanignore"), "!secret.env\n").unwrap();
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan]\nrespect_gitignore = true\n",
    )
    .unwrap();

    let paths = paths_scanned(project.path());
    assert!(
        paths.contains(&"secret.env".to_string()),
        "negation must re-include: {paths:?}"
    );
}
