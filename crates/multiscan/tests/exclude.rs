//! Exclude acceptance at the CLI boundary: `[scan] exclude` (spec 4.5,
//! CLI-007), per-layer `[scan.<layer>] exclude` (ADR 0004), and the
//! `--exclude` flag with spec 4.5 precedence. Hermetic: isolated scan dirs,
//! no network (`--offline`).

// Test-support helpers outside #[test] fns; the in-tests clippy allowance
// does not reach them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

/// A line the entropy detector always fires on (no provider rule matches).
const ENTROPY_LINE: &str = "token = Zx9Qw3Vb7Nk2Rt5Yu8Pm1Lo4Hf6Gd0Sa\n";

fn multiscan(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("binary runs")
}

fn finding_paths(out: &Output) -> Vec<String> {
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    findings
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["location"]["path"].as_str().unwrap().to_string())
        .collect()
}

/// `[scan] exclude` in the config file removes matched files from discovery.
#[test]
fn global_exclude_skips_matched_files() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("kept.txt"), ENTROPY_LINE).unwrap();
    std::fs::write(project.path().join("skipped.txt"), ENTROPY_LINE).unwrap();
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan]\nexclude = [\"skipped.txt\"]\n",
    )
    .unwrap();

    let out = multiscan(
        project.path(),
        &["scan", ".", "--layers", "secrets", "--offline", "--format", "json", "--no-store"],
    );
    let paths = finding_paths(&out);
    assert!(paths.contains(&"kept.txt".to_string()), "kept.txt must still be scanned");
    assert!(!paths.contains(&"skipped.txt".to_string()), "skipped.txt was excluded");
}

/// A pattern matching a directory path prunes everything beneath it.
#[test]
fn directory_exclude_prunes_subtree() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("generated")).unwrap();
    std::fs::write(project.path().join("generated/blob.txt"), ENTROPY_LINE).unwrap();
    std::fs::write(project.path().join("src.txt"), ENTROPY_LINE).unwrap();
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan]\nexclude = [\"generated\"]\n",
    )
    .unwrap();

    let out = multiscan(
        project.path(),
        &["scan", ".", "--layers", "secrets", "--offline", "--format", "json", "--no-store"],
    );
    let paths = finding_paths(&out);
    assert!(paths.contains(&"src.txt".to_string()));
    assert!(!paths.iter().any(|p| p.starts_with("generated/")));
}

/// `--exclude` works with no config file at all.
#[test]
fn exclude_flag_without_config() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("kept.txt"), ENTROPY_LINE).unwrap();
    std::fs::write(project.path().join("skipped.txt"), ENTROPY_LINE).unwrap();

    let out = multiscan(
        project.path(),
        &[
            "scan", ".", "--layers", "secrets", "--offline", "--format", "json", "--no-store",
            "--exclude", "skipped.txt",
        ],
    );
    let paths = finding_paths(&out);
    assert!(paths.contains(&"kept.txt".to_string()));
    assert!(!paths.contains(&"skipped.txt".to_string()));
}

/// Spec 4.5 precedence: the flag REPLACES the file's global list — the file's
/// pattern stops applying when a flag is given.
#[test]
fn exclude_flag_overrides_file_global_list() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("a.txt"), ENTROPY_LINE).unwrap();
    std::fs::write(project.path().join("b.txt"), ENTROPY_LINE).unwrap();
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan]\nexclude = [\"a.txt\"]\n",
    )
    .unwrap();

    let out = multiscan(
        project.path(),
        &[
            "scan", ".", "--layers", "secrets", "--offline", "--format", "json", "--no-store",
            "--exclude", "b.txt",
        ],
    );
    let paths = finding_paths(&out);
    assert!(paths.contains(&"a.txt".to_string()), "file exclude replaced by flag");
    assert!(!paths.contains(&"b.txt".to_string()), "flag exclude applies");
}

/// ADR 0004: `[scan.secrets] exclude` hides a lockfile from the secrets layer
/// while the sca layer still reads it (the SBOM inventories its packages).
#[test]
fn layer_exclude_scopes_to_one_layer() {
    let project = tempfile::tempdir().unwrap();
    // High-entropy content in a lockfile: secrets would flag it, sca parses it.
    std::fs::write(
        project.path().join("requirements.txt"),
        format!("requests==2.31.0\n# {ENTROPY_LINE}"),
    )
    .unwrap();
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan.secrets]\nexclude = [\"**/*.txt\"]\n",
    )
    .unwrap();

    // Secrets layer: the file is excluded, no findings from it.
    let out = multiscan(
        project.path(),
        &["scan", ".", "--layers", "secrets", "--offline", "--format", "json", "--no-store"],
    );
    assert!(finding_paths(&out).is_empty(), "secrets must not scan the excluded lockfile");

    // Sca layer: the same file is still discovered — its package reaches the SBOM.
    let out = multiscan(
        project.path(),
        &["scan", ".", "--layers", "sca", "--offline", "--format", "sbom", "--no-store"],
    );
    let sbom = String::from_utf8_lossy(&out.stdout);
    assert!(
        sbom.contains("requests"),
        "sca layer must still inventory the lockfile; sbom was: {sbom}"
    );
}

/// A global exclude, by contrast, removes the lockfile from the SBOM too.
#[test]
fn global_exclude_reaches_sbom_inventory() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("requirements.txt"), "requests==2.31.0\n").unwrap();
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan]\nexclude = [\"requirements.txt\"]\n",
    )
    .unwrap();

    let out = multiscan(
        project.path(),
        &["scan", ".", "--layers", "sca", "--offline", "--format", "sbom", "--no-store"],
    );
    let sbom = String::from_utf8_lossy(&out.stdout);
    assert!(!sbom.contains("requests"), "globally excluded lockfile leaked into sbom");
}

/// An invalid glob is a config error: exit 2, named pattern and section.
#[test]
fn invalid_glob_in_config_is_usage_error() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan]\nexclude = [\"a{b\"]\n",
    )
    .unwrap();

    let out = multiscan(project.path(), &["scan", ".", "--offline", "--no-store"]);
    assert_eq!(out.status.code().unwrap(), 2);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("a{b") && stderr.contains("[scan]"), "stderr: {stderr}");
}

/// Same for a bad pattern given via the flag.
#[test]
fn invalid_glob_flag_is_usage_error() {
    let project = tempfile::tempdir().unwrap();
    let out = multiscan(
        project.path(),
        &["scan", ".", "--offline", "--no-store", "--exclude", "a{b"],
    );
    assert_eq!(out.status.code().unwrap(), 2);
}
