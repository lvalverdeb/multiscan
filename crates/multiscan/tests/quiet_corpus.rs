//! SDD §13.3 FP-006: the "quiet corpus". Realistic benign inputs that
//! historically tripped the secrets heuristics — lockfile checksums, IDE
//! state, hex digests, UUIDs, content-address URLs, minified bundles, and
//! secret-named config placeholders — MUST produce zero findings. A change
//! that makes any of them fire is a build failure, guarding the exact
//! regression that once produced 1,586 false positives.
//!
//! This is the false-positive counterpart to the golden true-positive corpus;
//! add a fixture here for every new benign shape a heuristic detector learns
//! to ignore.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

fn quiet_dir() -> PathBuf {
    // repo-root/testdata/corpus/quiet, from crates/multiscan.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/corpus/quiet")
        .canonicalize()
        .expect("quiet corpus directory exists")
}

/// The whole quiet corpus scans clean on the secrets layer.
#[test]
fn quiet_corpus_produces_no_secrets_findings() {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .args([
            "scan",
            quiet_dir().join("secrets").to_str().unwrap(),
            "--layers",
            "secrets",
            "--offline",
            "--no-store",
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");

    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().expect("json array");
    if !arr.is_empty() {
        let detail: Vec<String> = arr
            .iter()
            .map(|f| {
                format!(
                    "{} @ {}",
                    f["identity"]["rule_id"].as_str().unwrap_or("?"),
                    f["location"]["path"].as_str().unwrap_or("?")
                )
            })
            .collect();
        panic!(
            "quiet corpus fired {} finding(s) — a false-positive regression (FP-006):\n  {}",
            arr.len(),
            detail.join("\n  ")
        );
    }
}
