//! T-203 acceptance at the CLI boundary: FR-005 (a detected secret value
//! never appears in ANY output artifact) plus detection and entropy-cap
//! behaviour. Hermetic: an isolated scan dir, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

/// A fake AWS key pair in the classic documented-example shape. Not a live
/// credential, but exactly what the rules target.
const AWS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn scan(project: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(project)
        .args(["scan", ".", "--layers", "secrets", "--offline"])
        .args(extra)
        .output()
        .expect("binary runs")
}

/// FR-005 / SEC-101: after a scan, no output artifact contains the full value.
#[test]
fn secret_value_never_appears_in_output() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("config.py"),
        format!("AWS_ACCESS_KEY_ID = \"{AWS_KEY_ID}\"\naws_secret_access_key = \"{AWS_SECRET}\"\n"),
    )
    .unwrap();

    for format in ["json", "jsonl", "sarif", "table", "markdown"] {
        let out = scan(project.path(), &["--format", format]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains(AWS_KEY_ID) && !stdout.contains(AWS_SECRET),
            "{format}: secret value leaked to stdout"
        );
        assert!(
            !stderr.contains(AWS_KEY_ID) && !stderr.contains(AWS_SECRET),
            "{format}: secret value leaked to stderr"
        );
        // But the finding IS reported (type + masked preview present).
        if format == "json" {
            let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert!(!findings.as_array().unwrap().is_empty());
        }
    }
}

/// The AWS access key is detected as High severity, Proven confidence.
#[test]
fn aws_key_detected_high_proven() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("app.env"),
        format!("KEY={AWS_KEY_ID}\n"),
    )
    .unwrap();
    let out = scan(project.path(), &["--format", "json"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();
    let aws = arr
        .iter()
        .find(|f| f["identity"]["rule_id"] == "aws-access-key-id")
        .expect("aws key finding");
    assert_eq!(aws["severity"], "high");
    assert_eq!(aws["confidence"], "proven");
    // Identity carries a fingerprint, not the value.
    let fp = aws["identity"]["fingerprint"].as_str().unwrap();
    assert_eq!(fp.len(), 16);
    assert!(!AWS_KEY_ID.contains(fp));
}

/// SEC-103: an entropy-only detection is capped at Medium/Heuristic.
#[test]
fn entropy_only_capped_medium_heuristic() {
    let project = tempfile::tempdir().unwrap();
    // A high-entropy blob that matches no provider rule.
    std::fs::write(
        project.path().join("data.txt"),
        "token = Zx9Qw3Vb7Nk2Rt5Yu8Pm1Lo4Hf6Gd0Sa\n",
    )
    .unwrap();
    let out = scan(project.path(), &["--format", "json"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();
    let entropy = arr
        .iter()
        .find(|f| f["identity"]["rule_id"] == "high-entropy-string")
        .expect("entropy finding");
    assert_eq!(entropy["severity"], "medium");
    assert_eq!(entropy["confidence"], "heuristic");
}

/// A clean file yields no secret findings.
#[test]
fn clean_file_no_findings() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.rs"),
        "fn main() { println!(\"hello world\"); }\n",
    )
    .unwrap();
    let out = scan(project.path(), &["--format", "json"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(findings.as_array().unwrap().is_empty());
}
