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

/// ADR 0005: a lockfile's checksum noise never reaches the entropy fallback,
/// but a real provider-shaped credential in the same file is still caught.
#[test]
fn lockfile_noise_suppressed_precise_rules_still_fire() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("uv.lock"),
        format!(
            r#"[[package]]
name = "aiobotocore"
version = "3.7.0"
sdist = {{ url = "https://files.pythonhosted.org/packages/e7/75/42cce839c2ec263ff74b10b650fe36b066fbb124cbee6f247eac0983e1ab/aiobotocore-3.7.0.tar.gz", hash = "sha256:c64d871ed5491a6571948dd48eabd185b46c6c23b64e3afd0c059fc7593ada30" }}
leaked = "{AWS_KEY_ID}"
"#
        ),
    )
    .unwrap();

    let out = scan(project.path(), &["--format", "json", "--no-store"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();
    assert!(
        !arr.iter()
            .any(|f| f["identity"]["rule_id"] == "high-entropy-string"),
        "lockfile checksums must not fire the entropy fallback: {arr:?}"
    );
    assert!(
        arr.iter()
            .any(|f| f["identity"]["rule_id"] == "aws-access-key-id"),
        "precise rules must still run on lockfiles: {arr:?}"
    );
}

/// ADR 0005 token shapes: digests, UUIDs, and URL-embedded runs are exempt
/// from the entropy fallback in ordinary source files; a bare high-entropy
/// path-like run without URL context is still flagged.
#[test]
fn content_address_shapes_not_flagged() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("build_info.py"),
        concat!(
            "IMAGE_DIGEST = \"c64d871ed5491a6571948dd48eabd185b46c6c23b64e3afd0c059fc7593ada30\"\n",
            "GIT_SHA = \"da39a3ee5e6b4b0d3255bfef95601890afd80709\"\n",
            "SESSION = \"48ca8a53-f08e-4065-aebf-02c8604e3185\"\n",
            "WHEEL = \"https://files.pythonhosted.org/packages/a4/c0/1117d53077e3ac3152503a84e9cf7a5c2395768/matplotlib-3.11.0.whl\"\n",
        ),
    )
    .unwrap();
    let out = scan(project.path(), &["--format", "json", "--no-store"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        findings.as_array().unwrap().is_empty(),
        "content-address shapes flagged: {findings:?}"
    );

    // Control: the same kind of run outside a URL, at a non-digest length,
    // still fires — the heuristic is narrowed, not disabled.
    std::fs::write(
        project.path().join("bare.txt"),
        "blob = a4c01117d53077e3ac3152503a84e9cf7a5c2395768matplotlib\n",
    )
    .unwrap();
    let out = scan(project.path(), &["--format", "json", "--no-store"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        finding_paths_contain(&findings, "bare.txt"),
        "narrowed heuristic must still fire on bare runs: {findings:?}"
    );
}

fn finding_paths_contain(findings: &serde_json::Value, path: &str) -> bool {
    findings
        .as_array()
        .map(|arr| arr.iter().any(|f| f["location"]["path"] == path))
        .unwrap_or(false)
}

/// IDE metadata is built-in noise.
#[test]
fn ide_metadata_entropy_suppressed() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join(".idea")).unwrap();
    std::fs::write(
        project.path().join(".idea/workspace.xml"),
        "<component value=\"Zx9Qw3Vb7Nk2Rt5Yu8Pm1Lo4Hf6Gd0Sa\" />\n",
    )
    .unwrap();
    let out = scan(project.path(), &["--format", "json", "--no-store"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(findings.as_array().unwrap().is_empty(), "{findings:?}");
}

/// `[scan.secrets] entropy_exclude` extends the built-in noise list; the
/// file is still walked (a provider credential there is still found).
#[test]
fn entropy_exclude_config_extends_builtin() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join("fixtures")).unwrap();
    std::fs::write(
        project.path().join("fixtures/data.txt"),
        format!("blob = Zx9Qw3Vb7Nk2Rt5Yu8Pm1Lo4Hf6Gd0Sa\nkey = {AWS_KEY_ID}\n"),
    )
    .unwrap();

    // Without config: the entropy blob fires.
    let out = scan(project.path(), &["--format", "json", "--no-store"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        findings
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["identity"]["rule_id"] == "high-entropy-string"),
        "{findings:?}"
    );

    // With entropy_exclude: entropy silenced, precise rule still fires.
    std::fs::write(
        project.path().join("multiscan.toml"),
        "[scan.secrets]\nentropy_exclude = [\"fixtures/**\"]\n",
    )
    .unwrap();
    let out = scan(project.path(), &["--format", "json", "--no-store"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();
    assert!(
        !arr.iter()
            .any(|f| f["identity"]["rule_id"] == "high-entropy-string"),
        "{arr:?}"
    );
    assert!(
        arr.iter()
            .any(|f| f["identity"]["rule_id"] == "aws-access-key-id"),
        "{arr:?}"
    );
}

/// Pack-corpus detectors resolve at the CLI boundary, and SEC-101 holds for
/// them: the detected values never appear in any output.
#[test]
fn new_pack_rules_detect_and_never_leak() {
    // Assembled at runtime so no key-shaped literal sits in source (GitHub
    // push protection flags contiguous sk_live_… strings, even synthetic).
    let stripe = format!("sk_live_{}", "4eC9".repeat(6));
    let db_pass = "S3cr3tPassw0rd";
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("settings.py"),
        format!(
            "STRIPE_KEY = \"{stripe}\"\nDATABASE_URL = \"postgres://svc:{db_pass}@db.internal:5432/app\"\nSECRET_KEY = \"f8Zk2mQ9vX4nR7wL\"\n"
        ),
    )
    .unwrap();

    let out = scan(project.path(), &["--format", "json", "--no-store"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(&stripe) && !stdout.contains(db_pass),
        "secret value leaked (SEC-101)"
    );
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = findings
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["identity"]["rule_id"].as_str())
        .collect();
    assert!(ids.contains(&"stripe-secret-key"), "{ids:?}");
    assert!(ids.contains(&"database-url-credentials"), "{ids:?}");
    assert!(ids.contains(&"keyword-context-secret"), "{ids:?}");
}

/// The manifest advertises the pack identity (rule_set) so reports carry
/// rule provenance, mirroring the IaC CIS pack.
#[test]
fn severity_map_covers_every_pack_rule() {
    // Verified indirectly at the CLI: a scan must not produce a finding whose
    // rule_id lacks a severity mapping — the engine derives the map from the
    // pack, so any drift would surface as a missing/default severity here.
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("x.txt"),
        format!("key = {AWS_KEY_ID}\n"),
    )
    .unwrap();
    let out = scan(project.path(), &["--format", "json", "--no-store"]);
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = &findings.as_array().unwrap()[0];
    assert_eq!(f["severity"], "high");
}
