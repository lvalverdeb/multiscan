//! ADR 0010, generalized to IaC: a policy pack distributed in the pinned feed
//! snapshot (`rules/iac.json`) is used at scan time, evaluating a policy the
//! embedded CIS pack does not contain. Hermetic: isolated feed cache.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use chrono::Utc;
use multiscan_feeds::{write_snapshot, SnapshotData};

/// A pack with one policy the embedded CIS pack does not have: KMS keys must
/// enable rotation.
const FEED_IAC_PACK: &str = r#"{
  "pack_id": "custom-iac",
  "version": "1.0.0",
  "policies": [
    {
      "id": "custom-kms-rotation",
      "title": "KMS key does not enable rotation",
      "resource_kinds": ["aws_kms_key"],
      "severity": "medium",
      "cwe": ["CWE-320"],
      "compliance_controls": ["CIS-AWS-3.8"],
      "remediation": "Set enable_key_rotation = true.",
      "condition": { "op": "is_false_or_absent", "attribute": "enable_key_rotation" }
    }
  ]
}"#;

fn seed_iac_pack(cache: &Path, pack: &str) {
    let mut rule_packs = BTreeMap::new();
    rule_packs.insert("iac".to_string(), pack.as_bytes().to_vec());
    let data = SnapshotData {
        rule_packs,
        ..Default::default()
    };
    write_snapshot(cache, &data, Utc::now()).unwrap();
}

fn scan(cache: &Path, project: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(project)
        .args(["scan", ".", "--layers", "iac", "--offline", "--no-store", "--format", "json"])
        .args(extra)
        .output()
        .expect("binary runs")
}

fn policy_ids(out: &Output) -> Vec<String> {
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    findings
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["identity"]["policy_id"].as_str().map(str::to_string))
        .collect()
}

fn project_with_kms() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("main.tf"),
        "resource \"aws_kms_key\" \"k\" {\n  description = \"app key\"\n}\n",
    )
    .unwrap();
    dir
}

#[test]
fn feed_iac_pack_evaluates_new_policy() {
    let cache = tempfile::tempdir().unwrap();
    let project = project_with_kms();

    // Baseline: embedded CIS pack has no KMS-rotation policy.
    let out = scan(cache.path(), project.path(), &[]);
    assert!(
        !policy_ids(&out).contains(&"custom-kms-rotation".to_string()),
        "embedded pack should not know this policy"
    );

    // Distribute the pack via the snapshot → the policy now evaluates.
    seed_iac_pack(cache.path(), FEED_IAC_PACK);
    let out = scan(cache.path(), project.path(), &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        policy_ids(&out).contains(&"custom-kms-rotation".to_string()),
        "feed-distributed policy must apply: {:?}",
        policy_ids(&out)
    );
}

#[test]
fn corrupt_feed_iac_pack_falls_back_to_builtin() {
    let cache = tempfile::tempdir().unwrap();
    seed_iac_pack(cache.path(), "{ not valid json");

    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.tf"),
        "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n",
    )
    .unwrap();

    // The embedded CIS S3 policy still fires despite the bad feed pack.
    let out = scan(cache.path(), project.path(), &["--quiet"]);
    assert!(
        policy_ids(&out).iter().any(|p| p.contains("s3")),
        "must fall back to embedded CIS pack: {:?}",
        policy_ids(&out)
    );
}
