//! ADR 0010 acceptance: a secrets rule pack distributed in the pinned feed
//! snapshot is used at scan time, detecting a rule the embedded pack lacks;
//! integrity failures fall back to the embedded baseline. Hermetic: an
//! isolated feed cache, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use chrono::Utc;
use multiscan_feeds::{write_snapshot, SnapshotData};

/// A pack with one detector that does NOT exist in the embedded builtin.
const FEED_PACK: &str = r#"{
  "pack_id": "feed-secrets",
  "version": "9.9.9",
  "rules": [
    {
      "id": "acme-deploy-token",
      "description": "Acme deploy token",
      "pattern": "\\b(acme_deploy_[A-Za-z0-9]{20})\\b",
      "severity": "high",
      "confidence": "proven"
    }
  ]
}"#;

fn seed_pack(cache: &Path, pack: &str) {
    let mut rule_packs = BTreeMap::new();
    rule_packs.insert("secrets".to_string(), pack.as_bytes().to_vec());
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
        .args([
            "scan",
            ".",
            "--layers",
            "secrets",
            "--offline",
            "--no-store",
            "--format",
            "json",
        ])
        .args(extra)
        .output()
        .expect("binary runs")
}

fn rule_ids(out: &Output) -> Vec<String> {
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    findings
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["identity"]["rule_id"].as_str().map(str::to_string))
        .collect()
}

fn project_with_token() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("deploy.sh"),
        "TOKEN=acme_deploy_ABCDEFGHIJKLMNOPQRST\n",
    )
    .unwrap();
    dir
}

/// The feed-distributed detector fires; the embedded pack alone would not.
#[test]
fn feed_pack_detects_new_rule() {
    let cache = tempfile::tempdir().unwrap();
    let project = project_with_token();

    // Baseline: no feed pack → the embedded builtin has no such rule.
    let out = scan(cache.path(), project.path(), &[]);
    assert!(
        !rule_ids(&out).contains(&"acme-deploy-token".to_string()),
        "embedded pack should not know this rule"
    );

    // Distribute the pack via the snapshot → the rule now fires.
    seed_pack(cache.path(), FEED_PACK);
    let out = scan(cache.path(), project.path(), &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        rule_ids(&out).contains(&"acme-deploy-token".to_string()),
        "feed-distributed rule must apply: {:?}",
        rule_ids(&out)
    );
}

/// A corrupt feed pack falls back to the embedded baseline — the scan never
/// loses secrets detection.
#[test]
fn corrupt_feed_pack_falls_back_to_builtin() {
    let cache = tempfile::tempdir().unwrap();
    seed_pack(cache.path(), "{ not valid json");

    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.env"), "KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();

    let out = scan(cache.path(), project.path(), &["--quiet"]);
    // Embedded rule still detects the AWS key despite the bad feed pack.
    assert!(
        rule_ids(&out).contains(&"aws-access-key-id".to_string()),
        "must fall back to embedded pack: {:?}",
        rule_ids(&out)
    );
}

/// `--verbose` reports the pack provenance (id, version, source).
#[test]
fn verbose_reports_pack_provenance() {
    let cache = tempfile::tempdir().unwrap();
    seed_pack(cache.path(), FEED_PACK);
    let project = project_with_token();

    let out = scan(cache.path(), project.path(), &["--verbose"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("feed-secrets@9.9.9") && stderr.contains("feed snapshot"),
        "provenance missing from --verbose: {stderr}"
    );
}
