//! T-204 acceptance at the CLI boundary: FR-006 (a public S3 bucket in
//! Terraform yields a Finding with at least one CIS control), plus IAC-003
//! (unresolved interpolation → Heuristic, not a silent pass).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

fn scan_json(project: &Path) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(project)
        .args([
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");
    serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
}

/// FR-006: public S3 bucket → Finding with ≥1 CIS control mapping.
#[test]
fn public_s3_bucket_flagged_with_cis_control() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.tf"),
        r#"
resource "aws_s3_bucket" "data" {
  bucket = "public-data"
  acl    = "public-read"
}
"#,
    )
    .unwrap();

    let findings = scan_json(project.path());
    let arr = findings.as_array().unwrap();
    let s3 = arr
        .iter()
        .find(|f| f["identity"]["policy_id"] == "cis-aws-s3-public-acl")
        .expect("public S3 ACL finding");
    // ≥1 CIS control mapping present in evidence detail.
    let controls = s3["evidence"][0]["detail"]["compliance_controls"]
        .as_array()
        .unwrap();
    assert!(controls
        .iter()
        .any(|c| c.as_str().unwrap().starts_with("CIS-")));
    assert_eq!(s3["severity"], "high");
    assert_eq!(s3["confidence"], "corroborated");
}

/// IAC-003: an unresolved interpolation on the checked attribute degrades to a
/// Heuristic finding, never a silent pass.
#[test]
fn unresolved_interpolation_is_heuristic() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.tf"),
        r#"
variable "acl" { default = "public-read" }
resource "aws_s3_bucket" "data" {
  acl = var.acl
}
"#,
    )
    .unwrap();

    let findings = scan_json(project.path());
    let arr = findings.as_array().unwrap();
    let s3 = arr
        .iter()
        .find(|f| f["identity"]["policy_id"] == "cis-aws-s3-public-acl")
        .expect("heuristic S3 finding");
    assert_eq!(s3["confidence"], "heuristic");
}

/// A private, encrypted bucket produces no S3-ACL finding.
#[test]
fn private_bucket_no_acl_finding() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.tf"),
        r#"
resource "aws_s3_bucket" "data" {
  acl = "private"
  server_side_encryption_configuration {
    rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
  }
}
"#,
    )
    .unwrap();

    let findings = scan_json(project.path());
    let arr = findings.as_array().unwrap();
    assert!(!arr
        .iter()
        .any(|f| f["identity"]["policy_id"] == "cis-aws-s3-public-acl"));
}

/// A privileged Kubernetes Pod is flagged via the YAML path.
#[test]
fn privileged_pod_flagged() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("pod.yaml"),
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  securityContext:\n    privileged: true\n",
    )
    .unwrap();

    let findings = scan_json(project.path());
    let arr = findings.as_array().unwrap();
    assert!(arr
        .iter()
        .any(|f| f["identity"]["policy_id"] == "cis-k8s-privileged-container"));
}
