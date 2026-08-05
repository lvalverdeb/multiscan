//! T-305: importer unit tests — each tool parses to the right identity class,
//! declares a severity map (BRG-002), attributes the tool (BRG-001), and keeps
//! unknown ids namespaced (BRG-003).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use multiscan_bridge::{detect, import, Format};
use multiscan_core::{IdentityKey, Severity};

#[test]
fn trivy_imports_vulnerable_dependency() {
    let json = r#"{
      "SchemaVersion": 2,
      "Results": [{
        "Target": "package-lock.json",
        "Type": "npm",
        "Vulnerabilities": [{
          "VulnerabilityID": "GHSA-35jh-r3h4-6jhm",
          "PkgName": "lodash",
          "InstalledVersion": "4.17.20",
          "FixedVersion": "4.17.21",
          "Severity": "HIGH"
        }]
      }]
    }"#;
    assert_eq!(detect(json.as_bytes()), Some(Format::Trivy));
    let findings = import(json.as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.sources[0].engine_id, "external:trivy");
    match &f.identity {
        IdentityKey::VulnerableDependency {
            purl,
            advisory_id,
            manifest_path,
        } => {
            assert_eq!(purl, "pkg:npm/lodash@4.17.20");
            assert_eq!(advisory_id, "GHSA-35jh-r3h4-6jhm");
            assert_eq!(manifest_path, "package-lock.json");
        }
        other => panic!("expected VulnerableDependency, got {other:?}"),
    }
    assert_eq!(
        f.remediation.as_ref().unwrap().fixed_version.as_deref(),
        Some("4.17.21")
    );
}

#[test]
fn semgrep_imports_structural_pattern() {
    let json = r#"{
      "results": [{
        "check_id": "python.lang.security.sqli",
        "path": "app/db.py",
        "start": { "line": 12 },
        "extra": { "severity": "ERROR", "message": "SQL injection", "metadata": { "cwe": ["CWE-89"] } }
      }],
      "errors": []
    }"#;
    assert_eq!(detect(json.as_bytes()), Some(Format::Semgrep));
    let findings = import(json.as_bytes()).unwrap();
    let f = &findings[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.sources[0].engine_id, "external:semgrep");
    assert_eq!(f.location.line, Some(12));
    assert!(matches!(f.identity, IdentityKey::StructuralPattern { .. }));
    assert_eq!(f.cwe, vec!["CWE-89"]);
}

#[test]
fn checkov_imports_iac_misconfiguration() {
    let json = r#"{
      "check_type": "terraform",
      "results": {
        "failed_checks": [{
          "check_id": "CKV_AWS_20",
          "check_name": "S3 Bucket has an ACL defined which allows public access",
          "file_path": "/main.tf",
          "resource": "aws_s3_bucket.data",
          "severity": "HIGH"
        }]
      }
    }"#;
    assert_eq!(detect(json.as_bytes()), Some(Format::Checkov));
    let f = &import(json.as_bytes()).unwrap()[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.sources[0].engine_id, "external:checkov");
    match &f.identity {
        IdentityKey::IacMisconfiguration {
            policy_id,
            resource_address,
            ..
        } => {
            assert_eq!(policy_id, "CKV_AWS_20");
            assert_eq!(resource_address, "aws_s3_bucket.data");
        }
        other => panic!("expected IacMisconfiguration, got {other:?}"),
    }
}

#[test]
fn checkov_missing_severity_defaults_medium() {
    let json = r#"{"check_type":"terraform","results":{"failed_checks":[
      {"check_id":"CKV_AWS_1","file_path":"/a.tf","resource":"r.x"}]}}"#;
    let f = &import(json.as_bytes()).unwrap()[0];
    // BRG-002: documented default when the tool omits severity.
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn zap_imports_web_exposure() {
    let json = r#"{
      "site": [{
        "@name": "https://staging.example.com",
        "alerts": [{
          "pluginid": "40012",
          "alert": "Cross Site Scripting (Reflected)",
          "riskcode": "3",
          "cweid": "79",
          "instances": [{ "uri": "https://staging.example.com/search" }]
        }]
      }]
    }"#;
    assert_eq!(detect(json.as_bytes()), Some(Format::Zap));
    let f = &import(json.as_bytes()).unwrap()[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.sources[0].engine_id, "external:zap");
    assert_eq!(f.cwe, vec!["CWE-79"]);
    match &f.identity {
        IdentityKey::WebExposure {
            template_id,
            origin,
            request_path,
        } => {
            assert_eq!(template_id, "40012");
            assert_eq!(origin, "https://staging.example.com");
            assert_eq!(request_path, "/search");
        }
        other => panic!("expected WebExposure, got {other:?}"),
    }
}

/// BRG-003: an importer's tool namespace keeps a foreign rule id distinct — two
/// tools reporting id "X" never collide because engine_id differs.
#[test]
fn tool_namespacing_keeps_sources_distinct() {
    let trivy = r#"{"SchemaVersion":2,"Results":[{"Target":"go.mod","Type":"gomod",
      "Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"x","InstalledVersion":"1.0.0","Severity":"LOW"}]}]}"#;
    let f = &import(trivy.as_bytes()).unwrap()[0];
    assert!(f.sources[0].engine_id.starts_with("external:trivy"));
    assert_eq!(f.sources[0].rule_id.as_deref(), Some("CVE-1"));
}
