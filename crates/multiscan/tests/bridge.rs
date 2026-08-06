//! T-305 acceptance at the CLI boundary: FR-004 cross-engine dedup — a native
//! SCA finding and an imported Trivy report of the same package merge into one
//! Finding with two sources and confidence ≥ Corroborated (7.7.5).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use chrono::Utc;
use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};

const ADVISORY: &str = r#"{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command injection","aliases":["CVE-2021-23337"],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;

fn seed(cache: &Path) {
    let mut osv = BTreeMap::new();
    osv.insert("npm".to_string(), format!("{ADVISORY}\n").into_bytes());
    let mut counts = BTreeMap::new();
    counts.insert("npm".to_string(), 1u64);
    write_snapshot(
        cache,
        &SnapshotData {
            kev_json: b"{\"vulnerabilities\":[]}".to_vec(),
            epss_csv: b"cve,epss,percentile\n".to_vec(),
            osv_jsonl: osv,
            rule_packs: std::collections::BTreeMap::new(),
            counts: SnapshotCounts {
                kev: 0,
                epss: 0,
                osv: counts,
            },
            sources: BTreeMap::new(),
        },
        Utc::now(),
    )
    .unwrap();
}

/// FR-004: native SCA + Trivy import of the same package → one Finding, two
/// sources, confidence ≥ Corroborated.
#[test]
fn native_and_trivy_merge_into_one_corroborated_finding() {
    let cache = tempfile::tempdir().unwrap();
    seed(cache.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();
    // A Trivy report flagging the same package + advisory + lockfile — same
    // identity, so it must merge with the native finding.
    std::fs::write(
        project.path().join("trivy.json"),
        r#"{"SchemaVersion":2,"Results":[{"Target":"package-lock.json","Type":"npm",
          "Vulnerabilities":[{"VulnerabilityID":"GHSA-35jh-r3h4-6jhm","PkgName":"lodash",
          "InstalledVersion":"4.17.20","FixedVersion":"4.17.21","Severity":"HIGH"}]}]}"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache.path())
        .current_dir(project.path())
        .args([
            "scan",
            ".",
            "--layers",
            "sca",
            "--offline",
            "--no-store",
            "--import",
            "trivy.json",
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();

    // One merged Finding, not two.
    assert_eq!(
        arr.len(),
        1,
        "native + import of same package must dedup to one"
    );
    let f = &arr[0];
    let sources = f["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 2, "two sources after merge (FR-004)");
    let engines: Vec<&str> = sources
        .iter()
        .map(|s| s["engine_id"].as_str().unwrap())
        .collect();
    assert!(engines.contains(&"multiscan.sca"));
    assert!(engines.iter().any(|e| e.starts_with("external:trivy")));
    // 7.7.5: two distinct engines escalate to at least Corroborated.
    assert!(matches!(
        f["confidence"].as_str(),
        Some("corroborated") | Some("proven")
    ));
}

/// scan --import with an unrelated Trivy package adds a second, distinct
/// finding rather than merging (near-miss).
#[test]
fn different_package_does_not_merge() {
    let cache = tempfile::tempdir().unwrap();
    seed(cache.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("trivy.json"),
        r#"{"SchemaVersion":2,"Results":[{"Target":"package-lock.json","Type":"npm",
          "Vulnerabilities":[{"VulnerabilityID":"CVE-OTHER","PkgName":"express",
          "InstalledVersion":"4.0.0","Severity":"MEDIUM"}]}]}"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache.path())
        .current_dir(project.path())
        .args([
            "scan",
            ".",
            "--layers",
            "sca",
            "--offline",
            "--no-store",
            "--import",
            "trivy.json",
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // Native lodash finding + imported express finding = two distinct.
    assert_eq!(findings.as_array().unwrap().len(), 2);
}
