//! T-304 acceptance: CycloneDX 1.5 SBOM from the SCA resolved graph (spec 12),
//! components + vulnerabilities, and byte-determinism (NFR-006). Hermetic:
//! snapshot seeded into an isolated cache.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use chrono::Utc;
use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};

const LODASH_ADVISORY: &str = r#"{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command injection","aliases":["CVE-2021-23337"],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;

fn seed(cache: &Path) {
    let mut osv = BTreeMap::new();
    osv.insert(
        "npm".to_string(),
        format!("{LODASH_ADVISORY}\n").into_bytes(),
    );
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

fn write_lock(project: &Path) {
    // Two components; one (lodash) is vulnerable.
    std::fs::write(
        project.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/express":{"version":"4.18.0"}}}"#,
    )
    .unwrap();
}

fn sbom(cache: &Path, project: &Path) -> (Vec<u8>, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(project)
        .args([
            "scan",
            ".",
            "--layers",
            "sca",
            "--offline",
            "--no-store",
            "--format",
            "sbom",
        ])
        .output()
        .expect("binary runs");
    let value = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    (out.stdout, value)
}

#[test]
fn sbom_lists_components_and_vulnerabilities() {
    let cache = tempfile::tempdir().unwrap();
    seed(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_lock(project.path());

    let (_bytes, doc) = sbom(cache.path(), project.path());
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert_eq!(doc["specVersion"], "1.5");

    // Both packages are components, sorted by purl.
    let components = doc["components"].as_array().unwrap();
    let purls: Vec<&str> = components
        .iter()
        .map(|c| c["purl"].as_str().unwrap())
        .collect();
    assert_eq!(
        purls,
        vec!["pkg:npm/express@4.18.0", "pkg:npm/lodash@4.17.20"]
    );
    assert_eq!(components[0]["type"], "library");
    assert_eq!(components[1]["name"], "lodash");
    assert_eq!(components[1]["version"], "4.17.20");

    // The vulnerable package produces a vulnerability entry (OUT-001).
    let vulns = doc["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0]["id"], "CVE-2021-23337");
    assert_eq!(vulns[0]["affects"][0]["ref"], "pkg:npm/lodash@4.17.20");
    assert_eq!(vulns[0]["ratings"][0]["severity"], "high");

    // Determinism: byte-identical across runs, and no random serialNumber /
    // timestamp (NFR-006).
    let obj = doc.as_object().unwrap();
    assert!(!obj.contains_key("serialNumber"));
    assert!(!obj.contains_key("metadata"));
}

#[test]
fn sbom_is_byte_deterministic() {
    let cache = tempfile::tempdir().unwrap();
    seed(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_lock(project.path());
    let (a, _) = sbom(cache.path(), project.path());
    let (b, _) = sbom(cache.path(), project.path());
    assert_eq!(a, b, "SBOM must be byte-identical across runs (NFR-006)");
}

/// No lockfiles → a valid, empty SBOM.
#[test]
fn empty_project_yields_empty_sbom() {
    let cache = tempfile::tempdir().unwrap();
    seed(cache.path());
    let project = tempfile::tempdir().unwrap();
    let (_bytes, doc) = sbom(cache.path(), project.path());
    assert_eq!(doc["components"].as_array().unwrap().len(), 0);
    assert!(doc.get("vulnerabilities").is_none());
}
