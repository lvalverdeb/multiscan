//! T-303 acceptance at the CLI boundary: `scan --format sarif` piped through
//! `import` preserves the key fields (FR-013), and `import` handles foreign
//! SARIF.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

fn run(project: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .current_dir(project)
        .args(args)
        .output()
        .expect("binary runs")
}

/// End-to-end: scan → SARIF file → import → json; the finding survives.
#[test]
fn scan_export_import_round_trip() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.tf"),
        "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}\n",
    )
    .unwrap();

    // Scan to SARIF.
    let scan = run(
        project.path(),
        &[
            "scan",
            ".",
            "--layers",
            "iac",
            "--offline",
            "--no-store",
            "--format",
            "sarif",
        ],
    );
    assert_eq!(scan.status.code(), Some(0));
    let sarif_path = project.path().join("out.sarif");
    std::fs::write(&sarif_path, &scan.stdout).unwrap();

    // Re-import as json.
    let imported = run(project.path(), &["import", "out.sarif", "--format", "json"]);
    assert_eq!(imported.status.code(), Some(0));
    let scanned: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let reimported: serde_json::Value = serde_json::from_slice(&imported.stdout).unwrap();

    // The SARIF results and the re-imported findings describe the same set.
    let sarif_ids: Vec<&str> = scanned["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r["partialFingerprints"]["multiscan/findingId"]
                .as_str()
                .unwrap()
        })
        .collect();
    let imported_ids: Vec<&str> = reimported
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["finding_id"].as_str().unwrap())
        .collect();
    assert_eq!(sarif_ids, imported_ids);
    // Severity, location, sources survive (FR-013).
    let f = &reimported[0];
    assert_eq!(f["severity"], "high");
    assert_eq!(f["location"]["path"], "main.tf");
    assert!(f["sources"][0]["engine_id"]
        .as_str()
        .unwrap()
        .starts_with("multiscan.iac"));
}

/// import surfaces an unrecognized format as a usage error.
#[test]
fn import_rejects_unknown_format() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("junk.json"), "{\"hello\":1}").unwrap();
    let out = run(project.path(), &["import", "junk.json"]);
    assert_eq!(out.status.code(), Some(2));
}
