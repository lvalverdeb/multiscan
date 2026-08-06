//! T-306 acceptance at the CLI boundary: FR-012 — `db export` on machine A,
//! `db import` on machine B, then B scans offline with identical results.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

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
            kev_json: b"{\"vulnerabilities\":[{\"cveID\":\"CVE-2021-23337\"}]}".to_vec(),
            epss_csv: b"cve,epss,percentile\nCVE-2021-23337,0.6,0.97\n".to_vec(),
            osv_jsonl: osv,
            rule_packs: std::collections::BTreeMap::new(),
            counts: SnapshotCounts {
                kev: 1,
                epss: 1,
                osv: counts,
            },
            sources: BTreeMap::new(),
        },
        Utc::now(),
    )
    .unwrap();
}

fn multiscan(cache: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("binary runs")
}

fn write_lock(project: &Path) {
    std::fs::write(
        project.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();
}

/// FR-012: A exports, B imports, B scans offline → identical scan output.
#[test]
fn airgap_export_import_scan_identical() {
    let cache_a = tempfile::tempdir().unwrap();
    let cache_b = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let bundle = work.path().join("feeds.tar.zst");

    // Machine A has feeds; export a signed bundle.
    seed(cache_a.path());
    let export = multiscan(
        cache_a.path(),
        work.path(),
        &["db", "export", "--out", bundle.to_str().unwrap()],
    );
    assert_eq!(
        export.status.code(),
        Some(0),
        "export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert!(bundle.exists());

    // Machine B is air-gapped and empty; import the bundle.
    let import = multiscan(
        cache_b.path(),
        work.path(),
        &["db", "import", bundle.to_str().unwrap()],
    );
    assert_eq!(
        import.status.code(),
        Some(0),
        "import failed: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    // Both machines scan the same project offline; output must be identical.
    let project_a = tempfile::tempdir().unwrap();
    let project_b = tempfile::tempdir().unwrap();
    write_lock(project_a.path());
    write_lock(project_b.path());

    let scan_a = multiscan(
        cache_a.path(),
        project_a.path(),
        &[
            "scan",
            ".",
            "--layers",
            "sca",
            "--offline",
            "--no-store",
            "--format",
            "json",
        ],
    );
    let scan_b = multiscan(
        cache_b.path(),
        project_b.path(),
        &[
            "scan",
            ".",
            "--layers",
            "sca",
            "--offline",
            "--no-store",
            "--format",
            "json",
        ],
    );
    assert_eq!(scan_a.status.code(), Some(0));
    assert_eq!(scan_b.status.code(), Some(0));
    // FR-012: byte-identical machine output.
    assert_eq!(scan_a.stdout, scan_b.stdout);
    // And it actually found the vulnerability (not identical-but-empty).
    let findings: serde_json::Value = serde_json::from_slice(&scan_b.stdout).unwrap();
    assert_eq!(findings.as_array().unwrap().len(), 1);
    assert_eq!(
        findings[0]["identity"]["advisory_id"],
        "GHSA-35jh-r3h4-6jhm"
    );
}
