//! T-306 acceptance: signed air-gap bundle round-trip (FR-012), signature
//! verification and tamper rejection (FD-005), and hardened import.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{TimeZone, Utc};
use multiscan_feeds::{
    current_snapshot, export_bundle, import_bundle, load_or_create_signing_key, public_key_bytes,
    write_snapshot, SnapshotCounts, SnapshotData,
};

fn seed(cache: &Path) -> String {
    let mut osv = BTreeMap::new();
    osv.insert("npm".to_string(), b"{\"id\":\"GHSA-1\"}\n".to_vec());
    let mut osv_counts = BTreeMap::new();
    osv_counts.insert("npm".to_string(), 1u64);
    let snapshot = write_snapshot(
        cache,
        &SnapshotData {
            kev_json: b"{\"vulnerabilities\":[{\"cveID\":\"CVE-1\"}]}".to_vec(),
            epss_csv: b"cve,epss,percentile\nCVE-1,0.5,0.9\n".to_vec(),
            osv_jsonl: osv,
            counts: SnapshotCounts {
                kev: 1,
                epss: 1,
                osv: osv_counts,
            },
            sources: BTreeMap::new(),
        },
        Utc.with_ymd_and_hms(2026, 8, 5, 0, 0, 0).unwrap(),
    )
    .unwrap();
    snapshot.manifest.snapshot_id
}

/// FR-012: export on A, import on B → B has the byte-identical snapshot.
#[test]
fn export_import_gives_identical_snapshot() {
    let machine_a = tempfile::tempdir().unwrap();
    let machine_b = tempfile::tempdir().unwrap();
    let bundle_dir = tempfile::tempdir().unwrap();
    let bundle = bundle_dir.path().join("bundle.tar.zst");

    let id_a = seed(machine_a.path());
    let key = load_or_create_signing_key(machine_a.path()).unwrap();
    let exported = export_bundle(machine_a.path(), &bundle, &key).unwrap();
    assert_eq!(exported, id_a);

    // B starts empty, imports the bundle.
    assert!(current_snapshot(machine_b.path()).unwrap().is_none());
    let id_b = import_bundle(machine_b.path(), &bundle, None).unwrap();

    // Content-addressed ids match — the data is identical (FR-012).
    assert_eq!(id_a, id_b);

    let snap_a = current_snapshot(machine_a.path()).unwrap().unwrap();
    let snap_b = current_snapshot(machine_b.path()).unwrap().unwrap();
    assert_eq!(snap_a.manifest, snap_b.manifest);
    // Enrichment loads identically (digest-verified on read).
    let en_a = snap_a.enrichment().unwrap();
    let en_b = snap_b.enrichment().unwrap();
    assert_eq!(en_a.counts(), en_b.counts());
    assert_eq!(
        snap_b.read_file("osv/npm.jsonl").unwrap(),
        b"{\"id\":\"GHSA-1\"}\n"
    );
}

/// FD-005: a bundle signed by an untrusted key is rejected when a trusted key
/// is required.
#[test]
fn trusted_key_mismatch_is_rejected() {
    let machine_a = tempfile::tempdir().unwrap();
    let machine_b = tempfile::tempdir().unwrap();
    let bundle = tempfile::tempdir().unwrap().path().join("b.tar.zst");
    let _ = std::fs::create_dir_all(bundle.parent().unwrap());

    seed(machine_a.path());
    let key = load_or_create_signing_key(machine_a.path()).unwrap();
    export_bundle(machine_a.path(), &bundle, &key).unwrap();

    // Import demanding a different signer must fail.
    let wrong = [0x11u8; 32];
    match import_bundle(machine_b.path(), &bundle, Some(wrong)) {
        Err(e) => assert!(e.to_string().contains("trusted-key"), "got {e}"),
        Ok(_) => panic!("expected trusted-key rejection"),
    }

    // Import demanding the correct signer succeeds.
    let right = public_key_bytes(&key);
    assert!(import_bundle(machine_b.path(), &bundle, Some(right)).is_ok());
}

/// FD-005: a tampered bundle fails signature verification.
#[test]
fn tampered_bundle_is_rejected() {
    let machine_a = tempfile::tempdir().unwrap();
    let machine_b = tempfile::tempdir().unwrap();
    let bundle = tempfile::tempdir().unwrap().path().join("b.tar.zst");
    let _ = std::fs::create_dir_all(bundle.parent().unwrap());

    seed(machine_a.path());
    let key = load_or_create_signing_key(machine_a.path()).unwrap();
    export_bundle(machine_a.path(), &bundle, &key).unwrap();

    // Flip bytes in the compressed bundle.
    let mut bytes = std::fs::read(&bundle).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    std::fs::write(&bundle, &bytes).unwrap();

    // Either the container fails to parse or the signature fails — both are
    // rejections, never a silent install.
    assert!(import_bundle(machine_b.path(), &bundle, None).is_err());
    assert!(current_snapshot(machine_b.path()).unwrap().is_none());
}
