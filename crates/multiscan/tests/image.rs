//! T-402 acceptance at the CLI boundary: `scan image` pulls a container image
//! from a loopback mock registry, extracts it, reads the dpkg package DB, and
//! resolves a vulnerable OS package against a seeded OSV Debian advisory
//! (FR-002 for images). Hermetic — no real host, isolated cache.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;
use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

/// openssl 1.1.1n-0+deb11u1 on Debian 11, fixed in ...u3.
const ADVISORY: &str = r#"{"id":"DSA-5169-1","summary":"openssl vulnerability","aliases":["CVE-2022-2068"],"database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"Debian:11","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.1.1n-0+deb11u3"}]}]}]}"#;

/// The openSUSE record for the xz backdoor, verbatim from the OSV bucket
/// (2026-08-13) but for its `summary`. Two properties are under test that the
/// Debian advisory above does not exercise: OSV names the release
/// `openSUSE:Tumbleweed` where `os-release` says `ID=opensuse-tumbleweed` with
/// an unrelated datestamp `VERSION_ID`, and the CVE is in `related`, not
/// `aliases` (ADR 0022, ADR 0023).
const XZ_ADVISORY: &str = r#"{"id":"openSUSE-SU-2024:14017-1","summary":"malicious code in the xz upstream tarballs","related":["CVE-2024-3094"],"upstream":["CVE-2024-3094"],"database_specific":{"severity":"CRITICAL"},"affected":[{"package":{"ecosystem":"openSUSE:Tumbleweed","name":"xz"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.6.2-1.1"}]}]}]}"#;

/// Seed a snapshot the way `db update` writes one after ADR 0022: base
/// ecosystem buckets, whose records carry the release-qualified ecosystem.
fn seed(cache: &Path) {
    let mut osv = BTreeMap::new();
    osv.insert("Debian".to_string(), format!("{ADVISORY}\n").into_bytes());
    osv.insert(
        "openSUSE".to_string(),
        format!("{XZ_ADVISORY}\n").into_bytes(),
    );
    let mut counts = BTreeMap::new();
    counts.insert("Debian".to_string(), 1u64);
    counts.insert("openSUSE".to_string(), 1u64);
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
            skipped_ecosystems: Default::default(),
        },
        Utc::now(),
    )
    .unwrap();
}

/// A single-layer image whose rootfs has an os-release and a dpkg status with a
/// vulnerable openssl.
fn image_layer() -> Vec<u8> {
    let dpkg = "Package: bash\nStatus: install ok installed\nVersion: 5.1-2+deb11u1\nArchitecture: amd64\n\nPackage: openssl\nStatus: install ok installed\nVersion: 1.1.1n-0+deb11u1\nArchitecture: amd64\n";
    let os_release =
        "PRETTY_NAME=\"Debian GNU/Linux 11 (bullseye)\"\nID=debian\nVERSION_ID=\"11\"\n";
    let mut tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar);
        for (name, content) in [
            ("etc/os-release", os_release.as_bytes()),
            ("var/lib/dpkg/status", dpkg.as_bytes()),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, content).unwrap();
        }
        b.finish().unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

/// A Wolfi image: an apk database, and an `os-release` with no `VERSION_ID`
/// at all — Wolfi is unversioned, and its OSV bucket is likewise `Wolfi` with
/// no release qualifier.
fn wolfi_layer() -> Vec<u8> {
    let apk = "C:Q1abc\nP:xz\nV:5.6.1-r0\nA:x86_64\n\nP:busybox\nV:1.36.1-r5\nA:x86_64\n";
    let os_release = "ID=wolfi\nNAME=\"Wolfi\"\nPRETTY_NAME=\"Wolfi\"\n";
    let mut tar = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar);
        for (name, content) in [
            ("etc/os-release", os_release.as_bytes()),
            ("lib/apk/db/installed", apk.as_bytes()),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, content).unwrap();
        }
        b.finish().unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

fn serve(routes: BTreeMap<String, Vec<u8>>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
            if path == "/quit" {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length:0\r\n\r\n");
                break;
            }
            match routes.get(&path) {
                Some(body) => {
                    let h = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(h.as_bytes());
                    let _ = stream.write_all(body);
                }
                None => {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length:0\r\n\r\n");
                }
            }
        }
    });
    (addr, handle)
}

#[test]
fn scan_image_finds_vulnerable_os_package() {
    let cache = tempfile::tempdir().unwrap();
    seed(cache.path());

    let layer = image_layer();
    let layer_digest = sha256(&layer);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
        layer.len()
    );

    let mut routes = BTreeMap::new();
    routes.insert(
        "/v2/library/debian/manifests/11".to_string(),
        manifest.into_bytes(),
    );
    routes.insert(format!("/v2/library/debian/blobs/{layer_digest}"), layer);
    let (addr, handle) = serve(routes);

    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache.path())
        .args([
            "scan",
            "image",
            &format!("{addr}/library/debian:11"),
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");

    let _ = ureq::get(format!("http://{addr}/quit")).call();
    let _ = handle.join();

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1, "expected one container vulnerability");
    let f = &arr[0];
    assert_eq!(f["identity"]["finding_class"], "container_vulnerability");
    assert_eq!(f["identity"]["advisory_id"], "CVE-2022-2068");
    assert_eq!(
        f["identity"]["purl"],
        "pkg:deb/debian/openssl@1.1.1n-0+deb11u1"
    );
    assert_eq!(f["severity"], "high");
    assert_eq!(f["remediation"]["fixed_version"], "1.1.1n-0+deb11u3");
}

/// ADR 0022/0023 at the CLI boundary, on the shape the lockfile ecosystems
/// never produce: an unversioned distro whose advisory carries its CVE in
/// `related` rather than `aliases`, resolved out of a base ecosystem bucket.
#[test]
fn scan_image_resolves_unversioned_distro_and_related_cve() {
    let cache = tempfile::tempdir().unwrap();
    // xz 5.6.1 — the backdoored release — installed on Wolfi.
    const WOLFI_ADVISORY: &str = r#"{"id":"CGA-8crc-r3gg-jr73","summary":"malicious code in the xz upstream tarballs","related":["CVE-2024-3094"],"upstream":["CVE-2024-3094"],"database_specific":{"severity":"CRITICAL"},"affected":[{"package":{"ecosystem":"Wolfi","name":"xz"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.6.2-r0"}]}]}]}"#;
    let mut osv = BTreeMap::new();
    osv.insert(
        "Wolfi".to_string(),
        format!("{WOLFI_ADVISORY}\n").into_bytes(),
    );
    let mut counts = BTreeMap::new();
    counts.insert("Wolfi".to_string(), 1u64);
    write_snapshot(
        cache.path(),
        &SnapshotData {
            kev_json: b"{\"vulnerabilities\":[]}".to_vec(),
            epss_csv: b"cve,epss,percentile\n".to_vec(),
            osv_jsonl: osv,
            rule_packs: BTreeMap::new(),
            counts: SnapshotCounts {
                kev: 0,
                epss: 0,
                osv: counts,
            },
            sources: BTreeMap::new(),
            skipped_ecosystems: Default::default(),
        },
        Utc::now(),
    )
    .unwrap();

    let layer = wolfi_layer();
    let layer_digest = sha256(&layer);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
        layer.len()
    );
    let mut routes = BTreeMap::new();
    routes.insert(
        "/v2/wolfi-base/manifests/latest".to_string(),
        manifest.into_bytes(),
    );
    routes.insert(format!("/v2/wolfi-base/blobs/{layer_digest}"), layer);
    let (addr, handle) = serve(routes);

    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache.path())
        .args([
            "scan",
            "image",
            &format!("{addr}/wolfi-base:latest"),
            "--format",
            "json",
        ])
        .output()
        .expect("binary runs");

    let _ = ureq::get(format!("http://{addr}/quit")).call();
    let _ = handle.join();

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let findings: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1, "expected one container vulnerability");
    let f = &arr[0];
    assert_eq!(f["identity"]["purl"], "pkg:apk/wolfi/xz@5.6.1-r0");
    // ADR 0023: identity keys on the CVE the record names in
    // `upstream`/`related`, not on the distro advisory id, so this finding
    // merges with any other source reporting the same weakness.
    assert_eq!(f["identity"]["advisory_id"], "CVE-2024-3094");
    // The CVE also reaches evidence, so KEV/EPSS enrichment can look it up.
    let cves = f["evidence"][0]["detail"]["cve_aliases"]
        .as_array()
        .unwrap();
    assert_eq!(cves, &vec![serde_json::json!("CVE-2024-3094")]);
    assert_eq!(f["remediation"]["fixed_version"], "5.6.2-r0");
}
