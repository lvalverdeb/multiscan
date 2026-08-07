//! T-201 acceptance: end-to-end `update` against a loopback fixture server
//! (never a real host, spec 16), snapshot round-trip with digest
//! verification, and corruption detection.

// Test-support helpers outside #[test] fns; the in-tests clippy allowance
// does not reach them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;

use chrono::TimeZone;
use multiscan_feeds::{
    current_snapshot, update, write_snapshot, FeedClient, FeedSources, SnapshotCounts, SnapshotData,
};

const KEV_FIXTURE: &str = r#"{"title":"KEV","catalogVersion":"2026.08.05","vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache"}]}"#;
const EPSS_FIXTURE: &str =
    "#score_date:2026-08-05\ncve,epss,percentile\nCVE-2021-44228,0.97565,0.99988\n";

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn osv_zip() -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut buffer);
    let options = zip::write::SimpleFileOptions::default();
    // Deliberately unsorted names and pretty-printed JSON: update() must
    // normalize to sorted, compact JSONL.
    writer.start_file("ZZZ-2026-2.json", options).unwrap();
    writer
        .write_all(b"{\n  \"id\": \"ZZZ-2026-2\",\n  \"summary\": \"b\"\n}")
        .unwrap();
    writer.start_file("AAA-2026-1.json", options).unwrap();
    writer
        .write_all(b"{\"id\":\"AAA-2026-1\",\"summary\":\"a\"}")
        .unwrap();
    writer.start_file("README.md", options).unwrap();
    writer.write_all(b"not an advisory").unwrap();
    writer.finish().unwrap();
    buffer.into_inner()
}

/// Minimal single-threaded HTTP/1.1 fixture server; serves each request from
/// a path → body map until dropped.
fn serve(routes: BTreeMap<String, Vec<u8>>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut request = [0u8; 4096];
            let n = stream.read(&mut request).unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..n]).to_string();
            let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
            match routes.get(&path) {
                Some(body) => {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(body);
                }
                None if path == "/quit" => {
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
                    break;
                }
                None => {
                    let _ =
                        stream.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
                }
            }
        }
    });
    (base, handle)
}

fn stop(base: &str, handle: std::thread::JoinHandle<()>) {
    let _ = FeedClient::with_allowlist(["127.0.0.1".to_string()]).fetch(&format!("{base}/quit"));
    let _ = handle.join();
}

#[test]
fn update_writes_pinned_snapshot_end_to_end() {
    let mut routes = BTreeMap::new();
    routes.insert("/kev.json".to_string(), KEV_FIXTURE.as_bytes().to_vec());
    routes.insert("/epss.csv.gz".to_string(), gzip(EPSS_FIXTURE.as_bytes()));
    routes.insert("/npm/all.zip".to_string(), osv_zip());
    let (base, handle) = serve(routes);

    let cache = tempfile::tempdir().unwrap();
    let client = FeedClient::with_allowlist(["127.0.0.1".to_string()]);
    let sources = FeedSources {
        kev_url: format!("{base}/kev.json"),
        epss_url: format!("{base}/epss.csv.gz"),
        osv_base_url: base.clone(),
        osv_ecosystems: vec!["npm".to_string()],
        rules_url: None,
    };
    let now = chrono::Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();

    let written = update(&client, &sources, cache.path(), now).unwrap();
    stop(&base, handle);

    // The snapshot is pinned and loadable.
    let snapshot = current_snapshot(cache.path()).unwrap().expect("pinned");
    assert_eq!(snapshot.manifest.snapshot_id, written.manifest.snapshot_id);
    assert!(snapshot.manifest.snapshot_id.starts_with("20260805-"));
    assert_eq!(snapshot.manifest.counts.kev, 1);
    assert_eq!(snapshot.manifest.counts.epss, 1);
    assert_eq!(snapshot.manifest.counts.osv["npm"], 2);

    // OSV normalized: sorted by entry name, compact, non-.json entry skipped.
    let jsonl = snapshot.read_file("osv/npm.jsonl").unwrap();
    let text = String::from_utf8(jsonl).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec![
            r#"{"id":"AAA-2026-1","summary":"a"}"#,
            r#"{"id":"ZZZ-2026-2","summary":"b"}"#,
        ]
    );

    // Enrichment loads with digest verification on the way.
    let enrichment = snapshot.enrichment().unwrap();
    assert!(enrichment.any_kev(&["CVE-2021-44228".to_string()]));
    assert!(
        enrichment
            .max_epss(&["CVE-2021-44228".to_string()])
            .unwrap()
            > 0.9
    );
}

#[test]
fn tampered_snapshot_file_is_detected() {
    let cache = tempfile::tempdir().unwrap();
    let now = chrono::Utc.with_ymd_and_hms(2026, 8, 5, 0, 0, 0).unwrap();
    let snapshot = write_snapshot(
        cache.path(),
        &SnapshotData {
            kev_json: KEV_FIXTURE.as_bytes().to_vec(),
            epss_csv: EPSS_FIXTURE.as_bytes().to_vec(),
            osv_jsonl: BTreeMap::new(),
            rule_packs: std::collections::BTreeMap::new(),
            counts: SnapshotCounts::default(),
            sources: BTreeMap::new(),
        },
        now,
    )
    .unwrap();

    // Tamper with a cached file (FD-002: digests must catch it).
    let kev_path = cache
        .path()
        .join("feeds/snapshots")
        .join(&snapshot.manifest.snapshot_id)
        .join("kev.json");
    std::fs::write(&kev_path, b"{\"vulnerabilities\":[]}").unwrap();

    let reloaded = current_snapshot(cache.path()).unwrap().unwrap();
    assert!(reloaded.read_file("kev.json").is_err());
}

#[test]
fn no_snapshot_is_none_not_error() {
    let cache = tempfile::tempdir().unwrap();
    assert!(current_snapshot(cache.path()).unwrap().is_none());
}

#[test]
fn identical_content_same_day_converges_on_one_snapshot_id() {
    let cache = tempfile::tempdir().unwrap();
    let now = chrono::Utc.with_ymd_and_hms(2026, 8, 5, 0, 0, 0).unwrap();
    let data = || SnapshotData {
        kev_json: KEV_FIXTURE.as_bytes().to_vec(),
        epss_csv: EPSS_FIXTURE.as_bytes().to_vec(),
        osv_jsonl: BTreeMap::new(),
        rule_packs: std::collections::BTreeMap::new(),
        counts: SnapshotCounts::default(),
        sources: BTreeMap::new(),
    };
    let first = write_snapshot(cache.path(), &data(), now).unwrap();
    let second = write_snapshot(cache.path(), &data(), now).unwrap();
    assert_eq!(first.manifest.snapshot_id, second.manifest.snapshot_id);
}

/// ADR 0010: with a rules_url configured, `update` fetches the secrets rule
/// pack into the snapshot as `rules/secrets.json`, digest-verified.
#[test]
fn update_fetches_rules_pack_into_snapshot() {
    const PACK: &str = r#"{"pack_id":"feed-secrets","version":"1.0.0","rules":[]}"#;
    let mut routes = BTreeMap::new();
    routes.insert("/kev.json".to_string(), KEV_FIXTURE.as_bytes().to_vec());
    routes.insert("/epss.csv.gz".to_string(), gzip(EPSS_FIXTURE.as_bytes()));
    routes.insert("/npm/all.zip".to_string(), osv_zip());
    routes.insert("/rules.json".to_string(), PACK.as_bytes().to_vec());
    let (base, handle) = serve(routes);

    let cache = tempfile::tempdir().unwrap();
    let client = FeedClient::with_allowlist(["127.0.0.1".to_string()]);
    let sources = FeedSources {
        kev_url: format!("{base}/kev.json"),
        epss_url: format!("{base}/epss.csv.gz"),
        osv_base_url: base.clone(),
        osv_ecosystems: vec!["npm".to_string()],
        rules_url: Some(format!("{base}/rules.json")),
    };
    let now = chrono::Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();

    update(&client, &sources, cache.path(), now).unwrap();
    stop(&base, handle);

    let snapshot = current_snapshot(cache.path()).unwrap().expect("pinned");
    let pack = snapshot
        .rule_pack("secrets")
        .expect("snapshot carries the rules pack")
        .expect("digest verifies");
    assert_eq!(
        pack,
        PACK.as_bytes(),
        "pack bytes round-trip through the snapshot"
    );
}
