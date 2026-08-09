//! `T-901` / `FR-018`: the opt-in freshness path, against a loopback fixture.
//!
//! Never a real host (CLAUDE.md): a local server serves recorded OSV-shaped
//! responses, and the client is built with a loopback allow-list.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;

use multiscan_feeds::{query_freshness, FeedClient};

/// Serve one canned JSON body to one request, then stop.
fn serve(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}/v1/querybatch")
}

fn client() -> FeedClient {
    FeedClient::with_allowlist(["127.0.0.1".to_string()])
}

#[test]
fn advisories_are_attributed_to_the_right_package() {
    // Results are positional; misalignment would attribute a CVE to a package
    // that does not have it.
    let url = serve(r#"{"results":[{"vulns":[{"id":"GHSA-aaa"}]},{},{"vulns":[{"id":"CVE-2"}]}]}"#);
    let purls = vec![
        "pkg:npm/a@1".to_string(),
        "pkg:npm/b@2".to_string(),
        "pkg:npm/c@3".to_string(),
    ];
    let fresh = query_freshness(&client(), &url, &purls).unwrap();

    assert_eq!(
        fresh.by_purl.len(),
        2,
        "the empty result contributes nothing"
    );
    assert!(fresh.by_purl["pkg:npm/a@1"].contains("GHSA-aaa"));
    assert!(fresh.by_purl["pkg:npm/c@3"].contains("CVE-2"));
    assert!(!fresh.by_purl.contains_key("pkg:npm/b@2"));
    assert_eq!(fresh.skipped, 0);
}

#[test]
fn input_is_deduplicated_and_ordered() {
    // Same input, same batches, same result — DET-001 through a network path.
    let url = serve(r#"{"results":[{"vulns":[{"id":"CVE-1"}]}]}"#);
    let purls = vec![
        "pkg:npm/a@1".to_string(),
        "pkg:npm/a@1".to_string(),
        "pkg:npm/a@1".to_string(),
    ];
    let fresh = query_freshness(&client(), &url, &purls).unwrap();
    assert_eq!(fresh.by_purl.len(), 1);
}

#[test]
fn a_non_allow_listed_host_is_refused_before_any_packet() {
    // R-6: the freshness path is still allow-listed feed traffic.
    let restricted = FeedClient::with_allowlist(["api.osv.dev".to_string()]);
    let err = query_freshness(
        &restricted,
        "https://evil.test/v1/querybatch",
        &["pkg:npm/a@1".to_string()],
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("evil.test"),
        "refused by host, got: {err}"
    );
}

#[test]
fn an_empty_input_makes_no_request() {
    // Nothing to ask about is not a reason to contact anyone.
    let unreachable = FeedClient::with_allowlist(["127.0.0.1".to_string()]);
    let fresh = query_freshness(&unreachable, "http://127.0.0.1:1/v1/querybatch", &[]).unwrap();
    assert!(fresh.by_purl.is_empty());
}
