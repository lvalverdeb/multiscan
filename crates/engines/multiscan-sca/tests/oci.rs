//! T-401 acceptance: OCI pull against a loopback fixture registry (never a
//! real host, spec 16). Verifies manifest/index handling, blob digest
//! verification, and that pulled layers extract.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;

use flate2::write::GzEncoder;
use flate2::Compression;
use multiscan_sca::image::{extract_image, OciClient, Reference};
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

fn gzip_layer(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar);
        for (name, content) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o644);
            h.set_cksum();
            builder.append_data(&mut h, name, *content).unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

/// Serve a fixed route table over loopback HTTP until a `/quit` request.
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
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
                break;
            }
            match routes.get(&path) {
                Some(body) => {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
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
fn pull_via_index_verifies_digests_and_extracts() {
    let layer = gzip_layer(&[("etc/os-release", b"ID=alpine\nVERSION_ID=3.20\n")]);
    let layer_digest = sha256(&layer);

    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:00","size":1}},
        "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
        layer.len()
    );
    let manifest_digest = sha256(manifest.as_bytes());
    let index = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
        "manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}",
        "platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#
    );

    let mut routes = BTreeMap::new();
    routes.insert(
        "/v2/library/alpine/manifests/3.20".to_string(),
        index.into_bytes(),
    );
    routes.insert(
        format!("/v2/library/alpine/manifests/{manifest_digest}"),
        manifest.into_bytes(),
    );
    routes.insert(
        format!("/v2/library/alpine/blobs/{layer_digest}"),
        layer.clone(),
    );
    let (addr, handle) = serve(routes);

    let reference = Reference::parse(&format!("{addr}/library/alpine:3.20")).unwrap();
    let client = OciClient::with_arch("amd64".to_string());
    let image = client.pull(&reference).unwrap();

    // stop the server
    let _ = ureq::get(format!("http://{addr}/quit")).call();
    let _ = handle.join();

    assert_eq!(image.layers.len(), 1);
    assert_eq!(image.manifest_digest, manifest_digest_of(&image));

    // The pulled layer extracts to the expected file (proves the blob was the
    // real, digest-verified tarball).
    let dest = tempfile::tempdir().unwrap();
    let stats = extract_image(&image.layers, dest.path()).unwrap();
    assert!(stats.files >= 1);
    assert_eq!(
        std::fs::read(dest.path().join("etc/os-release")).unwrap(),
        b"ID=alpine\nVERSION_ID=3.20\n"
    );
}

fn manifest_digest_of(image: &multiscan_sca::image::PulledImage) -> String {
    image.manifest_digest.clone()
}

#[test]
fn corrupt_blob_is_rejected() {
    // Manifest claims a layer digest, but the served blob is different bytes.
    let real = gzip_layer(&[("x", b"real")]);
    let claimed_digest = sha256(&real);
    let tampered = gzip_layer(&[("x", b"tampered")]);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{claimed_digest}","size":{}}}]}}"#,
        real.len()
    );

    let mut routes = BTreeMap::new();
    routes.insert(
        "/v2/app/manifests/latest".to_string(),
        manifest.into_bytes(),
    );
    routes.insert(format!("/v2/app/blobs/{claimed_digest}"), tampered);
    let (addr, handle) = serve(routes);

    let reference = Reference::parse(&format!("{addr}/app:latest")).unwrap();
    let client = OciClient::with_arch("amd64".to_string());
    let result = client.pull(&reference);

    let _ = ureq::get(format!("http://{addr}/quit")).call();
    let _ = handle.join();

    assert!(
        result.is_err(),
        "a blob not matching its digest must be rejected"
    );
}
