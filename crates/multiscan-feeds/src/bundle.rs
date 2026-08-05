//! Signed air-gap bundles (FR-012, FD-005). `export` packages the pinned feed
//! snapshot into a `.tar.zst` carrying an ed25519 signature over the manifest;
//! `import` verifies it and installs the snapshot on an air-gapped machine.
//!
//! The bundle is our own format, but it is still untrusted input on import:
//! extraction only accepts known entry names, and every size is capped
//! (SCA-005 discipline — no path traversal, no decompression bomb).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use crate::cache::{current_snapshot, write_snapshot, SnapshotData, SnapshotManifest};
use crate::signing::{self, public_key_bytes, sign, to_hex, verify};
use crate::FeedError;

use ed25519_dalek::SigningKey;

const MANIFEST_ENTRY: &str = "MANIFEST";
const SIGNATURE_ENTRY: &str = "SIGNATURE";
const SIGNER_ENTRY: &str = "SIGNER.pub";
const FILE_PREFIX: &str = "files/";

/// Caps for the untrusted import path.
const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

fn io<E: std::fmt::Display>(e: E) -> FeedError {
    FeedError::Corrupt(e.to_string())
}

/// Export the current pinned snapshot to `out_path`, signed with `key`.
/// Returns the snapshot id that was exported.
pub fn export(cache: &Path, out_path: &Path, key: &SigningKey) -> Result<String, FeedError> {
    let snapshot = current_snapshot(cache)?
        .ok_or_else(|| FeedError::Corrupt("no feed snapshot to export".to_string()))?;

    // Sign the manifest — it carries every file's digest, so a valid signature
    // over it plus digest-checked extraction covers the whole payload.
    let manifest_bytes = serde_json::to_vec(&snapshot.manifest)
        .map_err(|e| FeedError::Corrupt(format!("manifest serialize: {e}")))?;
    let signature = sign(key, &manifest_bytes);
    let public_key = public_key_bytes(key);

    // Build the tar in memory: control entries + snapshot files.
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        append(&mut builder, MANIFEST_ENTRY, &manifest_bytes)?;
        append(&mut builder, SIGNATURE_ENTRY, to_hex(&signature).as_bytes())?;
        append(&mut builder, SIGNER_ENTRY, to_hex(&public_key).as_bytes())?;
        for name in snapshot.manifest.files.keys() {
            let bytes = snapshot.read_file(name)?; // digest-verified read
            append(&mut builder, &format!("{FILE_PREFIX}{name}"), &bytes)?;
        }
        builder.finish().map_err(io)?;
    }

    let compressed = zstd::stream::encode_all(tar_buf.as_slice(), 19).map_err(io)?;
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, compressed)?;
    Ok(snapshot.manifest.snapshot_id)
}

fn append<W: Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    bytes: &[u8],
) -> Result<(), FeedError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, name, bytes).map_err(io)
}

/// Import a bundle: verify its signature, then install the snapshot into the
/// cache as the current one. With `trusted`, the embedded public key must
/// match (authenticity); without it, the signature only proves integrity.
/// Returns the installed snapshot id.
pub fn import(
    cache: &Path,
    bundle_path: &Path,
    trusted: Option<[u8; 32]>,
) -> Result<String, FeedError> {
    let compressed = std::fs::read(bundle_path)?;
    if compressed.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(FeedError::TooLarge("bundle file".to_string()));
    }

    // Bounded decompression (no zstd bomb).
    let mut decoder = zstd::stream::read::Decoder::new(compressed.as_slice())
        .map_err(io)?
        .take(MAX_DECOMPRESSED_BYTES + 1);
    let mut tar_bytes = Vec::new();
    decoder.read_to_end(&mut tar_bytes).map_err(io)?;
    if tar_bytes.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(FeedError::TooLarge("decompressed bundle".to_string()));
    }

    // Hardened untar into memory: only accept known/relative names.
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    let mut count = 0usize;
    for entry in archive.entries().map_err(io)? {
        let mut entry = entry.map_err(io)?;
        count += 1;
        if count > MAX_ENTRIES {
            return Err(FeedError::TooLarge("bundle entry count".to_string()));
        }
        let path = entry.path().map_err(io)?;
        let name = path
            .to_str()
            .ok_or_else(|| FeedError::Corrupt("non-UTF-8 entry name".to_string()))?
            .to_string();
        if name.contains("..") || name.starts_with('/') || name.contains('\\') {
            return Err(FeedError::Corrupt(format!("unsafe bundle entry `{name}`")));
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(io)?;
        entries.insert(name, data);
    }

    // Verify the signature over the manifest.
    let manifest_bytes = entries
        .get(MANIFEST_ENTRY)
        .ok_or_else(|| FeedError::Corrupt("bundle missing MANIFEST".to_string()))?;
    let signer_hex = entries
        .get(SIGNER_ENTRY)
        .ok_or_else(|| FeedError::Corrupt("bundle missing SIGNER.pub".to_string()))?;
    let signature_hex = entries
        .get(SIGNATURE_ENTRY)
        .ok_or_else(|| FeedError::Corrupt("bundle missing SIGNATURE".to_string()))?;

    let public_key: [u8; 32] = signing::decode_hex(std::str::from_utf8(signer_hex).map_err(io)?)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| FeedError::Corrupt("bad SIGNER.pub".to_string()))?;
    let signature: [u8; 64] = signing::decode_hex(std::str::from_utf8(signature_hex).map_err(io)?)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| FeedError::Corrupt("bad SIGNATURE".to_string()))?;

    if let Some(trusted_key) = trusted {
        if public_key != trusted_key {
            return Err(FeedError::Corrupt(
                "bundle signer does not match --trusted-key".to_string(),
            ));
        }
    }
    if !verify(&public_key, manifest_bytes, &signature) {
        return Err(FeedError::Corrupt(
            "bundle signature verification failed".to_string(),
        ));
    }

    // Reconstruct the snapshot from the manifest + files and install it. The
    // content-addressed id will match the exporter's (FR-012).
    let manifest: SnapshotManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| FeedError::Corrupt(format!("manifest: {e}")))?;

    let take = |name: &str| -> Result<Vec<u8>, FeedError> {
        entries
            .get(&format!("{FILE_PREFIX}{name}"))
            .cloned()
            .ok_or_else(|| FeedError::Corrupt(format!("bundle missing file {name}")))
    };
    let mut osv_jsonl = BTreeMap::new();
    for name in manifest.files.keys() {
        if let Some(eco) = name
            .strip_prefix("osv/")
            .and_then(|n| n.strip_suffix(".jsonl"))
        {
            osv_jsonl.insert(eco.to_string(), take(name)?);
        }
    }
    let data = SnapshotData {
        kev_json: take("kev.json")?,
        epss_csv: take("epss.csv")?,
        osv_jsonl,
        counts: manifest.counts.clone(),
        sources: manifest.sources.clone(),
    };
    let installed = write_snapshot(cache, &data, manifest.as_of)?;
    Ok(installed.manifest.snapshot_id)
}
