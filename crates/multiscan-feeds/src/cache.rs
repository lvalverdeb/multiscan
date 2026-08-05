//! Snapshot cache under the platform cache directory (FD-001, FD-002).
//!
//! Layout:
//! ```text
//! <cache>/feeds/
//!   CURRENT                          — file containing the pinned snapshot id
//!   snapshots/<snapshot_id>/
//!     manifest.json                  — as_of, per-file digests, counts, sources
//!     kev.json                       — CISA KEV catalog, as fetched
//!     epss.csv                       — EPSS scores, gunzipped
//!     osv/<ecosystem>.jsonl          — one advisory per line, entry-name order
//! ```
//! Snapshots are written to a staging directory and renamed into place, then
//! `CURRENT` flips atomically — a crashed update never corrupts the pinned
//! snapshot.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::FeedError;

/// Resolve the cache root (FD-001): `MULTISCAN_CACHE_DIR` override (tests,
/// unusual setups) → `XDG_CACHE_HOME/multiscan` → `~/.cache/multiscan`.
pub fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MULTISCAN_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return Path::new(&xdg).join("multiscan");
    }
    match std::env::var("HOME") {
        Ok(home) => Path::new(&home).join(".cache/multiscan"),
        // No HOME (odd CI container): a local dot-directory beats failing.
        Err(_) => PathBuf::from(".multiscan-cache"),
    }
}

/// Digest and size of one file in a snapshot (FD-002).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMeta {
    /// `blake3:<hex>` of the file content.
    pub digest: String,
    /// Size in bytes.
    pub bytes: u64,
}

/// Entry counts per feed, for `db status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotCounts {
    /// KEV catalog entries.
    pub kev: u64,
    /// EPSS score rows.
    pub epss: u64,
    /// OSV advisories per ecosystem.
    pub osv: BTreeMap<String, u64>,
}

/// The manifest pinned by a Scan (FD-002).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// Content-derived id: `<date>-<12 hex of combined digest>`.
    pub snapshot_id: String,
    /// When the data was fetched (RFC 3339).
    pub as_of: DateTime<Utc>,
    /// Relative file path → digest and size.
    pub files: BTreeMap<String, FileMeta>,
    /// Entry counts for status display.
    pub counts: SnapshotCounts,
    /// Feed name → source URL the data came from.
    pub sources: BTreeMap<String, String>,
}

/// A loaded, pinned snapshot.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// The manifest.
    pub manifest: SnapshotManifest,
    dir: PathBuf,
}

/// Payload for writing a new snapshot.
pub struct SnapshotData {
    /// Raw KEV catalog JSON.
    pub kev_json: Vec<u8>,
    /// Gunzipped EPSS CSV.
    pub epss_csv: Vec<u8>,
    /// Ecosystem → JSONL advisory content.
    pub osv_jsonl: BTreeMap<String, Vec<u8>>,
    /// Entry counts.
    pub counts: SnapshotCounts,
    /// Feed name → source URL.
    pub sources: BTreeMap<String, String>,
}

fn feeds_dir(cache: &Path) -> PathBuf {
    cache.join("feeds")
}

fn digest_of(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

/// Load the currently pinned snapshot, if any. Corrupt state is an error,
/// never silently ignored (FD-004 spirit).
pub fn current_snapshot(cache: &Path) -> Result<Option<Snapshot>, FeedError> {
    let current_file = feeds_dir(cache).join("CURRENT");
    let snapshot_id = match std::fs::read_to_string(&current_file) {
        Ok(id) => id.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if snapshot_id.is_empty() || snapshot_id.contains(['/', '\\', '.']) {
        return Err(FeedError::Corrupt(format!(
            "CURRENT contains an invalid snapshot id `{snapshot_id}`"
        )));
    }
    let dir = feeds_dir(cache).join("snapshots").join(&snapshot_id);
    let manifest_bytes = std::fs::read(dir.join("manifest.json"))
        .map_err(|e| FeedError::Corrupt(format!("snapshot {snapshot_id}: manifest: {e}")))?;
    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| FeedError::Corrupt(format!("snapshot {snapshot_id}: manifest: {e}")))?;
    if manifest.snapshot_id != snapshot_id {
        return Err(FeedError::Corrupt(format!(
            "snapshot {snapshot_id}: manifest claims id {}",
            manifest.snapshot_id
        )));
    }
    Ok(Some(Snapshot { manifest, dir }))
}

impl Snapshot {
    /// Read a file from the snapshot, verifying its recorded digest (FD-002).
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, FeedError> {
        let meta = self.manifest.files.get(name).ok_or_else(|| {
            FeedError::Corrupt(format!(
                "snapshot {}: file `{name}` not in manifest",
                self.manifest.snapshot_id
            ))
        })?;
        let bytes = std::fs::read(self.dir.join(name))?;
        let actual = digest_of(&bytes);
        if actual != meta.digest {
            return Err(FeedError::Corrupt(format!(
                "snapshot {}: `{name}` digest mismatch (manifest {}, actual {actual})",
                self.manifest.snapshot_id, meta.digest
            )));
        }
        Ok(bytes)
    }

    /// Load the KEV/EPSS enrichment maps for scoring.
    pub fn enrichment(&self) -> Result<crate::Enrichment, FeedError> {
        let kev = self.read_file("kev.json")?;
        let epss = self.read_file("epss.csv")?;
        crate::Enrichment::from_parts(&kev, &epss)
    }
}

/// Write a snapshot atomically and flip `CURRENT` to it. Returns the loaded
/// snapshot. The id is derived from content digests + date, so identical data
/// re-fetched the same day converges on the same id.
pub fn write_snapshot(
    cache: &Path,
    data: &SnapshotData,
    as_of: DateTime<Utc>,
) -> Result<Snapshot, FeedError> {
    // Assemble (name → bytes) in deterministic order.
    let mut files: BTreeMap<String, &[u8]> = BTreeMap::new();
    files.insert("kev.json".to_string(), &data.kev_json);
    files.insert("epss.csv".to_string(), &data.epss_csv);
    for (ecosystem, jsonl) in &data.osv_jsonl {
        if ecosystem.contains(['/', '\\']) || ecosystem.contains("..") {
            return Err(FeedError::Corrupt(format!(
                "invalid ecosystem name `{ecosystem}`"
            )));
        }
        files.insert(format!("osv/{ecosystem}.jsonl"), jsonl);
    }

    let mut metas: BTreeMap<String, FileMeta> = BTreeMap::new();
    let mut combined = blake3::Hasher::new();
    for (name, bytes) in &files {
        let digest = digest_of(bytes);
        combined.update(name.as_bytes());
        combined.update(digest.as_bytes());
        metas.insert(
            name.clone(),
            FileMeta {
                digest,
                bytes: bytes.len() as u64,
            },
        );
    }
    let snapshot_id = format!(
        "{}-{}",
        as_of.format("%Y%m%d"),
        &combined.finalize().to_hex().to_string()[..12]
    );

    let manifest = SnapshotManifest {
        snapshot_id: snapshot_id.clone(),
        as_of,
        files: metas,
        counts: data.counts.clone(),
        sources: data.sources.clone(),
    };

    let snapshots_dir = feeds_dir(cache).join("snapshots");
    let staging = snapshots_dir.join(format!("{snapshot_id}.staging"));
    let final_dir = snapshots_dir.join(&snapshot_id);
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(staging.join("osv"))?;
    for (name, bytes) in &files {
        std::fs::write(staging.join(name), bytes)?;
    }
    std::fs::write(
        staging.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)
            .map_err(|e| FeedError::Corrupt(format!("manifest serialize: {e}")))?,
    )?;
    if final_dir.exists() {
        // Same content already cached — reuse it.
        std::fs::remove_dir_all(&staging)?;
    } else {
        std::fs::rename(&staging, &final_dir)?;
    }

    let current_tmp = feeds_dir(cache).join("CURRENT.tmp");
    std::fs::write(&current_tmp, &snapshot_id)?;
    std::fs::rename(&current_tmp, feeds_dir(cache).join("CURRENT"))?;

    Ok(Snapshot {
        manifest,
        dir: final_dir,
    })
}
