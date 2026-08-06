//! `multiscan db update` orchestration — the ONLY code path permitted to
//! fetch feeds (FD-003). Downloads each source, validates and normalizes it
//! defensively (feeds are still untrusted input: caps on entry counts and
//! decompressed sizes), and writes one atomic snapshot.

use std::collections::BTreeMap;
use std::io::Read;

use chrono::{DateTime, Utc};

use crate::cache::{write_snapshot, Snapshot, SnapshotCounts, SnapshotData};
use crate::{Enrichment, FeedClient, FeedError};

/// Defensive caps for untrusted archive content.
const MAX_GUNZIP_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 1_000_000;
const MAX_ZIP_ENTRY_BYTES: u64 = 10 * 1024 * 1024;
const MAX_ZIP_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Where each feed comes from. `Default` is the production set; tests inject
/// loopback fixture URLs.
#[derive(Debug, Clone)]
pub struct FeedSources {
    /// CISA KEV catalog (JSON).
    pub kev_url: String,
    /// EPSS scores (gzipped CSV).
    pub epss_url: String,
    /// Base URL: `{osv_base_url}/{ecosystem}/all.zip`.
    pub osv_base_url: String,
    /// OSV ecosystems to mirror (Q-01: local mirror is the default posture).
    pub osv_ecosystems: Vec<String>,
}

impl Default for FeedSources {
    fn default() -> Self {
        Self {
            kev_url:
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                    .to_string(),
            epss_url: "https://epss.cyentia.com/epss_scores-current.csv.gz".to_string(),
            osv_base_url: "https://osv-vulnerabilities.storage.googleapis.com".to_string(),
            // The spec 7.1 lockfile ecosystems (OS package ecosystems join in
            // phase 4 with image scanning).
            osv_ecosystems: [
                "crates.io",
                "npm",
                "PyPI",
                "Go",
                "Maven",
                "RubyGems",
                "Packagist",
                "NuGet",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

/// Fetch all sources and write a new pinned snapshot. Progress goes to
/// stderr; this is a long-running, explicitly user-invoked operation.
pub fn update(
    client: &FeedClient,
    sources: &FeedSources,
    cache: &std::path::Path,
    now: DateTime<Utc>,
) -> Result<Snapshot, FeedError> {
    eprintln!("multiscan db update: fetching KEV catalog...");
    let kev_json = client.fetch(&sources.kev_url)?;

    eprintln!("multiscan db update: fetching EPSS scores...");
    let epss_gz = client.fetch(&sources.epss_url)?;
    let epss_csv = gunzip(&epss_gz)?;

    // Validate both before writing anything.
    let enrichment = Enrichment::from_parts(&kev_json, &epss_csv)?;
    let (kev_count, epss_count) = enrichment.counts();

    let mut osv_jsonl: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut osv_counts: BTreeMap<String, u64> = BTreeMap::new();
    for ecosystem in &sources.osv_ecosystems {
        let url = format!("{}/{}/all.zip", sources.osv_base_url, ecosystem);
        eprintln!("multiscan db update: fetching OSV {ecosystem}...");
        let zip_bytes = client.fetch(&url)?;
        let (jsonl, count) = zip_to_jsonl(&zip_bytes, ecosystem)?;
        osv_jsonl.insert(ecosystem.clone(), jsonl);
        osv_counts.insert(ecosystem.clone(), count);
    }

    let mut source_map = BTreeMap::new();
    source_map.insert("kev".to_string(), sources.kev_url.clone());
    source_map.insert("epss".to_string(), sources.epss_url.clone());
    for ecosystem in &sources.osv_ecosystems {
        source_map.insert(
            format!("osv/{ecosystem}"),
            format!("{}/{}/all.zip", sources.osv_base_url, ecosystem),
        );
    }

    let snapshot = write_snapshot(
        cache,
        &SnapshotData {
            kev_json,
            epss_csv,
            osv_jsonl,
            // Live update fetches advisory feeds only; rule packs are
            // distributed via signed air-gap bundles (ADR 0010), not the
            // network fetch, until a dedicated rules-feed URL exists.
            rule_packs: BTreeMap::new(),
            counts: SnapshotCounts {
                kev: kev_count,
                epss: epss_count,
                osv: osv_counts,
            },
            sources: source_map,
        },
        now,
    )?;
    eprintln!(
        "multiscan db update: snapshot {} written ({} KEV, {} EPSS)",
        snapshot.manifest.snapshot_id, kev_count, epss_count
    );
    Ok(snapshot)
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, FeedError> {
    let mut decoder = flate2::read::GzDecoder::new(bytes).take(MAX_GUNZIP_BYTES + 1);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| FeedError::Corrupt(format!("gunzip: {e}")))?;
    if out.len() as u64 > MAX_GUNZIP_BYTES {
        return Err(FeedError::TooLarge("gunzipped EPSS data".to_string()));
    }
    Ok(out)
}

/// Convert an OSV `all.zip` into deterministic JSONL: entries sorted by name,
/// each advisory re-serialized compact on one line. Caps: entry count, per-
/// entry size, total size (untrusted-archive discipline; cf. SCA-005).
fn zip_to_jsonl(zip_bytes: &[u8], ecosystem: &str) -> Result<(Vec<u8>, u64), FeedError> {
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| FeedError::Corrupt(format!("OSV {ecosystem} zip: {e}")))?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(FeedError::TooLarge(format!(
            "OSV {ecosystem} zip has {} entries",
            archive.len()
        )));
    }
    let mut names: Vec<String> = archive.file_names().map(String::from).collect();
    names.sort();

    let mut jsonl = Vec::new();
    let mut total: u64 = 0;
    let mut count: u64 = 0;
    for name in names {
        if !name.ends_with(".json") {
            continue; // some ecosystems ship non-advisory metadata files
        }
        let entry = archive
            .by_name(&name)
            .map_err(|e| FeedError::Corrupt(format!("OSV {ecosystem} {name}: {e}")))?;
        let mut content = Vec::new();
        entry
            .take(MAX_ZIP_ENTRY_BYTES + 1)
            .read_to_end(&mut content)
            .map_err(|e| FeedError::Corrupt(format!("OSV {ecosystem} {name}: {e}")))?;
        if content.len() as u64 > MAX_ZIP_ENTRY_BYTES {
            return Err(FeedError::TooLarge(format!("OSV {ecosystem} {name}")));
        }
        total += content.len() as u64;
        if total > MAX_ZIP_TOTAL_BYTES {
            return Err(FeedError::TooLarge(format!("OSV {ecosystem} zip content")));
        }
        // Re-serialize compact: validates the JSON and guarantees one line.
        let value: serde_json::Value = serde_json::from_slice(&content)
            .map_err(|e| FeedError::Corrupt(format!("OSV {ecosystem} {name}: {e}")))?;
        let line = serde_json::to_string(&value)
            .map_err(|e| FeedError::Corrupt(format!("OSV {ecosystem} {name}: {e}")))?;
        jsonl.extend_from_slice(line.as_bytes());
        jsonl.push(b'\n');
        count += 1;
    }
    Ok((jsonl, count))
}
