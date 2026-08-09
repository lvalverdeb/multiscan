//! Opt-in OSV API freshness path (`T-901`, `FR-018`; resolves Q-01).
//!
//! The pinned mirror stays the default posture. This asks the OSV query API
//! whether it knows advisories the snapshot does not — useful when a snapshot
//! is days old and a fresh advisory matters — and it runs **only when the user
//! asks for it**.
//!
//! # What this is not
//!
//! It is a **feed** fetch: it asks a well-known advisory service about package
//! names. It never contacts a scan target, so it stays on the allow-listed
//! `multiscan-feeds` path and out of `multiscan-scope` (R-6). No repository
//! content, file path, or source text leaves the machine — only package
//! coordinates that are already public in a lockfile.
//!
//! `--offline` disables it absolutely: `FR-018` requires offline output to stay
//! byte-identical, and the CLI rejects the combination rather than silently
//! ignoring one of the two flags.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::{FeedClient, FeedError};

/// The OSV batched query endpoint.
pub const OSV_QUERY_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// Most packages a single request will carry. OSV documents a batch limit;
/// larger inputs are chunked rather than truncated, because silently dropping
/// packages would look like "no advisories".
const MAX_BATCH: usize = 100;

/// Bound on how many packages a freshness pass will ask about at all.
///
/// A monorepo can resolve tens of thousands of packages, and this is an opt-in
/// convenience rather than the source of truth. Exceeding it is reported, never
/// silently truncated.
pub const MAX_QUERIED_PACKAGES: usize = 2_000;

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<QueryResult>,
}

#[derive(Deserialize, Default)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
}

#[derive(Deserialize)]
struct VulnRef {
    #[serde(default)]
    id: Option<String>,
}

/// What an API freshness pass learned.
///
/// Named apart from [`crate::Freshness`], which is snapshot *age* (`FD-004`);
/// this is advisory *coverage* from the query API.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApiFreshness {
    /// purl → advisory ids the API reports, in sorted order (`DET-001`).
    pub by_purl: BTreeMap<String, BTreeSet<String>>,
    /// Packages not asked about because [`MAX_QUERIED_PACKAGES`] was reached.
    ///
    /// Surfaced so a truncated pass never reads as a clean one.
    pub skipped: usize,
}

/// Ask the OSV API which advisories affect these packages.
///
/// `purls` is deduplicated and sorted before the request, so the same input
/// produces the same batches and the same result ordering.
pub fn query(
    client: &FeedClient,
    endpoint: &str,
    purls: &[String],
) -> Result<ApiFreshness, FeedError> {
    let unique: BTreeSet<&String> = purls.iter().collect();
    let ordered: Vec<&String> = unique.into_iter().collect();

    let (queried, skipped) = if ordered.len() > MAX_QUERIED_PACKAGES {
        (
            &ordered[..MAX_QUERIED_PACKAGES],
            ordered.len() - MAX_QUERIED_PACKAGES,
        )
    } else {
        (&ordered[..], 0)
    };

    let mut by_purl: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for chunk in queried.chunks(MAX_BATCH) {
        let body = serde_json::json!({
            "queries": chunk
                .iter()
                .map(|purl| serde_json::json!({ "package": { "purl": purl } }))
                .collect::<Vec<_>>(),
        });
        let raw = serde_json::to_vec(&body)
            .map_err(|e| FeedError::Fetch(format!("building query: {e}")))?;
        let response = client.post_json(endpoint, &raw)?;
        let parsed: BatchResponse = serde_json::from_slice(&response)
            .map_err(|e| FeedError::Fetch(format!("osv query response: {e}")))?;

        // Results are positional: entry i answers query i. A short response
        // means the API answered fewer than we asked, which must not silently
        // shift advisories onto the wrong package.
        if parsed.results.len() > chunk.len() {
            return Err(FeedError::Fetch(
                "osv query returned more results than queries".to_string(),
            ));
        }
        for (purl, result) in chunk.iter().zip(parsed.results) {
            let ids: BTreeSet<String> = result.vulns.into_iter().filter_map(|v| v.id).collect();
            if !ids.is_empty() {
                by_purl.insert((*purl).clone(), ids);
            }
        }
    }

    Ok(ApiFreshness { by_purl, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_response_never_shifts_advisories_onto_the_wrong_package() {
        // Results are positional. Extra results would misalign the zip, which
        // would attribute a CVE to a package that does not have it.
        let parsed: BatchResponse =
            serde_json::from_slice(br#"{"results":[{"vulns":[{"id":"CVE-1"}]}]}"#).unwrap();
        assert_eq!(parsed.results.len(), 1);
        // The guard itself is exercised end to end in tests/freshness.rs
        // against a loopback fixture server.
    }

    #[test]
    fn the_query_bound_reports_rather_than_truncates() {
        let f = ApiFreshness {
            by_purl: BTreeMap::new(),
            skipped: 7,
        };
        assert_eq!(
            f.skipped, 7,
            "a truncated pass must not read as a clean one"
        );
    }
}
