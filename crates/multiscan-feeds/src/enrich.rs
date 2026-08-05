//! KEV/EPSS enrichment lookups for the risk stage (spec 8, factor X).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::FeedError;

#[derive(Deserialize)]
struct KevCatalog {
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

/// In-memory exploit-likelihood data from a pinned snapshot.
#[derive(Debug, Clone, Default)]
pub struct Enrichment {
    kev: BTreeSet<String>,
    epss: BTreeMap<String, f64>,
}

impl Enrichment {
    /// Parse from raw snapshot files: the KEV catalog JSON and the EPSS CSV
    /// (`cve,epss,percentile` rows; `#` comment lines and the header are
    /// skipped; malformed rows are an error, never silently dropped).
    pub fn from_parts(kev_json: &[u8], epss_csv: &[u8]) -> Result<Self, FeedError> {
        let catalog: KevCatalog = serde_json::from_slice(kev_json)
            .map_err(|e| FeedError::Corrupt(format!("KEV catalog: {e}")))?;
        let kev: BTreeSet<String> = catalog
            .vulnerabilities
            .into_iter()
            .map(|entry| entry.cve_id)
            .collect();

        let text = std::str::from_utf8(epss_csv)
            .map_err(|e| FeedError::Corrupt(format!("EPSS csv is not UTF-8: {e}")))?;
        let mut epss = BTreeMap::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("cve,") {
                continue;
            }
            let mut parts = line.split(',');
            let (Some(cve), Some(score)) = (parts.next(), parts.next()) else {
                return Err(FeedError::Corrupt(format!(
                    "EPSS csv line {}: expected cve,epss[,percentile]",
                    lineno + 1
                )));
            };
            let score: f64 = score.parse().map_err(|_| {
                FeedError::Corrupt(format!("EPSS csv line {}: bad score `{score}`", lineno + 1))
            })?;
            epss.insert(cve.to_string(), score);
        }
        Ok(Self { kev, epss })
    }

    /// Whether any of the CVE ids is in the CISA KEV catalog (factor X = 1.00).
    pub fn any_kev(&self, cve_ids: &[String]) -> bool {
        cve_ids.iter().any(|id| self.kev.contains(id))
    }

    /// Highest EPSS probability across the CVE ids, if any are scored.
    pub fn max_epss(&self, cve_ids: &[String]) -> Option<f64> {
        cve_ids
            .iter()
            .filter_map(|id| self.epss.get(id).copied())
            .max_by(f64::total_cmp)
    }

    /// (KEV count, EPSS count) for status display.
    pub fn counts(&self) -> (u64, u64) {
        (self.kev.len() as u64, self.epss.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEV: &[u8] = br#"{"title":"KEV","vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache"},{"cveID":"CVE-2023-1234"}]}"#;
    const EPSS: &[u8] = b"#model_version:v2025.03.14,score_date:2026-08-05\ncve,epss,percentile\nCVE-2021-44228,0.97565,0.99988\nCVE-2020-0001,0.00123,0.31000\n";

    #[test]
    fn parses_and_looks_up() {
        let enrichment = Enrichment::from_parts(KEV, EPSS).unwrap();
        assert!(enrichment.any_kev(&["CVE-2021-44228".to_string()]));
        assert!(!enrichment.any_kev(&["CVE-2020-0001".to_string()]));
        let max = enrichment
            .max_epss(&["CVE-2020-0001".to_string(), "CVE-2021-44228".to_string()])
            .unwrap();
        assert!((max - 0.97565).abs() < 1e-9);
        assert_eq!(enrichment.max_epss(&["CVE-1999-0000".to_string()]), None);
        assert_eq!(enrichment.counts(), (2, 2));
    }

    #[test]
    fn malformed_epss_row_is_an_error() {
        assert!(Enrichment::from_parts(KEV, b"CVE-2020-0001,not-a-number\n").is_err());
    }

    #[test]
    fn malformed_kev_is_an_error() {
        assert!(Enrichment::from_parts(b"[1,2,3]", EPSS).is_err());
    }
}
