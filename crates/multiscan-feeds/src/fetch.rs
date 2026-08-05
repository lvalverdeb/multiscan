//! The allow-listed feed fetch path — the only network code outside
//! `multiscan-scope` (R-6, NG-6). Every URL is checked against the host
//! allow-list BEFORE any connection is attempted; non-loopback hosts must be
//! https. Downloads are size-capped.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::FeedError;

/// Hosts feed data may be fetched from. Additions are a reviewable event.
pub const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
    "osv-vulnerabilities.storage.googleapis.com",
    "epss.cyentia.com",
    "www.cisa.gov",
];

/// Hard cap on any single download (OSV ecosystem zips are the largest).
const MAX_DOWNLOAD_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Blocking HTTP client restricted to allow-listed feed hosts.
pub struct FeedClient {
    agent: ureq::Agent,
    allowed: BTreeSet<String>,
}

impl FeedClient {
    /// Client with the production allow-list.
    pub fn new() -> Self {
        Self::with_allowlist(DEFAULT_ALLOWED_HOSTS.iter().map(|h| h.to_string()))
    }

    /// Client with a custom allow-list. Exists for tests against loopback
    /// fixtures; production code uses [`FeedClient::new`].
    pub fn with_allowlist(hosts: impl IntoIterator<Item = String>) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(600)))
            .build();
        Self {
            agent: config.into(),
            allowed: hosts.into_iter().collect(),
        }
    }

    /// Fetch a URL. Refuses non-allow-listed hosts and non-https schemes
    /// (loopback excepted, for tests) before any packet is sent.
    pub fn fetch(&self, url: &str) -> Result<Vec<u8>, FeedError> {
        let uri: ureq::http::Uri = url
            .parse()
            .map_err(|_| FeedError::BadUrl(url.to_string()))?;
        let host = uri
            .host()
            .ok_or_else(|| FeedError::BadUrl(url.to_string()))?
            .to_string();
        let loopback = host == "127.0.0.1" || host == "localhost" || host == "::1";
        if !self.allowed.contains(&host) {
            return Err(FeedError::NotAllowed(host));
        }
        match uri.scheme_str() {
            Some("https") => {}
            Some("http") if loopback => {}
            _ => {
                return Err(FeedError::BadUrl(format!(
                    "{url}: feeds require https (http allowed for loopback tests only)"
                )))
            }
        }

        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| FeedError::Fetch(format!("{url}: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(FeedError::Fetch(format!("{url}: HTTP {status}")));
        }
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD_BYTES)
            .read_to_vec()
            .map_err(|e| FeedError::Fetch(format!("{url}: body: {e}")))?;
        Ok(bytes)
    }
}

impl Default for FeedClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allow-list refuses unknown hosts before any connection: a port
    /// that could never be dialled proves no dial was attempted.
    #[test]
    fn unknown_host_refused_without_connection() {
        let client = FeedClient::new();
        match client.fetch("https://evil.example:1/x") {
            Err(FeedError::NotAllowed(host)) => assert_eq!(host, "evil.example"),
            other => panic!("expected NotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn plain_http_refused_for_non_loopback() {
        let client = FeedClient::with_allowlist(["www.cisa.gov".to_string()]);
        match client.fetch("http://www.cisa.gov/feed.json") {
            Err(FeedError::BadUrl(_)) => {}
            other => panic!("expected BadUrl, got {other:?}"),
        }
    }

    #[test]
    fn garbage_url_rejected() {
        let client = FeedClient::new();
        assert!(matches!(
            client.fetch("not a url"),
            Err(FeedError::BadUrl(_))
        ));
    }
}
