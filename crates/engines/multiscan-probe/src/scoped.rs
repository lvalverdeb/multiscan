//! Production transport: enforces SEC-004 by **pinning the connection to the
//! exact allowed IP** and never following redirects (SEC-005). Uses ureq (no
//! tokio).
//!
//! The pinning is structural: ureq calls our [`ScopeResolver`] immediately
//! before connecting and dials exactly the addresses it returns, so there is
//! no separate re-resolution the attacker could race (no DNS-rebinding TOCTOU).
//! The resolver returns only public, routable addresses — reserved/internal/
//! metadata IPs (and IPv4-mapped-IPv6 forms) are dropped by
//! `multiscan_scope::resolve_pinned`; if none remain the host is refused.

use std::time::Duration;

use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::DefaultConnector;

use crate::executor::Transport;
use crate::matcher::Response;

const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// A ureq resolver that returns only scope-allowed, pinned addresses (SEC-004).
#[derive(Debug)]
struct ScopeResolver;

impl Resolver for ScopeResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let host = uri.host().ok_or(ureq::Error::HostNotFound)?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("http") {
                80
            } else {
                443
            });
        // resolve_pinned resolves once, drops reserved/rebinding IPs, and
        // returns the exact SocketAddrs to dial (tested in multiscan-scope).
        let pinned = multiscan_scope::resolve_pinned(host, port, None)
            .map_err(|_| ureq::Error::HostNotFound)?;
        let fallback: std::net::SocketAddr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
        let mut out = ResolvedSocketAddrs::from_fn(|_| fallback);
        out.truncate(0);
        // ureq's ResolvedSocketAddrs is a fixed-capacity ArrayVec; cap the pins.
        const MAX_PINS: usize = 16;
        for addr in pinned.into_iter().take(MAX_PINS) {
            out.push(addr);
        }
        if out.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(out)
    }
}

/// A ureq-backed transport scoped to one origin, pinning connections to
/// allowed IPs and never following redirects.
pub struct ScopedTransport {
    agent: ureq::Agent,
    origin: String,
}

impl ScopedTransport {
    /// Build a transport for `origin` (scheme://host:port). Redirects are
    /// disabled (SEC-005) and the connection is pinned to scope-allowed IPs
    /// (SEC-004).
    pub fn new(origin: &str, _host: &str, _port: u16) -> Self {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(20)))
            .build();
        let agent = ureq::Agent::with_parts(config, DefaultConnector::default(), ScopeResolver);
        Self {
            agent,
            origin: origin.trim_end_matches('/').to_string(),
        }
    }
}

impl Transport for ScopedTransport {
    fn fetch(&self, method: &str, path: &str) -> Result<Response, String> {
        let url = format!("{}{path}", self.origin);
        // The pinning resolver (SEC-004) runs inside .call() at connect time.
        let mut response = match method.to_ascii_uppercase().as_str() {
            "GET" => self.agent.get(&url).call(),
            "HEAD" => self.agent.head(&url).call(),
            other => {
                return Err(format!(
                    "method {other} not supported by probe transport yet"
                ));
            }
        }
        .map_err(|e| format!("{url}: {e}"))?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_to_string()
            .unwrap_or_default();
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}
