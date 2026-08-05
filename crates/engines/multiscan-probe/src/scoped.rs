//! Production transport: enforces SEC-004 (resolve → reject reserved IPs →
//! connect) and never follows redirects (SEC-005). Uses ureq (no tokio).
//!
//! The reserved-IP predicate is applied via `multiscan_scope::resolve_pinned`
//! before any connection: a host resolving only to loopback/private/metadata
//! addresses is refused. (Dialing the *exact* pinned `SocketAddr` via a custom
//! ureq resolver — closing the residual re-resolution window — is the remaining
//! hardening; the reserved-range rejection is the primary defence and is in
//! force here.)

use std::time::Duration;

use crate::executor::Transport;
use crate::matcher::Response;

const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// A ureq-backed transport scoped to one origin.
pub struct ScopedTransport {
    agent: ureq::Agent,
    origin: String,
    host: String,
    port: u16,
}

impl ScopedTransport {
    /// Build a transport for `origin` (scheme://host:port). Redirects are
    /// disabled (SEC-005): a 3xx is returned as-is for matchers, never
    /// followed out of scope.
    pub fn new(origin: &str, host: &str, port: u16) -> Self {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(20)))
            .build();
        Self {
            agent: config.into(),
            origin: origin.trim_end_matches('/').to_string(),
            host: host.to_string(),
            port,
        }
    }
}

impl Transport for ScopedTransport {
    fn fetch(&self, method: &str, path: &str) -> Result<Response, String> {
        // SEC-004: resolve and reject reserved/rebinding addresses before any
        // connection. A host that resolves to no allowed address is refused.
        multiscan_scope::resolve_pinned(&self.host, self.port, None)
            .map_err(|d| format!("scope: {}", d.rule()))?;

        let url = format!("{}{path}", self.origin);
        let mut response = match method.to_ascii_uppercase().as_str() {
            "GET" => self.agent.get(&url).call(),
            "HEAD" => self.agent.head(&url).call(),
            other => {
                // OPTIONS support lands with a broader transport; GET/HEAD cover
                // the bundled read-only templates.
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
