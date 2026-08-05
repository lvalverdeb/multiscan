//! ScopeAuthorization, target resolution guard, rate control (spec 9). The
//! highest-scrutiny crate: **no code path may produce a connection without a
//! passing decision, and every deny runs with zero network I/O** (SEC-009,
//! SEC-001, FR-007).
//!
//! Two-stage gate, hard-ordered and type-enforced:
//! 1. **Static gate** (`Authorization::verify` → [`VerifiedAuthorization`]):
//!    parse, signature, validity window, attestation, wildcard safety, and the
//!    per-request host+method check. All lexical — decides `evil.com` is out of
//!    scope without resolving it.
//! 2. **Connect-time gate** ([`VerifiedAuthorization`] + [`resolve_pinned`]):
//!    resolve once, reject reserved/rebinding IPs, and pin the exact
//!    `SocketAddr`s to dial (SEC-004).
//!
//! A [`VerifiedAuthorization`] is the only capability that unlocks connection
//! resolution; there is no other constructor. `multiscan-probe` (T-502)
//! consumes this per hop.

mod audit;
mod authorization;
mod decision;
mod net;
mod ratelimit;
mod scope;

pub use audit::AuditLog;
pub use authorization::{sign_authorization, Authorization, VerifiedAuthorization};
pub use decision::{Decision, Denied};
pub use net::ip_allowed;
pub use ratelimit::{Permit, RateControl};

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// An injectable host resolver (tests supply a mock; production uses the system
/// resolver). Returns the IPs a host resolves to.
pub type Resolver<'a> = &'a dyn Fn(&str) -> std::io::Result<Vec<IpAddr>>;

/// Resolve `host:port` and return only the pinned, allowed `SocketAddr`s to
/// dial (SEC-004). Reserved/internal/rebinding addresses are dropped; if none
/// remain, the host is denied. The connection MUST dial one of these exact
/// addresses — never re-resolve the host — so a DNS-rebinding TOCTOU is
/// impossible.
///
/// A `resolver` may be injected for tests; production passes `None` to use the
/// system resolver.
pub fn resolve_pinned(
    host: &str,
    port: u16,
    resolver: Option<Resolver<'_>>,
) -> Result<Vec<SocketAddr>, Denied> {
    let ips = match resolver {
        Some(resolve) => {
            resolve(host).map_err(|e| Denied::NoAllowedAddress(format!("{host}: {e}")))?
        }
        None => (host, port)
            .to_socket_addrs()
            .map_err(|e| Denied::NoAllowedAddress(format!("{host}: {e}")))?
            .map(|sa| sa.ip())
            .collect(),
    };
    if ips.is_empty() {
        return Err(Denied::NoAllowedAddress(host.to_string()));
    }
    // Fail closed: keep only allowed IPs; drop reserved ones but require at
    // least one to remain.
    let pinned: Vec<SocketAddr> = ips
        .into_iter()
        .filter(|ip| ip_allowed(*ip))
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    if pinned.is_empty() {
        return Err(Denied::NoAllowedAddress(host.to_string()));
    }
    Ok(pinned)
}

/// The first reserved IP a host resolves to, if any — used to surface the exact
/// offending address for the audit log ([`resolve_pinned`] is the enforcement
/// point).
pub fn first_reserved_ip(host: &str, resolver: Resolver<'_>) -> Option<IpAddr> {
    resolver(host).ok()?.into_iter().find(|ip| !ip_allowed(*ip))
}
