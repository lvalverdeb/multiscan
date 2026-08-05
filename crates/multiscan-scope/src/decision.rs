//! Authorization decisions. Every decision carries the deciding rule so the
//! audit log can record it (SEC-008).

use std::net::IpAddr;

/// The outcome of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permitted; records which include pattern matched.
    Allowed {
        /// The include pattern that matched the target host.
        matched_pattern: String,
    },
    /// Denied, with the reason (the "deciding rule", SEC-008).
    Denied(Denied),
}

impl Decision {
    /// Whether the decision permits the request.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allowed { .. })
    }

    /// A stable, human-readable description of the deciding rule for the audit
    /// log.
    pub fn rule(&self) -> String {
        match self {
            Decision::Allowed { matched_pattern } => {
                format!("allow: matched include `{matched_pattern}`")
            }
            Decision::Denied(d) => format!("deny: {}", d.rule()),
        }
    }
}

/// Why a request was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// No authorization was provided (SEC-001).
    NoAuthorization,
    /// Signature missing, malformed, or not verifiable against a trusted key.
    BadSignature(String),
    /// Outside the authorization's validity window (SEC-001).
    Expired {
        /// Human-readable window / now.
        detail: String,
    },
    /// The attestation field was empty (A-1).
    MissingAttestation,
    /// An include/exclude pattern's wildcard spans a public suffix (SEC-003).
    UnsafeWildcard(String),
    /// The host matched an `exclude` pattern (SEC-002).
    ExcludedBy(String),
    /// The host matched no `include` pattern.
    NotIncluded(String),
    /// The method is not permitted under the active profile or authorization
    /// (PRB-003).
    MethodNotPermitted(String),
    /// A resolved IP was reserved/internal (SEC-004).
    ReservedIp(IpAddr),
    /// The host did not resolve to any allowed address (SEC-004).
    NoAllowedAddress(String),
}

impl Denied {
    /// The deciding-rule string recorded in the audit log.
    pub fn rule(&self) -> String {
        match self {
            Denied::NoAuthorization => "no authorization provided (SEC-001)".to_string(),
            Denied::BadSignature(d) => format!("signature invalid: {d} (SEC-001)"),
            Denied::Expired { detail } => format!("outside validity window: {detail} (SEC-001)"),
            Denied::MissingAttestation => "attestation is empty (A-1)".to_string(),
            Denied::UnsafeWildcard(p) => {
                format!("wildcard `{p}` spans a public suffix (SEC-003)")
            }
            Denied::ExcludedBy(p) => format!("host matches exclude `{p}` (SEC-002)"),
            Denied::NotIncluded(h) => format!("host `{h}` matches no include pattern"),
            Denied::MethodNotPermitted(m) => format!("method `{m}` not permitted (PRB-003)"),
            Denied::ReservedIp(ip) => format!("resolved IP {ip} is reserved/internal (SEC-004)"),
            Denied::NoAllowedAddress(h) => {
                format!("host `{h}` resolved to no allowed address (SEC-004)")
            }
        }
    }
}
