//! Probe execution (spec 7.4). Every request passes the scope gate before it
//! is sent (PRB-002), the transport never follows redirects out of scope
//! (SEC-005), and a match yields `Proven` confidence only with a redacted
//! request/response exchange attached as Evidence (PRB-005).
//!
//! I/O is behind the [`Transport`] trait so the executor's security logic is
//! testable without pointing at any host (spec 16). [`ScopedTransport`] is the
//! production implementation; it enforces SEC-004 by resolving the target and
//! rejecting reserved/rebinding IPs before any connection.

use multiscan_core::{
    Asset, AssetKind, Confidence, Evidence, IdentityKey, Location, RawFinding, Severity,
};
use multiscan_scope::{AuditLog, RateControl, VerifiedAuthorization};

use crate::matcher::{self, Response};
use crate::redact;
use crate::template::Template;

const MAX_EVIDENCE_BYTES: usize = 4096;

/// The transport that performs a single request. Production dials a scope-pinned
/// address; tests supply canned responses.
pub trait Transport {
    /// Fetch `path` (relative to the target origin) with `method`. Returns the
    /// response, or an error string if the request could not be completed
    /// (including a refusal to connect out of scope).
    fn fetch(&self, method: &str, path: &str) -> Result<Response, String>;
}

/// Inputs to an execution run.
pub struct ProbeRun<'a> {
    /// The verified authorization gating every request (PRB-002).
    pub authorization: &'a VerifiedAuthorization,
    /// Target origin: scheme + host + port (normalized, for identity).
    pub origin: String,
    /// Host used for the scope check.
    pub host: String,
    /// Injected timestamp (RFC 3339) for the audit log.
    pub now: String,
}

/// Execute templates against the target, returning WebExposure findings.
/// `rate` enforces per-host pacing and the 5xx breaker (SEC-006/007); `audit`
/// records every authorize decision (SEC-008).
pub fn execute(
    templates: &[Template],
    run: &ProbeRun,
    transport: &dyn Transport,
    rate: &mut RateControl,
    audit: &AuditLog,
) -> Vec<RawFinding> {
    let mut findings = Vec::new();
    let mut clock_ms: u64 = 0;

    for template in templates {
        for req in &template.requests {
            for path in &req.path {
                // PRB-002: every request passes the scope gate first.
                let decision = run.authorization.authorize(&run.host, &req.method);
                let _ = audit.record(
                    &run.now,
                    &run.authorization.authorization_id,
                    &format!("{}{path}", run.origin),
                    &req.method,
                    &decision,
                );
                if !decision.is_allowed() {
                    continue;
                }

                // SEC-006/007: pace, and abort the host on the 5xx breaker.
                clock_ms += 1;
                match rate.poll(&run.host, clock_ms) {
                    multiscan_scope::Permit::Go => {}
                    multiscan_scope::Permit::Wait(ms) => clock_ms += ms,
                    multiscan_scope::Permit::Abort => return findings,
                }

                let response = match transport.fetch(&req.method, path) {
                    Ok(r) => r,
                    Err(_) => continue, // unreachable/refused — not a finding
                };
                rate.record_response(&run.host, clock_ms, response.status);

                if matcher::evaluate(&req.matchers, req.matchers_condition, &response) {
                    findings.push(build_finding(template, run, path, &req.method, &response));
                }
            }
        }
    }
    findings
}

fn build_finding(
    template: &Template,
    run: &ProbeRun,
    path: &str,
    method: &str,
    response: &Response,
) -> RawFinding {
    // PRB-005: attach the redacted exchange; that is what earns `Proven`.
    let exchange = format!(
        "> {method} {path}\n< HTTP {}\n< {}\n\n{}",
        response.status,
        redact::cap(&redact::redact(&response.headers), 512),
        redact::cap(&redact::redact(&response.body), MAX_EVIDENCE_BYTES),
    );
    RawFinding {
        identity: IdentityKey::WebExposure {
            template_id: template.id.clone(),
            origin: run.origin.clone(),
            request_path: path.to_string(),
        },
        title: template
            .description
            .clone()
            .unwrap_or_else(|| format!("Web exposure: {}", template.id)),
        description: template.description.clone(),
        severity: parse_severity(&template.severity),
        // A probe finding is internet-reachable and the exchange is proof.
        confidence: Confidence::Proven,
        asset: Asset {
            kind: AssetKind::Endpoint,
            identifier: format!("{}{path}", run.origin),
        },
        location: Location {
            path: format!("{}{path}", run.origin),
            line: None,
        },
        evidence: vec![Evidence {
            kind: "http_exchange".to_string(),
            summary: format!("{method} {path} → HTTP {}", response.status),
            detail: {
                let mut m = serde_json::Map::new();
                m.insert("exchange".to_string(), serde_json::Value::String(exchange));
                m
            },
            dependency_path: vec![],
        }],
        rule_id: Some(template.id.clone()),
        remediation: None,
        cwe: template.cwe.clone(),
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}
