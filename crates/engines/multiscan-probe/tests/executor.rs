//! T-502 acceptance: probe executor security logic (PRB-002, PRB-005) using a
//! mock transport — no real host (spec 16). A transport that panics if called
//! proves out-of-scope requests are never sent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use multiscan_core::{
    AuthorizedScope, AuthorizedScopePermittedMethodsItem, IdentityKey, Profile, ScopeAuthorization,
};
use multiscan_probe::{execute, ProbeRun, Response, Template, Transport};
use multiscan_scope::{sign_authorization, AuditLog, Authorization, RateControl};

/// Canned-response transport keyed by path.
struct MockTransport {
    responses: BTreeMap<String, Response>,
}

impl Transport for MockTransport {
    fn fetch(&self, _method: &str, path: &str) -> Result<Response, String> {
        match self.responses.get(path) {
            Some(r) => Ok(Response {
                status: r.status,
                headers: r.headers.clone(),
                body: r.body.clone(),
            }),
            None => Ok(Response {
                status: 404,
                headers: String::new(),
                body: String::new(),
            }),
        }
    }
}

/// A transport that must never be called (out-of-scope requests must not send).
struct PanicTransport;
impl Transport for PanicTransport {
    fn fetch(&self, _m: &str, _p: &str) -> Result<Response, String> {
        panic!("out-of-scope request was sent — PRB-002 violated");
    }
}

fn verified(host_in_scope: &str, profile: Profile) -> multiscan_scope::VerifiedAuthorization {
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let mut auth = ScopeAuthorization {
        authorization_id: "auth-1".into(),
        scope: AuthorizedScope {
            include: vec![host_in_scope.to_string()],
            exclude: vec![],
            permitted_methods: vec![AuthorizedScopePermittedMethodsItem::Get],
            valid_from: "2026-08-01T00:00:00Z".into(),
            valid_until: "2026-08-31T00:00:00Z".into(),
            authorized_by: "a@b.c".into(),
            attestation: "on file".into(),
            signature: String::new(),
        },
    };
    auth.scope.signature = sign_authorization(&auth, &key);
    let toml = {
        let v: toml::Value = serde_json::from_str(&serde_json::to_string(&auth).unwrap()).unwrap();
        toml::to_string(&v).unwrap()
    };
    Authorization::from_toml(&toml)
        .unwrap()
        .verify(
            Some(&key.verifying_key().to_bytes()),
            Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap(),
            profile,
        )
        .unwrap()
}

fn env_template() -> Vec<Template> {
    Template::parse_pack(
        r#"
- id: exposed-env-file
  severity: high
  cwe: [CWE-200]
  requests:
    - method: GET
      path: ["/.env"]
      matchers:
        - type: status
          values: [200]
        - type: regex
          part: body
          patterns: ["(?m)^[A-Z_]+_(KEY|SECRET|TOKEN)="]
      matchers_condition: and
"#,
    )
    .unwrap()
}

fn audit() -> (AuditLog, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    (AuditLog::open(&dir.path().join("audit.log")), dir)
}

/// A matched template yields a Proven WebExposure with redacted evidence
/// (PRB-005).
#[test]
fn match_yields_proven_finding_with_redacted_evidence() {
    let auth = verified("staging.acme.com", Profile::Standard);
    let (log, _d) = audit();
    let mut responses = BTreeMap::new();
    responses.insert(
        "/.env".to_string(),
        Response {
            status: 200,
            headers: "Content-Type: text/plain".into(),
            body: "AWS_SECRET_KEY=wJalrXUtnFEMIabcdEXAMPLEKEY\n".into(),
        },
    );
    let transport = MockTransport { responses };
    let mut rate = RateControl::for_rps(25.0);

    let findings = execute(
        &env_template(),
        &ProbeRun {
            authorization: &auth,
            origin: "https://staging.acme.com".into(),
            host: "staging.acme.com".into(),
            now: "2026-08-15T00:00:00Z".into(),
        },
        &transport,
        &mut rate,
        &log,
    );

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert!(matches!(f.identity, IdentityKey::WebExposure { .. }));
    // PRB-005: Proven, with an http_exchange evidence entry...
    assert_eq!(f.confidence, multiscan_core::Confidence::Proven);
    let ev = &f.evidence[0];
    let exchange = ev.detail["exchange"].as_str().unwrap();
    // ...that is redacted — the secret value must not appear.
    assert!(!exchange.contains("wJalrXUtnFEMIabcdEXAMPLEKEY"));
    assert!(exchange.contains("REDACTED"));
}

/// No match → no finding (a benign 200 without the secret pattern).
#[test]
fn no_match_no_finding() {
    let auth = verified("staging.acme.com", Profile::Standard);
    let (log, _d) = audit();
    let mut responses = BTreeMap::new();
    responses.insert(
        "/.env".to_string(),
        Response {
            status: 200,
            headers: String::new(),
            body: "just a readme".into(),
        },
    );
    let mut rate = RateControl::for_rps(25.0);
    let findings = execute(
        &env_template(),
        &ProbeRun {
            authorization: &auth,
            origin: "https://staging.acme.com".into(),
            host: "staging.acme.com".into(),
            now: "2026-08-15T00:00:00Z".into(),
        },
        &MockTransport { responses },
        &mut rate,
        &log,
    );
    assert!(findings.is_empty());
}

/// PRB-002: an out-of-scope host is never fetched (the panic transport proves
/// no request was sent).
#[test]
fn out_of_scope_host_never_fetched() {
    // Authorization is for staging.acme.com; the run targets evil.com.
    let auth = verified("staging.acme.com", Profile::Standard);
    let (log, _d) = audit();
    let mut rate = RateControl::for_rps(25.0);
    let findings = execute(
        &env_template(),
        &ProbeRun {
            authorization: &auth,
            origin: "https://evil.com".into(),
            host: "evil.com".into(),
            now: "2026-08-15T00:00:00Z".into(),
        },
        &PanicTransport,
        &mut rate,
        &log,
    );
    assert!(findings.is_empty());
}
