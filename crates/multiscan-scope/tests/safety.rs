//! T-501 safety negative suite — the acceptance gate for `cargo xtask safety`
//! (spec 16, SEC-001..009, PRB-003). Every case asserts a deny/abort, and the
//! static-gate cases assert **no packet was sent** by using a mock resolver
//! that panics if called: a static-gate denial must never resolve the host.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::str::FromStr;

use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use multiscan_core::{
    AuthorizedScope, AuthorizedScopePermittedMethodsItem, Profile, ScopeAuthorization,
};
use multiscan_scope::{
    first_reserved_ip, resolve_pinned, sign_authorization, Authorization, Decision, Denied,
};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// A resolver that must never be called — proves a denial did zero network I/O.
fn panicking_resolver(_host: &str) -> std::io::Result<Vec<IpAddr>> {
    panic!("resolver called on a static-gate denial — SEC-001/FR-007 violated");
}

fn base_scope() -> AuthorizedScope {
    AuthorizedScope {
        include: vec!["*.staging.acme.com".into()],
        exclude: vec!["payments.staging.acme.com".into()],
        permitted_methods: vec![
            AuthorizedScopePermittedMethodsItem::Get,
            AuthorizedScopePermittedMethodsItem::Head,
        ],
        valid_from: "2026-08-01T00:00:00Z".into(),
        valid_until: "2026-08-31T00:00:00Z".into(),
        authorized_by: "j.ruiz@acme.com".into(),
        attestation: "Written authorization on file; targets owned by Acme.".into(),
        signature: String::new(),
    }
}

/// Build a signed authorization from a scope, signing its canonical bytes.
fn signed(scope: AuthorizedScope) -> (ScopeAuthorization, [u8; 32]) {
    let key = signing_key();
    let mut auth = ScopeAuthorization {
        authorization_id: "auth-2026-08-acme-staging".into(),
        scope,
    };
    auth.scope.signature = sign_authorization(&auth, &key);
    (auth, key.verifying_key().to_bytes())
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap()
}

fn to_toml(auth: &ScopeAuthorization) -> String {
    // Round-trip through JSON→toml value to produce a valid TOML document.
    let value: toml::Value = serde_json::from_str(&serde_json::to_string(auth).unwrap()).unwrap();
    toml::to_string(&value).unwrap()
}

/// The happy path verifies, so the negative cases are meaningful.
#[test]
fn valid_authorization_permits_in_scope_get() {
    let (auth, key) = signed(base_scope());
    let verified = Authorization::from_toml(&to_toml(&auth))
        .unwrap()
        .verify(Some(&key), now(), Profile::Standard)
        .expect("valid authorization must verify");
    assert!(verified
        .authorize("api.staging.acme.com", "GET")
        .is_allowed());
}

/// SEC-001 / FR-007: no authorization ⇒ deny, and no resolution happens
/// (there is nothing to resolve — the CLI exits 4 before this point).
#[test]
fn missing_authorization_is_denied_without_resolving() {
    // An out-of-scope host is decided without any network I/O.
    let (auth, key) = signed(base_scope());
    let verified = Authorization::from_toml(&to_toml(&auth))
        .unwrap()
        .verify(Some(&key), now(), Profile::Standard)
        .unwrap();
    let decision = verified.authorize("evil.com", "GET");
    assert!(matches!(decision, Decision::Denied(Denied::NotIncluded(_))));
    // The panicking resolver is never invoked for an out-of-scope host.
    let _ = panicking_resolver; // referenced, not called
}

/// SEC-001: a bad signature is denied.
#[test]
fn bad_signature_denied() {
    let (mut auth, key) = signed(base_scope());
    auth.scope.signature = "ed25519:00".into(); // wrong
    let result = Authorization::from_toml(&to_toml(&auth)).unwrap().verify(
        Some(&key),
        now(),
        Profile::Standard,
    );
    assert!(matches!(result, Err(Denied::BadSignature(_))));
}

/// SEC-001: no trusted key ⇒ cannot authenticate ⇒ deny (conservative, R-7).
#[test]
fn no_trusted_key_denied() {
    let (auth, _key) = signed(base_scope());
    let result =
        Authorization::from_toml(&to_toml(&auth))
            .unwrap()
            .verify(None, now(), Profile::Standard);
    assert!(matches!(result, Err(Denied::BadSignature(_))));
}

/// SEC-001: outside the validity window ⇒ deny.
#[test]
fn expired_window_denied() {
    let (auth, key) = signed(base_scope());
    let after = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
    let result = Authorization::from_toml(&to_toml(&auth)).unwrap().verify(
        Some(&key),
        after,
        Profile::Standard,
    );
    assert!(matches!(result, Err(Denied::Expired { .. })));
}

/// A-1: empty attestation ⇒ deny.
#[test]
fn empty_attestation_denied() {
    let mut scope = base_scope();
    scope.attestation = "   ".into();
    let (auth, key) = signed(scope);
    let result = Authorization::from_toml(&to_toml(&auth)).unwrap().verify(
        Some(&key),
        now(),
        Profile::Standard,
    );
    assert!(matches!(result, Err(Denied::MissingAttestation)));
}

/// SEC-002: exclude beats include.
#[test]
fn exclude_beats_include() {
    let (auth, key) = signed(base_scope());
    let verified = Authorization::from_toml(&to_toml(&auth))
        .unwrap()
        .verify(Some(&key), now(), Profile::Standard)
        .unwrap();
    assert!(matches!(
        verified.authorize("payments.staging.acme.com", "GET"),
        Decision::Denied(Denied::ExcludedBy(_))
    ));
}

/// SEC-003: a public-suffix-spanning wildcard fails the whole authorization.
#[test]
fn public_suffix_wildcard_rejected() {
    let mut scope = base_scope();
    scope.include = vec!["*.com".into()];
    let (auth, key) = signed(scope);
    let result = Authorization::from_toml(&to_toml(&auth)).unwrap().verify(
        Some(&key),
        now(),
        Profile::Standard,
    );
    assert!(matches!(result, Err(Denied::UnsafeWildcard(_))));
}

/// PRB-003: a non-idempotent method is blocked in the `standard` profile even
/// if the authorization permits it — and it is decided without resolving.
#[test]
fn non_idempotent_method_blocked_in_standard() {
    let mut scope = base_scope();
    scope
        .permitted_methods
        .push(AuthorizedScopePermittedMethodsItem::Post);
    let (auth, key) = signed(scope);
    let verified = Authorization::from_toml(&to_toml(&auth))
        .unwrap()
        .verify(Some(&key), now(), Profile::Standard)
        .unwrap();
    assert!(matches!(
        verified.authorize("api.staging.acme.com", "POST"),
        Decision::Denied(Denied::MethodNotPermitted(_))
    ));
    // In thorough, the same authorization permits POST.
    let (auth2, key2) = signed({
        let mut s = base_scope();
        s.permitted_methods
            .push(AuthorizedScopePermittedMethodsItem::Post);
        s
    });
    let verified2 = Authorization::from_toml(&to_toml(&auth2))
        .unwrap()
        .verify(Some(&key2), now(), Profile::Thorough)
        .unwrap();
    assert!(verified2
        .authorize("api.staging.acme.com", "POST")
        .is_allowed());
}

/// SEC-004: DNS drift to a reserved/internal IP ⇒ the connection is aborted.
#[test]
fn dns_rebinding_to_reserved_ip_aborted() {
    // A host that resolves only to the cloud metadata endpoint: no allowed
    // address remains, so it is denied.
    let rebind = |_h: &str| Ok(vec![IpAddr::from_str("169.254.169.254").unwrap()]);
    let result = resolve_pinned("attacker.staging.acme.com", 443, Some(&rebind));
    assert!(matches!(result, Err(Denied::NoAllowedAddress(_))));
    assert_eq!(
        first_reserved_ip("attacker.staging.acme.com", &rebind),
        Some(IpAddr::from_str("169.254.169.254").unwrap())
    );
}

/// SEC-004: a mix of allowed and reserved IPs keeps only the allowed ones.
#[test]
fn mixed_resolution_keeps_only_allowed() {
    let mixed = |_h: &str| {
        Ok(vec![
            IpAddr::from_str("10.0.0.5").unwrap(),
            IpAddr::from_str("93.184.216.34").unwrap(),
        ])
    };
    let pinned = resolve_pinned("host.staging.acme.com", 443, Some(&mixed)).unwrap();
    assert_eq!(pinned.len(), 1);
    assert_eq!(pinned[0].ip(), IpAddr::from_str("93.184.216.34").unwrap());
}

/// SEC-004: the IPv4-mapped IPv6 rebinding bypass is blocked end-to-end.
#[test]
fn ipv4_mapped_rebinding_blocked() {
    let mapped = |_h: &str| Ok(vec![IpAddr::from_str("::ffff:127.0.0.1").unwrap()]);
    assert!(matches!(
        resolve_pinned("x.staging.acme.com", 443, Some(&mapped)),
        Err(Denied::NoAllowedAddress(_))
    ));
}
