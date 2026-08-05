//! Authorization parsing, signing input, and the static gate that yields a
//! `VerifiedAuthorization` (SEC-001, A-1, SEC-003, PRB-003).
//!
//! The static gate does **zero network I/O**: parse → verify signature →
//! check validity window → attestation non-empty → build the (wildcard-checked)
//! scope. A `VerifiedAuthorization` is the *only* way to obtain a scoped
//! connection (see `lib.rs`), so the type system — not a runtime check someone
//! could forget — enforces SEC-009.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use multiscan_core::{Profile, ScopeAuthorization};

use crate::decision::{Decision, Denied};
use crate::scope::Scope;

/// Domain separator for the authorization signing input. Bumping it is a
/// breaking change to every issued authorization.
const SIGN_DOMAIN: &[u8] = b"multiscan:scope-auth:v1";

/// A parsed-but-unverified authorization. The only thing you can do with it is
/// [`Authorization::verify`].
pub struct Authorization {
    inner: ScopeAuthorization,
}

/// An authorization that has passed the full static gate. Holds the validated
/// scope and the active profile; this is the capability required to open a
/// scoped connection.
pub struct VerifiedAuthorization {
    /// The authorization id, for audit records.
    pub authorization_id: String,
    scope: Scope,
    profile: Profile,
}

impl Authorization {
    /// Parse an authorization from TOML (the spec 9.1 file form).
    pub fn from_toml(text: &str) -> Result<Self, Denied> {
        let inner: ScopeAuthorization =
            toml::from_str(text).map_err(|e| Denied::BadSignature(format!("parse: {e}")))?;
        Ok(Self { inner })
    }

    /// Parse from JSON (same schema).
    pub fn from_json(text: &str) -> Result<Self, Denied> {
        let inner: ScopeAuthorization =
            serde_json::from_str(text).map_err(|e| Denied::BadSignature(format!("parse: {e}")))?;
        Ok(Self { inner })
    }

    /// The canonical byte string that is signed. Length-prefixed and
    /// domain-separated so it cannot drift with JSON key ordering or
    /// whitespace (a signer and verifier that disagree would be a silent hole).
    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(&self.inner)
    }

    /// Run the static gate. `trusted_key` is the ed25519 public key the
    /// signature must verify against; absent or non-verifying ⇒ deny (the
    /// conservative choice for the underspecified key-management story, R-7 /
    /// §17). `now` is injected (DET-004).
    pub fn verify(
        self,
        trusted_key: Option<&[u8; 32]>,
        now: DateTime<Utc>,
        profile: Profile,
    ) -> Result<VerifiedAuthorization, Denied> {
        let scope = &self.inner.scope;

        // 1. Attestation must be non-empty (A-1).
        if scope.attestation.trim().is_empty() {
            return Err(Denied::MissingAttestation);
        }

        // 2. Signature must verify against a trusted key.
        let key = trusted_key.ok_or_else(|| {
            Denied::BadSignature("no trusted key supplied; cannot authenticate".to_string())
        })?;
        verify_signature(&self.inner, key)?;

        // 3. Validity window (SEC-001).
        let from = parse_time(&scope.valid_from).map_err(|e| Denied::Expired {
            detail: format!("valid_from: {e}"),
        })?;
        let until = parse_time(&scope.valid_until).map_err(|e| Denied::Expired {
            detail: format!("valid_until: {e}"),
        })?;
        if now < from || now > until {
            return Err(Denied::Expired {
                detail: format!("now {now} not in [{from}, {until}]"),
            });
        }

        // 4. Build the scope, rejecting public-suffix-spanning wildcards
        //    (SEC-003).
        let methods: Vec<String> = scope
            .permitted_methods
            .iter()
            .map(|m| format!("{m:?}").to_ascii_uppercase())
            .collect();
        let scope = Scope::new(scope.include.clone(), scope.exclude.clone(), methods)?;

        Ok(VerifiedAuthorization {
            authorization_id: self.inner.authorization_id.clone(),
            scope,
            profile,
        })
    }
}

impl VerifiedAuthorization {
    /// The per-request static gate: host in scope AND method permitted under
    /// both the profile (PRB-003) and the authorization. Zero I/O.
    pub fn authorize(&self, host: &str, method: &str) -> Decision {
        // Method: profile restricts before the authorization's own list.
        if !method_allowed_by_profile(method, self.profile) {
            return Decision::Denied(Denied::MethodNotPermitted(format!(
                "{} under {:?} profile",
                method.to_ascii_uppercase(),
                self.profile
            )));
        }
        if !self.scope.method_permitted(method) {
            return Decision::Denied(Denied::MethodNotPermitted(method.to_ascii_uppercase()));
        }
        self.scope.decide_host(host)
    }
}

/// Profile-level method policy (PRB-003): only idempotent methods outside
/// `thorough`. This is checked *before* the authorization's `permitted_methods`
/// so a POST is blocked in `standard` even if the authorization lists it.
fn method_allowed_by_profile(method: &str, profile: Profile) -> bool {
    let m = method.to_ascii_uppercase();
    let idempotent = matches!(m.as_str(), "GET" | "HEAD" | "OPTIONS");
    match profile {
        Profile::Quick | Profile::Standard => idempotent,
        Profile::Thorough => true,
    }
}

fn parse_time(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| e.to_string())
}

fn signing_bytes(auth: &ScopeAuthorization) -> Vec<u8> {
    let scope = &auth.scope;
    let mut out = Vec::new();
    out.extend_from_slice(SIGN_DOMAIN);
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
    };
    field(auth.authorization_id.as_bytes());
    field(&(scope.include.len() as u64).to_le_bytes());
    for p in &scope.include {
        field(p.as_bytes());
    }
    field(&(scope.exclude.len() as u64).to_le_bytes());
    for p in &scope.exclude {
        field(p.as_bytes());
    }
    field(&(scope.permitted_methods.len() as u64).to_le_bytes());
    for m in &scope.permitted_methods {
        field(format!("{m:?}").as_bytes());
    }
    field(scope.valid_from.as_bytes());
    field(scope.valid_until.as_bytes());
    field(scope.authorized_by.as_bytes());
    field(scope.attestation.as_bytes());
    out
}

fn verify_signature(auth: &ScopeAuthorization, key: &[u8; 32]) -> Result<(), Denied> {
    let sig_hex = auth
        .scope
        .signature
        .strip_prefix("ed25519:")
        .ok_or_else(|| Denied::BadSignature("signature must be `ed25519:<hex>`".to_string()))?;
    let sig_bytes = decode_hex(sig_hex)
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or_else(|| Denied::BadSignature("malformed signature".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(key)
        .map_err(|e| Denied::BadSignature(format!("bad trusted key: {e}")))?;
    verifying_key
        .verify(&signing_bytes(auth), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| Denied::BadSignature("signature does not verify".to_string()))
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Test-only: sign an authorization's canonical bytes, returning the
/// `ed25519:<hex>` signature string. Exposed so the safety suite (and, later,
/// `authorize create`) can produce valid authorizations.
#[doc(hidden)]
pub fn sign_authorization(
    auth: &ScopeAuthorization,
    signing_key: &ed25519_dalek::SigningKey,
) -> String {
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&signing_bytes(auth));
    let mut hex = String::from("ed25519:");
    for b in sig.to_bytes() {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}
