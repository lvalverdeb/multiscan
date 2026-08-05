//! `finding_id` construction (spec 7.7.1–7.7.3) and the normalizations that
//! feed it (DET-005).
//!
//! The canonical encoding is frozen: changing it invalidates every user's
//! history and baselines (CLAUDE.md "when to stop and ask"). Encoding v1:
//! a domain-separation prefix, then each tuple field as a little-endian u64
//! length followed by the field's UTF-8 bytes. Length-prefixing makes the
//! encoding injective — no separator can be spoofed by field content.

use multiscan_core::IdentityKey;

/// Domain separator and version tag for the identity encoding. Bumping this is
/// a baseline-invalidating event and requires an ADR.
const DOMAIN: &[u8] = b"multiscan:finding_id:v1";

/// Compute the stable `finding_id` for an identity tuple: blake3 over the
/// canonical encoding, 32 bytes, lowercase hex (spec 7.7.1).
///
/// Path and origin fields are normalized here (DET-005), so callers may pass
/// engine-emitted identities directly; `a\b.tf` and `a/b.tf` yield the same id.
pub fn finding_id(identity: &IdentityKey) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    for field in canonical_fields(identity) {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// The identity tuple as ordered strings: `finding_class` first, then the
/// class-specific fields in spec 7.7.2 table order, normalized per DET-005.
/// Line numbers, timestamps, engine versions, and secret values are absent by
/// construction (spec 7.7.3) — the type does not carry them.
fn canonical_fields(identity: &IdentityKey) -> Vec<String> {
    match identity {
        IdentityKey::VulnerableDependency {
            purl,
            advisory_id,
            manifest_path,
        } => vec![
            "vulnerable_dependency".into(),
            purl.clone(),
            advisory_id.clone(),
            normalize_path(manifest_path),
        ],
        IdentityKey::ContainerVulnerability {
            purl,
            advisory_id,
            image_digest,
        } => vec![
            "container_vulnerability".into(),
            purl.clone(),
            advisory_id.clone(),
            image_digest.clone(),
        ],
        IdentityKey::ExposedSecret {
            rule_id,
            path,
            fingerprint,
        } => vec![
            "exposed_secret".into(),
            rule_id.clone(),
            normalize_path(path),
            fingerprint.clone(),
        ],
        IdentityKey::IacMisconfiguration {
            policy_id,
            path,
            resource_address,
        } => vec![
            "iac_misconfiguration".into(),
            policy_id.clone(),
            normalize_path(path),
            resource_address.clone(),
        ],
        IdentityKey::WebExposure {
            template_id,
            origin,
            request_path,
        } => vec![
            "web_exposure".into(),
            template_id.clone(),
            normalize_origin(origin),
            request_path.clone(),
        ],
        IdentityKey::StructuralPattern {
            rule_id,
            path,
            structural_hash,
        } => vec![
            "structural_pattern".into(),
            rule_id.clone(),
            normalize_path(path),
            structural_hash.clone(),
        ],
    }
}

/// Normalize a path to POSIX separators, root-relative form (DET-005):
/// backslashes become `/`, a leading `./` and leading slashes are stripped,
/// repeated slashes collapse, and a trailing slash is removed. Windows and
/// POSIX spellings of the same file must not produce different `finding_id`s.
pub fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut last_was_slash = false;
    for c in path.chars() {
        let c = if c == '\\' { '/' } else { c };
        if c == '/' {
            if last_was_slash {
                continue;
            }
            last_was_slash = true;
        } else {
            last_was_slash = false;
        }
        out.push(c);
    }
    // Strip leading "./" segments and any leading slash (root-relative form).
    let mut s = out.as_str();
    loop {
        if let Some(rest) = s.strip_prefix("./") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix('/') {
            s = rest;
        } else {
            break;
        }
    }
    s.strip_suffix('/').unwrap_or(s).to_string()
}

/// Normalize an origin (scheme + host + port) for identity: lowercase and
/// without a trailing slash. `HTTPS://Example.com:8443/` ≡ `https://example.com:8443`.
pub fn normalize_origin(origin: &str) -> String {
    origin.trim_end_matches('/').to_ascii_lowercase()
}
