//! ed25519 signing for air-gap bundles (FD-005). The signing key lives under
//! the cache dir; bundles carry the public key and a signature so import can
//! verify integrity (and, with `--trusted-key`, authenticity).

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::FeedError;

/// Load the local signing key, creating one on first use. Stored as a raw
/// 32-byte seed under `<cache>/keys/ed25519.seed` with owner-only permissions.
pub fn load_or_create_signing_key(cache: &Path) -> Result<SigningKey, FeedError> {
    let path = cache.join("keys/ed25519.seed");
    if let Ok(bytes) = std::fs::read(&path) {
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| FeedError::Corrupt("signing key is not 32 bytes".to_string()))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    // Generate a fresh seed from the OS CSPRNG.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| FeedError::Corrupt(format!("generating signing key: {e}")))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, seed)?;
    restrict_permissions(&path);
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// The public key (32 bytes) for a signing key.
pub fn public_key_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// Sign a message, returning the 64-byte signature.
pub fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

/// Verify a signature over `message` with the given 32-byte public key.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(message, &sig).is_ok()
}

/// Parse a hex-encoded 32-byte public key (for `--trusted-key`).
pub fn parse_public_key_hex(hex: &str) -> Option<[u8; 32]> {
    decode_hex(hex.trim())?.try_into().ok()
}

/// Lowercase-hex encode.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode lowercase/uppercase hex to bytes.
pub fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let mut seed = [7u8; 32];
        seed[0] = 42;
        let key = SigningKey::from_bytes(&seed);
        let pubkey = public_key_bytes(&key);
        let sig = sign(&key, b"hello");
        assert!(verify(&pubkey, b"hello", &sig));
        // Tampered message fails.
        assert!(!verify(&pubkey, b"hell0", &sig));
        // Wrong key fails.
        let other = public_key_bytes(&SigningKey::from_bytes(&[9u8; 32]));
        assert!(!verify(&other, b"hello", &sig));
    }

    #[test]
    fn hex_round_trip() {
        let pubkey = public_key_bytes(&SigningKey::from_bytes(&[3u8; 32]));
        let hex = to_hex(&pubkey);
        assert_eq!(parse_public_key_hex(&hex), Some(pubkey));
    }
}
