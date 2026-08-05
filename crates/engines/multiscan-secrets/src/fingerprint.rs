//! Secret fingerprinting and masking (SEC-101).
//!
//! The raw secret value NEVER leaves this module. Callers receive only a
//! keyed, truncated blake3 fingerprint (for identity) and a heavily-masked
//! preview (for human evidence) — neither is reversible to the value.

/// Domain separator so fingerprints are not raw hashes an attacker could
/// precompute against a wordlist of known tokens.
const FINGERPRINT_KEY: &[u8] = b"multiscan:secret-fingerprint:v1";

/// Truncated keyed fingerprint of a secret value: 16 lowercase hex chars.
/// Stable for identity (spec 7.7.2) yet not the value itself (SEC-101).
pub fn fingerprint(value: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FINGERPRINT_KEY);
    hasher.update(value.as_bytes());
    hasher.finalize().to_hex()[..16].to_string()
}

/// A masked preview safe to show a human: first two and last two characters
/// with the middle elided, and never more than 4 revealed characters total.
/// Short secrets are fully masked.
pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len().min(8));
    }
    let head: String = chars.iter().take(2).collect();
    let tail: String = chars
        .iter()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}****{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_not_the_value() {
        let fp = fingerprint("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(fp, fingerprint("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(fp.len(), 16);
        assert!(!fp.contains("AKIA"));
        assert_ne!(fp, fingerprint("AKIAIOSFODNN7EXAMPLF"));
    }

    #[test]
    fn mask_reveals_at_most_four_chars() {
        assert_eq!(mask("AKIAIOSFODNN7EXAMPLE"), "AK****LE");
        // The bulk of the value never appears.
        assert!(!mask("AKIAIOSFODNN7EXAMPLE").contains("IOSFODNN"));
        assert_eq!(mask("short"), "*****");
    }
}
