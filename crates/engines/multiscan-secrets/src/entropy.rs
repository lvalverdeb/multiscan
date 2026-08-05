//! Shannon entropy over bytes, for the entropy-based detector (spec 7.2).

/// Shannon entropy (bits per symbol) of a byte string. Empty input is 0.
pub fn shannon_bits(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_string_has_low_entropy() {
        assert!(shannon_bits(b"aaaaaaaaaaaaaaaa") < 0.01);
    }

    #[test]
    fn random_looking_string_has_high_entropy() {
        // A base64-ish 40-char token.
        let token = b"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY123";
        assert!(shannon_bits(token) > 4.0);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_bits(b""), 0.0);
    }
}
