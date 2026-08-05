//! Evidence redaction (PRB-005, SEC-101 spirit). A matched template yields
//! `Proven` confidence only when the request/response exchange is attached as
//! Evidence with secrets redacted — so the evidence proves the finding without
//! leaking the very credentials it found.

use regex::Regex;

/// Patterns whose *value* must be masked in evidence (assignments of
/// key/secret/token/password, and common provider token shapes).
fn redaction_patterns() -> Vec<Regex> {
    // Specific patterns first so a general assignment match can't consume a
    // token (e.g. `Bearer`) before its dedicated pattern redacts the value.
    [
        // Bearer tokens.
        r"(?i)(bearer\s+)([A-Za-z0-9._\-]+)",
        // AWS access key ids.
        r"\b(AKIA)[0-9A-Z]{16}\b",
        // Assignment of a secret-ish key: `<...>KEY = value`, `SECRET: value`,
        // etc. `\w*` lets the keyword be a suffix (`AWS_SECRET_KEY`); the value
        // is the first non-space token.
        r#"(?i)(\w*(?:key|secret|token|password|passwd|authorization)\s*[:=]\s*)("?[^"\s]+"?)"#,
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
}

/// Redact secrets from a text (request or response) for safe evidence.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for re in redaction_patterns() {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                // Keep the label/prefix (group 1) when present; mask the rest.
                match caps.get(1) {
                    Some(prefix) => format!("{}***REDACTED***", prefix.as_str()),
                    None => "***REDACTED***".to_string(),
                }
            })
            .into_owned();
    }
    out
}

/// Cap evidence text so a huge body can't bloat a finding.
pub fn cap(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        format!("{}… [{} bytes truncated]", &text[..max], text.len() - max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_secret_values_keeps_labels() {
        let body = "AWS_SECRET_KEY=wJalrXUtnFEMIabcdEXAMPLE\nDB_PASSWORD: hunter2\nok=fine";
        let red = redact(body);
        assert!(!red.contains("wJalrXUtnFEMIabcdEXAMPLE"));
        assert!(!red.contains("hunter2"));
        assert!(red.contains("REDACTED"));
        // Non-secret assignments survive.
        assert!(red.contains("ok=fine"));
    }

    #[test]
    fn masks_bearer_and_aws_key() {
        let h = "Authorization: Bearer abc.def.ghi";
        assert!(!redact(h).contains("abc.def.ghi"));
        assert!(!redact("id AKIAIOSFODNN7EXAMPLE here").contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
