//! Probe engine: declarative HTTP template execution (spec 7.4).
//!
//! Scope-limited by design (NG-3): declarative templates only — no crawling, no
//! session management, no form inference, no scripting (PRB-001). Every request
//! passes `multiscan-scope` before it is sent (PRB-002), only idempotent
//! methods run (PRB-003/PRB-004), and a match earns `Proven` confidence only
//! with a redacted request/response exchange (PRB-005).

mod executor;
mod matcher;
mod redact;
mod scoped;
mod template;

pub use executor::{execute, ProbeRun, Transport};
pub use matcher::Response;
pub use scoped::ScopedTransport;
pub use template::{Template, TemplateError};

/// The bundled probe template pack, embedded so the probe layer needs no
/// network access to obtain its rules (content-addressed provenance via the
/// digest below).
const BUILTIN_TEMPLATES: &str = include_str!("../../../../rules/probe/builtin.yaml");

/// Parse the bundled template pack.
pub fn builtin_templates() -> Result<Vec<Template>, TemplateError> {
    Template::parse_pack(BUILTIN_TEMPLATES)
}

/// blake3 digest of the bundled template pack (FD-006 provenance).
pub fn builtin_digest() -> String {
    format!(
        "blake3:{}",
        blake3::hash(BUILTIN_TEMPLATES.as_bytes()).to_hex()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_pack_is_valid() {
        let templates = builtin_templates().expect("bundled templates must parse and validate");
        assert!(templates.len() >= 3);
        assert!(templates.iter().any(|t| t.id == "exposed-env-file"));
    }
}
