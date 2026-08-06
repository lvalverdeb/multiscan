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
const BUILTIN_TEMPLATES: &str = include_str!("../rules/builtin.yaml");

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

    use crate::matcher::evaluate;
    use crate::template::{Matcher, Part};

    fn resp(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: String::new(),
            body: body.to_string(),
        }
    }

    #[test]
    fn builtin_pack_is_valid() {
        let templates = builtin_templates().expect("bundled templates must parse and validate");
        assert!(templates.len() >= 14, "corpus shrank: {}", templates.len());
        assert!(templates.iter().any(|t| t.id == "exposed-env-file"));

        // Structural invariants for every template.
        let mut ids = std::collections::BTreeSet::new();
        for t in &templates {
            assert!(ids.insert(t.id.clone()), "duplicate template id {}", t.id);
            assert!(
                matches!(t.severity.as_str(), "critical" | "high" | "medium" | "low" | "info"),
                "{}: bad severity {}",
                t.id,
                t.severity
            );
            assert!(!t.cwe.is_empty(), "{}: no CWE", t.id);
            assert!(!t.requests.is_empty(), "{}: no requests", t.id);
            for r in &t.requests {
                assert!(!r.path.is_empty(), "{}: empty path list", t.id);
                assert!(!r.matchers.is_empty(), "{}: no matchers", t.id);
                // PRB-004: every request stays idempotent/read-only.
                assert!(
                    matches!(
                        r.method.to_ascii_uppercase().as_str(),
                        "GET" | "HEAD" | "OPTIONS"
                    ),
                    "{}: non-idempotent method {}",
                    t.id,
                    r.method
                );
                // A body content matcher plus a status matcher — never status
                // alone, which is the low-FP contract of this corpus.
                let has_status = r
                    .matchers
                    .iter()
                    .any(|m| matches!(m, Matcher::Status { .. }));
                let has_content = r.matchers.iter().any(|m| {
                    matches!(
                        m,
                        Matcher::Regex { part: Part::Body, .. }
                            | Matcher::Word { part: Part::Body, .. }
                    )
                });
                assert!(
                    has_status && has_content,
                    "{}: needs status AND body content",
                    t.id
                );
            }
        }
    }

    /// Each template fires on a realistic positive and stays quiet on a
    /// plausible negative (200 with unrelated content, or the right content
    /// at a 404). Proves the corpus catches real exposures without matching
    /// on status alone.
    #[test]
    fn corpus_matches_positives_not_negatives() {
        let templates = builtin_templates().unwrap();
        let req_of =
            |id: &str| templates.iter().find(|t| t.id == id).unwrap().requests[0].clone();

        // (template id, matching body, non-matching body)
        let cases = [
            ("exposed-env-file", "DB_SECRET=hunter2\n", "<html>ok</html>"),
            ("exposed-npmrc", "//registry.npmjs.org/:_authToken=abc", "registry=https://x"),
            ("exposed-aws-credentials", "[default]\naws_access_key_id = AKIA", "nothing here"),
            ("exposed-ssh-private-key", "-----BEGIN OPENSSH PRIVATE KEY-----", "ssh-rsa AAAA"),
            ("exposed-wp-config-backup", "define('DB_PASSWORD', 'x');", "<?php echo 1;"),
            ("exposed-sql-dump", "INSERT INTO users VALUES (1);", "not a dump"),
            ("exposed-git-config", "[core]\n\trepositoryformatversion = 0", "hello"),
            ("exposed-git-head", "ref: refs/heads/main\n", "just text"),
            ("exposed-svn", "SQLite format 3\u{0}", "plain"),
            ("exposed-ds-store", "Bud1\u{0}\u{0}", "text"),
            ("phpinfo-exposed", "<title>PHP Version 8.2.1</title>", "<html></html>"),
            ("apache-server-status", "<h1>Apache Server Status for x</h1>", "welcome"),
            ("nginx-status", "Active connections: 43", "welcome"),
            ("spring-actuator-env", "{\"propertySources\":[]}", "{\"status\":\"UP\"}"),
        ];
        assert_eq!(cases.len(), 14, "cover every template");

        for (id, hit, miss) in cases {
            let req = req_of(id);
            assert!(
                evaluate(&req.matchers, req.matchers_condition, &resp(200, hit)),
                "{id}: should match its own content"
            );
            assert!(
                !evaluate(&req.matchers, req.matchers_condition, &resp(200, miss)),
                "{id}: matched unrelated 200 content (false positive)"
            );
            // Right content but a 404 must not fire (status is required).
            assert!(
                !evaluate(&req.matchers, req.matchers_condition, &resp(404, hit)),
                "{id}: fired on a 404"
            );
        }
    }
}
