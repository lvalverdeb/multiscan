//! Declarative probe templates (spec 7.4, PRB-001). Templates are data: a
//! request spec + a matcher spec. There is no scripting, no eval, no
//! template-controlled shell-out — parsing produces plain structs, and the
//! executor only ever performs a bounded HTTP request and regex/status/word
//! matching.

use serde::Deserialize;

/// Errors validating a template.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// The YAML/JSON did not parse.
    #[error("template parse error: {0}")]
    Parse(String),
    /// The template violates a safety rule (PRB-003/PRB-004).
    #[error("unsafe template `{id}`: {reason}")]
    Unsafe {
        /// Template id.
        id: String,
        /// Why it was rejected.
        reason: String,
    },
}

/// A probe template.
#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    /// Stable template id (identity input, spec 7.7.2).
    pub id: String,
    /// Severity for a match.
    pub severity: String,
    /// CWE ids.
    #[serde(default)]
    pub cwe: Vec<String>,
    /// Human title/description.
    #[serde(default)]
    pub description: Option<String>,
    /// Request specifications.
    pub requests: Vec<RequestSpec>,
}

/// One request specification, expanded over its `path` list.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestSpec {
    /// HTTP method.
    #[serde(default = "default_method")]
    pub method: String,
    /// Paths to probe (each becomes a separate request).
    pub path: Vec<String>,
    /// Matchers to evaluate against the response.
    pub matchers: Vec<Matcher>,
    /// How to combine matchers.
    #[serde(default = "default_condition", rename = "matchers_condition")]
    pub matchers_condition: Condition,
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_condition() -> Condition {
    Condition::And
}

/// Matcher-combination logic.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    /// All matchers must hold.
    And,
    /// Any matcher may hold.
    Or,
}

/// A response matcher (a closed set — no code).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Matcher {
    /// The response status is one of these.
    Status {
        /// Acceptable status codes.
        values: Vec<u16>,
    },
    /// A regex matches the given part.
    Regex {
        /// `body` or `header`.
        #[serde(default = "default_part")]
        part: Part,
        /// Patterns; any match satisfies this matcher.
        patterns: Vec<String>,
    },
    /// A literal substring appears in the given part.
    Word {
        /// `body` or `header`.
        #[serde(default = "default_part")]
        part: Part,
        /// Words; any presence satisfies this matcher.
        words: Vec<String>,
    },
}

fn default_part() -> Part {
    Part::Body
}

/// Which part of the response a matcher inspects.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Part {
    /// The response body.
    Body,
    /// The response headers (joined).
    Header,
}

impl Template {
    /// Parse a template pack (a YAML list of templates) and validate each.
    pub fn parse_pack(yaml: &str) -> Result<Vec<Template>, TemplateError> {
        let templates: Vec<Template> =
            serde_yaml_ng::from_str(yaml).map_err(|e| TemplateError::Parse(e.to_string()))?;
        for t in &templates {
            t.validate()?;
        }
        Ok(templates)
    }

    /// Validate safety invariants (PRB-003, PRB-004). v1 permits only
    /// idempotent, body-less requests — which structurally cannot write,
    /// delete, or persist state on the target.
    pub fn validate(&self) -> Result<(), TemplateError> {
        for req in &self.requests {
            let method = req.method.to_ascii_uppercase();
            if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
                return Err(TemplateError::Unsafe {
                    id: self.id.clone(),
                    reason: format!(
                        "method `{method}` is not idempotent; v1 templates are read-only (PRB-004)"
                    ),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACK: &str = r#"
- id: exposed-env-file
  severity: high
  cwe: [CWE-200]
  requests:
    - method: GET
      path: ["/.env", "/.env.local"]
      matchers:
        - type: status
          values: [200]
        - type: regex
          part: body
          patterns: ["(?m)^[A-Z_]+_(KEY|SECRET|TOKEN)="]
      matchers_condition: and
"#;

    #[test]
    fn parses_and_expands() {
        let templates = Template::parse_pack(PACK).unwrap();
        assert_eq!(templates.len(), 1);
        let t = &templates[0];
        assert_eq!(t.id, "exposed-env-file");
        assert_eq!(t.requests[0].path.len(), 2);
        assert_eq!(t.requests[0].matchers.len(), 2);
        assert_eq!(t.requests[0].matchers_condition, Condition::And);
    }

    #[test]
    fn rejects_non_idempotent_method() {
        let bad = r#"
- id: bad
  severity: high
  requests:
    - method: POST
      path: ["/x"]
      matchers:
        - type: status
          values: [200]
"#;
        assert!(matches!(
            Template::parse_pack(bad),
            Err(TemplateError::Unsafe { .. })
        ));
    }
}
