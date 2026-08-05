//! Matcher evaluation against a response (spec 7.4). Pure and bounded — regex
//! only, no code execution (PRB-001).

use regex::Regex;

use crate::template::{Condition, Matcher, Part};

/// A response the matchers evaluate against.
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Header lines joined with `\n` (`Name: value`).
    pub headers: String,
    /// Response body (already size-capped by the transport).
    pub body: String,
}

/// Evaluate a single matcher against a response.
fn eval_one(matcher: &Matcher, response: &Response) -> bool {
    match matcher {
        Matcher::Status { values } => values.contains(&response.status),
        Matcher::Regex { part, patterns } => {
            let hay = part_text(*part, response);
            patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .any(|re| re.is_match(hay))
        }
        Matcher::Word { part, words } => {
            let hay = part_text(*part, response);
            words.iter().any(|w| hay.contains(w))
        }
    }
}

fn part_text(part: Part, response: &Response) -> &str {
    match part {
        Part::Body => &response.body,
        Part::Header => &response.headers,
    }
}

/// Evaluate a matcher set under its combination condition.
pub fn evaluate(matchers: &[Matcher], condition: Condition, response: &Response) -> bool {
    match condition {
        Condition::And => matchers.iter().all(|m| eval_one(m, response)),
        Condition::Or => matchers.iter().any(|m| eval_one(m, response)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: "Content-Type: text/plain".to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn and_requires_all() {
        let matchers = vec![
            Matcher::Status { values: vec![200] },
            Matcher::Regex {
                part: Part::Body,
                patterns: vec!["(?m)^[A-Z_]+_(KEY|SECRET)=".to_string()],
            },
        ];
        assert!(evaluate(
            &matchers,
            Condition::And,
            &resp(200, "AWS_SECRET=xyz\n")
        ));
        // Status matches but body doesn't → AND fails.
        assert!(!evaluate(&matchers, Condition::And, &resp(200, "hello")));
        // Body matches but status doesn't → AND fails.
        assert!(!evaluate(
            &matchers,
            Condition::And,
            &resp(404, "AWS_KEY=1")
        ));
    }

    #[test]
    fn or_requires_any() {
        let matchers = vec![
            Matcher::Status { values: vec![200] },
            Matcher::Word {
                part: Part::Body,
                words: vec!["phpinfo()".to_string()],
            },
        ];
        assert!(evaluate(&matchers, Condition::Or, &resp(200, "nothing")));
        assert!(evaluate(
            &matchers,
            Condition::Or,
            &resp(500, "phpinfo() output")
        ));
        assert!(!evaluate(&matchers, Condition::Or, &resp(500, "nothing")));
    }
}
