//! Data-driven policy model and evaluator (IAC-001). A policy is data, never
//! code: no eval, no shell-out. Conditions are a small closed set evaluated
//! against the normalized resource tree.

use serde::Deserialize;

use crate::resource::{Resource, Value};

/// One policy from the bundled pack.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    /// Stable policy id (identity input, spec 7.7.2), e.g. `cis-aws-s3-1`.
    pub id: String,
    /// Human title.
    pub title: String,
    /// Resource kinds this policy applies to.
    pub resource_kinds: Vec<String>,
    /// Severity when the condition matches (a violation).
    pub severity: String,
    /// CWE ids.
    #[serde(default)]
    pub cwe: Vec<String>,
    /// Compliance controls — at least one, or the policy is counted in
    /// `mapping_gaps` (IAC-004).
    #[serde(default)]
    pub compliance_controls: Vec<String>,
    /// Remediation guidance.
    pub remediation: String,
    /// The condition that, when TRUE, indicates a violation.
    pub condition: Condition,
}

/// A closed set of declarative conditions (no embedded code, PRB-001 spirit).
// Field names (`attribute`, `value`, `values`, `conditions`) are self-
// describing and repeat across variants; the variant docs carry the meaning.
#[allow(missing_docs)]
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    /// Attribute equals a string value.
    Equals { attribute: String, value: String },
    /// Attribute is one of several string values.
    In {
        attribute: String,
        values: Vec<String>,
    },
    /// Attribute is absent or null.
    Absent { attribute: String },
    /// Attribute (a bool) is true.
    IsTrue { attribute: String },
    /// Attribute (a bool) is false or absent.
    IsFalseOrAbsent { attribute: String },
    /// Attribute (a list) contains the given string.
    Contains { attribute: String, value: String },
    /// Logical negation.
    Not { condition: Box<Condition> },
    /// All sub-conditions hold.
    All { conditions: Vec<Condition> },
    /// Any sub-condition holds.
    Any { conditions: Vec<Condition> },
}

/// Outcome of evaluating a condition against a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eval {
    /// Condition holds (a violation).
    Violation,
    /// Condition does not hold.
    Pass,
    /// Could not be determined because it depends on an unresolved value.
    /// The engine reports it as a `Heuristic` violation rather than a silent
    /// pass (IAC-003).
    Unresolved,
}

impl Condition {
    /// Evaluate against a resource.
    pub fn eval(&self, resource: &Resource) -> Eval {
        match self {
            Condition::Equals { attribute, value } => match resource.get(attribute) {
                Some(v) if v.has_unresolved() => Eval::Unresolved,
                Some(Value::String(s)) if s == value => Eval::Violation,
                Some(_) => Eval::Pass,
                None => Eval::Pass,
            },
            Condition::In { attribute, values } => match resource.get(attribute) {
                Some(v) if v.has_unresolved() => Eval::Unresolved,
                Some(Value::String(s)) if values.contains(s) => Eval::Violation,
                _ => Eval::Pass,
            },
            Condition::Absent { attribute } => match resource.get(attribute) {
                None | Some(Value::Null) => Eval::Violation,
                Some(v) if v.has_unresolved() => Eval::Unresolved,
                Some(_) => Eval::Pass,
            },
            Condition::IsTrue { attribute } => match resource.get(attribute) {
                Some(v) if v.has_unresolved() => Eval::Unresolved,
                Some(v) => {
                    if v.as_bool() == Some(true) {
                        Eval::Violation
                    } else {
                        Eval::Pass
                    }
                }
                None => Eval::Pass,
            },
            Condition::IsFalseOrAbsent { attribute } => match resource.get(attribute) {
                None => Eval::Violation,
                Some(v) if v.has_unresolved() => Eval::Unresolved,
                Some(v) => {
                    if v.as_bool() == Some(false) {
                        Eval::Violation
                    } else {
                        Eval::Pass
                    }
                }
            },
            Condition::Contains { attribute, value } => match resource.get(attribute) {
                Some(v) if v.has_unresolved() => Eval::Unresolved,
                Some(Value::List(items)) => {
                    if items.iter().any(|i| i.as_str() == Some(value.as_str())) {
                        Eval::Violation
                    } else {
                        Eval::Pass
                    }
                }
                _ => Eval::Pass,
            },
            Condition::Not { condition } => match condition.eval(resource) {
                Eval::Violation => Eval::Pass,
                Eval::Pass => Eval::Violation,
                Eval::Unresolved => Eval::Unresolved,
            },
            Condition::All { conditions } => {
                let mut unresolved = false;
                for c in conditions {
                    match c.eval(resource) {
                        Eval::Pass => return Eval::Pass,
                        Eval::Unresolved => unresolved = true,
                        Eval::Violation => {}
                    }
                }
                if unresolved {
                    Eval::Unresolved
                } else {
                    Eval::Violation
                }
            }
            Condition::Any { conditions } => {
                let mut unresolved = false;
                for c in conditions {
                    match c.eval(resource) {
                        Eval::Violation => return Eval::Violation,
                        Eval::Unresolved => unresolved = true,
                        Eval::Pass => {}
                    }
                }
                if unresolved {
                    Eval::Unresolved
                } else {
                    Eval::Pass
                }
            }
        }
    }
}
