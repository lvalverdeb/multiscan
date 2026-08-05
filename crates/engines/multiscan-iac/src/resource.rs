//! Normalized resource tree (spec 7.3). HCL, YAML, and JSON all parse into
//! this single shape so policies evaluate against one model.

use std::collections::BTreeMap;

/// A normalized attribute value. `Unresolved` marks a value the parser could
/// not statically determine (e.g. an HCL `var.*` interpolation) — policies
/// touching it degrade to `Heuristic` rather than silently passing (IAC-003).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Null / absent.
    Null,
    /// Boolean.
    Bool(bool),
    /// Number (kept as text to avoid float identity issues).
    Number(String),
    /// String literal.
    String(String),
    /// Ordered list.
    List(Vec<Value>),
    /// Ordered map.
    Map(BTreeMap<String, Value>),
    /// A value that could not be resolved statically (interpolation, ref).
    Unresolved,
}

impl Value {
    /// Whether this value (or anything within it) is unresolved (IAC-003).
    pub fn has_unresolved(&self) -> bool {
        match self {
            Value::Unresolved => true,
            Value::List(items) => items.iter().any(Value::has_unresolved),
            Value::Map(map) => map.values().any(Value::has_unresolved),
            _ => false,
        }
    }

    /// As a string, if it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// As a bool, if it is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// One normalized resource: a Terraform `resource`, a K8s object, a
/// CloudFormation resource, etc.
#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    /// Resource type, e.g. `aws_s3_bucket`, `Pod`.
    pub kind: String,
    /// Local name, e.g. `data` in `aws_s3_bucket.data`.
    pub name: String,
    /// Full address within the file, e.g. `aws_s3_bucket.data`.
    pub address: String,
    /// Attributes (nested blocks folded into maps/lists).
    pub attributes: BTreeMap<String, Value>,
    /// Root-relative POSIX path of the source file (DET-005).
    pub source_path: String,
}

impl Resource {
    /// Look up a possibly-nested attribute by dotted path, e.g. `acl` or
    /// `versioning.enabled`. Returns `None` if any segment is missing.
    pub fn get(&self, path: &str) -> Option<&Value> {
        let mut segments = path.split('.');
        let first = segments.next()?;
        let mut current = self.attributes.get(first)?;
        for segment in segments {
            match current {
                Value::Map(map) => current = map.get(segment)?,
                _ => return None,
            }
        }
        Some(current)
    }
}
