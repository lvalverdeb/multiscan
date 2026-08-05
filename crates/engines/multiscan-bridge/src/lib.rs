//! Bridges: external scanner output importers (spec 7.6).
//!
//! A Bridge normalizes another tool's output into our `Finding` model so
//! `multiscan import` can fold it into the same pipeline. Imported Findings
//! record the external tool in `sources[].engine_id` (BRG-001) and unknown
//! native policy ids fall back to `external:{tool}:{id}` (BRG-003).
//!
//! v1 ships the generic SARIF 2.1.0 importer (T-303); Trivy/Semgrep/Checkov/
//! ZAP land in T-305.

mod sarif;

pub use sarif::import_sarif;

use multiscan_core::Finding;

/// Errors from importing an external report.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// The input was not valid for the detected/declared format.
    #[error("bridge parse error: {0}")]
    Parse(String),
    /// The format could not be recognized.
    #[error("unrecognized report format")]
    Unrecognized,
}

/// A recognized external report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// SARIF 2.1.0 (generic).
    Sarif,
}

/// Best-effort format detection from file bytes. v1 recognizes SARIF by its
/// `version`/`runs` shape; other tools are added with their importers (T-305).
pub fn detect(bytes: &[u8]) -> Option<Format> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;
    if obj.get("version").and_then(|v| v.as_str()) == Some("2.1.0") && obj.contains_key("runs") {
        return Some(Format::Sarif);
    }
    if obj.contains_key("$schema")
        && obj
            .get("$schema")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.contains("sarif"))
    {
        return Some(Format::Sarif);
    }
    None
}

/// Import a report, detecting its format.
pub fn import(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    match detect(bytes) {
        Some(Format::Sarif) => import_sarif(bytes),
        None => Err(BridgeError::Unrecognized),
    }
}
