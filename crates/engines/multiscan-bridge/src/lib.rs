//! Bridges: external scanner output importers (spec 7.6).
//!
//! A Bridge normalizes another tool's output into our `Finding` model so
//! `multiscan import` (or `scan --import`) can fold it into the same pipeline.
//! Imported Findings record the external tool in `sources[].engine_id`
//! (BRG-001), each importer declares an explicit severity map (BRG-002), and
//! unknown native ids stay namespaced under the tool (BRG-003). Because
//! identity is reconstructed the same way native engines build it, an import
//! of the same weakness merges with the native finding in dedup (FR-004).

mod checkov;
mod common;
mod sarif;
mod semgrep;
mod trivy;
mod zap;

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
    /// Trivy JSON.
    Trivy,
    /// Semgrep JSON.
    Semgrep,
    /// Checkov JSON.
    Checkov,
    /// OWASP ZAP JSON.
    Zap,
}

impl Format {
    /// The tool label used in `sources[].engine_id` (`external:{label}`).
    pub fn tool(self) -> &'static str {
        match self {
            Format::Sarif => "sarif",
            Format::Trivy => "trivy",
            Format::Semgrep => "semgrep",
            Format::Checkov => "checkov",
            Format::Zap => "zap",
        }
    }
}

/// Best-effort format detection from JSON shape. Order matters: the most
/// specific discriminators are checked first.
pub fn detect(bytes: &[u8]) -> Option<Format> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;

    // SARIF: version 2.1.0 + runs, or a sarif $schema.
    if obj.get("version").and_then(|v| v.as_str()) == Some("2.1.0") && obj.contains_key("runs") {
        return Some(Format::Sarif);
    }
    if obj
        .get("$schema")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.contains("sarif"))
    {
        return Some(Format::Sarif);
    }
    // Trivy: SchemaVersion + Results.
    if obj.contains_key("SchemaVersion") && obj.contains_key("Results") {
        return Some(Format::Trivy);
    }
    // Checkov: check_type + results.failed_checks.
    if obj.contains_key("check_type")
        || obj
            .get("results")
            .and_then(|r| r.as_object())
            .is_some_and(|r| r.contains_key("failed_checks"))
    {
        return Some(Format::Checkov);
    }
    // ZAP: a `site` array of alert containers.
    if obj.get("site").and_then(|s| s.as_array()).is_some() {
        return Some(Format::Zap);
    }
    // Semgrep: a `results` array whose items carry `check_id`.
    if obj
        .get("results")
        .and_then(|r| r.as_array())
        .and_then(|a| a.first())
        .and_then(|r| r.as_object())
        .is_some_and(|r| r.contains_key("check_id"))
    {
        return Some(Format::Semgrep);
    }
    // A Semgrep report with zero results still has `results` + `errors`.
    if obj.contains_key("results") && obj.contains_key("errors") {
        return Some(Format::Semgrep);
    }
    None
}

/// Import a report of the given format.
pub fn import_as(format: Format, bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    match format {
        Format::Sarif => import_sarif(bytes),
        Format::Trivy => trivy::import(bytes),
        Format::Semgrep => semgrep::import(bytes),
        Format::Checkov => checkov::import(bytes),
        Format::Zap => zap::import(bytes),
    }
}

/// Import a report, detecting its format.
pub fn import(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    match detect(bytes) {
        Some(format) => import_as(format, bytes),
        None => Err(BridgeError::Unrecognized),
    }
}
