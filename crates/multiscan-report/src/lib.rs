//! Renderers: table, json, jsonl, sarif, sbom, markdown (spec 12).
//!
//! Walking-skeleton versions (T-105): structurally correct, deterministic,
//! refined in T-205/T-303/T-304. Every renderer takes findings ALREADY sorted
//! by [`sort_findings`] (CLI-003) and returns the complete stdout payload —
//! renderers never print (CLI-001 is the caller's contract).

use multiscan_core::{Finding, IdentityKey, Severity};

/// Output format (spec 4.2 `--format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Human terminal table, severity-banded.
    Table,
    /// Full-fidelity JSON array of Findings.
    Json,
    /// One Finding per line.
    Jsonl,
    /// SARIF 2.1.0.
    Sarif,
    /// CycloneDX 1.5 SBOM.
    Sbom,
    /// Markdown for PR comments; no timestamps in the body (OUT-002).
    Markdown,
}

impl Format {
    /// Parse the `--format` value.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "table" => Some(Self::Table),
            "json" => Some(Self::Json),
            "jsonl" => Some(Self::Jsonl),
            "sarif" => Some(Self::Sarif),
            "sbom" => Some(Self::Sbom),
            "markdown" => Some(Self::Markdown),
            _ => None,
        }
    }

    /// Machine formats go to stdout with nothing else interleaved (CLI-001).
    pub fn is_machine(self) -> bool {
        !matches!(self, Self::Table)
    }
}

/// Deterministic output order: `risk_score` DESC (total order on floats,
/// DET-003), then `finding_id` ASC (CLI-003).
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.risk_score
            .total_cmp(&a.risk_score)
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
}

/// Render sorted findings in the requested format.
pub fn render(format: Format, findings: &[Finding]) -> String {
    match format {
        Format::Table => table(findings),
        Format::Json => json(findings),
        Format::Jsonl => jsonl(findings),
        Format::Sarif => sarif(findings),
        Format::Sbom => sbom(findings),
        Format::Markdown => markdown(findings),
    }
}

/// The canonical rule/policy/advisory id for a Finding (OUT-001).
fn rule_id(finding: &Finding) -> String {
    match &finding.identity {
        IdentityKey::VulnerableDependency { advisory_id, .. }
        | IdentityKey::ContainerVulnerability { advisory_id, .. } => advisory_id.clone(),
        IdentityKey::ExposedSecret { rule_id, .. }
        | IdentityKey::StructuralPattern { rule_id, .. } => rule_id.clone(),
        IdentityKey::IacMisconfiguration { policy_id, .. } => policy_id.clone(),
        IdentityKey::WebExposure { template_id, .. } => template_id.clone(),
    }
}

fn location_of(finding: &Finding) -> String {
    match finding.location.line {
        Some(line) => format!("{}:{line}", finding.location.path),
        None => finding.location.path.clone(),
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Informational => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn json(findings: &[Finding]) -> String {
    let mut out = serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string());
    out.push('\n');
    out
}

fn jsonl(findings: &[Finding]) -> String {
    let mut out = String::new();
    for finding in findings {
        if let Ok(line) = serde_json::to_string(finding) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Severity-banded plain table. No ANSI, no spinners, no width-dependent
/// truncation (CLI-002); id prefix is 12 hex chars so `multiscan explain`
/// is copy-pasteable (CLI-004). No timestamp in the body (OUT-002).
fn table(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No findings.\n".to_string();
    }
    let mut out = String::new();
    let bands = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Informational,
    ];
    for band in bands {
        let in_band: Vec<&Finding> = findings.iter().filter(|f| f.severity == band).collect();
        if in_band.is_empty() {
            continue;
        }
        out.push_str(&format!("{} ({})\n", severity_label(band), in_band.len()));
        for f in in_band {
            out.push_str(&format!(
                "  {}  {:>5.1}  {}  {}  {}\n",
                &f.finding_id[..12.min(f.finding_id.len())],
                f.risk_score,
                rule_id(f),
                location_of(f),
                f.remediation
                    .as_ref()
                    .and_then(|r| r.fixed_version.as_deref())
                    .unwrap_or("-"),
            ));
        }
    }
    out.push_str(&format!("\n{} finding(s)\n", findings.len()));
    out
}

fn markdown(findings: &[Finding]) -> String {
    let mut out = String::from("## MultiScan findings\n\n");
    if findings.is_empty() {
        out.push_str("No findings.\n");
        return out;
    }
    out.push_str("| Severity | ID | Score | Rule | Location | Fix |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for f in findings {
        out.push_str(&format!(
            "| {} | `{}` | {:.1} | {} | `{}` | {} |\n",
            severity_label(f.severity),
            &f.finding_id[..12.min(f.finding_id.len())],
            f.risk_score,
            rule_id(f),
            location_of(f),
            f.remediation
                .as_ref()
                .and_then(|r| r.fixed_version.as_deref())
                .unwrap_or("-"),
        ));
    }
    out.push_str(&format!("\n{} finding(s)\n", findings.len()));
    out
}

/// Minimal SARIF 2.1.0 (upgraded to full round-trip fidelity in T-303).
/// `ruleId` is the canonical policy/advisory id and `partialFingerprints`
/// carries `finding_id` (OUT-001).
fn sarif(findings: &[Finding]) -> String {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": rule_id(f),
                "level": match f.severity {
                    Severity::Informational => "note",
                    Severity::Low | Severity::Medium => "warning",
                    Severity::High | Severity::Critical => "error",
                },
                "message": { "text": f.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.location.path },
                        "region": f.location.line.map(|l| serde_json::json!({"startLine": l}))
                            .unwrap_or(serde_json::json!({"startLine": 1})),
                    }
                }],
                "partialFingerprints": { "multiscan/findingId": f.finding_id },
            })
        })
        .collect();
    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "multiscan",
                "informationUri": "https://example.invalid/multiscan",
                "rules": [],
            }},
            "results": results,
        }],
    });
    let mut out = serde_json::to_string_pretty(&doc).unwrap_or_default();
    out.push('\n');
    out
}

/// Minimal CycloneDX 1.5 document (real dependency graph lands with T-304).
/// `serialNumber` is deliberately omitted — it would be random, and machine
/// output must be byte-deterministic (NFR-006).
fn sbom(_findings: &[Finding]) -> String {
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [],
    });
    let mut out = serde_json::to_string_pretty(&doc).unwrap_or_default();
    out.push('\n');
    out
}
