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

/// Footer metadata for human formats. The scan timestamp lives here, never in
/// the body, so table/markdown diffs stay clean (OUT-002).
pub struct Footer {
    /// RFC 3339 scan timestamp (injected clock, DET-004).
    pub scanned_at: String,
    /// Feed snapshot the scan pinned, if any.
    pub feed_snapshot_id: Option<String>,
}

/// Render sorted findings in the requested format. `footer` supplies the
/// timestamp line for human formats; machine formats ignore it (CLI-001,
/// OUT-002) so their bytes never depend on the clock.
pub fn render(format: Format, findings: &[Finding], footer: &Footer) -> String {
    match format {
        Format::Table => table(findings, footer),
        Format::Json => json(findings),
        Format::Jsonl => jsonl(findings),
        Format::Sarif => sarif(findings),
        Format::Sbom => sbom(findings),
        Format::Markdown => markdown(findings, footer),
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

/// Short class label for the table/markdown class column.
fn class_label(finding: &Finding) -> &'static str {
    match &finding.identity {
        IdentityKey::VulnerableDependency { .. } => "dependency",
        IdentityKey::ContainerVulnerability { .. } => "container",
        IdentityKey::ExposedSecret { .. } => "secret",
        IdentityKey::IacMisconfiguration { .. } => "iac",
        IdentityKey::WebExposure { .. } => "web",
        IdentityKey::StructuralPattern { .. } => "sast",
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

/// One SBOM component: a resolved package (spec 12). The CLI maps the SCA
/// engine's resolved inventory into these; the report crate stays free of an
/// SCA dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomComponent {
    /// Package URL, also used as the CycloneDX `bom-ref`.
    pub purl: String,
    /// Package name.
    pub name: String,
    /// Resolved version, if pinned.
    pub version: Option<String>,
}

/// CycloneDX severity label for a Severity.
fn cyclonedx_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Informational => "info",
    }
}

/// CycloneDX 1.5 SBOM from the resolved component inventory plus any
/// `VulnerableDependency` findings (spec 12, OUT-001). Deterministic by
/// construction: `serialNumber` and `metadata.timestamp` are omitted (they
/// would be random / clock-derived and break NFR-006); components and
/// vulnerabilities are sorted.
pub fn render_sbom(components: &[SbomComponent], findings: &[Finding], _footer: &Footer) -> String {
    let mut sorted: Vec<&SbomComponent> = components.iter().collect();
    sorted.sort_by(|a, b| a.purl.cmp(&b.purl));
    sorted.dedup_by(|a, b| a.purl == b.purl);

    let component_json: Vec<serde_json::Value> = sorted
        .iter()
        .map(|c| {
            let mut obj = serde_json::json!({
                "type": "library",
                "bom-ref": c.purl,
                "name": c.name,
                "purl": c.purl,
            });
            if let Some(version) = &c.version {
                obj["version"] = serde_json::Value::String(version.clone());
            }
            obj
        })
        .collect();

    // Vulnerabilities from dependency findings, keyed by advisory id → the
    // affected component bom-ref (the package purl).
    let mut vulns: Vec<serde_json::Value> = findings
        .iter()
        .filter_map(|f| match &f.identity {
            IdentityKey::VulnerableDependency {
                purl, advisory_id, ..
            }
            | IdentityKey::ContainerVulnerability {
                purl, advisory_id, ..
            } => Some((
                advisory_id.clone(),
                purl.clone(),
                cyclonedx_severity(f.severity),
            )),
            _ => None,
        })
        .map(|(id, purl, severity)| {
            serde_json::json!({
                "id": id,
                "ratings": [{ "severity": severity }],
                "affects": [{ "ref": purl }],
            })
        })
        .collect();
    vulns.sort_by(|a, b| {
        a["id"]
            .as_str()
            .unwrap_or("")
            .cmp(b["id"].as_str().unwrap_or(""))
            .then_with(|| {
                a["affects"][0]["ref"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["affects"][0]["ref"].as_str().unwrap_or(""))
            })
    });

    let mut doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": component_json,
    });
    if !vulns.is_empty() {
        doc["vulnerabilities"] = serde_json::Value::Array(vulns);
    }
    let mut out = serde_json::to_string_pretty(&doc).unwrap_or_default();
    out.push('\n');
    out
}

/// SBOM with no external inventory — used by the generic `render()` entry
/// point, which has only findings. The CLI calls [`render_sbom`] with the SCA
/// inventory for a populated document.
fn sbom(findings: &[Finding]) -> String {
    render_sbom(
        &[],
        findings,
        &Footer {
            scanned_at: String::new(),
            feed_snapshot_id: None,
        },
    )
}

fn id_prefix(finding: &Finding) -> &str {
    &finding.finding_id[..12.min(finding.finding_id.len())]
}

fn fix_cell(finding: &Finding) -> &str {
    finding
        .remediation
        .as_ref()
        .and_then(|r| r.fixed_version.as_deref())
        .unwrap_or("-")
}

fn footer_lines(footer: &Footer) -> String {
    // OUT-002: the timestamp is a footer line, isolated from the body.
    let snapshot = footer.feed_snapshot_id.as_deref().unwrap_or("none");
    format!(
        "scanned at {} · feed snapshot {snapshot}\n",
        footer.scanned_at
    )
}

/// Severity-banded plain table. No ANSI, no spinners, no width-dependent
/// truncation (CLI-002); id prefix is 12 hex chars so `multiscan explain`
/// is copy-pasteable (CLI-004). The timestamp is a footer line (OUT-002).
fn table(findings: &[Finding], footer: &Footer) -> String {
    if findings.is_empty() {
        return format!("No findings.\n\n{}", footer_lines(footer));
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
                "  {:<12}  {:>5.1}  {:<10}  {}  {}  {}\n",
                id_prefix(f),
                f.risk_score,
                class_label(f),
                rule_id(f),
                location_of(f),
                fix_cell(f),
            ));
        }
    }
    out.push_str(&format!("\n{} finding(s)\n", findings.len()));
    out.push_str(&footer_lines(footer));
    out
}

fn markdown(findings: &[Finding], footer: &Footer) -> String {
    let mut out = String::from("## MultiScan findings\n\n");
    if findings.is_empty() {
        out.push_str("No findings.\n\n");
        out.push_str(&format!("_{}_\n", footer_lines(footer).trim_end()));
        return out;
    }
    out.push_str("| Severity | ID | Score | Class | Rule | Location | Fix |\n");
    out.push_str("|---|---|---|---|---|---|---|\n");
    for f in findings {
        out.push_str(&format!(
            "| {} | `{}` | {:.1} | {} | {} | `{}` | {} |\n",
            severity_label(f.severity),
            id_prefix(f),
            f.risk_score,
            class_label(f),
            rule_id(f),
            location_of(f),
            fix_cell(f),
        ));
    }
    out.push_str(&format!("\n{} finding(s)\n\n", findings.len()));
    // OUT-002: timestamp in an italic footer line, never in a finding row.
    out.push_str(&format!("_{}_\n", footer_lines(footer).trim_end()));
    out
}

/// SARIF 2.1.0 level for a severity. Coarse by design — SARIF has three
/// levels — so exact severity is preserved in the properties bag instead.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Informational => "note",
        Severity::Low | Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

/// The property-bag key under which the complete Finding is embedded. External
/// tools read the native SARIF fields; our own importer reads this for a
/// lossless round-trip (FR-013).
pub const SARIF_FINDING_PROPERTY: &str = "multiscan/finding";

/// SARIF 2.1.0. Native fields serve GitHub/GitLab (OUT-001: `ruleId` is the
/// canonical id, `partialFingerprints` carries `finding_id`); a per-result
/// properties bag embeds the full Finding so a re-import is lossless (FR-013).
fn sarif(findings: &[Finding]) -> String {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let region = match f.location.line {
                Some(line) => serde_json::json!({ "startLine": line }),
                None => serde_json::json!({ "startLine": 1 }),
            };
            serde_json::json!({
                "ruleId": rule_id(f),
                "level": sarif_level(f.severity),
                "message": { "text": f.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.location.path },
                        "region": region,
                    }
                }],
                "partialFingerprints": { "multiscan/findingId": f.finding_id.0 },
                "properties": { SARIF_FINDING_PROPERTY: f },
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

#[cfg(test)]
mod tests {
    use super::*;
    use multiscan_core::{
        Asset, AssetKind, Confidence, FindingId, FindingStatus, Location, ScoreExplanation,
        ScoreFactors,
    };

    fn sample() -> Finding {
        Finding {
            finding_id: FindingId("a".repeat(64)),
            identity: IdentityKey::VulnerableDependency {
                purl: "pkg:npm/lodash@4.17.20".into(),
                advisory_id: "GHSA-xxxx".into(),
                manifest_path: "package-lock.json".into(),
            },
            title: "lodash vulnerable".into(),
            description: None,
            severity: Severity::High,
            confidence: Confidence::Corroborated,
            status: FindingStatus::Open,
            risk_score: 82.4,
            score_explanation: ScoreExplanation {
                formula_version: "1".into(),
                feed_snapshot_id: None,
                factors: ScoreFactors {
                    severity_base: 0.75,
                    exposure: 0.7,
                    exploitability: 1.0,
                    confidence: 0.85,
                    asset_criticality: 1.0,
                },
                raw_product: 0.44,
                defaults_applied: vec![],
            },
            asset: Asset {
                kind: AssetKind::Package,
                identifier: "pkg:npm/lodash@4.17.20".into(),
            },
            location: Location {
                path: "package-lock.json".into(),
                line: Some(10),
            },
            evidence: vec![],
            sources: vec![],
            remediation: Some(multiscan_core::Remediation {
                fix_available: true,
                fixed_version: Some("4.17.21".into()),
                summary: None,
            }),
            cwe: vec![],
        }
    }

    fn footer() -> Footer {
        Footer {
            scanned_at: "2026-01-01T00:00:00Z".into(),
            feed_snapshot_id: Some("osv-2026".into()),
        }
    }

    /// OUT-002: the timestamp is in a footer line, never in a finding row.
    #[test]
    fn timestamp_only_in_footer() {
        for format in [Format::Table, Format::Markdown] {
            let out = render(format, &[sample()], &footer());
            let lines: Vec<&str> = out.lines().collect();
            let footer_line = lines
                .iter()
                .position(|l| l.contains("2026-01-01T00:00:00Z"))
                .expect("footer present");
            // The timestamp appears exactly once, and after the finding row.
            let finding_line = lines.iter().position(|l| l.contains("GHSA-xxxx")).unwrap();
            assert!(footer_line > finding_line);
            assert_eq!(out.matches("2026-01-01T00:00:00Z").count(), 1);
        }
    }

    /// Machine formats never embed the timestamp (CLI-001) even with a footer.
    #[test]
    fn machine_formats_have_no_timestamp() {
        for format in [Format::Json, Format::Jsonl, Format::Sarif, Format::Sbom] {
            let out = render(format, &[sample()], &footer());
            assert!(
                !out.contains("2026-01-01T00:00:00Z"),
                "{format:?} leaked time"
            );
        }
    }

    /// render_sbom links a vulnerable finding to its component by purl.
    #[test]
    fn sbom_links_vulnerability_to_component() {
        let components = vec![SbomComponent {
            purl: "pkg:npm/lodash@4.17.20".into(),
            name: "lodash".into(),
            version: Some("4.17.20".into()),
        }];
        let out = render_sbom(&components, &[sample()], &footer());
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(doc["specVersion"], "1.5");
        assert_eq!(doc["components"][0]["purl"], "pkg:npm/lodash@4.17.20");
        assert_eq!(
            doc["vulnerabilities"][0]["affects"][0]["ref"],
            "pkg:npm/lodash@4.17.20"
        );
        // Deterministic: no random serialNumber / clock timestamp (NFR-006).
        assert!(!out.contains("serialNumber"));
    }

    /// OUT-001: SARIF ruleId is the advisory id and partialFingerprints carries
    /// the finding_id.
    #[test]
    fn sarif_carries_ruleid_and_fingerprint() {
        let out = render(Format::Sarif, &[sample()], &footer());
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        let result = &doc["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "GHSA-xxxx");
        assert_eq!(
            result["partialFingerprints"]["multiscan/findingId"],
            "a".repeat(64)
        );
    }

    /// json validates as an array of the Finding schema and round-trips.
    #[test]
    fn json_round_trips() {
        let out = render(Format::Json, &[sample()], &footer());
        let parsed: Vec<Finding> = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], sample());
    }
}
