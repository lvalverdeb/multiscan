//! `multiscan suppress` and `multiscan diff` — the store-backed lifecycle
//! commands (T-302). Both operate on `.multiscan/multiscan.db` under the
//! current directory.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use multiscan_core::{Finding, FindingId, IdentityKey};
use multiscan_store::{FindingEventKind, SqliteStore, Store, Suppression};

use crate::cli::SuppressCmd;
use crate::exit::Exit;

fn db_path() -> PathBuf {
    Path::new(".multiscan/multiscan.db").to_path_buf()
}

fn open_store() -> Result<SqliteStore, Exit> {
    SqliteStore::open(&db_path()).map_err(|e| {
        eprintln!("multiscan: error: cannot open findings database: {e}");
        Exit::ScanError
    })
}

/// `multiscan suppress add|list|expire`.
pub fn suppress(action: &SuppressCmd) -> Result<Exit> {
    match action {
        SuppressCmd::Add {
            finding_id,
            justification,
            approver,
            expires,
        } => {
            // CLI-006: all three fields are mandatory; clap already enforces
            // presence. Validate the expiry parses.
            let expires_dt = match parse_expiry(expires) {
                Some(dt) => dt,
                None => {
                    eprintln!(
                        "multiscan: error: --expires must be RFC 3339 or YYYY-MM-DD, got `{expires}`"
                    );
                    return Ok(Exit::Usage);
                }
            };
            let mut store = match open_store() {
                Ok(s) => s,
                Err(exit) => return Ok(exit),
            };
            let suppression = Suppression {
                finding_id: finding_id.clone(),
                justification: justification.clone(),
                approver: approver.clone(),
                expires: expires_dt,
            };
            if let Err(e) = store.put_suppression(&suppression) {
                eprintln!("multiscan: error: {e}");
                return Ok(Exit::ScanError);
            }
            eprintln!("multiscan: suppressed {finding_id} until {expires}");
            Ok(Exit::Clean)
        }
        SuppressCmd::List => {
            let store = match open_store() {
                Ok(s) => s,
                Err(exit) => return Ok(exit),
            };
            let all = store.all_suppressions().unwrap_or_default();
            let now = chrono::Utc::now();
            if all.is_empty() {
                println!("No suppressions.");
            }
            for s in all {
                let state = if s.expires > now {
                    "active "
                } else {
                    "expired"
                };
                println!(
                    "{state}  {}  expires {}  by {}  — {}",
                    s.finding_id,
                    s.expires.to_rfc3339(),
                    s.approver,
                    s.justification
                );
            }
            Ok(Exit::Clean)
        }
        SuppressCmd::Expire { finding_id } => {
            let mut store = match open_store() {
                Ok(s) => s,
                Err(exit) => return Ok(exit),
            };
            let existing = store
                .all_suppressions()
                .unwrap_or_default()
                .into_iter()
                .find(|s| s.finding_id == *finding_id);
            let Some(mut s) = existing else {
                eprintln!("multiscan: no suppression for {finding_id}");
                return Ok(Exit::Usage);
            };
            // Expire now: set the boundary into the past so it is no longer
            // active. A minute in the past is unambiguous.
            s.expires = chrono::Utc::now() - chrono::Duration::minutes(1);
            if let Err(e) = store.put_suppression(&s) {
                eprintln!("multiscan: error: {e}");
                return Ok(Exit::ScanError);
            }
            eprintln!("multiscan: expired suppression for {finding_id}");
            Ok(Exit::Clean)
        }
    }
}

/// `multiscan diff <baseline>` — delta of the current stored Findings against a
/// baseline Finding-set JSON file.
pub fn diff(baseline: &Path) -> Result<Exit> {
    let baseline_findings: Vec<Finding> = match std::fs::read_to_string(baseline) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("multiscan: error: parsing {}: {e}", baseline.display());
                return Ok(Exit::Usage);
            }
        },
        Err(e) => {
            eprintln!("multiscan: error: reading {}: {e}", baseline.display());
            return Ok(Exit::Usage);
        }
    };
    let store = match open_store() {
        Ok(s) => s,
        Err(exit) => return Ok(exit),
    };
    let current = store.all_findings().unwrap_or_default();

    let baseline_ids: BTreeSet<String> = baseline_findings
        .iter()
        .map(|f| f.finding_id.0.clone())
        .collect();
    let current_ids: BTreeSet<String> = current.iter().map(|f| f.finding_id.0.clone()).collect();

    let added: Vec<&String> = current_ids.difference(&baseline_ids).collect();
    let removed: Vec<&String> = baseline_ids.difference(&current_ids).collect();

    println!("baseline {}", baseline.display());
    println!("+{} new, -{} resolved", added.len(), removed.len());
    for id in &added {
        println!("+ {id}");
    }
    for id in &removed {
        println!("- {id}");
    }
    Ok(Exit::Clean)
}

/// `multiscan import <file>` — ingest an external scanner report (SARIF in v1)
/// and render it in the requested format (spec 7.6). Imported findings carry
/// their producing tool in `sources[].engine_id` (BRG-001).
pub fn import(file: &Path, format: multiscan_report::Format) -> Result<Exit> {
    let bytes = match std::fs::read(file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("multiscan: error: reading {}: {e}", file.display());
            return Ok(Exit::Usage);
        }
    };
    let mut findings = match multiscan_bridge::import(&bytes) {
        Ok(findings) => findings,
        Err(e) => {
            eprintln!("multiscan: error: import failed: {e}");
            return Ok(Exit::Usage);
        }
    };
    multiscan_report::sort_findings(&mut findings);
    let footer = multiscan_report::Footer {
        scanned_at: crate::scan::scan_timestamp(),
        feed_snapshot_id: None,
    };
    print!("{}", multiscan_report::render(format, &findings, &footer));
    Ok(Exit::Clean)
}

/// `multiscan explain <finding_id> [--history]` — full score breakdown,
/// evidence, and remediation for one stored Finding (FR-016, RSK-005).
pub fn explain(finding_id: &str, history: bool) -> Result<Exit> {
    let store = match open_store() {
        Ok(s) => s,
        Err(exit) => return Ok(exit),
    };
    let findings = store.all_findings().unwrap_or_default();
    // Accept a unique prefix so a table id-prefix is copy-pasteable (CLI-004).
    let matches: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.finding_id.0.starts_with(finding_id))
        .collect();
    let finding = match matches.as_slice() {
        [one] => one,
        [] => {
            eprintln!("multiscan: no stored finding matches `{finding_id}` (run a scan first?)");
            return Ok(Exit::Usage);
        }
        many => {
            eprintln!(
                "multiscan: `{finding_id}` is ambiguous ({} matches); use a longer prefix",
                many.len()
            );
            return Ok(Exit::Usage);
        }
    };

    print_explanation(finding);

    if history {
        println!();
        println!("History");
        let events = store
            .history(&FindingId(finding.finding_id.0.clone()))
            .unwrap_or_default();
        if events.is_empty() {
            println!("  (no recorded events)");
        }
        for event in events {
            let desc = match event.kind {
                FindingEventKind::FirstSeen { status } => format!("first seen ({status})"),
                FindingEventKind::StatusChanged { from, to } => {
                    format!("status {from} → {to}")
                }
                FindingEventKind::ScoreChanged { from, to } => {
                    format!("score {from:.1} → {to:.1}")
                }
            };
            println!("  {}  {desc}", event.at.to_rfc3339());
        }
    }

    Ok(Exit::Clean)
}

fn print_explanation(f: &Finding) {
    let rule = match &f.identity {
        IdentityKey::VulnerableDependency { advisory_id, .. }
        | IdentityKey::ContainerVulnerability { advisory_id, .. } => advisory_id.clone(),
        IdentityKey::ExposedSecret { rule_id, .. }
        | IdentityKey::StructuralPattern { rule_id, .. } => rule_id.clone(),
        IdentityKey::IacMisconfiguration { policy_id, .. } => policy_id.clone(),
        IdentityKey::WebExposure { template_id, .. } => template_id.clone(),
    };
    println!("{}", f.finding_id.0);
    println!("  {}", f.title);
    println!(
        "  {:?} · risk {:.1} · confidence {:?} · status {:?}",
        f.severity, f.risk_score, f.confidence, f.status
    );
    println!("  rule: {rule}");
    println!("  location: {}", f.location.path);

    // RSK-005: all five factors, the raw product, defaults applied, snapshot.
    let e = &f.score_explanation;
    println!();
    println!("Score (formula {})", e.formula_version);
    println!("  S severity_base       {:.3}", e.factors.severity_base);
    println!("  E exposure            {:.3}", e.factors.exposure);
    println!("  X exploitability      {:.3}", e.factors.exploitability);
    println!("  C confidence          {:.3}", e.factors.confidence);
    println!("  A asset_criticality   {:.3}", e.factors.asset_criticality);
    println!("  ── raw product        {:.4}", e.raw_product);
    println!("  → risk_score          {:.1}", f.risk_score);
    if e.defaults_applied.is_empty() {
        println!("  defaults applied: none");
    } else {
        println!("  defaults applied: {}", e.defaults_applied.join(", "));
    }
    println!(
        "  feed snapshot: {}",
        e.feed_snapshot_id.as_deref().unwrap_or("none")
    );

    if !f.evidence.is_empty() {
        println!();
        println!("Evidence");
        for ev in &f.evidence {
            println!("  [{}] {}", ev.kind, ev.summary);
        }
    }

    println!();
    println!("Remediation");
    match &f.remediation {
        Some(r) => {
            if let Some(v) = &r.fixed_version {
                println!("  fixed in: {v}");
            }
            if let Some(s) = &r.summary {
                println!("  {s}");
            }
            if r.fixed_version.is_none() && r.summary.is_none() {
                println!("  no fix available");
            }
        }
        None => println!("  none recorded"),
    }
}

fn parse_expiry(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    let date = chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()?;
    Some(date.and_hms_opt(23, 59, 59)?.and_utc())
}
