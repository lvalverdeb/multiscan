//! `multiscan suppress` and `multiscan diff` — the store-backed lifecycle
//! commands (T-302). Both operate on `.multiscan/multiscan.db` under the
//! current directory.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use multiscan_core::Finding;
use multiscan_store::{SqliteStore, Store, Suppression};

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

fn parse_expiry(raw: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    let date = chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()?;
    Some(date.and_hms_opt(23, 59, 59)?.and_utc())
}
