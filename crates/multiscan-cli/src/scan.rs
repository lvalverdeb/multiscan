//! `multiscan scan` — the pipeline: context → engines → dedup → risk →
//! report → exit code (spec 5.3). Machine output goes to stdout alone;
//! everything else to stderr (CLI-001).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Result;
use multiscan_core::{
    FailOn, Finding, FindingClass, FindingId, FindingStatus, IdentityKey, Layer, Profile, Severity,
};
use multiscan_dedup::{Attributed, MergedFinding};
use multiscan_engine::testkit::FixtureEngine;
use multiscan_engine::{EngineOutcome, Registry, ScanContext};
use multiscan_report::{render, sort_findings, Format};
use multiscan_risk::{score, ExploitSignal, ExposureSignal, RiskContext, ScoringInputs};

use crate::cli::{ScanArgs, ScanTarget};
use crate::configfile;
use crate::exit::Exit;

/// Parse a kebab-case enum value the same way serde would.
fn parse_enum<T: serde::de::DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

fn usage(message: &str) -> Exit {
    eprintln!("multiscan: error: {message}");
    Exit::Usage
}

/// Finding ids that are actively suppressed at `now` — the union of config
/// `[[suppress]]` entries and store suppressions, each filtered by expiry
/// (FR-014). Config entries work even with `--no-store` since they live in the
/// committed config.
fn active_suppression_ids(
    config: &multiscan_core::Config,
    root: &std::path::Path,
    no_store: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> std::collections::BTreeSet<String> {
    let mut ids = std::collections::BTreeSet::new();

    for entry in &config.suppress {
        // `expires` is a date (or datetime); treat a bare date as end-of-day
        // UTC so a suppression is active through its stated day.
        if suppression_active(&entry.expires, now) {
            ids.insert(entry.finding_id.0.clone());
        }
    }

    if !no_store {
        use multiscan_store::{SqliteStore, Store};
        let db_path = root.join(".multiscan/multiscan.db");
        if db_path.exists() {
            if let Ok(store) = SqliteStore::open(&db_path) {
                if let Ok(active) = store.active_suppressions(now) {
                    for s in active {
                        ids.insert(s.finding_id);
                    }
                }
            }
        }
    }
    ids
}

/// Whether an `expires` string (RFC 3339 datetime or bare `YYYY-MM-DD`) is
/// still in the future relative to `now`.
fn suppression_active(expires: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(expires) {
        return dt.with_timezone(&chrono::Utc) > now;
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(expires, "%Y-%m-%d") {
        // Active through the end of the stated day.
        if let Some(end) = date.and_hms_opt(23, 59, 59) {
            return end.and_utc() > now;
        }
    }
    false
}

/// Baseline finding ids from `--baseline` or `[gate].baseline` (FR-010). The
/// baseline is a JSON array of Findings (the `--format json` shape). Returns
/// `Ok(None)` when no baseline is configured.
fn load_baseline_ids(
    args: &ScanArgs,
    config: &multiscan_core::Config,
) -> Result<Option<std::collections::BTreeSet<String>>, String> {
    let path = match &args.baseline {
        Some(p) => Some(p.clone()),
        None => config
            .gate
            .as_ref()
            .and_then(|g| g.baseline.as_ref())
            .map(|rel| args.path.join(rel)),
    };
    let Some(path) = path else {
        return Ok(None);
    };
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let findings: Vec<Finding> =
        serde_json::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    Ok(Some(findings.into_iter().map(|f| f.finding_id.0).collect()))
}

/// Read an external report and convert its Findings into `Attributed` raw
/// findings so they join the native dedup pass (BRG-001). The engine_id comes
/// from the imported finding's own source (`external:{tool}`).
fn import_attributed(file: &std::path::Path) -> Result<Vec<Attributed>, String> {
    let bytes = std::fs::read(file).map_err(|e| e.to_string())?;
    let findings = multiscan_bridge::import(&bytes).map_err(|e| e.to_string())?;
    Ok(findings
        .into_iter()
        .map(|f| {
            let engine_id = f
                .sources
                .first()
                .map(|s| s.engine_id.clone())
                .unwrap_or_else(|| "external:unknown".to_string());
            Attributed {
                engine_id,
                raw: to_raw_finding(f),
            }
        })
        .collect())
}

/// Project a fully-formed Finding back down to the `RawFinding` an engine would
/// have emitted, so imports and native emissions dedup identically.
fn to_raw_finding(f: Finding) -> multiscan_core::RawFinding {
    multiscan_core::RawFinding {
        identity: f.identity,
        title: f.title,
        description: f.description,
        severity: f.severity,
        confidence: f.confidence,
        asset: f.asset,
        location: f.location,
        evidence: f.evidence,
        rule_id: f.sources.first().and_then(|s| s.rule_id.clone()),
        remediation: f.remediation,
        cwe: f.cwe,
    }
}

/// Persist findings to `.multiscan/multiscan.db` under the scan root (STO-001).
/// Best-effort: a store error never fails the scan (STO-003 keeps state
/// optional), it degrades to a stderr warning.
fn persist(root: &std::path::Path, findings: &[Finding], started_at: &str, quiet: bool) {
    use multiscan_store::{SqliteStore, Store};
    let db_path = root.join(".multiscan/multiscan.db");
    let now = chrono::DateTime::parse_from_rfc3339(started_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let result =
        SqliteStore::open(&db_path).and_then(|mut store| store.upsert_findings(findings, now));
    match result {
        Ok(stats) if !quiet => {
            eprintln!(
                "multiscan: store: {} new, {} updated, {} unchanged",
                stats.new, stats.updated, stats.unchanged
            );
        }
        Ok(_) => {}
        Err(err) if !quiet => {
            eprintln!("multiscan: warning: could not persist findings: {err}");
        }
        Err(_) => {}
    }
}

/// The scan's wall-clock timestamp, RFC 3339. Honours `MULTISCAN_NOW` as an
/// injected-clock override so golden and determinism tests can hold time
/// constant (DET-004). It only ever reaches the human-format footer, never
/// machine output, so it does not violate DET-006.
pub fn scan_timestamp() -> String {
    match std::env::var("MULTISCAN_NOW") {
        Ok(value) if !value.is_empty() => value,
        _ => chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

/// `multiscan scan web <url>` — the authorization gate (SEC-001, spec 9) then
/// declarative probing (spec 7.4). The static gate (parse → signature → window
/// → attestation → wildcard safety → host+method in scope) runs with zero
/// network I/O; any failure exits 4 and is written to the audit log (SEC-008).
/// On success the bundled templates run over the scoped transport (every
/// request re-checked, PRB-002; no out-of-scope redirects, SEC-005).
fn scan_web(url: &str, args: &crate::cli::ScanArgs) -> Result<Exit> {
    use multiscan_scope::{AuditLog, Authorization, Decision};

    // SEC-001: no authorization ⇒ deny before anything is resolved or sent.
    let Some(auth_path) = &args.authorization else {
        eprintln!(
            "multiscan: scan web {url}: refusing to probe without --authorization \
             (SEC-001); no request was sent"
        );
        return Ok(Exit::AuthDenied);
    };

    let host = match target_host(url) {
        Some(h) => h,
        None => return Ok(usage(&format!("scan web: cannot parse host from `{url}`"))),
    };

    let text = match std::fs::read_to_string(auth_path) {
        Ok(t) => t,
        Err(e) => return Ok(usage(&format!("reading {}: {e}", auth_path.display()))),
    };
    let parsed = match Authorization::from_toml(&text) {
        Ok(a) => a,
        Err(denied) => {
            eprintln!(
                "multiscan: scan web: authorization rejected: {}",
                denied.rule()
            );
            return Ok(Exit::AuthDenied);
        }
    };

    // Trusted key (hex) the signature must verify against; absent ⇒ deny.
    let trusted_key = args.authorization_key.as_deref().and_then(parse_hex32);

    let now = chrono::Utc::now();
    let profile = args
        .profile
        .as_deref()
        .and_then(parse_enum::<Profile>)
        .unwrap_or(Profile::Standard);

    let audit = AuditLog::open(std::path::Path::new(".multiscan/scope-audit.log"));

    let verified = match parsed.verify(trusted_key.as_ref(), now, profile) {
        Ok(v) => v,
        Err(denied) => {
            let decision = Decision::Denied(denied);
            let _ = audit.record(&now.to_rfc3339(), "unknown", &host, "GET", &decision);
            eprintln!("multiscan: scan web: {}", decision.rule());
            return Ok(Exit::AuthDenied);
        }
    };

    // Per-request static gate (host + method in scope).
    let decision = verified.authorize(&host, "GET");
    // SEC-008: record every decision with its deciding rule.
    if audit
        .record(
            &now.to_rfc3339(),
            &verified.authorization_id,
            &host,
            "GET",
            &decision,
        )
        .is_err()
    {
        // Fail closed: a security audit that can't be written must not proceed.
        eprintln!("multiscan: scan web: could not write the authorization audit log; refusing");
        return Ok(Exit::AuthDenied);
    }
    if !decision.is_allowed() {
        eprintln!("multiscan: scan web: {}", decision.rule());
        return Ok(Exit::AuthDenied);
    }

    if !args.quiet {
        eprintln!(
            "multiscan: scan web {url}: authorization {} verified; {host} is in scope",
            verified.authorization_id
        );
    }

    // Execute the bundled declarative templates over the scoped transport.
    let (scheme, port) = scheme_and_port(url);
    let origin = format!("{scheme}://{host}:{port}");
    let templates = match multiscan_probe::builtin_templates() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("multiscan: error: probe templates: {e}");
            return Ok(Exit::ScanError);
        }
    };
    let transport = multiscan_probe::ScopedTransport::new(&origin, &host, port);
    let mut rate =
        multiscan_scope::RateControl::for_rps(if profile == Profile::Quick { 5.0 } else { 25.0 });
    let raw = multiscan_probe::execute(
        &templates,
        &multiscan_probe::ProbeRun {
            authorization: &verified,
            origin: origin.clone(),
            host: host.clone(),
            now: now.to_rfc3339(),
        },
        &transport,
        &mut rate,
        &audit,
    );

    // Score the web findings through the shared pipeline.
    let format = match args.format.as_deref() {
        None => Format::Table,
        Some(name) => match Format::parse(name) {
            Some(f) => f,
            None => return Ok(usage(&format!("unknown format `{name}`"))),
        },
    };
    let attributed: Vec<Attributed> = raw
        .into_iter()
        .map(|raw| Attributed {
            engine_id: "multiscan.probe".to_string(),
            raw,
        })
        .collect();
    let merged = multiscan_dedup::merge(attributed);
    let mut findings: Vec<Finding> = merged
        .into_iter()
        .map(|m| assemble_finding(m, &RiskContext::default(), None, None))
        .collect();
    sort_findings(&mut findings);

    let footer = multiscan_report::Footer {
        scanned_at: now.to_rfc3339(),
        feed_snapshot_id: None,
    };
    print!("{}", render(format, &findings, &footer));
    Ok(Exit::Clean)
}

/// Scheme and default port from a URL.
fn scheme_and_port(url: &str) -> (&str, u16) {
    // Honour an explicit port if present in the authority.
    let after = url.split_once("://").unwrap_or(("https", url));
    let authority = after.1.split(['/', '?', '#']).next().unwrap_or(after.1);
    let port = authority
        .rsplit('@')
        .next()
        .and_then(|hostport| {
            hostport
                .rsplit(':')
                .next()
                .filter(|p| p.chars().all(|c| c.is_ascii_digit()))
        })
        .and_then(|p| p.parse::<u16>().ok());
    match after.0 {
        "http" => ("http", port.unwrap_or(80)),
        _ => ("https", port.unwrap_or(443)),
    }
}

/// Extract the host from a URL for scope checking (no external URL crate).
fn target_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip userinfo and port.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn parse_hex32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `multiscan scan image <ref>` — pull the image (digest-verified), extract its
/// layers into a confined temp root (SCA-005), resolve OS packages against the
/// pinned OSV snapshot, and emit `ContainerVulnerability` findings (FR-002).
fn scan_image(reference: &str, args: &ScanArgs) -> Result<Exit> {
    use multiscan_sca::image::{extract_image, scan_os_packages, OciClient, Reference};

    let format = match args.format.as_deref() {
        None => Format::Table,
        Some(name) => match Format::parse(name) {
            Some(f) => f,
            None => return Ok(usage(&format!("unknown format `{name}`"))),
        },
    };
    let fail_on = match parse_fail_on(args.fail_on.as_deref())? {
        Ok(f) => f,
        Err(exit) => return Ok(exit),
    };

    let parsed = match Reference::parse(reference) {
        Ok(r) => r,
        Err(e) => return Ok(usage(&e.to_string())),
    };
    let image = match OciClient::new().pull(&parsed) {
        Ok(image) => image,
        Err(e) => {
            eprintln!("multiscan: error: pulling {reference}: {e}");
            return Ok(Exit::ScanError);
        }
    };
    let temp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("multiscan: error: creating extraction dir: {e}");
            return Ok(Exit::ScanError);
        }
    };
    if let Err(e) = extract_image(&image.layers, temp.path()) {
        // A hostile layer (path escape, cap exceeded) is a scan error.
        eprintln!("multiscan: error: extracting image layers: {e}");
        return Ok(Exit::ScanError);
    }

    // OS-package resolution needs the pinned OSV snapshot.
    let feed_cache = multiscan_feeds::current_snapshot(&multiscan_feeds::cache_dir())
        .ok()
        .flatten()
        .map(|_| multiscan_feeds::cache_dir());
    let scan = scan_os_packages(temp.path(), &image.manifest_digest, feed_cache.as_deref());

    if !args.quiet {
        let os = scan
            .os
            .as_ref()
            .map(|o| {
                format!(
                    "{}{}",
                    o.id,
                    o.version_id
                        .as_deref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default()
                )
            })
            .unwrap_or_else(|| "unknown OS".to_string());
        eprintln!(
            "multiscan: {reference} ({}): {os}, {} package(s)",
            image.manifest_digest, scan.package_count
        );
        if let Some(reason) = &scan.partial {
            eprintln!("multiscan: warning: {reason}");
        }
    }

    // Score the container findings through the shared pipeline.
    let attributed: Vec<Attributed> = scan
        .findings
        .into_iter()
        .map(|raw| Attributed {
            engine_id: "multiscan.sca".to_string(),
            raw,
        })
        .collect();
    let merged = multiscan_dedup::merge(attributed);
    let enrichment = feed_cache
        .as_ref()
        .and_then(|cache| multiscan_feeds::current_snapshot(cache).ok().flatten())
        .and_then(|s| s.enrichment().ok());
    let feed_snapshot_id = feed_cache
        .as_ref()
        .and_then(|cache| multiscan_feeds::current_snapshot(cache).ok().flatten())
        .map(|s| s.manifest.snapshot_id);
    let mut findings: Vec<Finding> = merged
        .into_iter()
        .map(|m| {
            assemble_finding(
                m,
                &RiskContext::default(),
                feed_snapshot_id.clone(),
                enrichment.as_ref(),
            )
        })
        .collect();
    sort_findings(&mut findings);

    let blocking: Vec<&Finding> = findings
        .iter()
        .filter(|f| match &fail_on {
            None => false,
            Some(FailOn::Number(t)) => f.risk_score >= *t,
            Some(FailOn::Severity(t)) => f.severity >= *t,
        })
        .collect();
    for f in &blocking {
        eprintln!(
            "multiscan: gate: {} (score {:.1}) meets --fail-on",
            f.finding_id, f.risk_score
        );
    }
    let gate_failed = !blocking.is_empty();

    let footer = multiscan_report::Footer {
        scanned_at: scan_timestamp(),
        feed_snapshot_id,
    };
    print!("{}", render(format, &findings, &footer));

    Ok(if scan.partial.is_some() {
        Exit::ScanError
    } else if gate_failed {
        Exit::GateFailed
    } else {
        Exit::Clean
    })
}

/// Parse a `--fail-on` value into a threshold. The outer Result is for I/O
/// errors (none here); the inner distinguishes a usage error (Exit) from a
/// parsed value.
fn parse_fail_on(raw: Option<&str>) -> Result<Result<Option<FailOn>, Exit>, anyhow::Error> {
    Ok(match raw {
        None => Ok(None),
        Some(raw) => match raw.parse::<f64>() {
            Ok(n) => Ok(Some(FailOn::Number(n))),
            Err(_) => match parse_enum::<Severity>(raw) {
                Some(sev) => Ok(Some(FailOn::Severity(sev))),
                None => Err(usage(&format!(
                    "--fail-on `{raw}` is neither a number nor a severity"
                ))),
            },
        },
    })
}

/// Entry point for `multiscan scan`.
pub fn run(args: &ScanArgs) -> Result<Exit> {
    // Remote targets first: authorization is a hard gate (SEC-001, NG-5).
    match &args.target {
        Some(ScanTarget::Web { url }) => {
            return scan_web(url, args);
        }
        Some(ScanTarget::Image { reference }) => {
            return scan_image(reference, args);
        }
        None => {}
    }

    let format = match args.format.as_deref() {
        None => Format::Table,
        Some(name) => match Format::parse(name) {
            Some(f) => f,
            None => return Ok(usage(&format!("unknown format `{name}`"))),
        },
    };

    if !args.path.exists() {
        return Ok(usage(&format!(
            "scan path {} does not exist",
            args.path.display()
        )));
    }

    let (config, config_path) = match configfile::load(args.config.as_deref(), &args.path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("multiscan: error: {err:#}");
            return Ok(Exit::Usage);
        }
    };
    if args.verbose && !args.quiet {
        match &config_path {
            Some(p) => eprintln!("multiscan: config: {}", p.display()),
            None => eprintln!("multiscan: config: defaults (no multiscan.toml found)"),
        }
    }

    // Precedence: flags > file > defaults (spec 4.5).
    let profile: Profile = match &args.profile {
        Some(s) => match parse_enum(s) {
            Some(p) => p,
            None => return Ok(usage(&format!("unknown profile `{s}`"))),
        },
        None => config
            .scan
            .as_ref()
            .and_then(|s| s.profile)
            .unwrap_or(Profile::Standard),
    };

    let layers: Vec<Layer> = match &args.layers {
        Some(names) => {
            let mut layers = Vec::new();
            for name in names {
                match parse_enum::<Layer>(name) {
                    Some(layer) => layers.push(layer),
                    None => return Ok(usage(&format!("unknown layer `{name}`"))),
                }
            }
            layers
        }
        None => {
            let from_file = config.scan.as_ref().map(|s| s.layers.clone());
            match from_file {
                Some(layers) if !layers.is_empty() => layers,
                // Auto-detect placeholder: all local layers; engines' own
                // applicable() checks narrow this (FR-001 lands with real
                // engines in phase 2).
                _ => vec![Layer::Sca, Layer::Secrets, Layer::Iac, Layer::Sast],
            }
        }
    };

    let min_severity: Option<Severity> = match &args.min_severity {
        Some(s) => match parse_enum(s) {
            Some(sev) => Some(sev),
            None => return Ok(usage(&format!("unknown severity `{s}`"))),
        },
        None => None,
    };

    let fail_on: Option<FailOn> = match &args.fail_on {
        Some(raw) => match raw.parse::<f64>() {
            Ok(n) => Some(FailOn::Number(n)),
            Err(_) => match parse_enum::<Severity>(raw) {
                Some(sev) => Some(FailOn::Severity(sev)),
                None => {
                    return Ok(usage(&format!(
                        "--fail-on `{raw}` is neither a number nor a severity"
                    )))
                }
            },
        },
        None => config.gate.as_ref().and_then(|g| g.fail_on.clone()),
    };

    if let Some(jobs) = args.jobs {
        // Best-effort: the global pool can only be built once.
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build_global();
    }

    // ---- Feed snapshot pinning and staleness (FD-002..004) ----
    // A scan NEVER fetches (FD-003); it pins whatever `db update` cached.
    let offline = args.offline
        || config
            .feeds
            .as_ref()
            .and_then(|f| f.offline)
            .unwrap_or(false);
    let max_age_raw = args
        .max_feed_age
        .clone()
        .or_else(|| config.feeds.as_ref().and_then(|f| f.max_age.clone()))
        .unwrap_or_else(|| "7d".to_string());
    let max_age = match multiscan_feeds::parse_max_age(&max_age_raw) {
        Ok(duration) => duration,
        Err(err) => return Ok(usage(&format!("--max-feed-age: {err}"))),
    };
    // Feeds only gate scans that explicitly ask for the sca layer; secrets
    // and iac must work with zero prior network access (FD-007). The
    // auto-detect default does not count as an explicit sca request until
    // real auto-detection lands with the sca engine (FR-001, T-202).
    let sca_explicit = args
        .layers
        .as_ref()
        .map(|l| l.iter().any(|s| s == "sca"))
        .unwrap_or_else(|| {
            config
                .scan
                .as_ref()
                .map(|s| s.layers.contains(&Layer::Sca))
                .unwrap_or(false)
        });
    let feed_snapshot_id = match multiscan_feeds::current_snapshot(&multiscan_feeds::cache_dir()) {
        Ok(Some(snapshot)) => {
            match multiscan_feeds::freshness(snapshot.manifest.as_of, chrono::Utc::now(), max_age) {
                multiscan_feeds::Freshness::Fresh => Some(snapshot.manifest.snapshot_id),
                multiscan_feeds::Freshness::Stale { age_hours } => {
                    if offline {
                        // FD-004: stale under --offline is a hard failure.
                        eprintln!(
                            "multiscan: error: feed snapshot {} is {age_hours}h old \
                             (max {max_age_raw}) and --offline forbids updating (FD-004)",
                            snapshot.manifest.snapshot_id
                        );
                        return Ok(Exit::FeedsStale);
                    }
                    if !args.quiet {
                        eprintln!(
                            "multiscan: warning: feed snapshot {} is {age_hours}h old \
                             (max {max_age_raw}); run `multiscan db update`",
                            snapshot.manifest.snapshot_id
                        );
                    }
                    Some(snapshot.manifest.snapshot_id)
                }
            }
        }
        Ok(None) => {
            if offline && sca_explicit {
                eprintln!(
                    "multiscan: error: --offline with the sca layer requires a feed \
                     snapshot; run `multiscan db update` while online (FD-004, FD-007)"
                );
                return Ok(Exit::FeedsStale);
            }
            // Only relevant when dependency scanning is actually running; the
            // secrets/iac layers need no feeds (FD-007).
            if !args.quiet && layers.contains(&Layer::Sca) {
                eprintln!(
                    "multiscan: warning: no feed snapshot; dependency enrichment \
                     unavailable (run `multiscan db update`)"
                );
            }
            None
        }
        Err(err) => {
            if offline {
                eprintln!("multiscan: error: feed cache is corrupt: {err}");
                return Ok(Exit::FeedsStale);
            }
            if !args.quiet {
                eprintln!("multiscan: warning: feed cache is corrupt, ignoring it: {err}");
            }
            None
        }
    };

    let ctx = ScanContext {
        root: args.path.clone(),
        config: config.clone(),
        profile,
        layers,
        feed_snapshot_id: feed_snapshot_id.clone(),
        feed_cache_dir: feed_snapshot_id
            .as_ref()
            .map(|_| multiscan_feeds::cache_dir()),
        authorization: None,
        cancel: Arc::new(AtomicBool::new(false)),
        deadline: None,
        started_at: scan_timestamp(),
    };

    let mut registry = Registry::new();
    // Production engines register here as phases land (T-2xx).
    if ctx.layers.contains(&Layer::Sca) {
        registry.register(Box::new(multiscan_sca::ScaEngine::new()));
    }
    if ctx.layers.contains(&Layer::Secrets) {
        registry.register(Box::new(multiscan_secrets::SecretsEngine::new()));
    }
    if ctx.layers.contains(&Layer::Iac) {
        registry.register(Box::new(multiscan_iac::IacEngine::new()));
    }
    if let Some(count) = args.testkit_fixture {
        if args.testkit_partial {
            registry.register(Box::new(FixtureEngine::partial(
                "testkit.fixture",
                count,
                "testkit forced partial",
            )));
        } else {
            registry.register(Box::new(FixtureEngine::new("testkit.fixture", count)));
        }
    }

    let runs = registry.run(&ctx);

    // FR-015: engine failure/partial degrades the scan (exit 3) but never
    // suppresses other engines' findings and never closes anything.
    let mut scan_degraded = false;
    let mut attributed: Vec<Attributed> = Vec::new();
    for run in runs {
        match &run.outcome {
            Ok(EngineOutcome::Complete { units_scanned }) => {
                if args.verbose && !args.quiet {
                    eprintln!(
                        "multiscan: {}: complete ({units_scanned} units)",
                        run.engine_id
                    );
                }
            }
            Ok(EngineOutcome::Partial {
                units_scanned,
                reason,
            }) => {
                scan_degraded = true;
                if !args.quiet {
                    eprintln!(
                        "multiscan: warning: {}: partial after {units_scanned} units: {reason}",
                        run.engine_id
                    );
                }
            }
            Err(err) => {
                scan_degraded = true;
                if !args.quiet {
                    eprintln!("multiscan: warning: {}: {err}", run.engine_id);
                }
            }
        }
        for raw in run.findings {
            attributed.push(Attributed {
                engine_id: run.engine_id.clone(),
                raw,
            });
        }
    }

    // Ingest external reports into the SAME dedup pass as native findings
    // (BRG-001): a Trivy/SARIF/... report of the same weakness merges with the
    // native finding, escalating confidence (FR-004, 7.7.5).
    for file in &args.import {
        match import_attributed(file) {
            Ok(mut imported) => attributed.append(&mut imported),
            Err(err) => {
                scan_degraded = true;
                if !args.quiet {
                    eprintln!("multiscan: warning: import {}: {err}", file.display());
                }
            }
        }
    }

    let merged = multiscan_dedup::merge(attributed);
    let risk_context = RiskContext {
        asset_criticality: config.risk.as_ref().and_then(|r| r.asset_criticality),
        data_classification: config.risk.as_ref().and_then(|r| r.data_classification),
    };
    // Enrichment stage (spec 5.3): load KEV/EPSS from the pinned snapshot so
    // dependency findings get a real factor X (spec 8). Absent snapshot ⇒
    // every dependency scores with the documented `unavailable` default.
    let enrichment = ctx
        .feed_cache_dir
        .as_ref()
        .and_then(|cache| multiscan_feeds::current_snapshot(cache).ok().flatten())
        .and_then(|snapshot| snapshot.enrichment().ok());
    let mut findings: Vec<Finding> = merged
        .into_iter()
        .map(|m| {
            assemble_finding(
                m,
                &risk_context,
                ctx.feed_snapshot_id.clone(),
                enrichment.as_ref(),
            )
        })
        .collect();
    // Deterministic order before anything downstream reads the list (CLI-003).
    sort_findings(&mut findings);

    // Apply active suppressions (config [[suppress]] + store), keyed by
    // finding_id. An expired entry is simply not active, so its Finding
    // reappears and gates normally (FR-014). Suppressed findings get status
    // Suppressed and are excluded from the gate.
    let now = chrono::DateTime::parse_from_rfc3339(&ctx.started_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let suppressed_ids = active_suppression_ids(&config, &args.path, args.no_store, now);
    for finding in &mut findings {
        if suppressed_ids.contains(&finding.finding_id.0) {
            finding.status = FindingStatus::Suppressed;
        }
    }

    // Persist to the findings database unless stateless (STO-003). Store
    // failures degrade to a warning — a scan must still produce results.
    if !args.no_store {
        persist(&args.path, &findings, &ctx.started_at, args.quiet);
    }

    // Baseline delta gating (FR-010): with a baseline, only Findings absent
    // from it can block. The baseline is a Finding-set JSON file.
    let baseline_ids = match load_baseline_ids(args, &config) {
        Ok(ids) => ids,
        Err(err) => return Ok(usage(&format!("--baseline: {err}"))),
    };

    // Gate before display filtering: --min-severity is a display filter,
    // never a gate (spec 4.2). Suppressed and baseline-known Findings never
    // block.
    let blocking: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.status != FindingStatus::Suppressed)
        .filter(|f| {
            baseline_ids
                .as_ref()
                .map(|ids| !ids.contains(&f.finding_id.0))
                .unwrap_or(true)
        })
        .filter(|f| match &fail_on {
            None => false,
            Some(FailOn::Number(threshold)) => f.risk_score >= *threshold,
            Some(FailOn::Severity(threshold)) => f.severity >= *threshold,
        })
        .collect();
    for finding in &blocking {
        // FR-009: the blocking id goes to stderr.
        eprintln!(
            "multiscan: gate: {} (score {:.1}) meets --fail-on",
            finding.finding_id, finding.risk_score
        );
    }
    let gate_failed = !blocking.is_empty();

    // Human formats hide suppressed findings (a Suppression is time-bounded
    // hiding, spec 2) and honour --min-severity; machine formats keep
    // everything (suppressed findings carry status "suppressed" for audit).
    let displayed: Vec<Finding> = if format.is_machine() {
        findings
    } else {
        findings
            .into_iter()
            .filter(|f| f.status != FindingStatus::Suppressed)
            .filter(|f| min_severity.map(|min| f.severity >= min).unwrap_or(true))
            .collect()
    };

    // The single stdout write (CLI-001). The footer carries the scan
    // timestamp for human formats only (OUT-002); machine formats ignore it.
    let footer = multiscan_report::Footer {
        scanned_at: ctx.started_at.clone(),
        feed_snapshot_id: ctx.feed_snapshot_id.clone(),
    };
    let output = if format == Format::Sbom {
        // SBOM is a component inventory from the SCA resolved graph (spec 12),
        // independent of which findings surfaced.
        let components: Vec<multiscan_report::SbomComponent> =
            multiscan_sca::resolve_inventory(&args.path)
                .into_iter()
                .map(|p| multiscan_report::SbomComponent {
                    purl: p.purl(),
                    name: p.name,
                    version: p.version,
                })
                .collect();
        multiscan_report::render_sbom(&components, &displayed, &footer)
    } else {
        render(format, &displayed, &footer)
    };
    print!("{}", output);

    Ok(if scan_degraded {
        Exit::ScanError
    } else if gate_failed {
        Exit::GateFailed
    } else {
        Exit::Clean
    })
}

/// CVE aliases the SCA engine stashed in evidence detail (`cve_aliases`).
fn cve_aliases(merged: &MergedFinding) -> Vec<String> {
    merged
        .evidence
        .iter()
        .filter_map(|e| e.detail.get("cve_aliases"))
        .filter_map(|v| v.as_array())
        .flatten()
        .filter_map(|v| v.as_str())
        .map(String::from)
        .collect()
}

/// Exploit signal for scoring (spec 8, factor X). Dependency classes are
/// enriched from KEV/EPSS when a snapshot is pinned; other classes have no CVE
/// by nature.
fn exploit_signal(
    merged: &MergedFinding,
    enrichment: Option<&multiscan_feeds::Enrichment>,
) -> ExploitSignal {
    match &merged.identity {
        IdentityKey::VulnerableDependency { .. } | IdentityKey::ContainerVulnerability { .. } => {
            let Some(enrichment) = enrichment else {
                return ExploitSignal::Unavailable;
            };
            let cves = cve_aliases(merged);
            if cves.is_empty() {
                // Advisory with no CVE alias: treat as no-CVE rather than
                // claiming enrichment was unavailable.
                return ExploitSignal::NoCve;
            }
            if enrichment.any_kev(&cves) {
                ExploitSignal::Kev
            } else if let Some(epss) = enrichment.max_epss(&cves) {
                ExploitSignal::Epss(epss)
            } else {
                ExploitSignal::Unavailable
            }
        }
        _ => ExploitSignal::NoCve,
    }
}

fn assemble_finding(
    merged: MergedFinding,
    risk_context: &RiskContext,
    feed_snapshot_id: Option<String>,
    enrichment: Option<&multiscan_feeds::Enrichment>,
) -> Finding {
    let exposure = match merged.identity {
        IdentityKey::WebExposure { .. } => ExposureSignal::InternetReachable,
        _ => ExposureSignal::Unknown,
    };
    let exploit = exploit_signal(&merged, enrichment);
    let scored = score(&ScoringInputs {
        severity: merged.severity,
        cvss_base: None,
        confidence: merged.confidence,
        exposure,
        exploit,
        context: *risk_context,
        feed_snapshot_id,
    });
    Finding {
        finding_id: FindingId(merged.finding_id),
        identity: merged.identity,
        title: merged.title,
        description: merged.description,
        severity: merged.severity,
        confidence: merged.confidence,
        status: FindingStatus::Open,
        risk_score: scored.risk_score,
        score_explanation: scored.explanation,
        asset: merged.asset,
        location: merged.location,
        evidence: merged.evidence,
        sources: merged.sources,
        remediation: merged.remediation,
        cwe: merged.cwe,
    }
}

/// Compile-time guarantee that fixture findings map into every class arm
/// above; keeps `exploit_signal` exhaustive as classes evolve.
#[allow(dead_code)]
fn _class_coverage(class: FindingClass) -> &'static str {
    match class {
        FindingClass::VulnerableDependency => "sca",
        FindingClass::ContainerVulnerability => "image",
        FindingClass::ExposedSecret => "secrets",
        FindingClass::IacMisconfiguration => "iac",
        FindingClass::WebExposure => "probe",
        FindingClass::StructuralPattern => "sast",
    }
}
