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

/// Entry point for `multiscan scan`.
pub fn run(args: &ScanArgs) -> Result<Exit> {
    // Remote targets first: authorization is a hard gate (SEC-001, NG-5).
    match &args.target {
        Some(ScanTarget::Web { url }) => {
            if args.authorization.is_none() {
                // Exit 4 before any packet is sent (FR-007). No packet-sending
                // code even exists on this path yet — T-501/T-502.
                eprintln!(
                    "multiscan: scan web {url}: refusing to probe without --authorization \
                     (SEC-001); no request was sent"
                );
                return Ok(Exit::AuthDenied);
            }
            return Ok(usage(
                "scan web is not implemented yet (lands in T-501/T-502)",
            ));
        }
        Some(ScanTarget::Image { .. }) => {
            return Ok(usage(
                "scan image is not implemented yet (lands in T-401/T-402)",
            ));
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
            if !args.quiet {
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
        started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };

    let mut registry = Registry::new();
    // Production engines register here as phases land (T-2xx).
    if ctx.layers.contains(&Layer::Sca) {
        registry.register(Box::new(multiscan_sca::ScaEngine::new()));
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
    sort_findings(&mut findings);

    // Gate before display filtering: --min-severity is a display filter,
    // never a gate (spec 4.2).
    let blocking: Vec<&Finding> = findings
        .iter()
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

    let displayed: Vec<Finding> = match (format.is_machine(), min_severity) {
        (false, Some(min)) => findings
            .iter()
            .filter(|f| f.severity >= min)
            .cloned()
            .collect(),
        _ => findings,
    };

    // The single stdout write (CLI-001).
    print!("{}", render(format, &displayed));

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
