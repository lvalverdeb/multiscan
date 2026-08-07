//! `cargo xtask bench-detect` — quantify detection quality against a committed
//! labeled corpus, turning "strong by construction" into measured precision,
//! recall, and F1 per engine.
//!
//! Method (no network, no real hosts — spec 16): scan a positive corpus whose
//! complete expected findings are labeled in `labels.json`, plus the quiet
//! corpus (which must stay silent) as the false-positive set. Match reported
//! findings to labels by (engine, rule/advisory/policy key, path):
//!   TP = labels matched; FN = labels missed; FP = any reported finding with
//!   no label (in either corpus). SCA needs advisory data, so the harness
//!   seeds an isolated snapshot from `labels.osv` and points the binary at it.
//!
//! This is a crafted regression/quality gate, not a real-world-scale labeled
//! dataset: it proves the detectors fire on their targets and stay silent on
//! benign look-alikes, and fails the build if that regresses. Broader
//! empirical measurement needs a larger corpus (and, for differential runs,
//! other scanners imported via the SARIF bridge).

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::util;

/// One ground-truth label or one reported finding, reduced to its match key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    engine: String,
    key: String,
    path: String,
}

/// Per-engine tally.
#[derive(Default)]
struct Tally {
    tp: u32,
    fp: u32,
    fn_: u32,
}

impl Tally {
    fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 {
            1.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    fn recall(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 {
            1.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

pub fn run(check: bool) -> Result<()> {
    util::ensure_binary()?;
    let root = util::workspace_root();
    let bench = root.join("testdata/corpus/bench");
    let labels: Value = serde_json::from_slice(&std::fs::read(bench.join("labels.json"))?)
        .context("parsing labels.json")?;

    // Seed an isolated snapshot with the advisories the SCA fixtures need.
    let cache = util::scratch_dir("bench-detect")?;
    seed_snapshot(&cache, &labels)?;

    // Positive corpus: every finding here should correspond to a label.
    let positive = scan(&bench.join("positive"), &cache)?;
    // Negative corpora: every finding here is a false positive. `quiet` is the
    // secrets FP-006 set; `bench/negative` adds realistic benign inputs across
    // engines — notably patched dependency versions that MUST NOT match the
    // seeded advisories (the FR-003 naive-comparison failure mode) and
    // correctly-configured IaC.
    let mut quiet = scan(&root.join("testdata/corpus/quiet"), &cache)?;
    quiet.extend(scan(&bench.join("negative"), &cache)?);

    let expected: BTreeSet<Key> = labels["expected"]
        .as_array()
        .context("labels.expected must be an array")?
        .iter()
        .map(|e| Key {
            engine: e["engine"].as_str().unwrap_or_default().to_string(),
            key: e["key"].as_str().unwrap_or_default().to_string(),
            path: e["path"].as_str().unwrap_or_default().to_string(),
        })
        .collect();

    // Match. A label is TP if any positive-corpus finding shares its key.
    let mut per_engine: BTreeMap<String, Tally> = BTreeMap::new();
    let positive_keys: BTreeSet<Key> = positive.iter().cloned().collect();

    for label in &expected {
        let t = per_engine.entry(label.engine.clone()).or_default();
        if positive_keys.contains(label) {
            t.tp += 1;
        } else {
            t.fn_ += 1;
        }
    }
    // False positives: positive-corpus findings with no label, plus every
    // quiet-corpus finding.
    let mut fp_detail: Vec<Key> = Vec::new();
    for f in positive.iter().chain(quiet.iter()) {
        let is_labeled = expected.contains(f);
        if !is_labeled {
            per_engine.entry(f.engine.clone()).or_default().fp += 1;
            fp_detail.push(f.clone());
        }
    }

    render(&per_engine, &expected, &positive_keys, &fp_detail);

    // JSON report for CI consumption.
    let overall = overall(&per_engine);
    let report = serde_json::json!({
        "per_engine": per_engine.iter().map(|(e, t)| {
            (e.clone(), serde_json::json!({
                "tp": t.tp, "fp": t.fp, "fn": t.fn_,
                "precision": t.precision(), "recall": t.recall(), "f1": t.f1(),
            }))
        }).collect::<serde_json::Map<_, _>>(),
        "overall": {
            "tp": overall.tp, "fp": overall.fp, "fn": overall.fn_,
            "precision": overall.precision(), "recall": overall.recall(), "f1": overall.f1(),
        }
    });
    let out_path = root.join("target/bench-detect.json");
    std::fs::write(&out_path, serde_json::to_vec_pretty(&report)?)?;
    eprintln!("xtask bench-detect: report → {}", out_path.display());

    if check {
        let floors = &labels["floors"];
        let p_floor = floors["precision"].as_f64().unwrap_or(1.0);
        let r_floor = floors["recall"].as_f64().unwrap_or(1.0);
        if overall.precision() + 1e-9 < p_floor || overall.recall() + 1e-9 < r_floor {
            bail!(
                "bench-detect: below floor — precision {:.3} (floor {p_floor}), recall {:.3} (floor {r_floor})",
                overall.precision(),
                overall.recall()
            );
        }
        eprintln!(
            "xtask bench-detect: OK (precision {:.3} ≥ {p_floor}, recall {:.3} ≥ {r_floor})",
            overall.precision(),
            overall.recall()
        );
    }
    Ok(())
}

fn overall(per_engine: &BTreeMap<String, Tally>) -> Tally {
    let mut o = Tally::default();
    for t in per_engine.values() {
        o.tp += t.tp;
        o.fp += t.fp;
        o.fn_ += t.fn_;
    }
    o
}

fn render(
    per_engine: &BTreeMap<String, Tally>,
    expected: &BTreeSet<Key>,
    found: &BTreeSet<Key>,
    fp_detail: &[Key],
) {
    println!("\nDetection benchmark (labeled corpus)\n");
    println!(
        "  {:<9} {:>4} {:>4} {:>4}   {:>9} {:>7} {:>6}",
        "engine", "TP", "FP", "FN", "precision", "recall", "F1"
    );
    println!("  {}", "-".repeat(56));
    for (engine, t) in per_engine {
        println!(
            "  {:<9} {:>4} {:>4} {:>4}   {:>9.3} {:>7.3} {:>6.3}",
            engine,
            t.tp,
            t.fp,
            t.fn_,
            t.precision(),
            t.recall(),
            t.f1()
        );
    }
    let o = overall(per_engine);
    println!("  {}", "-".repeat(56));
    println!(
        "  {:<9} {:>4} {:>4} {:>4}   {:>9.3} {:>7.3} {:>6.3}",
        "overall",
        o.tp,
        o.fp,
        o.fn_,
        o.precision(),
        o.recall(),
        o.f1()
    );

    // Missed labels (FN) and unexpected findings (FP) named for debugging.
    for label in expected {
        if !found.contains(label) {
            println!("  MISSED  {}/{} @ {}", label.engine, label.key, label.path);
        }
    }
    for f in fp_detail {
        println!("  UNEXPECTED  {}/{} @ {}", f.engine, f.key, f.path);
    }
    println!(
        "\n  Note: a crafted regression gate, not a real-world-scale dataset.\n"
    );
}

/// Scan `path` with all local layers, offline, against the seeded cache, and
/// reduce each finding to its match key.
fn scan(path: &std::path::Path, cache: &std::path::Path) -> Result<Vec<Key>> {
    let out = Command::new(util::binary_path())
        .args([
            "scan",
            path.to_str().context("non-UTF-8 path")?,
            "--layers",
            "sca,secrets,iac",
            "--offline",
            "--no-store",
            "--format",
            "json",
        ])
        .env("MULTISCAN_CACHE_DIR", cache)
        .env("NO_COLOR", "1")
        .output()
        .context("running multiscan")?;
    // Exit 3 (Partial) is acceptable; only a hard error (2/other) is a problem.
    let code = out.status.code().unwrap_or(-1);
    if !matches!(code, 0 | 1 | 3) {
        bail!(
            "scan {} exited {code}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let findings: Value = serde_json::from_slice(&out.stdout)
        .with_context(|| format!("parsing scan json for {}", path.display()))?;
    Ok(findings
        .as_array()
        .map(|arr| arr.iter().filter_map(finding_key).collect())
        .unwrap_or_default())
}

/// Reduce a finding JSON to (engine, key, path).
fn finding_key(f: &Value) -> Option<Key> {
    let identity = &f["identity"];
    let class = identity["finding_class"].as_str()?;
    let (engine, key) = match class {
        "exposed_secret" => ("secrets", identity["rule_id"].as_str()?),
        "vulnerable_dependency" | "container_vulnerability" => {
            ("sca", identity["advisory_id"].as_str()?)
        }
        "iac_misconfiguration" => ("iac", identity["policy_id"].as_str()?),
        "web_exposure" => ("probe", identity["template_id"].as_str()?),
        "structural_pattern" => ("sast", identity["rule_id"].as_str()?),
        _ => return None,
    };
    Some(Key {
        engine: engine.to_string(),
        key: key.to_string(),
        path: f["location"]["path"].as_str()?.to_string(),
    })
}

/// Seed an isolated snapshot with the labeled OSV advisories so SCA resolves
/// offline. KEV/EPSS are minimal but valid (enrichment must parse them).
fn seed_snapshot(cache: &std::path::Path, labels: &Value) -> Result<()> {
    use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};

    let mut osv_jsonl: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut osv_counts: BTreeMap<String, u64> = BTreeMap::new();
    if let Some(map) = labels["osv"].as_object() {
        for (ecosystem, advisories) in map {
            let mut jsonl = Vec::new();
            let mut n = 0u64;
            for adv in advisories.as_array().into_iter().flatten() {
                jsonl.extend_from_slice(serde_json::to_string(adv)?.as_bytes());
                jsonl.push(b'\n');
                n += 1;
            }
            osv_jsonl.insert(ecosystem.clone(), jsonl);
            osv_counts.insert(ecosystem.clone(), n);
        }
    }

    let data = SnapshotData {
        kev_json: br#"{"vulnerabilities":[]}"#.to_vec(),
        epss_csv: b"cve,epss,percentile\n".to_vec(),
        osv_jsonl,
        rule_packs: BTreeMap::new(),
        counts: SnapshotCounts {
            kev: 0,
            epss: 0,
            osv: osv_counts,
        },
        sources: BTreeMap::new(),
    };
    // Fresh timestamp so the snapshot is not stale under --offline (FD-004).
    write_snapshot(cache, &data, chrono::Utc::now()).context("seeding snapshot")?;
    Ok(())
}
