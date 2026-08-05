//! `cargo xtask determinism` — DET-007: repeat runs of the binary across
//! perturbed conditions must produce byte-identical machine output. One
//! mismatch fails the build.
//!
//! Perturbations per run (cycled): `--jobs` 1/2/8, hostile `TZ`/`LC_ALL`
//! values (DET-006), and two different working-directory spellings — a real
//! directory and a symlink to it (DET-005 / CLI-007 absolute-path leakage).

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use rayon::prelude::*;

use crate::util;

const FORMATS: &[&str] = &["table", "json", "jsonl", "sarif", "sbom", "markdown"];

const ENV_PERTURBATIONS: &[&[(&str, &str)]] = &[
    &[("TZ", "UTC"), ("LC_ALL", "C")],
    &[("TZ", "Asia/Tokyo"), ("LC_ALL", "tr_TR.UTF-8")],
    &[("TZ", "America/New_York"), ("LANG", "de_DE.UTF-8")],
];

const JOBS: &[&str] = &["1", "2", "8"];

pub fn run(runs: u32) -> Result<()> {
    util::ensure_binary()?;
    // Two spellings of the same empty scan root.
    let real = util::scratch_dir("det-real")?;
    let link: PathBuf = real.with_file_name("det-link");
    let _ = std::fs::remove_file(&link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).context("creating symlink prefix")?;
    #[cfg(not(unix))]
    let link = real.clone();
    let roots = [real, link];

    let mut mismatches = 0usize;
    for format in FORMATS {
        let digests: Vec<(u32, String)> = (0..runs)
            .into_par_iter()
            .map(|i| {
                let root = &roots[(i as usize) % roots.len()];
                let envs = ENV_PERTURBATIONS[(i as usize) % ENV_PERTURBATIONS.len()];
                let jobs = JOBS[(i as usize) % JOBS.len()];
                let output = Command::new(util::binary_path())
                    .current_dir(root)
                    .args([
                        "scan",
                        ".",
                        "--format",
                        format,
                        "--testkit-fixture",
                        "3",
                        "--jobs",
                        jobs,
                    ])
                    .envs(envs.iter().copied())
                    // Isolate from any real feed cache (FD-007): determinism
                    // must reflect the code, not machine state.
                    .env("MULTISCAN_CACHE_DIR", root.join("empty-cache"))
                    // Injected clock (DET-004): time is an input, held constant
                    // so real nondeterminism is what the compare catches.
                    .env("MULTISCAN_NOW", "2026-01-01T00:00:00Z")
                    .output()
                    .map_err(|e| format!("spawn failed: {e}"))?;
                if output.status.code() != Some(0) {
                    return Err(format!(
                        "run {i} ({format}) exited {:?}",
                        output.status.code()
                    ));
                }
                Ok((i, blake3::hash(&output.stdout).to_hex().to_string()))
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| anyhow::anyhow!(e))?;

        let reference = &digests[0].1;
        let diverging: Vec<u32> = digests
            .iter()
            .filter(|(_, d)| d != reference)
            .map(|(i, _)| *i)
            .collect();
        if diverging.is_empty() {
            eprintln!("xtask determinism: {format}: OK ({runs} runs byte-identical)");
        } else {
            eprintln!(
                "xtask determinism: {format}: FAIL — {} of {runs} runs diverged (runs {:?})",
                diverging.len(),
                &diverging[..diverging.len().min(10)]
            );
            mismatches += diverging.len();
        }
    }

    if mismatches > 0 {
        bail!("determinism violated: {mismatches} diverging run(s) (DET-007)");
    }
    Ok(())
}
