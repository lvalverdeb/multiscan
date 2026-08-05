//! `cargo xtask golden` — byte-compare walking-skeleton output against
//! committed goldens (spec 16). Churn in these files is a reviewable event:
//! every diff line must be explained in the PR.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::util;

const FORMATS: &[&str] = &["table", "json", "jsonl", "sarif", "sbom", "markdown"];

/// (name, extra args) — each case runs in a fresh empty directory.
const CASES: &[(&str, &[&str])] = &[("empty", &[]), ("fixture-2", &["--testkit-fixture", "2"])];

pub fn run(bless: bool) -> Result<()> {
    util::ensure_binary()?;
    let golden_dir = util::workspace_root().join("testdata/corpus/skeleton");
    std::fs::create_dir_all(&golden_dir)?;
    let scratch = util::scratch_dir("golden")?;

    let mut failures: Vec<String> = Vec::new();
    let mut blessed = 0usize;

    for (case, extra_args) in CASES {
        for format in FORMATS {
            let output = Command::new(util::binary_path())
                .current_dir(&scratch)
                .args(["scan", ".", "--no-store", "--format", format])
                .args(*extra_args)
                .env("TZ", "UTC")
                .env("LC_ALL", "C")
                .env("NO_COLOR", "1")
                // Isolate from any real feed cache so golden output depends
                // only on the code, never on machine state (FD-007).
                .env("MULTISCAN_CACHE_DIR", scratch.join("empty-cache"))
                // Injected clock so the human-format footer is stable (OUT-002).
                .env("MULTISCAN_NOW", "2026-01-01T00:00:00Z")
                .output()
                .context("running multiscan")?;
            if !output.status.success() {
                bail!(
                    "golden case {case}/{format}: multiscan exited {:?}\nstderr: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let golden_path: PathBuf = golden_dir.join(format!("{case}.{format}.golden"));
            if bless {
                std::fs::write(&golden_path, &output.stdout)?;
                blessed += 1;
                continue;
            }
            let expected = std::fs::read(&golden_path).with_context(|| {
                format!(
                    "missing golden {} — run `cargo xtask golden --bless` and commit it",
                    golden_path.display()
                )
            })?;
            if expected != output.stdout {
                failures.push(format!(
                    "{case}.{format}: output differs from {} ({} vs {} bytes) — if intended, \
                     re-bless and explain every diff line in the PR",
                    golden_path.display(),
                    expected.len(),
                    output.stdout.len(),
                ));
            }
        }
    }

    if bless {
        eprintln!("xtask golden: blessed {blessed} golden file(s) — commit and explain the diff");
        return Ok(());
    }
    if failures.is_empty() {
        eprintln!(
            "xtask golden: OK ({} cases x {} formats)",
            CASES.len(),
            FORMATS.len()
        );
        Ok(())
    } else {
        for failure in &failures {
            eprintln!("xtask golden: FAIL: {failure}");
        }
        bail!("{} golden mismatch(es)", failures.len());
    }
}
