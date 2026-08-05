//! MultiScan developer task runner (`cargo xtask <command>`).
//!
//! xtask is dev tooling: excluded from `default-members`, never part of the
//! shipped binary, and exempt from the unwrap/expect/panic bans (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod bench;
mod determinism;
mod gen;
mod golden;
mod offline;
mod purity;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "MultiScan developer tasks")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Regenerate multiscan-core types from schemas/ (R-4)
    Gen {
        /// Verify generated code is up to date instead of writing (CI drift gate)
        #[arg(long)]
        check: bool,
    },
    /// Golden corpus diff: engine fixtures + scoring vectors
    Golden {
        /// Update golden files instead of diffing (churn is a reviewable event)
        #[arg(long)]
        bless: bool,
    },
    /// N-run byte-compare of machine output (DET-007)
    Determinism {
        /// Number of repeat runs
        #[arg(long, default_value_t = 100)]
        runs: u32,
    },
    /// Scope/authorization negative tests — release-blocking (spec 16)
    Safety,
    /// Sandboxed no-network verification (FR-011)
    Offline,
    /// Performance gates NFR-001..005
    Bench,
    /// No-I/O purity check for core/dedup/risk + lint-inheritance check (spec 5.2)
    Purity,
    /// Full CI ladder: gen --check, fmt, clippy, purity, test, golden,
    /// determinism, safety, offline, cargo-deny
    Ci,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Gen { check } => gen::run(check),
        Cmd::Golden { bless } => golden::run(bless),
        Cmd::Determinism { runs } => determinism::run(runs),
        Cmd::Safety => safety(),
        Cmd::Offline => offline::run(),
        Cmd::Bench => bench::run(),
        Cmd::Purity => purity::run(),
        Cmd::Ci => ci(),
    }
}

/// Scope/authorization negative suite — release-blocking (spec 16, SEC-001..009).
/// Runs the authorization crate's safety tests plus the CLI-level web-scan
/// refusal test. A single failure blocks the build.
fn safety() -> Result<()> {
    eprintln!("xtask safety: running scope/authorization negative suite");
    util::run(
        "cargo",
        &["test", "-p", "multiscan-scope", "--test", "safety"],
    )?;
    // The CLI-level SEC-001 refusal (scan web without --authorization → exit 4).
    util::run(
        "cargo",
        &[
            "test",
            "-p",
            "multiscan",
            "--test",
            "cli",
            "web_scan_without_authorization_denied",
        ],
    )?;
    eprintln!("xtask safety: OK");
    Ok(())
}

fn ci() -> Result<()> {
    // Order matters: cheap and structural first, expensive last.
    util::run("cargo", &["xtask", "gen", "--check"])?;
    util::run("cargo", &["fmt", "--all", "--check"])?;
    util::run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    purity::run()?;
    util::run("cargo", &["test", "--workspace"])?;
    util::run("cargo", &["xtask", "golden"])?;
    util::run("cargo", &["xtask", "determinism"])?;
    util::run("cargo", &["xtask", "safety"])?;
    util::run("cargo", &["xtask", "offline"])?;
    util::run("cargo", &["xtask", "bench"])?;
    util::run("cargo", &["deny", "check"])?;
    eprintln!("xtask ci: all gates green");
    Ok(())
}
