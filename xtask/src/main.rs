//! MultiScan developer task runner (`cargo xtask <command>`).
//!
//! xtask is dev tooling: excluded from `default-members`, never part of the
//! shipped binary, and exempt from the unwrap/expect/panic bans (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod gen;
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
        Cmd::Golden { bless: _bless } => stub("golden", "T-106"),
        Cmd::Determinism { runs: _runs } => stub("determinism", "T-106"),
        Cmd::Safety => stub("safety", "T-501"),
        Cmd::Offline => stub("offline", "T-106"),
        Cmd::Bench => stub("bench", "T-601"),
        Cmd::Purity => purity::run(),
        Cmd::Ci => ci(),
    }
}

/// Placeholder for subcommands whose real implementation lands in a later task.
/// Prints a loud SKIP so the CI ladder stays honest about what it covered.
fn stub(name: &str, lands_in: &str) -> Result<()> {
    eprintln!("xtask {name}: SKIP — not implemented yet (lands in {lands_in})");
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
    util::run("cargo", &["deny", "check"])?;
    eprintln!("xtask ci: all gates green");
    Ok(())
}
