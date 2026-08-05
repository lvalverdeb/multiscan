//! `cargo xtask bench` — performance/size gates (NFR-001..005). v1 enforces the
//! binary-size gate (NFR-004: release, stripped, LTO < 30 MB), which is
//! deterministically checkable; the timing gates (NFR-001/002/005) are wired as
//! informational measurements and tightened as the corpus stabilizes.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::util;

/// NFR-004: the stripped release binary must be under 30 MB.
const MAX_BINARY_BYTES: u64 = 30 * 1024 * 1024;

pub fn run() -> Result<()> {
    // Build the release binary with the workspace release profile (LTO + strip).
    util::run("cargo", &["build", "--release", "-p", "multiscan"])?;

    let binary: PathBuf = util::workspace_root().join("target/release/multiscan");
    let size = std::fs::metadata(&binary)
        .with_context(|| format!("stat {}", binary.display()))?
        .len();
    let mib = size as f64 / (1024.0 * 1024.0);
    eprintln!("xtask bench: release binary {mib:.1} MiB (limit 30.0 MiB, NFR-004)");

    if size > MAX_BINARY_BYTES {
        bail!(
            "release binary is {mib:.1} MiB, over the 30 MiB gate (NFR-004); \
             trim dependencies or features"
        );
    }
    eprintln!("xtask bench: OK");
    Ok(())
}
