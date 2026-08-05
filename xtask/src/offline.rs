//! `cargo xtask offline` — FR-011: `--offline` scans must not touch the
//! network. On Linux the scan runs inside `unshare -r -n` (a network
//! namespace with no interfaces), so ANY network syscall fails hard — this is
//! the authoritative CI gate. On macOS, `sandbox-exec` with a deny-network
//! profile is used best-effort and the result is advisory (R-7: asymmetric
//! enforcement with one authoritative platform, loudly labelled).

use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::util;

const SCAN_ARGS: &[&str] = &[
    "scan",
    ".",
    "--offline",
    "--format",
    "json",
    "--testkit-fixture",
    "2",
];

pub fn run() -> Result<()> {
    util::ensure_binary()?;
    let scratch = util::scratch_dir("offline")?;
    let binary = util::binary_path();

    let mut command = if cfg!(target_os = "linux") {
        let mut c = Command::new("unshare");
        c.args(["-r", "-n"]).arg(&binary).args(SCAN_ARGS);
        c
    } else if cfg!(target_os = "macos") {
        eprintln!(
            "xtask offline: WARNING — macOS sandbox-exec is advisory only; \
             the authoritative no-network gate is Linux CI (FR-011)"
        );
        let mut c = Command::new("sandbox-exec");
        c.args(["-p", "(version 1)(allow default)(deny network*)"])
            .arg(&binary)
            .args(SCAN_ARGS);
        c
    } else {
        eprintln!("xtask offline: SKIP — no sandbox available on this platform");
        return Ok(());
    };

    let output = command
        .current_dir(&scratch)
        // Isolate from any real feed cache; the scan must succeed offline with
        // no snapshot for non-sca layers (FD-007).
        .env("MULTISCAN_CACHE_DIR", scratch.join("empty-cache"))
        .output()
        .context("launching sandboxed scan")?;
    if output.status.code() != Some(0) {
        bail!(
            "offline scan failed under the network-denying sandbox (exit {:?})\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // Sanity: stdout is the expected machine output.
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .context("offline scan stdout is not valid JSON")?;
    eprintln!("xtask offline: OK (scan succeeded with networking denied)");
    Ok(())
}
