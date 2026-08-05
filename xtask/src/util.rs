//! Shared helpers for xtask subcommands.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Workspace root, derived from this crate's manifest location.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

/// Run a command from the workspace root, inheriting stdio; fail on non-zero exit.
pub fn run(program: &str, args: &[&str]) -> Result<()> {
    eprintln!("xtask: $ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .current_dir(workspace_root())
        .status()
        .with_context(|| format!("failed to launch `{program}` — is it installed?"))?;
    if !status.success() {
        bail!("`{program} {}` failed with {status}", args.join(" "));
    }
    Ok(())
}

/// Recursively collect files under `dir` with the given extension.
pub fn files_with_extension(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == ext) {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}
