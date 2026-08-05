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

/// Path of the debug CLI binary the harnesses drive.
pub fn binary_path() -> PathBuf {
    workspace_root().join("target/debug/multiscan")
}

/// Build the CLI binary so harnesses always test current code.
pub fn ensure_binary() -> Result<()> {
    run("cargo", &["build", "-p", "multiscan"])
}

/// A fresh empty scratch directory under target/ (recreated each call).
pub fn scratch_dir(name: &str) -> Result<PathBuf> {
    let dir = workspace_root().join("target/xtask-scratch").join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("clearing {}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
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
