//! No-I/O purity enforcement for `multiscan-core`, `multiscan-dedup`,
//! `multiscan-risk` (spec 5.2, DET-004, CLAUDE.md rule 4), plus the
//! lints-inheritance check backing NFR-009.
//!
//! Three independent layers (clippy's per-crate `disallowed-*` config is a
//! fourth, enforced in the clippy step of the ladder):
//! 1. Transitive normal-dependency closure vs a checked-in allowlist
//!    (`xtask/purity-allowlist.toml`). Any new dependency is a red build until
//!    the allowlist is edited — a reviewable event.
//! 2. Every workspace member must inherit `[lints] workspace = true`, so the
//!    workspace-level `unsafe_code = "forbid"` actually applies everywhere.
//! 3. A best-effort source sweep for banned tokens in the pure crates'
//!    non-comment lines (belt-and-braces behind clippy).

use anyhow::{bail, Context, Result};
use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, Package, PackageId};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::util;

const PURE_CRATES: &[&str] = &["multiscan-core", "multiscan-dedup", "multiscan-risk"];

const SOURCE_BAN_TOKENS: &[&str] = &[
    "std::fs::",
    "std::net::",
    "std::time::SystemTime",
    "std::time::Instant",
    "std::env::var",
    "tokio::",
    "reqwest::",
    "ureq::",
];

pub fn run() -> Result<()> {
    let metadata = MetadataCommand::new()
        .current_dir(util::workspace_root())
        .exec()
        .context("running `cargo metadata`")?;

    let mut failures: Vec<String> = Vec::new();

    check_lints_inheritance(&metadata, &mut failures)?;
    check_dep_closures(&metadata, &mut failures)?;
    sweep_sources(&mut failures)?;
    report_disallowed_type_allows(&metadata)?;

    if failures.is_empty() {
        eprintln!("xtask purity: OK ({} pure crates clean)", PURE_CRATES.len());
        Ok(())
    } else {
        for f in &failures {
            eprintln!("xtask purity: FAIL: {f}");
        }
        bail!("{} purity violation(s)", failures.len());
    }
}

/// Layer 2: every member's Cargo.toml must contain `[lints] workspace = true`.
fn check_lints_inheritance(metadata: &Metadata, failures: &mut Vec<String>) -> Result<()> {
    for pkg in metadata.workspace_packages() {
        let manifest = std::fs::read_to_string(&pkg.manifest_path)
            .with_context(|| format!("reading {}", pkg.manifest_path))?;
        let doc: toml::Value = manifest
            .parse()
            .with_context(|| format!("parsing {}", pkg.manifest_path))?;
        let inherits = doc
            .get("lints")
            .and_then(|l| l.get("workspace"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if !inherits {
            failures.push(format!(
                "{}: missing `[lints] workspace = true` — workspace forbid(unsafe_code) \
                 does not apply (NFR-009)",
                pkg.name
            ));
        }
    }
    Ok(())
}

/// Layer 1: transitive normal-dep closure of each pure crate vs the allowlist.
fn check_dep_closures(metadata: &Metadata, failures: &mut Vec<String>) -> Result<()> {
    let allowlist = load_allowlist()?;
    let by_id: BTreeMap<&PackageId, &Package> =
        metadata.packages.iter().map(|p| (&p.id, p)).collect();
    let resolve = metadata
        .resolve
        .as_ref()
        .context("cargo metadata returned no resolve graph")?;
    let nodes: BTreeMap<&PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|n| (&n.id, n)).collect();
    let workspace_members: BTreeSet<&PackageId> = metadata.workspace_members.iter().collect();

    for crate_name in PURE_CRATES {
        let root = metadata
            .workspace_packages()
            .into_iter()
            .find(|p| p.name.as_str() == *crate_name)
            .with_context(|| format!("workspace member `{crate_name}` not found"))?;
        let allowed = allowlist.get(*crate_name).cloned().unwrap_or_default();

        // BFS over normal-kind dependency edges.
        let mut seen: BTreeSet<&PackageId> = BTreeSet::new();
        let mut queue = vec![&root.id];
        while let Some(id) = queue.pop() {
            let Some(node) = nodes.get(id) else { continue };
            for dep in &node.deps {
                let is_normal = dep
                    .dep_kinds
                    .iter()
                    .any(|k| k.kind == DependencyKind::Normal);
                if is_normal && seen.insert(&dep.pkg) {
                    queue.push(&dep.pkg);
                }
            }
        }

        for id in seen {
            let pkg = by_id[id];
            let name = pkg.name.as_str();
            if workspace_members.contains(id) {
                // Pure crates may depend only on other pure crates internally.
                if !PURE_CRATES.contains(&name) {
                    failures.push(format!(
                        "{crate_name}: depends on workspace crate `{name}`, which is not a \
                         pure crate (spec 5.2)"
                    ));
                }
            } else if !allowed.contains(name) {
                failures.push(format!(
                    "{crate_name}: transitive dependency `{name}` is not in \
                     xtask/purity-allowlist.toml — add it there (reviewable event) or drop it"
                ));
            }
        }
    }
    Ok(())
}

fn load_allowlist() -> Result<BTreeMap<String, BTreeSet<String>>> {
    let path = util::workspace_root().join("xtask/purity-allowlist.toml");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let doc: toml::Value = text.parse().context("parsing purity-allowlist.toml")?;
    let mut out = BTreeMap::new();
    if let Some(table) = doc.as_table() {
        for (crate_name, entry) in table {
            let allowed: BTreeSet<String> = entry
                .get("allow")
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(toml::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            out.insert(crate_name.clone(), allowed);
        }
    }
    Ok(out)
}

/// Layer 3: token sweep over non-comment source lines of the pure crates.
fn sweep_sources(failures: &mut Vec<String>) -> Result<()> {
    let root = util::workspace_root();
    for crate_name in PURE_CRATES {
        let src = root.join("crates").join(crate_name).join("src");
        for file in util::files_with_extension(&src, "rs")? {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            for (lineno, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                for token in SOURCE_BAN_TOKENS {
                    if trimmed.contains(token) {
                        failures.push(format!(
                            "{}:{}: banned token `{token}` in pure crate (spec 5.2 / DET-004)",
                            file.strip_prefix(&root).unwrap_or(&file).display(),
                            lineno + 1,
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Report (not gate): justified `#[allow(clippy::disallowed_types)]` escape
/// hatches across the workspace, so growth is visible in CI logs.
fn report_disallowed_type_allows(metadata: &Metadata) -> Result<()> {
    let mut count = 0usize;
    for pkg in metadata.workspace_packages() {
        let src_dir = Path::new(&pkg.manifest_path)
            .parent()
            .map(|p| p.join("src"));
        let Some(src_dir) = src_dir else { continue };
        for file in util::files_with_extension(src_dir.as_path(), "rs")? {
            let text = std::fs::read_to_string(&file)?;
            for (lineno, line) in text.lines().enumerate() {
                if line.contains("clippy::disallowed_types") && line.contains("allow") {
                    count += 1;
                    eprintln!(
                        "xtask purity: note: disallowed_types allow at {}:{}",
                        file.display(),
                        lineno + 1
                    );
                }
            }
        }
    }
    eprintln!("xtask purity: {count} disallowed_types allow(s) in workspace");
    Ok(())
}
