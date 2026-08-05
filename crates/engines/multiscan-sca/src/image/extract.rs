//! Hardened OCI layer extraction (SCA-005, NFR-010).
//!
//! Tar extraction is the single most-exploited surface in image scanners
//! (see RUSTSEC-2026-0148, an OCI symlink escape). The invariant here is
//! stronger than "the entry path looks clean": **no file operation ever
//! traverses a symlink out of the root**. We get that structurally from
//! `cap-std` — every write/read/remove goes through a `Dir` capability that,
//! on Linux, resolves with `RESOLVE_BENEATH`, so a write *through* an
//! attacker-planted symlink (entry 1: `x -> /etc`, entry 2: `x/passwd`) is
//! rejected by the OS, not by our own path math. Lexical checks below are
//! defense-in-depth on top of that.

use std::io::Read;

use cap_std::fs::Dir;
use flate2::read::GzDecoder;

/// Caps against tar/decompression bombs (untrusted input).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum number of entries processed per layer.
    pub max_entries: u64,
    /// Maximum total decompressed bytes written per layer.
    pub max_total_bytes: u64,
    /// Maximum size of any single entry.
    pub max_entry_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 2_000_000,
            max_total_bytes: 10 * 1024 * 1024 * 1024,
            max_entry_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

/// What an extraction did (for progress/telemetry).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Regular files written.
    pub files: u64,
    /// Directories created.
    pub dirs: u64,
    /// Symlinks created.
    pub symlinks: u64,
    /// Entries skipped (special files, unsafe entries, whiteouts applied).
    pub skipped: u64,
    /// Total bytes written.
    pub bytes: u64,
}

/// Extraction errors. An unsafe entry is a hard error, not a skip, so the
/// caller learns the image was hostile.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// Filesystem / capability error.
    #[error("layer extraction I/O: {0}")]
    Io(String),
    /// A cap on size or entry count was exceeded.
    #[error("layer exceeds cap: {0}")]
    TooLarge(String),
    /// An entry attempted to escape the extraction root.
    #[error("unsafe layer entry: {0}")]
    Unsafe(String),
}

fn io<E: std::fmt::Display>(e: E) -> ExtractError {
    ExtractError::Io(e.to_string())
}

/// Validate an entry path lexically and return its POSIX components. Rejects
/// absolute paths, `..`, and any Windows prefix. `.`/empty components are
/// dropped. An empty result (path was `.` or empty) yields `None`.
fn safe_components(path: &std::path::Path) -> Result<Vec<String>, ExtractError> {
    use std::path::Component;
    let mut out = Vec::new();
    for comp in path.components() {
        match comp {
            Component::Normal(c) => {
                let s = c
                    .to_str()
                    .ok_or_else(|| ExtractError::Unsafe("non-UTF-8 entry name".to_string()))?;
                out.push(s.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(ExtractError::Unsafe(format!(
                    "`..` in entry `{}`",
                    path.display()
                )))
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ExtractError::Unsafe(format!(
                    "absolute entry `{}`",
                    path.display()
                )))
            }
        }
    }
    Ok(out)
}

/// Reject symlink/hardlink targets that are absolute or escape the root when
/// resolved relative to the link's parent directory. (cap-std also blocks the
/// escape at traversal time; this keeps dangling escape-pointing links out of
/// the extracted tree entirely.)
fn link_target_ok(parent_components: &[String], target: &std::path::Path) -> bool {
    use std::path::Component;
    let mut depth = parent_components.len() as isize;
    for comp in target.components() {
        match comp {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false; // escaped above root
                }
            }
            Component::RootDir | Component::Prefix(_) => return false, // absolute
        }
    }
    true
}

/// Create all parent directories for `components` (all but the last) inside
/// `root`. cap-std confines this beneath root.
fn ensure_parents(root: &Dir, components: &[String]) -> Result<(), ExtractError> {
    if components.len() <= 1 {
        return Ok(());
    }
    let dir: std::path::PathBuf = components[..components.len() - 1].iter().collect();
    root.create_dir_all(&dir).map_err(io)
}

/// Extract one gzip-compressed layer tarball into `root`, applying OCI
/// whiteouts. `stats` accumulates across layers.
pub fn extract_layer<R: Read>(
    reader: R,
    root: &Dir,
    limits: &Limits,
    stats: &mut Stats,
) -> Result<(), ExtractError> {
    let decoder = GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    // We do our own confined writes; never let the tar crate touch the FS.
    let entries = archive.entries().map_err(io)?;

    let mut entry_count: u64 = 0;
    for entry in entries {
        let mut entry = entry.map_err(io)?;
        entry_count += 1;
        if entry_count > limits.max_entries {
            return Err(ExtractError::TooLarge(format!(
                "entry count exceeds {}",
                limits.max_entries
            )));
        }

        let path = entry.path().map_err(io)?.into_owned();
        let components = safe_components(&path)?;
        if components.is_empty() {
            continue; // root "." entry
        }

        // OCI whiteouts: a `.wh.`-prefixed basename marks a deletion.
        let base = components.last().cloned().unwrap_or_default();
        if let Some(name) = base.strip_prefix(".wh.") {
            apply_whiteout(root, &components, name, stats)?;
            continue;
        }

        let entry_type = entry.header().entry_type();
        let rel: std::path::PathBuf = components.iter().collect();

        if entry_type.is_dir() {
            root.create_dir_all(&rel).map_err(io)?;
            stats.dirs += 1;
        } else if entry_type.is_symlink() {
            let target = entry
                .link_name()
                .map_err(io)?
                .ok_or_else(|| ExtractError::Unsafe("symlink without target".to_string()))?
                .into_owned();
            if !link_target_ok(&components[..components.len() - 1], &target) {
                return Err(ExtractError::Unsafe(format!(
                    "symlink `{}` escapes root",
                    path.display()
                )));
            }
            ensure_parents(root, &components)?;
            // Replace any existing node at this path (later layers overwrite).
            let _ = root.remove_file(&rel);
            root.symlink(&target, &rel).map_err(io)?;
            stats.symlinks += 1;
        } else if entry_type.is_hard_link() {
            let target = entry
                .link_name()
                .map_err(io)?
                .ok_or_else(|| ExtractError::Unsafe("hardlink without target".to_string()))?
                .into_owned();
            let target_components = safe_components(&target)?;
            if target_components.is_empty() {
                return Err(ExtractError::Unsafe("hardlink to root".to_string()));
            }
            ensure_parents(root, &components)?;
            let target_rel: std::path::PathBuf = target_components.iter().collect();
            let _ = root.remove_file(&rel);
            // cap-std confines both source and dest beneath root.
            root.hard_link(&target_rel, root, &rel).map_err(io)?;
            stats.files += 1;
        } else if entry_type.is_file() {
            let size = entry.header().size().map_err(io)?;
            if size > limits.max_entry_bytes {
                return Err(ExtractError::TooLarge(format!(
                    "entry `{}` is {size} bytes",
                    path.display()
                )));
            }
            ensure_parents(root, &components)?;
            write_file(root, &rel, &mut entry, size, limits, stats)?;
        } else {
            // Character/block devices, FIFOs, sockets, GNU longname aux, etc.
            // Never create device nodes or special files in a scan tree.
            stats.skipped += 1;
        }
    }
    Ok(())
}

/// Write a regular file with fixed sane permissions (archive mode bits —
/// setuid/setgid included — are deliberately ignored for a scan extraction).
fn write_file<R: Read>(
    root: &Dir,
    rel: &std::path::Path,
    entry: &mut R,
    declared_size: u64,
    limits: &Limits,
    stats: &mut Stats,
) -> Result<(), ExtractError> {
    use std::io::Write;
    // Overwrite any existing node (later layers win); never follow a symlink.
    let _ = root.remove_file(rel);
    let mut file = root
        .open_with(
            rel,
            cap_std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true),
        )
        .map_err(io)?;

    let mut remaining = declared_size.min(limits.max_entry_bytes);
    let mut buf = [0u8; 64 * 1024];
    let mut written: u64 = 0;
    loop {
        let want = remaining.min(buf.len() as u64) as usize;
        if want == 0 {
            break;
        }
        let n = entry.read(&mut buf[..want]).map_err(io)?;
        if n == 0 {
            break;
        }
        if stats.bytes + n as u64 > limits.max_total_bytes {
            return Err(ExtractError::TooLarge("layer total size".to_string()));
        }
        file.write_all(&buf[..n]).map_err(io)?;
        written += n as u64;
        stats.bytes += n as u64;
        remaining -= n as u64;
    }
    stats.files += 1;
    let _ = written;
    Ok(())
}

/// Apply an OCI whiteout. `.wh..wh..opq` clears a directory's contents
/// (opaque); `.wh.<name>` removes `<name>`. Removal is confined beneath root
/// (a whiteout with `..` would already have been rejected by `safe_components`).
fn apply_whiteout(
    root: &Dir,
    components: &[String],
    name: &str,
    stats: &mut Stats,
) -> Result<(), ExtractError> {
    let parent: Vec<String> = components[..components.len() - 1].to_vec();
    stats.skipped += 1;

    if name == ".wh..opq" || components.last().map(String::as_str) == Some(".wh..wh..opq") {
        // Opaque marker: remove all children of the parent directory.
        let dir_path: std::path::PathBuf = parent.iter().collect();
        if let Ok(dir) = root.open_dir(&dir_path) {
            if let Ok(read) = dir.entries() {
                for child in read.flatten() {
                    let child_name = child.file_name();
                    if child.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let _ = dir.remove_dir_all(&child_name);
                    } else {
                        let _ = dir.remove_file(&child_name);
                    }
                }
            }
        }
        return Ok(());
    }

    let mut target = parent;
    target.push(name.to_string());
    let target_path: std::path::PathBuf = target.iter().collect();
    // Try file then directory; either may not exist (whiteout of an absent
    // path is a no-op), and both are confined beneath root.
    if root.remove_file(&target_path).is_err() {
        let _ = root.remove_dir_all(&target_path);
    }
    Ok(())
}
