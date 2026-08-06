//! Git-history blob enumeration for the opt-in `--history` pass (ADR 0006).
//!
//! A committed-then-removed secret is still live: it sits in every clone's
//! object store. This module lists historical blobs via the system `git` CLI
//! (`rev-list --objects --all`, then `cat-file --batch` in bounded chunks) —
//! no git library dependency, no unsafe, no network. Everything read is
//! attacker-controllable repository data, so every allocation is bounded:
//! per-blob and cumulative byte caps, a blob-count cap, and header parsing
//! that never trusts a size field beyond the cap.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// Hard caps (untrusted input; CLAUDE.md conventions). Exceeding a cap ends
/// the pass early — the caller reports `Partial`, never silence.
pub const MAX_HISTORY_BLOBS: usize = 20_000;
pub const MAX_BLOB_BYTES: u64 = 8 * 1024 * 1024; // matches the tree-scan cap
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Requests in flight per `cat-file --batch` chunk: small enough that the
/// request lines and responses cannot deadlock the pipe, large enough to
/// amortize syscalls.
const BATCH_CHUNK: usize = 100;

/// One historical blob: its repo-relative path (as of the commit that
/// introduced it) and UTF-8 content. Binary blobs are skipped.
pub struct HistoryBlob {
    /// Abbreviated object id — provenance for evidence, never identity.
    pub oid_short: String,
    /// Repo-relative POSIX path the blob was recorded under.
    pub path: String,
    /// Blob text.
    pub text: String,
}

/// Outcome of the enumeration: blobs plus whether any cap truncated the
/// pass (the engine degrades to `Partial` when set).
pub struct HistoryScan {
    /// Deduplicated, path-sorted blobs.
    pub blobs: Vec<HistoryBlob>,
    /// Set when a cap ended enumeration early.
    pub truncated: Option<String>,
}

fn run_git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("git unavailable: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Enumerate historical blobs under `root`. Blobs whose object id is still
/// in the index are skipped — the working-tree scan already covers that
/// content at its current path.
pub fn enumerate(root: &Path) -> Result<HistoryScan, String> {
    // Fails fast (and cleanly) when root is not a git repository.
    run_git(root, &["rev-parse", "--git-dir"])?;

    // Object ids currently in the index: already covered by the tree scan.
    let mut in_tree = BTreeSet::new();
    if let Ok(ls) = run_git(root, &["ls-files", "-s", "-z"]) {
        for entry in ls.split(|b| *b == 0) {
            // `<mode> <oid> <stage>\t<path>`
            let text = String::from_utf8_lossy(entry);
            if let Some(oid) = text.split_whitespace().nth(1) {
                in_tree.insert(oid.to_string());
            }
        }
    }

    // (oid, historical path) for every object reachable from any ref.
    let listing = run_git(root, &["rev-list", "--objects", "--all"])?;
    let mut truncated = None;
    let mut candidates: Vec<(String, String)> = Vec::new();
    let mut seen = BTreeSet::new();
    for line in listing.split(|b| *b == b'\n') {
        let text = String::from_utf8_lossy(line);
        // Blobs carry a path after the oid; commits/trees have none or none
        // we scan. Path presence is the blob discriminator that needs no
        // extra cat-file round-trip; trees with paths are filtered below by
        // the `blob` type check in the batch header.
        let Some((oid, path)) = text.split_once(' ') else {
            continue;
        };
        if oid.len() < 40 || path.is_empty() || in_tree.contains(oid) {
            continue;
        }
        if !seen.insert(oid.to_string()) {
            continue; // same content under several paths: scan once
        }
        candidates.push((oid.to_string(), path.to_string()));
        if candidates.len() >= MAX_HISTORY_BLOBS {
            truncated = Some(format!(
                "git history truncated at {MAX_HISTORY_BLOBS} blobs"
            ));
            break;
        }
    }
    // Deterministic scan order regardless of rev-list traversal order.
    candidates.sort();

    let mut blobs = Vec::new();
    let mut total: u64 = 0;

    // `cat-file --batch` in bounded chunks: write BATCH_CHUNK requests, then
    // read exactly that many responses — request lines and replies can never
    // outgrow the pipe together, so no deadlock and no reader thread.
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("git unavailable: {e}"))?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        return Err("git cat-file: no stdin".to_string());
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Err("git cat-file: no stdout".to_string());
    };
    let mut reader = BufReader::new(stdout);

    'chunks: for chunk in candidates.chunks(BATCH_CHUNK) {
        let mut request = String::new();
        for (oid, _) in chunk {
            request.push_str(oid);
            request.push('\n');
        }
        if stdin.write_all(request.as_bytes()).is_err() {
            truncated = Some("git cat-file ended early".to_string());
            break;
        }
        for (oid, path) in chunk {
            // Header: `<oid> <type> <size>` or `<oid> missing`.
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                truncated = Some("git cat-file ended early".to_string());
                break 'chunks;
            }
            let mut fields = header.split_whitespace();
            let (_oid, kind, size) = (
                fields.next().unwrap_or(""),
                fields.next().unwrap_or(""),
                fields.next().and_then(|s| s.parse::<u64>().ok()),
            );
            let Some(size) = size else {
                continue; // `missing` or malformed — nothing follows
            };
            // The size field is repository data: never allocate past the cap.
            // Oversized or non-blob content is drained, not stored.
            let mut body = (&mut reader).take(size + 1); // +1 trailing NL
            if kind == "blob" && size <= MAX_BLOB_BYTES && total + size <= MAX_TOTAL_BYTES {
                let mut bytes = Vec::with_capacity(size as usize);
                if body.read_to_end(&mut bytes).is_err() {
                    truncated = Some("git cat-file read failed".to_string());
                    break 'chunks;
                }
                bytes.truncate(size as usize); // drop the trailing NL
                total += size;
                if let Ok(text) = String::from_utf8(bytes) {
                    blobs.push(HistoryBlob {
                        oid_short: oid.chars().take(12).collect(),
                        path: path.clone(),
                        text,
                    });
                }
            } else {
                if std::io::copy(&mut body, &mut std::io::sink()).is_err() {
                    truncated = Some("git cat-file read failed".to_string());
                    break 'chunks;
                }
                if total + size > MAX_TOTAL_BYTES && truncated.is_none() {
                    truncated = Some(format!(
                        "git history truncated at {MAX_TOTAL_BYTES} bytes"
                    ));
                    break 'chunks;
                }
            }
        }
    }
    drop(stdin);
    let _ = child.wait();

    Ok(HistoryScan { blobs, truncated })
}
