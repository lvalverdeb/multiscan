# multiscan

The `multiscan` binary: argument parsing, config resolution, rendering dispatch, exit codes (spec §4).

This is the crate to `cargo install`. It was renamed from `multiscan-cli` so the crates.io name matches the binary (ADR 0003).

**Kept deliberately thin.** All real behaviour lives in the library crates — this crate parses flags, resolves config (flags > file > defaults, spec §4.5), wires the pipeline together, and maps outcomes to exit codes. It is the only crate allowed to use `anyhow`; libraries return typed errors.

## Commands

`scan` (path, `image`, or authorized `web` target) · `import` (external scanner output via a Bridge) · `report` · `explain` · `diff` · `suppress` · `db` (update/status/export/import/path) · `rules` · `authorize` (create/verify/show) · `completions` · `manpage`.

## Exit codes (spec §4.4, CLI-005)

| Code | Meaning |
|---|---|
| 0 | Scan completed; no Finding met `--fail-on` |
| 1 | Gate threshold met — the normal CI failure |
| 2 | Usage error (bad flags, bad config) |
| 3 | Scan error or partial completion (an Engine failed) |
| 4 | Authorization denied or missing (SEC-001) |
| 5 | Feed data unavailable or too stale under `--offline` |

Code 3 is never conflated with 1: a CI pipeline must be able to distinguish "you have vulnerabilities" from "the scan broke".

## Output discipline

Machine output goes to **stdout, alone**. Progress, warnings, and diagnostics go to stderr (CLI-001). A stray `println!` anywhere in the pipeline breaks every `--format json` consumer — renderers return strings, and only this crate prints them.

Normative reference: `MULTISCAN-SDD-v1.0.md` §4.
