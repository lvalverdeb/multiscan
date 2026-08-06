# ADR 0009: Ignore-file support (`.multiscanignore`, opt-in `.gitignore`)

- Status: Accepted
- Date: 2026-08-06
- Extends: `MULTISCAN-SDD-v1.0.md` §4.5 / §7 file discovery. Adds ignore-file
  filtering and one config key; the exclude mechanism (ADR 0004) is unchanged.

## Context

Skipping obvious non-source directories (`.idea/`, `.venv/`, `cache/`,
`logs/`) required an explicit `exclude` list in `multiscan.toml`. Repositories
already encode most of this in a `.gitignore`. A ripgrep-style "honor the
ignore files" behavior would give near-zero-config filtering.

But a security scanner is not a code search tool. **The files a developer
gitignores are disproportionately the ones a secrets scan must see** — `.env`,
`credentials.json`, `*.pem`, `id_rsa`. Honoring `.gitignore` by default would
silently blind the highest-value part of the scan.

## Decision

Two ignore sources, with deliberately different defaults:

- **`.multiscanignore`** (scan root, gitignore syntax) is **always honored**.
  It is multiscan-specific: a user who writes one is explicitly choosing what
  the scanner skips. This is the recommended near-zero-config path.
- **`.gitignore`** (scan root) is honored **only when
  `[scan] respect_gitignore = true`**. Default off — fail-safe for a security
  tool. Users who accept the trade-off (or scan non-secret layers) opt in.

Matching is a focused gitignore subset compiled onto `globset`
(`ignorefile.rs` in `multiscan-engine`): comments, blank lines, `!` negation
(last match wins), trailing-slash directory-only rules, leading-slash /
embedded-slash anchoring, and `*`/`?`/`**` globs. `.multiscanignore` rules are
applied after `.gitignore`, so a `!` there can re-include something gitignore
excluded. Rules live on the same `PathFilter` the engines already consult, so
ignore matching rides the existing walk and prunes ignored directories.

Ignore matching is **convenience filtering, not a security boundary**: it
applies to every layer uniformly, but the load-bearing skips (VCS/vendor dirs)
and the security-relevant defaults remain independent of any ignore file.

## Consequences

- Zero-config-ish filtering via one committed `.multiscanignore`.
- The default scan still sees gitignored files — no silent secret blindness.
- Only the root ignore files are read (not nested per-directory `.gitignore`);
  as in git, pruning an ignored directory also skips its contents, so a `!`
  re-include under an ignored directory does not resurrect it. Nested ignore
  files can be added later without changing this contract.
