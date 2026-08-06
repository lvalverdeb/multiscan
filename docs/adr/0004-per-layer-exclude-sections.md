# ADR 0004: Per-layer `[scan.<layer>] exclude` config sections

- Status: Accepted
- Date: 2026-08-06
- Deviates from: `MULTISCAN-SDD-v1.0.md` §4.5, whose config sample shows only
  a global `[scan] exclude` list. This ADR adds sections the spec does not
  define; it removes or changes nothing the spec does define.

## Context

A single global exclude list is the wrong shape for lockfiles. `uv.lock` /
`Cargo.lock` / `package-lock.json` are exactly what the sca layer must read —
they are the dependency manifests — while for the secrets layer they are pure
noise: a real-world scan of a Python workspace produced 1,586 findings, all
false positives of `high-entropy-string`, 1,550 of them package-checksum URLs
inside `uv.lock`. With only `[scan] exclude`, users must choose between
drowning the secrets report and blinding dependency scanning.

## Decision

`ScanConfig` gains three optional per-layer override sections — `[scan.sca]`,
`[scan.secrets]`, `[scan.iac]` — each carrying an `exclude` glob list
(`LayerScanConfig` in `schemas/config.json`). Semantics:

- The global `[scan] exclude` applies to every layer.
- A layer's list **extends** the global list for that layer's engines only.
- Patterns match the root-relative POSIX path (DET-005); a pattern matching a
  directory path prunes the walk beneath it.
- Globs are compiled once at config resolution (`PathFilter::from_config` in
  `multiscan-engine`); an invalid pattern is a config error, exit 2, naming
  the pattern and section. Engines receive the compiled filter via
  `ScanContext.excludes` and MUST consult it during file discovery.
- The `--exclude` flag overrides the file's **global** list (spec 4.5
  precedence). Per-layer lists have no flag and always apply.

Only file-walking layers get a section: `probe` targets URLs, not paths, and
`sast` is a v1 scaffold with no rules (NG-2). Writing `[scan.probe]` or
`[scan.sast]` is a config error today; a `[scan.sast]` section can be added
compatibly when v2 lands.

The sca layer's exclude also governs `resolve_inventory`, so a CycloneDX SBOM
never inventories a lockfile the scan was told not to read.

## Alternatives considered

- **Per-rule path suppressions** (`[[suppress]] rule_id + path`): richer, but
  suppression hides findings after detection — the excluded files would still
  be walked and hashed, and CLI-006's justification/approver/expiry ceremony
  is wrong for "this file class is never a secret". Complementary, not a
  substitute; may still land separately.
- **Secrets-engine built-in lockfile awareness**: desirable defaults, but a
  heuristic change with golden-corpus impact; orthogonal to giving users an
  explicit, committable control. Tracked separately.
