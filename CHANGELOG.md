# Changelog

## 0.3.0 — 2026-08-10

### Breaking

- **Minimum supported Rust version is now 1.95** (was 1.85). `cargo install
  multiscan` will fail on older toolchains. The phase-2 source parsers require
  it: `ruff_python_parser` declares 1.95 and `swc_ecma_parser` needs 1.88
  transitively, and every maintained alternative was measured and rejected
  (ADR 0015, superseding ADR 0001).
- **`risk_score` uses a six-factor formula**, `formula_version` `1` → `2`.
  Findings stored under version 1 keep their scores and stay valid — nothing is
  silently rewritten. **Users with no reachability signal see no score change**:
  the new factor is exactly neutral in that case, so rankings are preserved.
  Migration note: `docs/scoring-migrations.md` (ADR 0017).
- Several public types gained fields or variants and will break exhaustive
  construction or matching: `ScoreFactors::reachability`,
  `ScoringInputs::reachability`, `FeedSources::sast_rules_url`,
  `bridge::Format::{CycloneDx, Spdx}`, `sast::pattern::PatternNode::Sequence`.
  `matcher::for_each_match` now returns `MatchStats`.

### Added

- **SAST is a working engine.** Structural pattern matching over Python and
  JavaScript/TypeScript using the `MS-PAT-1` subset of Semgrep syntax
  (ADR 0014), with rules delivered as data over the feed channel. There is no
  embedded corpus by design — MultiScan consumes community rules, it does not
  author them — so the layer is inert until a pack is configured via
  `[rules] sast_pack` and `sast_rules_url`.
- **`cargo xtask translate-rules`** converts a community Semgrep corpus into an
  `MS-PAT-1` pack. The licence check is blocking, and the upstream licence text
  and copyright notice are carried in the pack's provenance.
- **Module-level reachability** as risk factor R: whether first-party source
  imports an affected package at all. Three-state — `Referenced`,
  `NotReferenced`, `Unknown` — where `Unknown` is neutral, never pessimistic.
  Not a dataflow claim; `explain` says *module-level* every time.
- **`--freshness`**: opt-in OSV API query for advisories newer than the pinned
  snapshot. Off by default, mutually exclusive with `--offline`, and it sends
  only package coordinates already public in a lockfile (ADR 0020, resolving
  Q-01).
- **NuGet ecosystem support** with a real `NuGetVersion` comparator, plus
  `Pipfile.lock` (pipenv).
- **CycloneDX and SPDX importers**, completing the §7.6 required set.
- `multiscan explain` shows the reachability determination and its evidence.

### Fixed

- **A 203-byte TypeScript file could hang a scan indefinitely.** `swc`'s
  TypeScript grammar backtracks exponentially; parsing is now bounded by a
  worker-thread timeout, and a language that repeatedly times out is abandoned
  for the rest of the scan. The upstream bug is contained, not fixed —
  reproducers and measurements in `testdata/corpus/sast-pathological/`
  (ADR 0018).
- Feed-cache-dependent behaviour in the `exclude` integration tests, which
  passed locally and would have failed on a clean machine.

### Known limitations

- TypeScript parsing of adversarial input is contained by a timeout rather than
  fixed upstream; a repository deliberately containing such files will produce
  a `Partial` scan for those files.
- Symbol-level reachability is deferred until a symbol-rich ecosystem joins the
  language set; module-level is weaker evidence and is scored accordingly.
- Native SAST findings and imported Semgrep findings for the same upstream rule
  do not merge — the Bridge cannot compute our structural hash from a JSON
  report.

## 0.2.1 and earlier

See the git history; this changelog starts at 0.3.0.
