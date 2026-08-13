# Changelog

## Unreleased

### Breaking

- **Findings whose advisory names its CVE outside `aliases` change
  `finding_id`.** The canonical vulnerability id now reads `aliases`, then
  `upstream`, then `related` — distro advisories almost never populate
  `aliases` (674 of 695 sampled openSUSE records name their CVE in `related`,
  none in `aliases`), so an OS package finding keyed on its distro advisory id
  and never merged with another source reporting the same weakness. **61
  advisory records across the mirrored lockfile ecosystems also move**
  (18 Packagist, 10 each PyPI and crates.io, 9 Go, 7 npm, 5 Maven, 2 RubyGems):
  baselines and `finding_id` suppressions referencing them stop matching, and
  those findings re-appear as new once. Rule- and path-scoped suppressions are
  unaffected, scores are unchanged, and stored findings are never rewritten.
  Migration note: `docs/identity-migrations.md` (ADR 0023).
- `Advisory` gained `related` and `upstream` fields, which breaks exhaustive
  construction.

### Added

- **`[feeds] osv_ecosystems`** replaces the default OSV mirror set, for
  operators who will not spend the disk on every distro. Base ecosystem names
  only — a release-qualified name is refused with an explanation, because each
  base bucket already carries every release (ADR 0022).
- **`multiscan db status` reports skipped ecosystems.** An ecosystem that could
  not be fetched is now recorded in the snapshot manifest with its reason,
  rather than being indistinguishable from one that carried no advisories.

### Fixed

- **OS package findings work at all.** `db update` mirrored only the eight
  lockfile ecosystems, so `multiscan scan image` resolved every installed
  package against an advisory set that contained no distro data: package counts
  were reported, findings were not, and the engine returned `Complete` because
  nothing had failed. FR-002 has been inert for images since the parsers
  shipped. The default mirror set now carries Debian, Ubuntu, Alpine, Red Hat,
  Rocky, AlmaLinux, openSUSE, SUSE, Chainguard, Wolfi, Azure Linux, openEuler,
  and Mageia (ADR 0022). **This adds roughly 900 MB of download and ~4 GB of
  cache**; `[feeds] osv_ecosystems` trims it.
- **Ubuntu and RHEL images now match their advisories.** OSV spells these
  releases `Ubuntu:22.04:LTS` and `Red Hat:enterprise_linux:9::appstream`,
  where an image reports `22.04` and `9.3`; the matcher compared ecosystem
  strings for equality, so those two — between them most of the installed
  base — would have matched nothing even with the feed data present. Both
  sides now normalize to a distro key. Ubuntu Pro advisories deliberately do
  not match a plain release: their fix requires a subscription (ADR 0022).
- **OS package findings carry their CVE**, so KEV/EPSS enrichment has something
  to look up and factor X no longer falls back to its default on every one of
  them. See the identity change above (ADR 0023).
- A scan now loads only the advisory files it can match against, instead of
  every ecosystem in the snapshot. Without this the larger default set would
  put NFR-003 (500 MB peak RSS) out of reach.
- One unreachable ecosystem no longer aborts `db update`, costing the operator
  the other twenty.

- **The entropy fallback no longer floods on source code.** Long identifiers
  (`test_parquet_reader_supports_lazy_dask`, `PafActionsTrackerCube`,
  `MAGIC_NUMBER_WELL_KNOWN_PORTS`) and filesystem paths clear 4.0 bits/symbol
  as easily as a key does, and the candidate charset includes the `_`, `-`
  and `/` that join them. A real 15-package workspace reported 697
  `high-entropy-string` findings, ~97% of them identifiers, with the
  credentials it genuinely contained buried among them; the same scan now
  reports 20, with nothing left to bury them. Precise provider rules are
  unchanged (ADR 0021).
- **An exclude glob ending in `/` now excludes that directory** instead of
  silently matching nothing. `.venv/`, `.mypy_cache/`, `*.egg-info/` is the
  spelling every ignore file uses, and configs written that way were dead —
  a whole `[scan] exclude` list could be inert with no diagnostic. A trailing
  `/` now compiles to the directory itself plus everything beneath it
  (CLI-007).

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
