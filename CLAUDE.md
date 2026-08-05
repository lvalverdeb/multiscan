# CLAUDE.md — MultiScan CLI

Guidance for Claude Code and other coding agents working in this repository.
Keep this file short. Detail belongs in the spec; this file covers what you can't infer from it.

---

## What this is

A single static Rust binary that scans a repo, image, or authorized web target with built-in engines, merges the results into one deduplicated `Finding` set, ranks by exploitability rather than CVSS, and exits with a policy-driven status code.

**The core principle: embed the engines, consume the community data.** We write fast Rust executors. We do not author or maintain vulnerability knowledge — that comes from OSV, EPSS, KEV, and community rule corpora. A new CVE ships as a data refresh, never a code release. If a task feels like "curate advisories" or "write our own CVE database," you have misread it.

---

## Source of truth, in order

1. `MULTISCAN-SDD-v1.0.md` (SDD-MULTISCAN-001) — the spec. **Normative.** Read §0.1 before your first change.
2. `schemas/*.json` — types in `multiscan-core` are generated from these.
3. This file — workflow and Rust-specific conventions.
4. Tests, then code comments.

Spec and code disagreeing means the code is wrong, unless an ADR in `docs/adr/` says otherwise. Never edit the spec to match code you just wrote.

---

## Non-negotiables

Release-blocking. No workarounds, no bypass flags, no `#[cfg(test)]` escape hatches outside the designated fakes.

| | Rule |
|---|---|
| 1 | **`#![forbid(unsafe_code)]` in every first-party crate.** No exceptions. If a dependency forces unsafe, wrap it or drop the dependency. `NFR-009`. |
| 2 | **Every request to a scan target goes through `multiscan-scope`.** No bare `reqwest::get`, no direct `TcpStream`, anywhere outside that crate. Feed downloads are a separate allow-listed path in `multiscan-feeds`. `SEC-001..009`. |
| 3 | **`NetworkImpact` has exactly two variants: `ReadOnly` and `ActiveSafe`.** Never add `Destructive`. The type system is how NG-1 is enforced. |
| 4 | **`multiscan-core`, `multiscan-dedup`, `multiscan-risk` have zero I/O dependencies.** No tokio, no reqwest, no `std::fs`, no `SystemTime`. CI enforces this. `§5.2`. |
| 5 | **Secret values are never persisted or printed.** Type, location, truncated fingerprint only. `SEC-101`. |
| 6 | **Machine output goes to stdout, alone.** Progress, warnings, diagnostics → stderr. A stray `println!` in an engine breaks every CI consumer. `CLI-001`. |
| 7 | **Exit code 3 ≠ exit code 1.** "You have vulnerabilities" and "the scanner broke" must stay distinguishable. `CLI-005`. |

If a task seems to require breaking one of these, stop and ask. Do not improvise.

---

## Determinism — read this before touching dedup, risk, or report

Rust makes non-determinism easy to introduce by accident. These cause real bugs here, not theoretical ones:

- **`HashMap`/`HashSet` iteration order is randomized per process.** Use `BTreeMap`/`BTreeSet`, or `IndexMap` when insertion order is what you want. Anywhere iteration can reach output, this is a hard rule. `DET-001`.
- **Engines run in parallel via rayon; emit order is meaningless.** Sort before rendering: `risk_score` DESC, then `finding_id` ASC. `DET-002`, `CLI-003`.
- **Never `partial_cmp().unwrap()` on floats.** Use `total_cmp`. `DET-003`.
- **No `SystemTime::now()` in `multiscan-dedup` or `multiscan-risk`.** Time is injected through `ScanContext`. `DET-004`.
- **Normalize paths to POSIX, root-relative, before any identity computation.** Windows backslashes must not produce different `finding_id`s. `DET-005`.
- **Locale and `TZ` must not reach machine output.** `DET-006`.

`make test-determinism` runs 100 iterations and byte-compares. One mismatch fails the build.

---

## Vocabulary discipline

Spec §2 is enforced by `make lint-vocab`. Use `Finding`, `Asset`, `Engine`, `Bridge`, `Scan`, `ScanContext`, `Evidence`, `RiskScore`, `Severity`, `RuleSet`, `FeedSnapshot`, `ScopeAuthorization`, `Suppression`, `Baseline`.

Never: `issue`, `alert`, `vuln`, `result`, `plugin`, `adapter`, `scanner` (for our own engines), `PoC`.

This isn't pedantry — the tool exists because five scanners use five vocabularies for the same thing.

---

## Workspace layout

```
crates/
  multiscan/           the binary crate: clap, config resolution, rendering, exit codes. Keep thin. (named `multiscan`, not `multiscan-cli` — ADR 0003)
  multiscan-core/      Finding, Asset, Severity, IDs. Generated. NO I/O.
  multiscan-engine/    Engine trait, manifests, FindingSink, registry.
  multiscan-scope/     Authorization, DNS re-check, rate control.   ← highest-scrutiny crate
  multiscan-feeds/     OSV/EPSS/KEV cache, snapshots, air-gap bundles.
  multiscan-dedup/     finding_id, merge, structural_hash.          ← pure
  multiscan-risk/      Scoring + explanations.                      ← pure
  multiscan-store/     Store trait + SqliteStore.
  multiscan-report/    table/json/jsonl/sarif/sbom/markdown.
  engines/
    multiscan-sca/     Lockfiles + OS packages → purl → OSV.
    multiscan-secrets/ Regex + entropy + fingerprints.
    multiscan-iac/     HCL/YAML/JSON → policy evaluation.
    multiscan-probe/   Declarative HTTP templates (limited DAST).
    multiscan-sast/    v2. Scaffold + structural_hash only. NO RULES IN v1.
    multiscan-bridge/  External scanner importers.
schemas/  rules/  testdata/{corpus,vectors,lab}/  fuzz/  docs/
```

MSRV 1.78, edition 2021. Workspace-level dependency versions only — no per-crate version drift.

---

## Commands

```bash
cargo xtask gen          # regenerate types from schemas/ — after ANY schema edit
cargo build --release
cargo test --workspace
cargo xtask golden       # golden corpus diff (engines + scoring vectors)
cargo xtask determinism  # 100-run byte-compare, DET-007
cargo xtask safety       # scope/authorization negative tests — MUST pass before push
cargo xtask offline      # sandboxed no-network verification, FR-011
cargo fuzz run tar_extract   # release-blocking for image work
cargo deny check         # licenses, advisories, bans
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask bench        # NFR-001..005 gates
```

`cargo xtask safety` and `cargo xtask determinism` are mandatory before any change under `multiscan-scope/`, `multiscan-dedup/`, `multiscan-risk/`, or `engines/multiscan-probe/`.

---

## How to work a task

1. Find the task (`T-nnn`) in spec §15 or the requirement (`FR-nnn`, `SEC-nnn`, `NFR-nnn`, `DET-nnn`).
2. Verify its `deps` are merged. Don't build on unmerged phases.
3. Write the acceptance test from spec §13 first — the Given/When/Then *is* the test.
4. Implement.
5. Reference IDs in code and commits.

```rust
// implements FR-003: PEP 440 ordering differs from semver for pre-releases
```

**Commit:** `[T-202] sca: PEP 440 version matcher (FR-003)`
**PR must state:** requirement IDs satisfied, which §13 criteria now pass, and whether golden corpus output changed and why.

---

## Rust conventions

- **Errors:** `thiserror` for library crates with typed variants; `anyhow` only in the `multiscan` binary crate. Engines return `EngineError`, never `Box<dyn Error>`.
- **No `unwrap`/`expect`/`panic!` outside tests, `xtask`, and `main`.** Clippy denies them in library crates. A malformed lockfile in someone's repo must not abort the scan — it degrades to a warning and `EngineOutcome::Partial`.
- **Cancellation:** every engine checks `ctx.cancel` between units of work and honours `ctx.deadline`. Ctrl-C must produce partial results, not a hang.
- **Allocation:** stream through `FindingSink`; never collect a whole result set in an engine. `NFR-003` is 500 MB on a 1 GB repo.
- **Parsing untrusted input is the threat model.** Lockfiles, tar layers, HCL, SARIF — all attacker-controllable. Bound every allocation by input size, cap recursion depth, cap entry counts.
- **Public API docs** on every `pub` item in library crates; `#![warn(missing_docs)]`.
- Comments explain *why*. Reference requirement IDs for anything non-obvious.
- No `TODO` in merged code — open an issue and reference it.

---

## Adding an engine

1. New crate under `crates/engines/`, `#![forbid(unsafe_code)]`.
2. Implement `Engine`. `applicable()` must be cheap — no file reads, no network.
3. Declare an explicit `severity_map` in the manifest. Inferred or passthrough severity is forbidden (`ENG-004`).
4. `scan()` streams into the sink, honours deadline and cancel, returns `Partial` rather than erroring out on recoverable problems.
5. Add ≥3 golden fixtures to `testdata/corpus/<engine>/`.
6. Map policy IDs to compliance controls, or accept the `mapping_gaps` counter. Unmapped IDs fall back to `native:{engine}:{id}` and **must not** merge with anything.
7. Add a fuzz target if it parses untrusted input.

---

## Things agents get wrong here

- **Naive version comparison.** `"1.10.0" < "1.9.0"` as strings. Each ecosystem has its own ordering — semver, PEP 440, Maven, RubyGems all differ on pre-release and epoch handling. `SCA-002`.
- **Tar extraction without path validation.** Absolute paths, `..`, and symlinks escaping the extraction root. This is the most-exploited surface in image scanners; see RUSTSEC-2026-0148 for a real OCI symlink escape in exactly this category. Reject, cap decompressed size, cap entry count, and fuzz it. `SCA-005`.
- **`HashMap` in an output path.** See determinism above. This one slips through review constantly.
- **Closing findings on a `Partial` outcome.** Only `Complete` can close. `§7.7.4`, `FR-015`.
- **Nulling a risk score when enrichment is missing.** Every factor has a documented default; record it in `score_explanation.defaults_applied`. `RSK-002`.
- **Printing progress to stdout.** Breaks `--format json`. Everything non-machine goes to stderr.
- **Following redirects out of scope** in `multiscan-probe`. `SEC-005`.
- **Adding scripting to probe templates.** Templates are data. No eval, no shell-out, no code execution. `PRB-001`.
- **Writing SAST rules.** v1 ships the scaffold and `structural_hash` only. Taint analysis is permanently out of scope. `NG-2`.
- **Editing generated code.** Edit `schemas/`, run `cargo xtask gen`.

---

## Testing rules that bite

- **Golden corpus churn is a reviewable event.** Explain every diff line in the PR. Silent churn is how normalization quality rots.
- **Dedup needs adversarial pairs.** For every merge case, add a near-miss that must not merge. False-merge and false-split are tracked separately; they trade off.
- **Scoring changes need a `formula_version` bump** and a migration note. Never mutate stored scores silently. `RSK-004`.
- **Never point a test at a real host.** Only `testdata/lab/` fixtures on an isolated network, or recorded responses. Not "just once to check" — not ever.
- **`--offline` tests run under a network-denying sandbox** that fails on any network syscall. `FR-011`.

---

## When to stop and ask

Per spec R-7: when the spec is ambiguous, **do not guess**. Add the question to §17, implement the most conservative option, flag it in the PR.

Always stop and ask, rather than deciding, when a change would:

- add any path that reaches a scan target without going through `multiscan-scope`
- introduce a flag, env var, or config key that relaxes authorization (`SEC-009` — reviewers must reject these outright)
- add `unsafe`, or a dependency that requires it
- alter `finding_id` construction (this invalidates every user's history and baselines)
- add I/O to `multiscan-core`, `multiscan-dedup`, or `multiscan-risk`
- make `multiscan-probe` capable of non-idempotent requests outside `thorough` + explicit authorization
- add network access from `applicable()`
- widen SAST beyond structural matching toward taint analysis

# Claude Configuration Override
- Never append co-author credits, attribution lines, or footers to git commits.
- Force `gitAttribution` and `includeCoAuthoredBy` to false.

