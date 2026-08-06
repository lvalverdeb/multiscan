# MultiScan

**Unified security scanning in a single static binary.**

MultiScan scans a repository, container image, or authorized web target with several built-in detection engines, merges their output into one deduplicated `Finding` set, ranks it by *exploitability* rather than raw CVSS, and exits with a policy-driven status code.

```sh
multiscan scan . --fail-on 80 --format sarif > results.sarif
```

One binary, no runtime dependencies, no daemon, no telemetry.

## Why

Most teams run five scanners with five vocabularies, five output formats, and five opinions about severity. MultiScan replaces that with:

- **One `Finding` model.** Every engine — and every imported external report — normalizes into the same schema, then deduplicates across engines. One weakness, one Finding.
- **Risk over CVSS.** Scores combine severity with exploit likelihood (EPSS, CISA KEV), exposure, and confidence, and every score ships with a human-readable explanation (`multiscan explain <id>`).
- **Deterministic output.** Same inputs produce byte-identical output. CI verifies this with a 100-run byte-compare; it is a correctness property, not a nicety.
- **CI-friendly gating.** Distinct exit codes for "policy failed" vs. "scanner broke", baseline-aware delta gating, SARIF/SBOM export.
- **Offline by construction.** Advisory data is cached in pinned, exportable snapshots; `--offline` runs fully air-gapped, including signed bundle export/import.

### The core principle

> **Embed the engines. Consume the community data.**

MultiScan writes fast Rust executors but does not author vulnerability knowledge. Advisories come from [OSV](https://osv.dev) (aggregating GHSA, PyPA, RustSec, and others), exploit-likelihood data from [EPSS](https://www.first.org/epss/) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and rules from community-maintained corpora in their published formats. A new CVE ships as a **data refresh**, never a code release.

## Engines

| Engine | What it does |
|---|---|
| `sca` | Lockfiles, manifests, and OS packages → purl → OSV advisory matching, with per-ecosystem version semantics (semver, PEP 440, Maven, RubyGems, Composer, …). Covers Rust, JavaScript (npm/yarn/pnpm), Python (pip/uv/poetry), Go, Ruby, PHP, and Java (Maven/Gradle); a manifest is parsed only when no lockfile shadows it |
| `secrets` | Provider rules (a versioned pack) + entropy + fingerprints. Built-in noise handling keeps lockfiles/IDE/minified files quiet by default; optional `--history` also scans git-history blobs. Secret *values* are never persisted or printed — type, location, and truncated fingerprint only |
| `iac` | Terraform HCL / Kubernetes YAML-JSON / Dockerfile → data-driven policy evaluation (CIS-mapped) |
| `probe` | Declarative HTTP templates against **authorized** web targets (limited DAST). Templates are data — no scripting, no code execution |
| `sast` | Scaffold only in v1 (structural hashing; no rules yet) |
| `bridge` | Importers for external scanner output (Trivy, Semgrep, Checkov, ZAP, generic SARIF) with cross-engine dedup |

## Quick start

```sh
# Build (Rust ≥ 1.85)
cargo build --release
# → target/release/multiscan

# Scan the current repo
multiscan scan .

# Scan an OCI image
multiscan scan image alpine:3.20

# Gate a CI pipeline: fail only on new Findings at or above the threshold
multiscan scan . --fail-on high --baseline .multiscan/baseline.json --format sarif > results.sarif

# Probe a web target you are authorized to test
multiscan authorize create --help
multiscan scan web https://staging.example.com --authorization auth.json

# Keep advisory data fresh / go air-gapped
multiscan db update
multiscan db export bundle.msdb   # signed bundle for offline import
```

Other commands: `import` (ingest external scanner output), `report` (re-render stored Findings), `explain <FINDING_ID>` (full score breakdown), `diff <BASELINE>`, `suppress add|list|expire`, `rules list|validate|pin`, `completions <SHELL>`.

New to MultiScan? **[GETTING_STARTED.md](GETTING_STARTED.md)** walks from install to a gated CI scan, step by step.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; no Finding met `--fail-on` |
| 1 | Scan completed; gate threshold met (the normal CI failure) |
| 2 | Usage error (bad flags, bad config) |
| 3 | Scan error or partial completion (an engine failed) |
| 4 | Authorization denied or missing |
| 5 | Feed data unavailable or too stale under `--offline` |

Codes 1 and 3 are never conflated: "you have vulnerabilities" and "the scanner broke" stay distinguishable.

Machine formats (`json`, `jsonl`, `sarif`, `sbom`) go to stdout with nothing interleaved; all progress and diagnostics go to stderr.

## Configuration

`multiscan.toml`, discovered upward from the scan root. Flags override file values; file values override defaults.

```toml
[scan]
layers = ["sca", "secrets", "iac"]
profile = "standard"            # quick | standard | thorough
exclude = ["vendor/**", "**/testdata/**"]   # globs, all layers

# Per-layer overrides extend the global exclude for one layer only.
[scan.secrets]
exclude        = ["fixtures/**"]   # skip these files in the secrets layer
entropy_exclude = ["*.snap"]       # silence only the entropy heuristic here
history        = false             # opt-in: also scan git-history blobs

[gate]
fail_on = 80.0
baseline = ".multiscan/baseline.json"

[feeds]
max_age = "7d"

[[suppress]]
finding_id = "a3f9c1e0..."
justification = "Vendored test fixture, not shipped"
approver = "sec-team"
expires = "2026-11-01"
```

Suppressions require a justification, an approver, and an expiry — permanent suppression does not exist.

## Safety model

- **No destructive checks.** The `NetworkImpact` type has exactly two variants — `ReadOnly` and `ActiveSafe`. No exploit code, no DoS, no brute-forcing; this is enforced by the type system, not by policy.
- **No unauthorized probing.** Every request to a remote scan target passes through `multiscan-scope`, which requires a signed `ScopeAuthorization`. There is no bypass flag.
- **No telemetry.** Feed fetches are the only outbound traffic, and `--offline` disables them.
- **Memory-safe.** `unsafe_code = "forbid"` across every first-party crate. Untrusted-input parsers (lockfiles, tar layers, HCL, SARIF) are bounded and fuzzed.

## Workspace layout

```
crates/
  multiscan/           Binary: clap, config resolution, rendering, exit codes
  multiscan-core/      Finding, Asset, Severity, IDs — generated from schemas/, no I/O
  multiscan-engine/    Engine trait, manifests, FindingSink, registry
  multiscan-scope/     Authorization, DNS re-check, rate control
  multiscan-feeds/     OSV/EPSS/KEV cache, snapshots, air-gap bundles
  multiscan-dedup/     finding_id, merge, structural_hash (pure)
  multiscan-risk/      Scoring + explanations (pure)
  multiscan-store/     Store trait + SQLite implementation
  multiscan-report/    table / json / jsonl / sarif / sbom / markdown
  engines/             sca, secrets, iac, probe, sast, bridge
schemas/               JSON Schemas — the source of truth for core types
rules/                 Bundled rule packs
testdata/              Golden corpus, scoring vectors, isolated lab fixtures
fuzz/                  cargo-fuzz targets for untrusted-input parsers
```

## Development

The normative spec is [`MULTISCAN-SDD-v1.0.md`](MULTISCAN-SDD-v1.0.md); contributor conventions are in [`CLAUDE.md`](CLAUDE.md). Read the spec's §0.1 before your first change — when spec and code disagree, the code is wrong.

```sh
cargo xtask gen          # regenerate types from schemas/ (after any schema edit)
cargo test --workspace
cargo xtask golden       # golden corpus diff
cargo xtask determinism  # 100-run byte-compare
cargo xtask safety       # scope/authorization negative tests
cargo xtask offline      # sandboxed no-network verification
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

`cargo xtask safety` and `cargo xtask determinism` are mandatory before any change under `multiscan-scope/`, `multiscan-dedup/`, `multiscan-risk/`, or `engines/multiscan-probe/`.

## License

[MIT](LICENSE)

## Status

Pre-release (`0.1.0`). The foundation, all local engines (SCA, secrets, IaC), feeds, reporting (SARIF, SBOM, markdown), storage, baselines/suppressions, and external-scanner bridges are implemented; OCI image scanning is in progress. The `sast` engine is a v2 scaffold and ships no rules in v1.
