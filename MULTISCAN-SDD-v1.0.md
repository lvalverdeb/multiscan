---
doc_id: SDD-MULTISCAN-001
title: MultiScan CLI — Unified Security Scanning in a Single Binary
version: 1.0.0
status: Draft
date: 2026-08-05
audience: [human-engineers, llm-coding-agents]
normative_keywords: RFC-2119 (MUST / MUST NOT / SHOULD / SHOULD NOT / MAY)
language: Rust (2021 edition, MSRV 1.78)
---

# 0. How to Use This Document

## 0.1 Rules of engagement for LLM agents

| Rule | Statement |
|---|---|
| R-1 | Vocabulary in §2 is locked. Never write `issue`, `alert`, `vuln`, `result`, `plugin`. |
| R-2 | Requirement IDs (`FR-nnn`, `NFR-nnn`, `SEC-nnn`, `CLI-nnn`) are stable. Reference them in code and commits. |
| R-3 | **[NORMATIVE]** sections bind. **[INFORMATIVE]** sections are rationale. |
| R-4 | Types are generated from `schemas/*.json` into `multiscan-core`. Do not hand-write divergent structs. |
| R-5 | Determinism is a correctness property, not a performance nicety. See §14. |
| R-6 | Any code path issuing a request to a remote *scan target* goes through `multiscan-scope`. Feed downloads are a separate, allow-listed path. |
| R-7 | When the spec is ambiguous, do not guess. Log it in §17 and pick the most conservative option. |

---

# 1. Purpose, Scope, Non-Goals [NORMATIVE]

## 1.1 Product definition

MultiScan is a **single static binary** that scans a repository, image, or authorized web target with several built-in detection engines, merges their output into one deduplicated `Finding` set, ranks it by exploitability rather than CVSS, and exits with a policy-driven status code.

```
multiscan scan . --fail-on 80 --format sarif > results.sarif
```

## 1.2 The core principle [NORMATIVE]

> **Embed the engines. Consume the community data.**

MultiScan writes fast Rust executors. It does NOT author or maintain vulnerability knowledge. Advisory data comes from OSV (which aggregates GHSA, PyPA, RustSec, and others), exploit-likelihood data from EPSS and CISA KEV, and rule content from community-maintained rule corpora in their published formats.

Consequence: a new CVE requires a **data refresh**, never a code release.

## 1.3 Personas [INFORMATIVE]

| Persona | Primary need | Design implication |
|---|---|---|
| Developer | Fast local feedback, low noise | Cold scan of a mid-size repo < 10 s; default profile hides `informational` |
| CI pipeline | Deterministic gate, machine output | Exit codes (§4.4), SARIF export, `--baseline` for delta-only gating |
| Auditor / consultant | Offline operation, evidence, history | `--offline` mode, portable DB export, SQLite store behind a trait |

## 1.4 Non-goals [NORMATIVE — do not implement]

| ID | Non-goal |
|---|---|
| NG-1 | No exploit code, no destructive checks, no DoS, no credential brute-forcing, no lateral movement. |
| NG-2 | No interprocedural taint/dataflow analysis. SAST is structural pattern matching only (v2 scope). |
| NG-3 | No web crawler, no authenticated session handling, no active DAST beyond declarative template probes (§7.4). Deep web testing means exporting to ZAP or Burp. |
| NG-4 | No daemon, no server, no scheduler, no web UI. If it needs to run continuously, it is out of scope. |
| NG-5 | No scanning of any remote target without a `ScopeAuthorization` (§9). No `--force`, no `--yolo`, no bypass. |
| NG-6 | No telemetry, no phone-home. Feed fetches are the only outbound traffic, and `--offline` disables them. |

---

# 2. Canonical Glossary [NORMATIVE]

| Term | Definition | Forbidden synonyms |
|---|---|---|
| `Asset` | Discrete scannable entity: repo, file, image, package, endpoint. | resource, target, entity |
| `Engine` | A built-in Rust detection module (§6). | plugin, adapter, scanner, module |
| `Bridge` | Importer for an external scanner's output file (§7.6). | adapter, connector |
| `Scan` | One `multiscan scan` invocation. | job, run |
| `ScanContext` | Immutable inputs to a Scan: root path, config, profile, feeds snapshot, authorization. | config, opts |
| `Finding` | One normalized, deduplicated observation. | issue, alert, vuln, result |
| `Evidence` | Non-destructive proof attached to a Finding. | PoC, exploit |
| `RiskScore` | f64 in 0.0–100.0 per §8. | priority, severity |
| `Severity` | Ordinal `Informational｜Low｜Medium｜High｜Critical`. Always derived. | criticality |
| `RuleSet` | Versioned, content-addressed corpus of rules or templates. | ruleset file, policies |
| `FeedSnapshot` | Pinned advisory/enrichment dataset with an `as_of` timestamp. | database, feed |
| `ScopeAuthorization` | Signed record permitting probing of named remote targets. | permission, allowlist |
| `Suppression` | Time-bounded, justified hiding of a Finding. | ignore, mute |
| `Baseline` | A prior Finding set used for delta gating. | snapshot, previous |

---

# 3. Design Principles [INFORMATIVE]

| ID | Principle | Consequence |
|---|---|---|
| P-1 | Embed engines, consume community data. | New CVEs ship as data (§10), not releases. |
| P-2 | One weakness, one Finding. | Dedup (§7.7) is core, not report formatting. |
| P-3 | Context beats CVSS. | Risk score multiplies severity by exploitability, exposure, confidence (§8). |
| P-4 | Deterministic or it's a bug. | Same inputs ⇒ byte-identical output. Enforced in CI (§14). |
| P-5 | Fast enough to run on save. | Cold-scan budget in NFR-001; engines stream into a sink, never buffer whole result sets. |
| P-6 | Offline-capable by construction. | Every network dependency has a cached, exportable form. |
| P-7 | Authorization is a hard gate. | Remote probing requires a signed authorization; no bypass flag exists. |
| P-8 | Store behind a trait. | SQLite today; a server backend later is a new impl, not a rewrite. |

---

# 4. CLI Surface [NORMATIVE]

## 4.1 Commands

```
multiscan scan [PATH]              Scan a local path (default: .)
multiscan scan image <REF>         Scan an OCI image by reference or digest
multiscan scan web <URL>           Template-probe an authorized web target
multiscan import <FILE>            Ingest external scanner output via a Bridge (§7.6)
multiscan report                   Re-render stored Findings in another format
multiscan explain <FINDING_ID>     Full score breakdown, evidence, remediation
multiscan diff <BASELINE>          Delta against a baseline Finding set
multiscan suppress <SUBCOMMAND>    add | list | expire
multiscan db <SUBCOMMAND>          update | status | export | import | path
multiscan rules <SUBCOMMAND>       list | validate | pin
multiscan authorize <SUBCOMMAND>   create | verify | show
multiscan completions <SHELL>      Shell completion script
```

## 4.2 Core flags

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--layers` | csv | auto-detect | `sca,secrets,iac,sast,probe` |
| `--profile` | enum | `standard` | `quick｜standard｜thorough` |
| `--format` | enum | `table` | `table｜json｜jsonl｜sarif｜sbom｜markdown` |
| `--fail-on` | number \| severity | none | Exit 1 if any Finding meets threshold |
| `--baseline` | path | none | Gate only on new Findings |
| `--offline` | bool | false | No network; fail loudly if feeds are stale beyond `--max-feed-age` |
| `--max-feed-age` | duration | `7d` | Warn/fail on stale advisory data |
| `--min-severity` | enum | `low` | Display filter, not a gate |
| `--config` | path | `./multiscan.toml` | §4.5 |
| `--authorization` | path | none | Required for `scan web` (SEC-001) |
| `--jobs` | int | logical CPUs | Engine parallelism |
| `--no-color`, `--quiet`, `--verbose` | | | `--quiet` implies machine output on stdout only |

## 4.3 Output discipline [NORMATIVE]

- CLI-001 Machine formats (`json`, `jsonl`, `sarif`, `sbom`) MUST go to **stdout** with nothing else interleaved. All progress, warnings, and diagnostics go to **stderr**.
- CLI-002 `table` output MUST degrade gracefully when not a TTY: no ANSI, no spinners, no width-dependent truncation.
- CLI-003 Findings MUST be emitted in a deterministic order: `risk_score` DESC, then `finding_id` ASC. Never rely on iteration order (§14).
- CLI-004 Every Finding row in `table` mode MUST show `finding_id` prefix (12 hex chars) so `multiscan explain` is copy-pasteable.

## 4.4 Exit codes [NORMATIVE]

| Code | Meaning |
|---|---|
| 0 | Scan completed; no Finding met `--fail-on` |
| 1 | Scan completed; gate threshold met (policy failure — the normal CI failure) |
| 2 | Usage error (bad flags, bad config) |
| 3 | Scan error or partial completion (an Engine failed) |
| 4 | Authorization denied or missing (SEC-001) |
| 5 | Feed data unavailable or staler than `--max-feed-age` under `--offline` |

CLI-005: Exit code 3 MUST NOT be conflated with 1. A CI pipeline must be able to distinguish "you have vulnerabilities" from "the scanner broke."

## 4.5 Configuration file

TOML, discovered upward from the scan root. CLI flags override file values; file values override defaults.

```toml
[scan]
layers = ["sca", "secrets", "iac"]
profile = "standard"
exclude = ["vendor/**", "**/testdata/**", "*.min.js"]

[gate]
fail_on = 80.0
baseline = ".multiscan/baseline.json"
ignore_unfixable = false

[risk]
asset_criticality = "high"
data_classification = "sensitive"

[feeds]
max_age = "7d"
offline = false

[rules]
sca_db = "osv@2026-08-05"
iac_pack = "cis-bundle@1.9.0"
secrets_pack = "builtin@2.0.0"

[[suppress]]
finding_id = "a3f9c1e0..."
justification = "Vendored test fixture, not shipped"
approver = "sec-team"
expires = "2026-11-01"
```

- CLI-006 A `[[suppress]]` entry without `justification`, `approver`, and `expires` MUST be a config error (exit 2). Permanent suppression does not exist.
- CLI-007 Config MUST be committable and diff-friendly; no absolute paths, no machine-specific values.

---

# 5. Architecture [NORMATIVE]

## 5.1 Cargo workspace

```
crates/
  multiscan-cli/       Binary. clap parsing, config resolution, output rendering. Thin.
  multiscan-core/      Finding, Asset, Severity, Confidence, IDs. Generated types. NO I/O.
  multiscan-engine/    Engine trait, EngineManifest, FindingSink, registry.
  multiscan-scope/     ScopeAuthorization, target resolution guard, rate control.   ← audit carefully
  multiscan-feeds/     OSV/EPSS/KEV fetch, cache, snapshot pinning, offline export.
  multiscan-dedup/     finding_id construction, structural_hash, merge.             ← pure
  multiscan-risk/      Scoring formula, explanations.                               ← pure
  multiscan-store/     Store trait + SQLite impl. Baselines, history, suppressions.
  multiscan-report/    table / json / jsonl / sarif / sbom / markdown renderers.
  engines/
    multiscan-sca/     Lockfile + OS package resolution → purl → OSV.
    multiscan-secrets/ Regex + entropy + optional verifiers.
    multiscan-iac/     HCL / YAML / JSON policy matching.
    multiscan-probe/   Declarative HTTP template execution (v1 DAST scope).
    multiscan-sast/    tree-sitter structural patterns. [v2 — scaffold only in v1]
    multiscan-bridge/  SARIF / Trivy / Semgrep / Checkov / ZAP output importers.
schemas/             JSON Schema — source of truth for Finding, manifests, config.
rules/               Bundled rule packs (secrets, IaC, probe templates).
testdata/
  corpus/            Golden fixtures per engine.
  vectors/           Scoring golden vectors.
  lab/               Deliberately vulnerable fixtures for recall tests.
```

## 5.2 Dependency rule [NORMATIVE]

`multiscan-core`, `multiscan-dedup`, and `multiscan-risk` MUST have **no I/O dependencies** — no `tokio`, no `reqwest`, no filesystem access. They are pure libraries. This is what makes determinism testable (§14). CI MUST enforce this with a dependency check.

## 5.3 Data flow

```
ScanContext
   │
   ├─► Engine::scan ──┐
   ├─► Engine::scan ──┤ streams raw Findings
   ├─► Engine::scan ──┘
   │                  ▼
   │            multiscan-dedup  (merge, stable IDs)
   │                  ▼
   │            multiscan-feeds  (EPSS / KEV / fix availability enrichment)
   │                  ▼
   │            multiscan-risk   (score + explanation)
   │                  ▼
   │            multiscan-store  (persist, baseline diff, suppressions)
   │                  ▼
   └────────────► multiscan-report ──► stdout + exit code
```

---

# 6. Engine Contract [NORMATIVE]

## 6.1 Trait

```rust
pub trait Engine: Send + Sync {
    fn manifest(&self) -> &EngineManifest;

    /// Cheap static check. MUST NOT touch the network or read file contents.
    fn applicable(&self, ctx: &ScanContext) -> Applicability;

    /// Detection. Streams Findings into the sink; MUST honour ctx.deadline
    /// and MUST check ctx.cancel between units of work.
    fn scan(&self, ctx: &ScanContext, sink: &mut dyn FindingSink) -> Result<EngineOutcome, EngineError>;
}

pub struct EngineManifest {
    pub id: &'static str,                      // "multiscan.sca"
    pub version: &'static str,
    pub finding_classes: &'static [FindingClass],
    pub layers: &'static [Layer],
    pub network_impact: NetworkImpact,         // ReadOnly | ActiveSafe  (no Destructive variant)
    pub requires_authorization: bool,
    pub rule_set: Option<RuleSetRef>,
}

pub trait FindingSink {
    fn emit(&mut self, f: RawFinding) -> Result<(), SinkError>;
    fn progress(&mut self, done: u64, total: Option<u64>);
}

pub enum EngineOutcome {
    Complete { units_scanned: u64 },
    Partial  { units_scanned: u64, reason: String },   // ⇒ exit code 3
}
```

- ENG-001 `NetworkImpact` MUST NOT gain a `Destructive` variant. NG-1 is enforced by the type system.
- ENG-002 An Engine returning `Partial` MUST NOT cause Findings to be closed (§7.7.4) and MUST set process exit to at least 3.
- ENG-003 Engines MUST NOT write to the store, read config directly, or print to stdout. Everything flows through `ScanContext` and the sink.
- ENG-004 Every Engine MUST declare an explicit severity mapping in its manifest. Inferred or passthrough severity is forbidden.

## 6.2 Concurrency

Engines run in parallel on a `rayon` pool bounded by `--jobs`. Within an engine, per-file work parallelizes. The sink is behind a mutex; ordering is **not** guaranteed at emit time and MUST NOT be relied upon (see CLI-003 — sorting happens at render).

---

# 7. Engines [NORMATIVE]

## 7.1 `multiscan-sca` — dependencies and OS packages

**Detection model:** parse manifests/lockfiles → construct purls → resolve against the OSV snapshot → emit `VulnerableDependency` / `ContainerVulnerability`.

Required lockfile support (v1):

| Ecosystem | Files |
|---|---|
| Rust | `Cargo.lock` |
| npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python | `poetry.lock`, `Pipfile.lock`, `requirements.txt` (pinned only), `uv.lock` |
| Go | `go.mod`, `go.sum` |
| Java | `pom.xml`, `gradle.lockfile` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| .NET | `packages.lock.json` |
| OS (images) | dpkg `status`, rpm db, apk `installed` |

- SCA-001 Unpinned dependency declarations MUST be reported as `Informational` with `confidence: Unconfirmed`, never silently skipped.
- SCA-002 Version range matching MUST follow each ecosystem's own semantics (semver, PEP 440, Maven, RubyGems). A shared naive comparator is a defect.
- SCA-003 Transitive dependencies MUST be attributed with a `dependency_path` in `Evidence` so developers know which direct dependency to bump.
- SCA-004 `fixed_version` MUST be the lowest non-vulnerable version satisfying the existing constraint where one exists; otherwise report `fix_available: false`.

**Container images:** pull layers via the OCI distribution API, extract package databases, then reuse the same resolution path.

- SCA-005 **[SECURITY]** Layer extraction MUST reject absolute paths, `..` traversal, and symlinks/hardlinks pointing outside the extraction root, and MUST cap decompressed size and entry count. Tar extraction is the single most-exploited surface in image scanners — see RUSTSEC-2026-0148 for a real OCI symlink-escape in this exact category. Extraction MUST be fuzzed (§14).

## 7.2 `multiscan-secrets`

Regex + Shannon entropy + structural validators, with an opt-in verification step.

- SEC-101 Detected secret **values** MUST NOT be persisted or printed. Store type, location, and a truncated fingerprint only.
- SEC-102 Live verification (checking whether a key is active) MUST be opt-in via `--verify-secrets`, MUST only call the issuing provider's documented validation endpoint, and MUST never call a target discovered from the scanned content.
- SEC-103 Entropy-only detections MUST cap at `Medium` severity and `Heuristic` confidence. The entropy fallback is further bounded by the signal-quality rules (§13.3, FP-001/FP-002): it does not fire on known-noise files or content-address token shapes, and its noise controls never disable the precise provider rules.
- SEC-104 Git history scanning is opt-in (`--history`) and, by default, scans every object reachable from any ref — a committed-then-removed secret may reside in any commit. Bounded by hard blob/size caps, degrading to `Partial` on truncation (ADR 0006); an explicit commit-range/`--since` selector is a permitted future refinement, not a requirement. (Amended by ADR 0011 from the original `--scan-history` + mandatory-commit-range wording.)

## 7.3 `multiscan-iac`

Parse HCL2, YAML (Kubernetes, CloudFormation, Compose), and JSON into a normalized resource tree; evaluate declarative policies against it.

- IAC-001 Policies are data, not code: a policy is `{id, resource_selector, condition, severity, cwe, compliance_controls, remediation}` in the bundled rule pack.
- IAC-002 v1 ships the CIS-mapped core set (~200 policies across AWS/Azure/GCP/Kubernetes/Terraform). Breadth parity with Checkov is a non-goal.
- IAC-003 Unresolvable variables/interpolations MUST degrade to `confidence: Heuristic`, never to a silent pass.
- IAC-004 Every policy MUST carry at least one `compliance_controls` entry or be recorded in the `mapping_gaps` counter.

## 7.4 `multiscan-probe` — declarative HTTP templates (limited DAST)

**Scope-limited by design (NG-3).** Executes declarative templates: request spec + matcher spec. No crawling, no session management, no form inference.

```yaml
id: exposed-env-file
severity: high
cwe: [CWE-200]
requests:
  - method: GET
    path: ["/.env", "/.env.local"]
    matchers:
      - type: status
        values: [200]
      - type: regex
        part: body
        patterns: ["(?m)^[A-Z_]+_(KEY|SECRET|TOKEN)="]
    matchers_condition: and
```

- PRB-001 Templates MUST be declarative data. No embedded scripting, no code execution, no template-controlled shell-out.
- PRB-002 Every request MUST pass `multiscan-scope::authorize()` (§9). No exceptions.
- PRB-003 Only idempotent methods (`GET`, `HEAD`, `OPTIONS`) in `standard` profile. `POST` requires `thorough` **and** an authorization explicitly permitting it.
- PRB-004 Templates MUST NOT include payloads intended to write, delete, or persist state on the target.
- PRB-005 A matched template yields `confidence: Proven` only when Evidence includes the request/response exchange with a redaction pass applied.

## 7.5 `multiscan-sast` — [v2 SCOPE — scaffold only in v1]

tree-sitter structural pattern matching. v1 ships the crate skeleton, the `Engine` impl returning `Applicability::NotApplicable`, and the `structural_hash` function (needed by dedup regardless). **No detection rules in v1.** NG-2 stands permanently: no taint analysis.

## 7.6 `multiscan-bridge` — external scanner import

`multiscan import` ingests output from tools the user already runs, normalizing into the same `Finding` model.

Required importers: SARIF 2.1.0 (generic), Trivy JSON, Semgrep JSON, Checkov JSON, ZAP JSON, CycloneDX, SPDX.

- BRG-001 Imported Findings MUST participate in the same dedup pass as native ones, with `sources[].engine_id` recording the external tool.
- BRG-002 Each importer MUST declare an explicit severity map (ENG-004 applies to Bridges).
- BRG-003 Unknown native policy IDs MUST fall back to `external:{tool}:{id}` and MUST NOT be merged with anything.

## 7.7 Dedup and merge [NORMATIVE]

- 7.7.1 `finding_id = blake3(identity_tuple)`, truncated to 32 bytes hex. (BLAKE3 over SHA-256 for speed; the value is an identity, not a security primitive.)
- 7.7.2 Identity keys per `finding_class`. Every tuple begins with `finding_class`; all paths enter the tuple normalized per DET-005:

| `finding_class` | Identity tuple fields (after `finding_class`) |
|---|---|
| `VulnerableDependency` | package purl (type, namespace, name, version), advisory ID, normalized lockfile/manifest path |
| `ContainerVulnerability` | package purl (type, namespace, name, version), advisory ID, image digest |
| `ExposedSecret` | rule ID, normalized path, truncated secret fingerprint |
| `IacMisconfiguration` | policy ID, normalized path, resource address |
| `WebExposure` | template ID, normalized origin (scheme + host + port), matched request path |
| `StructuralPattern` | rule ID, normalized path, `structural_hash` |

- 7.7.3 Identity tuples MUST NOT include line/column numbers, timestamps, engine versions, scan metadata, or secret values. A field that can change while the underlying weakness stays the same does not belong in identity.
- `structural_hash` lives in `multiscan-sast` and MUST hash tree-sitter node kinds plus normalized identifiers — never raw line numbers.
- 7.7.4 **Closure rule:** a Finding transitions to `Fixed` only when an Engine that previously reported it returns `Complete` and omits it. `Partial` never closes anything.
- 7.7.5 Two distinct `engine_id`s reporting the same `finding_id` MUST escalate confidence to at least `Corroborated`.

---

# 8. Risk Scoring [NORMATIVE]

```
risk_score = 100 × clamp01(S × E × X × C × A)
```

| Factor | Range | Notes |
|---|---|---|
| S — Severity base | 0.05–1.00 | `max(ordinal, cvss_base/10)` |
| E — Exposure | 0.30–1.00 | From config `asset_criticality` context + engine signal (a probe finding is by definition internet-reachable ⇒ 1.00) |
| X — Exploitability | 0.20–1.00 | KEV 1.00 · EPSS ≥0.5 → 0.90 · 0.1–0.5 → 0.70 · <0.1 → 0.45 · no CVE → 0.55 · unavailable → 0.50 |
| C — Confidence | 0.50–1.00 | Proven 1.00 · Corroborated 0.85 · Heuristic 0.70 · Unconfirmed 0.50 |
| A — Asset criticality | 0.50–1.30 | From `[risk]` config; +0.10 if `data_classification` is `sensitive` or `regulated`, clamped at 1.30 |

- RSK-001 Scoring MUST be a pure function. No clock, no RNG, no environment, no hash-order dependence.
- RSK-002 Missing inputs MUST use documented defaults and be listed in `score_explanation.defaults_applied`.
- RSK-003 Every score MUST record `feed_snapshot_id` and `formula_version`.
- RSK-004 Formula changes MUST bump `formula_version` and ship a documented migration note. Never mutate stored scores silently.
- RSK-005 `multiscan explain <id>` MUST print all five factors, the raw product, defaults applied, and the feed snapshot used.

---

# 9. Authorization & Safety [NORMATIVE]

Applies to `multiscan scan web` and to `--verify-secrets`. Local filesystem and image scanning need no authorization.

## 9.1 ScopeAuthorization

```toml
authorization_id = "auth-2026-08-acme-staging"
[scope]
include = ["staging.acme.com", "*.staging.acme.internal"]
exclude = ["payments.staging.acme.com"]
permitted_methods = ["GET", "HEAD", "OPTIONS"]
valid_from = "2026-08-01T00:00:00Z"
valid_until = "2026-08-31T00:00:00Z"
authorized_by = "j.ruiz@acme.com"
attestation = "Written authorization on file; targets owned by Acme Corp."
signature = "ed25519:..."
```

| ID | Requirement |
|---|---|
| SEC-001 | `scan web` without a valid, signed, in-window authorization MUST exit 4 before any packet is sent. |
| SEC-002 | `exclude` beats `include` always. |
| SEC-003 | Wildcards MUST NOT span a public suffix (`*.com` rejected). |
| SEC-004 | DNS results MUST be re-validated against scope immediately before connect, and the connection aborted if the resolved IP falls outside scope (rebinding defence). |
| SEC-005 | Redirects leaving scope MUST NOT be followed. |
| SEC-006 | Per-host rate limit: 5 rps (`quick`), 25 rps (`standard`/`thorough`), with backoff on 429/503 or rising latency. |
| SEC-007 | ≥20% 5xx over a 60 s window MUST abort the scan and report it. |
| SEC-008 | Every authorize/deny decision MUST be written to a local append-only audit log with the deciding rule. |
| SEC-009 | No flag, env var, or config key may bypass §9. Reviewers MUST reject any PR introducing one. |

---

# 10. Feeds & Rule Data [NORMATIVE]

| ID | Requirement |
|---|---|
| FD-001 | Advisory data (OSV), exploit data (EPSS, KEV) cached under the platform cache dir (`~/.cache/multiscan` or XDG/OS equivalent). |
| FD-002 | Each cache entry records `as_of` and a content digest. A Scan pins one `FeedSnapshot` for its whole duration. |
| FD-003 | `multiscan db update` is the only command permitted to fetch feeds. `scan` MUST NOT silently update mid-run. |
| FD-004 | Feeds older than `--max-feed-age` produce a **warning**; under `--offline` they produce exit code 5. Never a silent stale result. |
| FD-005 | `multiscan db export --out bundle.tar.zst` / `db import` MUST support air-gapped operation. Bundles MUST be signed and verified on import. |
| FD-006 | Bundled rule packs (secrets, IaC, probe templates) MUST be content-addressed and their digests recorded in every Finding's provenance. |
| FD-007 | The binary MUST be usable with zero prior network access for `secrets` and `iac` layers (rules are embedded). `sca` requires a feed snapshot. |

---

# 11. Storage [NORMATIVE]

```rust
pub trait Store {
    fn upsert_findings(&mut self, findings: &[Finding]) -> Result<UpsertStats>;
    fn load_baseline(&self, name: &str) -> Result<Vec<Finding>>;
    fn save_baseline(&mut self, name: &str, findings: &[Finding]) -> Result<()>;
    fn history(&self, finding_id: &FindingId) -> Result<Vec<FindingEvent>>;
    fn active_suppressions(&self, now: DateTime<Utc>) -> Result<Vec<Suppression>>;
}
```

- STO-001 v1 ships `SqliteStore` writing to `.multiscan/multiscan.db` (git-ignored) plus an in-memory impl for tests.
- STO-002 History MUST be event-sourced: status transitions and score changes append, never overwrite.
- STO-003 The DB MUST be optional. `--no-store` performs a stateless scan; only `diff`, `history`, and `explain --history` require it.
- STO-004 Schema migrations MUST be forward-only and versioned; the binary MUST refuse to open a newer schema rather than corrupt it.
- STO-005 The `Store` trait is the seam for a future server backend (P-8). No SQLite types may leak into other crates.

---

# 12. Output Formats [NORMATIVE]

| Format | Purpose | Requirement |
|---|---|---|
| `table` | Human terminal | Grouped by severity band; shows id prefix, score, class, location, fix |
| `json` | Full fidelity | Validates against `schemas/finding.json` |
| `jsonl` | Streaming/large sets | One Finding per line |
| `sarif` | CI code scanning | SARIF 2.1.0; round-trip preserving `finding_id`, `severity`, `location`, `sources` |
| `sbom` | Inventory | CycloneDX 1.5 from the SCA engine's resolved dependency graph |
| `markdown` | PR comments, reports | Deterministic, no timestamps in body (they break diffs) |

- OUT-001 SARIF `ruleId` MUST be the canonical policy/advisory ID, and `partialFingerprints` MUST carry `finding_id` for stable de-duplication in GitHub/GitLab.
- OUT-002 Markdown and table output MUST NOT embed the scan timestamp inside the body; it goes in a footer line so diffs stay clean.

---

# 13. Requirements Register [NORMATIVE]

## 13.1 Functional

| ID | Requirement | Acceptance |
|---|---|---|
| FR-001 | Auto-detect applicable layers | Given a repo with `Cargo.lock` and `*.tf`, when `multiscan scan .` runs, then sca+secrets+iac execute and sast does not. |
| FR-002 | SCA resolves lockfiles to advisories | Given a `package-lock.json` with a known-vulnerable version, when scanned offline with a pinned snapshot, then the expected CVE is reported with `fixed_version` populated. |
| FR-003 | Ecosystem-correct version matching | Given PEP 440 and semver fixtures, when matched, then no false positive from naive string comparison. |
| FR-004 | Cross-engine dedup | Given the same package flagged by native SCA and an imported Trivy report, when merged, then one Finding with 2 `sources` and `confidence ≥ Corroborated`. |
| FR-005 | Secrets never persisted | Given a detected AWS key, when output is written, then no output artefact or DB row contains the full value. |
| FR-006 | IaC policy evaluation | Given a public S3 bucket in Terraform, when scanned, then a Finding with ≥1 CIS control mapping. |
| FR-007 | Probe requires authorization | Given `scan web` with no `--authorization`, when run, then exit 4 with zero packets sent (verified by network mock). |
| FR-008 | Scoring correctness | Given the golden vectors, when scored, then values match to ±0.1 and `score_explanation` lists five factors. |
| FR-009 | Gate semantics | Given `--fail-on 80` and a Finding at 82.4, when run, then exit 1 and the blocking id is printed to stderr. |
| FR-010 | Baseline delta gating | Given a baseline containing the only high Finding, when run with `--baseline`, then exit 0. |
| FR-011 | Offline operation | Given `--offline` with a fresh snapshot, when scanned, then no network syscall occurs (verified by sandbox). |
| FR-012 | Air-gap bundle | Given `db export` on machine A and `db import` on machine B, when B scans offline, then results are identical to A. |
| FR-013 | SARIF round-trip | Given SARIF exported then re-imported, when compared, then `finding_id`/`severity`/`location`/`sources` are unchanged. |
| FR-014 | Suppression expiry | Given a suppression expiring yesterday, when scanned, then the Finding appears and gates normally. |
| FR-015 | Partial vs failure distinction | Given one engine erroring, when run, then exit 3, other engines' Findings are still reported, and nothing is closed. |
| FR-016 | Explainability | Given any `finding_id`, when `multiscan explain` runs, then factors, defaults, evidence, and remediation are printed. |

## 13.2 Non-functional

| ID | Requirement | Target |
|---|---|---|
| NFR-001 | Cold scan, 100k-LOC repo, sca+secrets+iac | < 10 s wall clock, 8 cores |
| NFR-002 | Warm scan (cached feeds, unchanged tree) | < 3 s |
| NFR-003 | Peak RSS on a 1 GB repo | < 500 MB |
| NFR-004 | Binary size (release, stripped, LTO) | < 30 MB |
| NFR-005 | Startup to first output | < 100 ms |
| NFR-006 | Determinism | 100 repeat runs ⇒ byte-identical machine output |
| NFR-007 | Platforms | linux-{x86_64,aarch64}-{gnu,musl}, macOS-{x86_64,aarch64}, windows-x86_64 |
| NFR-008 | Zero-dependency execution | Static musl build runs on a `scratch` container |
| NFR-009 | `unsafe` code | Zero in first-party crates; `#![forbid(unsafe_code)]` on every crate |
| NFR-010 | Image layer extraction | Fuzzed; no path escape under any input |
| NFR-011 | Signal quality | Per §13.3: false-positive control is a build-gated correctness property, not a polish item. |

## 13.3 Signal Quality & False-Positive Control [NORMATIVE]

For a scanner, signal quality *is* correctness. A report that cries wolf, or
that buries a real finding under a flood of near-duplicates, fails the tool's
purpose as surely as a missed vulnerability — and erodes the trust that makes
any finding actionable. False-positive control is therefore a first-class
normative property, gated in CI, not a refinement left to "later." The
governing rule across heuristic tiers is **precision over recall**: a
low-confidence heuristic must not degrade the usefulness of the
high-confidence detections it accompanies.

| ID | Rule |
|---|---|
| FP-001 | Heuristic detectors MUST be bounded on machine-generated content. The generic high-entropy secrets detector MUST NOT fire on known-noise files (lockfiles, IDE metadata, minified/generated assets) nor on content-address token shapes (hex digests at digest lengths, UUIDs, URL-embedded runs). Realized by ADR 0005. |
| FP-002 | Noise controls MUST target the heuristic tier only. Silencing a `Heuristic`-confidence detection — by shape, path, or config — MUST NOT disable `Proven`/`Corroborated` detections in the same file; a real credential in a lockfile is still reported. Realized by ADR 0005. |
| FP-003 | Every finding class MUST be suppressible by a committed, reviewable, expiring rule scoped by at least `(rule_id, path)`, so a *class* of false positive is retired in one entry without a baseline that grandfathers unrelated findings. The CLI-006 justification/approver/expires fields remain mandatory. Realized by ADR 0008. |
| FP-004 | Human output (`table`, `markdown`) MUST collapse more than a threshold of findings sharing one rule and one file into a single counted row. Machine formats (`json`/`jsonl`/`sarif`) MUST retain every per-instance finding, so baseline diffing and dedup are unaffected. Realized by ADR 0006. |
| FP-005 | Discovery MUST honor an explicit `.multiscanignore`. Reuse of the repository's `.gitignore` MUST be opt-in: a security scan MUST NOT skip a gitignored path (e.g. `.env`) by default. Realized by ADR 0009. |
| FP-006 | A false positive is a correctness defect. The acceptance suite (§16) MUST carry, for each heuristic detector, a benign "quiet corpus" of realistic inputs that MUST produce zero findings; a change that makes the quiet corpus fire fails the build, tracked alongside the golden true-positive corpus. |

Configurable thresholds and lists (FP-001, FP-004) have documented defaults; a
deployment MAY tune them but MUST NOT be *required* to configure anything to
get the default-safe behavior above.

---

# 14. Determinism [NORMATIVE]

Rust makes several determinism footguns easy. These are binding:

| ID | Rule |
|---|---|
| DET-001 | `HashMap`/`HashSet` MUST NOT be used where iteration order can influence output. Use `BTreeMap`/`BTreeSet`/`IndexMap`. Enforced by lint. |
| DET-002 | Parallel engine output MUST be sorted before rendering (CLI-003). Never emit in completion order. |
| DET-003 | Float comparison in sorting MUST use `total_cmp`, never `partial_cmp().unwrap()`. |
| DET-004 | No `SystemTime` inside `multiscan-dedup` or `multiscan-risk`. Timestamps are injected via `ScanContext`. |
| DET-005 | Paths MUST be normalized to POSIX separators and made root-relative before entering any identity computation. |
| DET-006 | Locale, `TZ`, and env vars MUST NOT affect machine output. |
| DET-007 | CI runs `make test-determinism`: 100 runs, byte-compare. A single mismatch fails the build. |

---

# 15. Implementation Task Graph [NORMATIVE — execution order]

```yaml
phase_1_foundation:
  T-101: { deps: [],      deliverable: "schemas/ + codegen into multiscan-core; Severity/Confidence ordinals", satisfies: [R-4] }
  T-102: { deps: [T-101], deliverable: "Engine trait, EngineManifest, FindingSink, registry", satisfies: [ENG-001..004] }
  T-103: { deps: [T-101], deliverable: "multiscan-dedup: finding_id (blake3), identity keys, merge", satisfies: [FR-004] }
  T-104: { deps: [T-101], deliverable: "multiscan-risk: formula, explanation, golden vectors", satisfies: [FR-008, RSK-001..005] }
  T-105: { deps: [T-101], deliverable: "multiscan-cli skeleton: clap, config resolution, exit codes", satisfies: [CLI-001..007, FR-009] }
  T-106: { deps: [T-101], deliverable: "no-I/O dependency check in CI; determinism harness", satisfies: [DET-007, NFR-006] }

phase_2_local_layers:
  T-201: { deps: [T-102], deliverable: "multiscan-feeds: OSV cache, EPSS, KEV, snapshot pinning, offline mode", satisfies: [FD-001..004, FR-011] }
  T-202: { deps: [T-102, T-201], deliverable: "multiscan-sca: lockfile parsers + ecosystem version matchers", satisfies: [FR-002, FR-003, SCA-001..004] }
  T-203: { deps: [T-102], deliverable: "multiscan-secrets: rules, entropy, fingerprints, no-persist guarantee", satisfies: [FR-005, SEC-101..104] }
  T-204: { deps: [T-102], deliverable: "multiscan-iac: HCL/YAML/JSON normalizer + CIS policy pack", satisfies: [FR-006, IAC-001..004] }
  T-205: { deps: [T-103, T-104], deliverable: "multiscan-report: table, json, jsonl, markdown", satisfies: [OUT-001, OUT-002] }

phase_3_state_and_ci:
  T-301: { deps: [T-205], deliverable: "multiscan-store: Store trait + SqliteStore + migrations", satisfies: [STO-001..005] }
  T-302: { deps: [T-301], deliverable: "Baselines, diff, suppression lifecycle", satisfies: [FR-010, FR-014] }
  T-303: { deps: [T-205], deliverable: "SARIF export/import with round-trip tests", satisfies: [FR-013] }
  T-304: { deps: [T-202], deliverable: "CycloneDX SBOM export", satisfies: [OUT-001] }
  T-305: { deps: [T-303], deliverable: "multiscan-bridge importers (trivy, semgrep, checkov, zap)", satisfies: [FR-004, BRG-001..003] }
  T-306: { deps: [T-201], deliverable: "db export/import signed air-gap bundles", satisfies: [FR-012, FD-005] }

phase_4_images:
  T-401: { deps: [T-202], deliverable: "OCI pull + hardened layer extraction + fuzz targets", satisfies: [SCA-005, NFR-010] }
  T-402: { deps: [T-401], deliverable: "dpkg/rpm/apk package DB parsers → OSV resolution", satisfies: [FR-002] }

phase_5_probe:
  T-501: { deps: [T-102], deliverable: "multiscan-scope: authorization parse/verify, DNS re-check, rate control, audit log", satisfies: [SEC-001..009, FR-007] }
  T-502: { deps: [T-501], deliverable: "multiscan-probe: template schema, executor, matchers, evidence redaction", satisfies: [PRB-001..005] }

phase_6_polish:
  T-601: { deps: [T-105], deliverable: "Cross-compilation matrix, musl static, release automation", satisfies: [NFR-007, NFR-008, NFR-004] }
  T-602: { deps: [T-105], deliverable: "Shell completions, man page, GitHub Action wrapper", satisfies: [] }
  T-603: { deps: [T-205], deliverable: "multiscan explain + history views", satisfies: [FR-016] }
  T-604: { deps: [T-103], deliverable: "multiscan-sast scaffold + structural_hash (NO rules)", satisfies: [NG-2] }
```

---

# 16. Test Strategy [NORMATIVE]

| Layer | Requirement |
|---|---|
| Golden corpus | Fixtures per engine with expected Finding output, committed. Any diff is a reviewable event explained in the PR. |
| Ecosystem matrix | Version-matching fixtures per ecosystem (semver, PEP 440, Maven, RubyGems). Naive comparison must fail these. |
| Determinism | 100-run byte-compare across all machine formats (DET-007). |
| Dedup adversarial | Every merge case pairs with a near-miss that must NOT merge. Track false-merge and false-split separately. |
| Fuzzing | `cargo-fuzz` targets for tar/OCI extraction, HCL parsing, SARIF import, lockfile parsers. Extraction fuzzing is release-blocking (NFR-010). |
| Safety negatives | Missing authorization, expired window, out-of-scope redirect, DNS drift, non-idempotent method in `standard` — each MUST block. Release-blocking. |
| Network isolation | `--offline` tests run under a sandbox that fails the test on any syscall to the network (FR-011). |
| Recall | `testdata/lab/` fixtures and locally-hosted deliberately-vulnerable apps on an isolated network. **Never** point tests at real or third-party hosts. |
| Signal quality | Per §13.3 FP-006: a benign "quiet corpus" per heuristic detector that MUST yield zero findings. A regression that makes it fire is a build failure, tracked like the golden corpus. |
| Detection benchmark | `cargo xtask bench-detect` measures precision/recall/F1 per engine against a committed labeled corpus (positive fixtures with a complete label set; the quiet corpus as the false-positive set). `--check` gates on the corpus floors. A crafted regression gate, not a real-world-scale dataset; differential runs against other scanners plug in via the SARIF bridge. |
| Performance | Benchmark suite gating NFR-001..005 in CI; regressions >15% fail. |
| Supply chain | `cargo-deny` (licenses, advisories, bans) and `cargo-audit` on every build. We eat our own dog food. |

---

# 17. Open Questions

| ID | Question | Status | Conservative default (R-7) |
|---|---|---|---|
| Q-01 | Full OSV mirror vs API queries? | Open | Local mirror; API only as an explicit opt-in for freshness. Offline is the default posture. |
| Q-02 | Reachability analysis for SCA (is the vulnerable symbol called?) | Deferred to v2 | Omit factor; treat as unknown. Do not guess. |
| Q-03 | Rule pack distribution: embedded vs downloadable? | Open | Embedded for secrets/IaC (FD-007); downloadable for OSV. |
| Q-04 | Semgrep rule syntax compatibility in v2 SAST | Open | Define own minimal pattern syntax first; compatibility later if demanded. |
| Q-05 | Plugin/WASM engines for third parties | Deferred | First-party engines only. Bridges cover external tools. |
| Q-06 | When does the auditor persona force a server? | Open | SQLite + `Store` trait until a concrete customer needs cross-machine history. |

---

# Appendix A — Legal & Licensing Posture [NORMATIVE]

- A-1 `scan web` and `--verify-secrets` MUST NOT be used against systems the operator does not own or lack written authorization to test. The `attestation` field records this and MUST be non-empty.
- A-2 Every bundled rule pack, advisory dataset, and dependency MUST have its license recorded; `cargo-deny` fails the build on an unreviewed license. Note that some rule corpora carry copyleft or non-commercial terms — check before vendoring.
- A-3 OSV data is consumed under its published terms; attribution MUST appear in `multiscan db status` and in generated reports.
