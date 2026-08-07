# Phase 2 — sketch

**Status:** sketch, INFORMATIVE. Nothing here binds until it lands in an SDD revision or an ADR.
**Assumption:** every task in SDD §15 (`T-101`…`T-604`) is merged and shipped at `v0.2.1`, so "phase 2"
means the v2 program — the work the spec itself defers with "v2 scope" (§7.5, Q-02, Q-04), not
`phase_2_local_layers`, which is done.

**Numbering:** phases and task IDs continue the SDD §15 sequence (`phase_7…`, `T-7nn`) rather than
restarting, so no ID ever refers to two pieces of work. "Phase 2" is the product generation; the task
graph keeps counting.

---

## Where v1.0 landed

Six phases, fifteen crates, published. Every layer a repo can present — dependencies, OS packages,
secrets, IaC, container layers — is covered by an engine, plus authorized template probes, five
external importers, a store with baselines and history, and six output formats. Feeds carry OSV, EPSS,
KEV, and (ADR 0010) the secrets/IaC/probe rule packs, so detection content already refreshes without a
release.

One layer is scaffolding: `multiscan-sast` returns `NotApplicable` and ships zero rules. And one risk
factor is permanently `Unknown`: nothing knows whether a flagged dependency is actually called.

## What phase 2 is

**Close the two holes v1.0 knowingly left, without becoming a different product.**

Source code is the only layer MultiScan can see but does not read, and reachability is the single
factor that would most change ranking — a vulnerable transitive package whose vulnerable symbol is
never referenced is noise, and today it scores the same as one that is. Both holes need the same new
capability: parsing source into a syntax tree. That shared dependency is why they are one phase.

Everything else in phase 2 is data breadth and freshness, which by the core principle should be the
cheap part.

## Non-goals — all of NG-1…NG-6 carry forward unchanged

`NG-2` deserves restating because phase 2 is where it will be tested: **SAST is structural pattern
matching. No interprocedural taint or dataflow analysis, permanently.** Reachability (workstream B) is
symbol presence, not a dataflow claim — see the three-state design below. A proposal that reaches for
taint is out of scope no matter how it is framed.

`NG-4` settles Q-06: no daemon, no server, no cross-machine history service. `Store` stays a trait.

Also still out: third-party WASM engines (Q-05, re-deferred — Bridges cover external tooling), and
*full* Semgrep rule-syntax compatibility — ADR 0014 (proposed) resolves Q-04 as `MS-PAT-1`, a
documented structural subset with a mechanically translated corpus, which is a contract, not a
compatibility claim.

---

## Workstream A — SAST that ships rules

Rules are **data**, in the rule-pack format, distributed through the feed channel (ADR 0010). A new
detection is a pack refresh, never a code release. The engine is a matcher; the knowledge is a
`RuleSet`.

```yaml
phase_7_sast:
  T-701: { deps: [T-604], deliverable: "pattern syntax + tree-matcher over a parsed source tree; RuleSet schema extension", satisfies: [SAST-001, SAST-002] }
  T-702: { deps: [T-701], deliverable: "language front-ends (initial set); applicable() stays extension-only, no reads", satisfies: [SAST-003, NFR-004] }
  T-703: { deps: [T-701], deliverable: "SAST identity on the existing structural_hash; dedup near-miss corpus", satisfies: [FR-004] }
  T-704: { deps: [T-702], deliverable: "parser+matcher fuzz target; golden fixtures; quiet-corpus FP gate", satisfies: [NFR-010, FP-001..006] }
  T-705: { deps: [T-701], deliverable: "sast rule pack on the feed channel; signature + provenance", satisfies: [FD-005, SAST-004] }
```

Proposed requirements:

| ID | Requirement | Acceptance |
|---|---|---|
| SAST-001 | Patterns are declarative data, no execution | Given a rule pack, when loaded, then no eval, shell-out, or code execution occurs (`PRB-001` posture applies to rule packs). |
| SAST-002 | Matching is structural, not textual | Given a pattern and a reformatted-but-equivalent source file, when matched, then the same Finding with the same `finding_id`. |
| SAST-003 | Unsupported languages degrade, never fail | Given a repo of an unhandled language, when scanned, then `NotApplicable` for those files and `Complete` overall. |
| SAST-004 | Every SAST rule declares its severity | Given a rule pack entry without an explicit `severity_map` entry, when loaded, then the pack is rejected (`ENG-004`). |

Constraints that bite here:

- **Rule authorship is constrained by §1.2** (ADR 0013, consequences): we do not author vulnerability
  knowledge, and a bespoke minimal syntax has no community corpus written in it. The initial pack must
  be adopted or mechanically translated from a community corpus; the Q-04 syntax decision is its own
  ADR, due before T-705, and "minimal bespoke syntax + hand-written rules" is not on the table.
- **Parser choice is the phase's biggest unresolved decision** (Q-07 below). tree-sitter is the obvious
  answer and pulls C and `unsafe` into the tree; `#![forbid(unsafe_code)]` still holds for our crates,
  but non-negotiable #1's "wrap it or drop it" needs an explicit, reviewed answer, not a default.
- **Binary size.** Grammars are megabytes each. `NFR-004` is a hard 30 MB. Either the initial language
  set stays small, or grammars ship as downloadable packs — decide before T-702, not after.
- **Parsing untrusted source is the threat model.** Fuzz target is release-blocking; bound allocation
  by input size, cap tree depth and node counts.
- **Determinism.** A new output-producing engine inherits DET-001/002 in full: ordered maps throughout,
  sort before render, rule iteration order fixed by the pack, not by the filesystem.
- **`structural_hash` already exists** from T-604 and SAST identity must build on it. Anything that
  would alter `finding_id` construction is a stop-and-ask item — it invalidates every user's baselines.

---

## Workstream B — reachability as a risk factor

Q-02, which the spec defers to v2 by name. Scope it narrowly: **does the first-party code reference the
vulnerable symbol or module at all?** Not "can tainted input reach it."

Three states, and the middle one is the point:

| State | Meaning | Score effect |
|---|---|---|
| `Referenced` | The vulnerable symbol/module is imported or called in scanned source | Factor raises the score |
| `NotReferenced` | Source parsed successfully; no reference found | Factor lowers the score |
| `Unknown` | Language unsupported, advisory has no symbol data, or parse degraded | Documented default, recorded in `defaults_applied` |

`Unknown` must not silently behave like `NotReferenced`. Suppressing a real finding because the parser
did not understand the file is a far worse failure than carrying noise, and `RSK-002` already forbids
nulling a factor.

```yaml
phase_8_reachability:
  # T-801 deps amended by ADR 0013: module-level import extraction needs the
  # parsed tree (T-701), not the full pattern-matching front-ends (T-702).
  T-801: { deps: [T-701], deliverable: "module/import reference extraction per supported ecosystem (symbol-level deferred — ADR 0013)", satisfies: [FR-017] }
  T-802: { deps: [T-801], deliverable: "reachability factor, formula_version bump, migration note, golden vectors", satisfies: [RSK-004, RSK-006] }
  T-803: { deps: [T-802], deliverable: "explain shows the reachability determination and its evidence", satisfies: [FR-016] }
```

| ID | Requirement | Acceptance |
|---|---|---|
| FR-017 | Reachability is three-state | Given an unsupported language, when scored, then the factor is `Unknown` with its default recorded, never `NotReferenced`. |
| RSK-006 | Reachability changes rank, not existence | Given a `NotReferenced` finding, when scanned, then it is still reported and still gateable — only its `risk_score` falls. |

This is a scoring change, so it carries the full `RSK-004` obligation: `formula_version` bump, migration
note, no silent mutation of stored scores. Historical Findings keep the score they were written with.

---

## Workstream C — data freshness and breadth

The cheap workstream, and the one that best honours the core principle.

```yaml
phase_9_data:
  T-901: { deps: [T-201], deliverable: "opt-in OSV API freshness path; mirror stays the default posture (resolves Q-01)", satisfies: [FR-018] }
  T-902: { deps: [T-202], deliverable: "ecosystem coverage gaps in lockfile + OS package parsing", satisfies: [FR-002] }
  T-903: { deps: [T-305], deliverable: "additional Bridge importers driven by user reports", satisfies: [BRG-001..003] }
```

| ID | Requirement | Acceptance |
|---|---|---|
| FR-018 | Freshness is opt-in, offline stays default | Given no explicit freshness flag, when scanned, then only the pinned snapshot is consulted and `--offline` remains byte-identical. |

The API path is a feed fetch, not a scan-target request — it belongs on the allow-listed
`multiscan-feeds` path and must never become a way to reach a target outside `multiscan-scope`.

---

## Exit criteria

1. `multiscan scan .` on a repo with source in a supported language produces SAST Findings from a
   feed-distributed rule pack, and a pack refresh changes detections with no rebuild.
2. Reachability appears as a scored factor with `Unknown` handled explicitly, behind a bumped
   `formula_version` with a migration note.
3. `cargo xtask determinism`, `safety`, `golden`, `offline`, and the quiet-corpus FP gate all pass, with
   the SAST engine active.
4. Fuzz target for source parsing runs in CI; `NFR-004` (30 MB) still holds.
5. Every golden-corpus diff introduced by the phase is explained.

## Open questions

| ID | Question | Conservative default (R-7) |
|---|---|---|
| Q-07 | tree-sitter (C, `unsafe`, large grammars) vs a pure-Rust parsing layer? | Narrowed by ADR 0013: pure-Rust parser families evaluated first against an explicit gate; tree-sitter only via its own stop-and-ask ADR. |
| Q-08 | Which languages first? | **Resolved by ADR 0013: Python and JavaScript/TypeScript.** |
| Q-09 | Do grammars ship in the binary or as downloadable packs? | Per ADR 0013: in-binary at two languages; `T-702` PR states the size delta against `NFR-004`. |
| Q-10 | Where does advisory symbol data for reachability come from? | OSV where present; `Unknown` otherwise. Do not author symbol lists — that is authoring vulnerability knowledge, which §1.2 forbids. ADR 0013 defers symbol-level reachability until a symbol-rich ecosystem (Go, Rust) joins the set; workstream B starts at module granularity. |

## Stop-and-ask list for this phase

Per CLAUDE.md, these need a decision before code, not a judgement call during it: adding the `unsafe`-
bearing parser dependency (Q-07); anything touching `finding_id` construction for SAST identity; any
widening of structural matching toward taint (`NG-2`); and any freshness path that could reach a scan
target outside `multiscan-scope`.
