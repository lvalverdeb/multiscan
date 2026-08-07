# ADR 0013: Phase-2 initial language set — Python and JavaScript/TypeScript

- Status: Accepted
- Date: 2026-08-07
- Extends: `docs/phase-2.md` (informative sketch); resolves its Q-08, narrows
  Q-07 and Q-09, and amends the `T-801` dependency. Binds nothing in
  `MULTISCAN-SDD-v1.0.md` v1 scope.

## Context

The phase-2 sketch defers three coupled questions: which languages the source
parser handles first (Q-08), whether that parser is tree-sitter or pure Rust
(Q-07), and whether grammars ship in the binary (Q-09). It also makes
workstream B (reachability) depend on workstream A's language front-ends
(`T-801` deps `T-702`).

These are not independent. The language set determines whether pure-Rust
parsers are viable at all — per-language parsers exist for some ecosystems and
not others — so choosing tree-sitter "by default" would let a dependency
decision make the product decision. Conversely, reachability's value is bounded
not by parser coverage but by *advisory symbol data*, which OSV carries richly
for Go and Rust and rarely for npm or PyPI. If reachability inherits SAST's
prevalence-driven language set at symbol granularity, the factor evaluates to
`Unknown` almost everywhere and the phase ships a factor that rarely fires.

Q-08's conservative default says: pick by what the SCA layer already sees most
in real repos. The SCA engine today parses npm/yarn, PyPI (`requirements.txt`,
`uv.lock`), Cargo, Go, RubyGems, Composer, and Maven/Gradle inputs; among
those, npm and PyPI are both the most common lockfile ecosystems in real repos
and the two largest advisory ecosystems in OSV, and they carry the largest
community SAST rule corpora.

## Decision

1. **The initial SAST language set is Python and JavaScript/TypeScript.** Two
   ecosystems, done well, per Q-08's own bar. TypeScript rides the same
   front-end as JavaScript or is excluded from the first cut — it does not
   justify a third parser.

2. **Reachability decouples from the SAST front-ends and starts at module
   granularity.** `T-801`'s deliverable becomes import/require extraction —
   "does first-party code import the affected package at all" — for the same
   two ecosystems. Module-level extraction needs only the import statements the
   SAST front-ends already parse, so the shared-parser rationale survives, but
   `T-801` no longer requires full pattern matching (`T-702`) to land.
   Symbol-level reachability is deferred until a symbol-rich ecosystem (Go,
   Rust) joins the language set; it must not be emulated for npm/PyPI by
   authoring symbol lists (Q-10, §1.2).

3. **Q-07 is narrowed, not resolved: pure-Rust parsers are evaluated first,
   and tree-sitter needs its own ADR.** With the set fixed at two languages,
   candidate pure-Rust front-ends exist for both (Python: the Ruff/RustPython
   parser family; JS/TS: the Biome or swc parser families). The evaluation
   gate is: no `unsafe` in our crates (non-negotiable #1), dependency `unsafe`
   surveyed via `cargo geiger` or equivalent and judged wrappable, parse-time
   within `NFR-001` budgets, and fuzz-clean per `NFR-010`. Only if both
   families fail that gate does tree-sitter come back — through the
   stop-and-ask path, as its own ADR.

4. **Q-09 defaults to grammars-in-binary.** Two front-ends against the 30 MB
   `NFR-004` cap; the `T-702` PR must state the binary-size delta. If a third
   language ever threatens the cap, that is the moment to revisit
   downloadable grammar packs — not before.

## Consequences

- Workstream B stops being hostage to workstream A's schedule: module-level
  reachability can ship against `T-801` alone, and its three-state design
  (`Referenced` / `NotReferenced` / `Unknown`) is exercised immediately by the
  two ecosystems where package-import evidence is actually extractable.
- At module granularity, `Referenced` means "the package is imported," which
  is weaker evidence than symbol presence. The score weight for the factor
  must be calibrated to that weaker claim, and `score_explanation` must say
  *module-level* so a user never reads it as a symbol-level determination.
- Most findings in unsupported languages still carry `Unknown` with its
  documented default (`RSK-002`); the `T-802` golden vectors must include a
  corpus-realistic, mostly-`Unknown` mix to prove the `formula_version` bump
  does not reshuffle rankings for users who get no reachability signal.
- The rule-authorship question for the SAST pack (who writes the rules, in
  what syntax) is **not** decided here. Constraint carried forward: §1.2
  forbids authoring vulnerability knowledge, so the initial pack must be
  adopted or mechanically translated from a community corpus — a bespoke
  syntax with a hand-written corpus is not an option. Resolving Q-04 (syntax
  choice vs. Semgrep-subset compatibility) is its own ADR, due before `T-705`.

## Rejected alternatives

- **tree-sitter first, languages by grammar availability.** Inverts the
  decision order: the dependency would pick the product scope, and pulls C and
  `unsafe` into the tree without the stop-and-ask review the non-negotiables
  require.
- **Go and/or Rust in the initial set for symbol-rich reachability.** Best
  ecosystems for workstream B, but weakest for workstream A: smaller SAST
  rule corpora and fewer repos seen by the SCA layer. Module-level
  reachability captures most of the ranking value for npm/PyPI now; Go/Rust
  join when the language set grows.
- **Reachability keeps `deps: [T-702]` and waits for full front-ends.**
  Couples the phase's two deliverables so the slower one gates both, for no
  technical gain — import extraction is a subset of parsing, not a client of
  pattern matching.
