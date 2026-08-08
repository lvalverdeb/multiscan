# ADR 0017: The risk formula gains a sixth factor — module-level reachability

- Status: Accepted
- Date: 2026-08-08
- Amends: §8 (risk formula, NORMATIVE) and `FR-008`; realizes `FR-017` and
  `RSK-006`. Implements the reachability workstream ADR 0013 scoped.

## Context

§8 states the formula as `risk_score = 100 × clamp01(S × E × X × C × A)`, and
`FR-008` requires the explanation to carry those factors. `T-802` adds a sixth,
R, so the normative text and the code now disagree — and per the rules of
engagement the code is wrong unless an ADR says otherwise. This is that ADR.

The phase-2 sketch is explicitly informative ("nothing here binds until it
lands in an SDD revision or an ADR") and ADR 0013 "binds nothing in v1 scope",
so neither sanctions the change. `docs/scoring-migrations.md` satisfies
`RSK-004`'s migration-note obligation, which is a different requirement.

Reachability is the one factor v1 left permanently `Unknown`: nothing knew
whether a flagged dependency was actually used, so a vulnerable transitive
package whose module is never imported scored the same as one on the hot path.

## Decision

1. **The formula becomes `100 × clamp01(S × E × X × C × A × R)`**, and
   `FR-008`'s "five factors" becomes six. `formula_version` moves `1` → `2`.

2. **R is module-level, and the weights are:**

   | State | R | Meaning |
   |---|---|---|
   | `Referenced` | 1.10 | Scanned source imports the package |
   | `Unknown` | 1.00 | No evidence — the documented default (`RSK-002`) |
   | `NotReferenced` | 0.65 | Source parsed cleanly, no import found |

   The spread is deliberately narrow. At module granularity `Referenced` means
   "the package is imported", not "the vulnerable symbol is called" — weaker
   evidence, so the factor nudges rank rather than dominating it (ADR 0013,
   consequences). **These specific numbers are a product calibration rather
   than a derivation, which is why they were put to the user rather than
   self-accepted; they were ratified on 2026-08-08.**

3. **`Unknown` is neutral, never pessimistic.** It must not behave like
   `NotReferenced`: suppressing a real Finding because the parser did not
   understand a file is a far worse failure than carrying noise (`FR-017`).
   Being exactly 1.00 also makes the product arithmetically identical to v1, so
   users with no reachability signal keep every ranking.

4. **A negative conclusion requires a reliable mapping.** `NotReferenced` is
   emitted only for npm, where the module specifier *is* the package name.
   PyPI negatives stay `Unknown`: distributions routinely import under another
   name (`PyYAML` → `yaml`, `Pillow` → `PIL`, `beautifulsoup4` → `bs4`), and
   authoring that mapping would be authoring ecosystem knowledge, which §1.2
   forbids. An ecosystem is trustworthy only if at least one of its files was
   parsed *and* none failed — a repo with no Python concludes nothing about
   PyPI.

5. **R never removes a Finding** (`RSK-006`). A `NotReferenced` Finding is
   still reported and still gates; only its `risk_score` falls.

## Consequences

- `ScoreFactors` gains `reachability`, so every stored Finding, SARIF export
  and JSON consumer sees a new field. The golden corpus moved by exactly three
  line-kinds per finding, with **no `risk_score` line changed**.
- Reachability is computed once per scan, gated on the **SCA** layer, because
  it is evidence for dependency findings and is consulted for nothing else.
  Gating it on SAST would starve `--layers sca`, the run that benefits most.
- The pass parses every supported source file, so a repo pays one extra parse
  of its own source. Bounded by the front-ends' size cap, cancellable, and
  skipped entirely when SCA is not selected.
- `explain` states the determination in words and says *module-level* every
  time, so it can never be read as a symbol-level or dataflow claim (`T-803`).
- Symbol-level reachability remains deferred (Q-10) and taint analysis remains
  permanently out of scope (`NG-2`). Nothing here is a step toward either.

## Rejected alternatives

- **`Unknown` pessimistic (< 1.00).** Would let an unsupported language or an
  unparseable file quietly deprioritize real Findings, and would reshuffle
  rankings for every user who gets no signal — the outcome ADR 0013 explicitly
  asked the golden vectors to prove against.
- **A wider spread (e.g. 1.50 / 0.20).** Overstates what a module-level import
  proves. The factor would dominate severity and exploitability on evidence
  that cannot distinguish "imported and called in a hot path" from "imported
  and never used".
- **Trusting PyPI negatives via a curated name map.** Authoring vulnerability-
  adjacent ecosystem knowledge (§1.2), and wrong entries would suppress real
  Findings — the failure direction this design is built to avoid.
- **Deferring R until symbol-level data exists.** OSV carries symbol data
  richly for Go and Rust and rarely for npm or PyPI, so waiting means shipping
  nothing for the two ecosystems the language set actually covers (ADR 0013).
