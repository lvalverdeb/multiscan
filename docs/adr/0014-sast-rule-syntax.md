# ADR 0014: SAST rule syntax — a defined subset of Semgrep pattern syntax

- Status: Accepted
- Date: 2026-08-07
- Extends: §7.5 (SAST, v2 scope) and the phase-2 sketch's workstream A;
  resolves §17 Q-04. Binds nothing in v1 scope.

## Context

Q-04's conservative default — "define our own minimal pattern syntax first,
Semgrep compatibility later if demanded" — was written when the corpus
question was open. ADR 0013 closed it: §1.2 forbids authoring vulnerability
knowledge, so the initial SAST rule pack must be adopted or mechanically
translated from a community corpus. That kills the default's premise. A
bespoke syntax has, by definition, no community corpus written in it; choosing
one commits us to hand-writing rules, which is exactly the work §1.2 says we
do not do. The syntax decision and the corpus decision are the same decision.

The community corpora that exist for the ADR 0013 language set (Python,
JS/TS) are overwhelmingly written in Semgrep's rule syntax — the Semgrep
community registry and GitLab's SAST rulesets among them. No comparably sized
corpus exists in any other declarative, structural pattern syntax.

Full Semgrep compatibility, the thing Q-04 rightly feared, is a much larger
claim than consuming these corpora requires: it includes taint mode (which
`NG-2` forbids permanently), join mode, autofix, and a long tail of operator
semantics. The corpora's bulk lives in a small structural core.

Rule packs already have a delivery shape: `RuleSet` packs on the feed channel
with signature and provenance (ADR 0010, `T-705`), explicit severity for every
rule (`SAST-004`, `ENG-004`), and no code execution (`SAST-001`, `PRB-001`
posture).

## Decision

1. **The SAST pattern language is a defined subset of Semgrep pattern syntax,
   named `MS-PAT-1`.** We document the subset exhaustively; a rule either fits
   `MS-PAT-1` or is rejected at pack load. We never claim "Semgrep
   compatible" — the claim is "accepts `MS-PAT-1`, a documented subset".
2. **`MS-PAT-1` contains the structural core only:** `pattern`,
   `pattern-either`, `pattern-not`, `pattern-inside`, `pattern-not-inside`,
   metavariables, and ellipsis. Excluded, permanently or until their own ADR:
   taint mode (`NG-2` — excluded permanently, no ADR can admit it), join
   mode, autofix, `pattern-regex` beyond what the secrets engine already
   covers, and cross-file analysis.
3. **The corpus is mechanically translated, never authored.** A translator
   (an `xtask`, not a shipped engine capability) ingests a community corpus,
   keeps rules that are in-subset and in-language, maps severities through an
   explicit declared mapping (`ENG-004` — no passthrough), stamps provenance
   (source repo, upstream rule id, license, translation date) into the pack,
   and drops the rest with a logged count. Dropped-rule counts are visible in
   the pack manifest — silent truncation would read as coverage.
4. **License gates corpus admission.** A corpus is admissible only if its
   license permits redistribution through our feed channel; the audit result
   is recorded in the pack provenance. This is a blocking check in the
   translator, not a review-time convention.

## Consequences

- The matcher (`T-701`) implements `MS-PAT-1` semantics against the parsed
  tree, and `SAST-002` (reformatted-equivalent source → same `finding_id`)
  becomes a test over the subset, not over Semgrep behaviour. Where Semgrep
  and our matcher disagree on an in-subset rule, that is a bug in our matcher
  unless our documented semantics say otherwise.
- Subset drift is a standing obligation: upstream corpora will adopt operators
  outside `MS-PAT-1`, and the in-subset fraction will decay. The translator's
  dropped-rule count is the metric; when it climbs, widening the subset is a
  new ADR, not a translator patch.
- License audit is now on the critical path for `T-705`. The Semgrep
  community registry's licensing (Commons Clause constraints) and GitLab's
  MIT-licensed rulesets must be verified per-corpus before anything ships on
  the feed channel — outcome recorded in provenance, per Decision 4.
- Every translated pack faces the quiet-corpus FP gate (`FP-001..006`) before
  distribution; community rules tuned for other engines will have different
  noise profiles under our matcher, and the gate — not upstream reputation —
  decides what ships.
- The translator is maintained infrastructure — the cost ADR 0013 flagged for
  the "translate" option, now accepted deliberately.

## Rejected alternatives

- **Bespoke minimal syntax (Q-04's original default).** Its premise — that a
  corpus could follow later — died with ADR 0013's authorship constraint: no
  community writes rules in a syntax that doesn't exist, and §1.2 forbids us
  writing them ourselves. It would ship a matcher with an empty magazine.
- **Full Semgrep rule-syntax compatibility.** Imports taint mode's surface
  area in direct conflict with `NG-2`, plus join/autofix semantics we would
  carry forever. Compatibility is a treadmill; a documented subset is a
  contract.
- **Run Semgrep itself via a Bridge.** Already works today for users who have
  Semgrep, and stays available — but it is not a built-in engine, does not
  work offline from our feed channel, and leaves detection content outside
  the pack refresh model that the phase-2 exit criteria require.
