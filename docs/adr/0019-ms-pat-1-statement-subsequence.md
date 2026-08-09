# ADR 0019: `MS-PAT-1` gains statement-subsequence patterns

- Status: Accepted
- Date: 2026-08-08
- Extends: ADR 0014 (`MS-PAT-1`) and `docs/ms-pat-1.md` §3. Resolves
  `docs/phase-2.md` Q-13.

## Context

ADR 0014 defined `MS-PAT-1` as a documented subset and said plainly that when
the translator's dropped-rule count climbs, "widening the subset is a new ADR,
not a translator patch". This is that ADR, and it is prompted by measurement
rather than anticipation.

Translating the first real corpus (GitLab's MIT-licensed `sast-rules`,
`docs/sast-corpus.md`) produced 135 rules, of which only **61 compiled**. The
single largest cause — 64 failures — was one shape:

```yaml
pattern: |
  $ALIAS = eval;
  ...
  $ALIAS($OBJ)
```

A **multi-statement leaf pattern**. Real rules use it constantly, because it is
how you express "this value comes from there, and is used here" without taint
analysis. It is the workhorse of pattern-only rule writing.

`MS-PAT-1` rejected it. A leaf pattern compiled to a single construct, so a
two-statement pattern became a whole-module pattern that could only match at
file root — never what the author meant. Rejecting was correct given that
compilation; the compilation was the limitation.

## Decision

1. **A multi-statement leaf pattern compiles to a statement subsequence.**
   `PatternNode::Sequence { items }` matches a contiguous run of children in
   some node, rather than requiring the whole node to match.

2. **The enclosing node's kind is not pinned.** The same two statements mean
   the same thing at file root, in a function body, or inside a `try` block, so
   the form matches against any node that has children. Pinning `Module` is
   what made the old compilation useless.

3. **Subsequence semantics are intrinsic, not sugar.** They are *not* expressed
   by wrapping the item list in bookend `...` entries. Wrapping would inflate
   the ellipsis count toward `MAX_ELLIPSES_PER_SEQUENCE` and could manufacture
   the adjacent-`...` rejection out of a pattern the author wrote correctly.

4. **Earliest start position wins.** Matching tries offsets in order and takes
   the first that succeeds, so the result does not depend on tree shape
   (`DET-001`). This inherits the first-solution semantics `docs/ms-pat-1.md`
   §3 already documents; it does not introduce a new kind of incompleteness.

5. **Everything else is unchanged.** Single-construct patterns compile exactly
   as before, metavariable binding still ties occurrences together across the
   subsequence, and `NG-2` is untouched — this is ordering and co-occurrence in
   a statement list, not dataflow. A rule can say "these statements appear in
   this order"; it still cannot say "this value reaches that sink".

## Consequences

- **61 → 80 working rules** from the same corpus, a 31% increase, with no
  change to the corpus or the translator.
- The quiet-corpus FP gate caught a regression the moment this landed, which is
  the outcome that justifies having it. The finding was **not** a matcher bug:
  GitLab's rule has a `$A.eval($OBJ)` branch, and the fixture contained
  `this.eval(expr)` on a user-defined class — genuinely ambiguous code that a
  security rule flags on purpose. The fixture was over-reaching and was
  narrowed; the `obj.eval(x)` distinction moved to the matcher's unit tests,
  where the pattern is ours to control.
- New failure surface: a `Sequence` tries every start offset, so a wide node
  costs more. `MAX_MATCH_STEPS` already bounds this and exhaustion degrades the
  file to `Partial`, so the cost is contained rather than unbounded.
- The remaining ~55 compile failures are genuine Semgrep syntax outside the
  subset — typed metavariables, deep-expression operators, `<... ...>` — plus a
  JSX-valued pattern. Each would be its own widening decision.

## Rejected alternatives

- **Leave it out and accept 61 rules.** Discards a third of a corpus that is
  already licence-cleared and FP-clean, over a form that is neither ambiguous
  nor dataflow-adjacent.
- **Translate multi-statement patterns into `pattern-inside` chains.** Changes
  the rule's meaning: `pattern-inside` is containment, not ordering, and it
  cannot express "then". It would silently make rules match more broadly than
  their authors wrote — the failure mode ADR 0014's "rejection is total"
  posture exists to prevent.
- **Pin the enclosing kind to `Module` or `Block`.** Two statements inside a
  `try` block, or a class body, would stop matching for no reason a rule author
  would recognise.
- **Express it by wrapping in bookend `...`.** Simpler to implement, but it
  inflates the ellipsis count and can turn a valid pattern into an
  adjacent-`...` rejection — a bug manufactured by the desugaring.
