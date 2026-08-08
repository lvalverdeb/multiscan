# ADR 0016: `structural_hash` consumes canonical node kinds, not the parser's

- Status: Accepted
- Date: 2026-08-07
- Amends: §7.7.2 (the `structural_hash` note under the identity tuples) and the
  §7.5 engine description. Entailed by ADR 0015; realizes `SAST-002`.

## Context

§7.7.2 says `structural_hash` "MUST hash tree-sitter node kinds plus normalized
identifiers", and §7.5 describes the Engine as "tree-sitter structural pattern
matching". Both were written when tree-sitter was the assumed substrate.
ADR 0015 selected `ruff_python_parser` and `swc_ecma_parser`, so the spec now
names a dependency the product does not have.

The wording is the small half of the problem. The real question `T-701` had to
answer is **whose vocabulary the hash consumes**, because `structural_hash` is
an identity input: the `StructuralPattern` tuple is (rule ID, normalized path,
`structural_hash`).

- **Parser-native kinds** (`ruff`'s `ExprCall`, `swc`'s `CallExpr`) make
  identity a function of the parser. The same construct in two languages hashes
  differently for no semantic reason, a parser upgrade that renames a node
  silently changes every `finding_id`, and replacing a front-end invalidates
  every user's baselines and suppressions. `ruff_python_parser` is a `0.0.x`
  crate published weekly with no semver guarantee (ADR 0015), so this is a
  live hazard, not a hypothetical one.
- **Canonical kinds owned by MultiScan** put a translation layer between the
  parser and identity. This is the only reading consistent with ADR 0015's
  decision 5, which already requires that no parser AST type crosses the
  front-end boundary.

Doing this now is free. v1 shipped zero SAST rules and the Engine is still
`NotApplicable`, so **no `StructuralPattern` Finding has ever existed** — there
is no baseline, suppression, or stored score to invalidate. Once a rule pack
ships, this same change would be a breaking identity migration.

## Decision

1. **`structural_hash` consumes MultiScan's canonical node-kind vocabulary**
   (`multiscan_sast::tree::Kind`), not any parser's. Front-ends translate into
   it; the hash never sees a `ruff_*` or `swc_*` name.

2. **The vocabulary is closed and append-only.** Adding a kind is routine.
   Renaming or removing one, or changing a kind's wire string, changes
   `finding_id` and is therefore a stop-and-ask change requiring its own ADR.

3. **The hashed form is frozen as:** pre-order traversal of the matched
   subtree's canonical kinds, plus that subtree's normalized identifiers in the
   same order. Spans, line and column numbers, raw literal text and source
   formatting are excluded (§7.7.3). The domain separator stays
   `multiscan:structural_hash:v1` — this ADR does not bump it, because no
   Finding exists whose hash could change.

4. **§7.7.2 and §7.5 are amended** to drop "tree-sitter" in favour of
   parser-agnostic wording, with an inline ADR pointer, so the normative
   document reads true on its own.

## Consequences

- `SAST-002` becomes a property of the design rather than a hope: reformatting
  a file changes spans only, and spans are not hashed, so the `finding_id` is
  unchanged.
- An unmapped construct lowers to the explicit `Other` kind rather than being
  approximated by a near-neighbour. Coarse is correct here — two different
  constructs sharing a kind would give them the same `structural_hash`.
- The vocabulary is now a compatibility surface that `T-702`'s two front-ends
  must both target, and that every later language must fit. Growing it is
  cheap by construction (append-only); the discipline is in never renaming.
- Every future front-end inherits a translation step it would not need if it
  emitted parser kinds directly. That cost is accepted deliberately: it is what
  buys identity stability across parser churn.
- `docs/ms-pat-1.md` §4–§5 documents the vocabulary and the frozen hash form
  for rule authors and pack translators.

## Rejected alternatives

- **Hash parser-native node kinds.** Cheaper, and no translation layer — but it
  makes `finding_id` a function of a `0.0.x` dependency's internal naming, and
  ADR 0015 accepted that dependency precisely on the condition that its AST
  stays behind the front-end boundary.
- **Leave the spec wording and let code diverge.** CLAUDE.md's rule is that
  code is wrong when it disagrees with the spec unless an ADR says otherwise;
  leaving §7.7.2 naming tree-sitter would make a correct implementation
  permanently non-conforming on paper.
- **Bump the domain separator to `v2` while renaming the vocabulary.** Nothing
  to migrate — no `StructuralPattern` Finding exists — so a bump would signal a
  breaking change that never happened and would invalidate the v1 constant for
  no gain.
