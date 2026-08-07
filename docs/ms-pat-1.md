# MS-PAT-1 — the MultiScan structural pattern subset

**Status:** normative for the SAST Engine. Defined by [ADR 0014](adr/0014-sast-rule-syntax.md);
parser substrate fixed by [ADR 0015](adr/0015-phase2-parser-selection.md).

MS-PAT-1 is a **defined subset of Semgrep pattern syntax**. MultiScan accepts
`MS-PAT-1`; it does not claim Semgrep compatibility. A rule either fits this
document or is **rejected at pack load** — never silently downgraded, never
partially applied.

Where MultiScan and Semgrep disagree on a rule that is inside this subset, that
is a bug in our matcher *unless this document says otherwise*.

---

## 1. Rule shape

A rule pack is JSON, in the same data-not-code shape as the secrets and IaC
packs (ADR 0010), delivered over the feed channel with signature and provenance.

```json
{
  "pack_id": "community-py-js",
  "version": "1.0.0",
  "rules": [
    {
      "id": "python.lang.security.eval-injection",
      "message": "eval() on a non-literal argument executes attacker-controlled code",
      "languages": ["python"],
      "severity": "high",
      "confidence": "heuristic",
      "pattern": "eval($X)"
    }
  ]
}
```

`id`, `message`, `languages`, `severity`, `confidence` and exactly one
top-level pattern expression (§2) are required. `severity` is explicit per
`ENG-004`/`SAST-004`: a rule without one is a pack-load error, never inferred
and never passed through from an upstream corpus.

## 2. Operators

The complete set. There are no others.

| Operator | Meaning |
|---|---|
| `pattern` | A single leaf pattern (§3). Matches a subtree. |
| `pattern-either` | Disjunction. Matches if **any** branch matches. |
| `pattern-not` | Negation. Matches if the operand does **not** match at this node. |
| `pattern-inside` | Context. The operand must match **at or above** the match site — the node itself or one of its ancestors. The nearest enclosing match wins. |
| `pattern-not-inside` | Negative context. No node at or above the match site may match the operand. |

`patterns` (conjunction) is spelled as a JSON array of operator objects, all of
which must hold at the same node.

Excluded — **permanently**: taint mode (`mode: taint`, `pattern-sources`,
`pattern-sinks`, `pattern-sanitizers`) is forbidden by `NG-2` and no ADR can
admit it. Excluded until their own ADR: join mode, autofix (`fix`, `fix-regex`),
`metavariable-pattern`, `metavariable-comparison`, `pattern-regex`, and any
cross-file construct. Encountering any of these is a rejection, and the
translator (`T-705`) counts the dropped rule rather than dropping it silently.

## 3. Leaf patterns, metavariables, and ellipsis

A leaf pattern is **source code of the target language with holes**. It is
compiled by that language's front-end (`T-702`), not by the operator layer.

A leaf pattern must be a **single construct**. A multi-statement pattern is
rejected at pack load: it would compile to a whole-file pattern that could only
match at the module root, silently never matching what the author meant. Use
`pattern-inside` for context, or separate rules.

### Metavariables

`$NAME` — uppercase ASCII letters, digits and underscore, beginning with a
letter. A metavariable matches exactly one node and **binds** it.

Binding is **consistent within a single match**: if `$X` appears more than
once, every occurrence must bind structurally equal content. `foo($X, $X)`
matches `foo(a, a)` and not `foo(a, b)`. Equality is structural — canonical
kinds and normalized identifiers, the same basis as `structural_hash` (§5) —
so it is insensitive to formatting.

`$_` is the anonymous metavariable: it matches one node and binds nothing, so
repeated `$_` imposes no equality constraint.

### Ellipsis

`...` matches **any, possibly empty, sequence of sibling nodes**. `foo(...)`
matches `foo()`, `foo(a)` and `foo(a, b, c)`. In statement position it spans
any run of statements, which is what makes `pattern-inside` useful.

Ellipsis is a sequence operator, never a node: it may not be bound to a
metavariable and may not appear as the entire leaf pattern.

Adjacent ellipses (`..., ...`) are rejected at load: they are redundant — the
pair is exactly `...` — and they multiply the search space for nothing. A single
child sequence may contain at most **four** `...` items; matching a sequence
with *k* ellipses against *n* siblings explores O(n^k) splits, and rule packs
are external data.

### First-solution semantics — a deliberate divergence from Semgrep

MS-PAT-1 matching finds the **first** solution, not all of them, and does not
backtrack across operator boundaries once a sub-match has succeeded:

- ellipsis splits are tried **shortest-first**,
- `pattern-either` takes the **first branch in declaration order** that matches,
- a conjunction (`patterns`) threads the bindings the earlier operand produced;
  if a later operand then fails, earlier choice points are **not** revisited.

So `foo(..., $X, ...)` followed by a sibling `$X` binds `$X` to the *first*
candidate and reports no match if the sibling disagrees, even where some other
split would have satisfied both. Semgrep explores these; we do not.

This is the "unless our documented semantics say otherwise" case from ADR 0014:
a disagreement of this shape is **not** a matcher bug. It buys deterministic,
bounded matching (`DET-001`) over untrusted input. If a translated corpus ever
needs full multi-solution matching, that is its own ADR — the dropped-rule count
is the signal.

### The placeholder convention

`$X` is not valid Python or JavaScript, so a front-end cannot hand pattern text
straight to `ruff`/`swc`. Front-ends **must** compile leaf patterns by
substitution:

1. Lex the pattern text and replace each `$NAME` with the reserved identifier
   `__ms_metavar_NAME`, and each `...` with a language-appropriate placeholder
   that parses in the position it occupies.
2. Parse the substituted text with the real parser.
3. Lower into the common tree (§4), converting placeholder identifiers back
   into metavariable and ellipsis pattern nodes.

The reserved prefix `__ms_metavar_` MUST NOT be treated as a metavariable when
it appears in *scanned source* — only pattern text is substituted. A rule whose
pattern text fails to parse after substitution is rejected at pack load.

## 4. The common tree

Both front-ends lower into one language-independent tree (ADR 0015 decision 5).
Node kinds are **MultiScan's own canonical vocabulary**, not `ruff`'s or
`swc`'s: identity must not change when a parser renames a node or when a
language's front-end is replaced.

The vocabulary is **closed and append-only**. Adding a kind is routine. Renaming
or removing one changes `structural_hash`, hence `finding_id`, hence every
user's baselines and suppressions — that is on CLAUDE.md's stop-and-ask list and
requires an ADR.

Nodes carry a source span for reporting. Spans are **never** part of identity
(§7.7.3).

## 5. Identity

For a match, `structural_hash` consumes:

- the **canonical kinds** of the matched subtree in **pre-order traversal**, and
- the **normalized identifiers** of that subtree, in the same order,

and excludes spans, line and column numbers, raw literal text, and the
formatting of the source. This is the definition frozen by the
`StructuralPattern` identity tuple (§7.7.2: rule ID, normalized path,
`structural_hash`).

The hash's domain separator is frozen at `multiscan:structural_hash:v1`.

Consequence, and the point of the whole design: **reformatting a file does not
change a Finding's `finding_id`** (`SAST-002`).

## 6. What the matcher may not do

`SAST-001`: patterns are data. The compiled pattern representation has **no
variant capable of expressing execution** — no eval, no shell-out, no callback,
no regex hook. This is a property of the type, not a check performed at load.

Rule iteration and metavariable binding use ordered collections; match emission
is sorted before it reaches a `FindingSink` (`DET-001`, `DET-002`).

Pattern nesting depth and match recursion are bounded. Pattern text arrives
from translated community corpora and scanned source arrives from the repo:
both are untrusted input.
