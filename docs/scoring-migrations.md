# Scoring formula migrations

`RSK-004`: a formula change MUST bump `formula_version` and ship a documented
migration note. **Stored scores are never mutated silently** — a Finding keeps
the score it was written with, alongside the `formula_version` that produced it,
so history stays interpretable.

Each section below is the note for one version.

---

## `1` → `2` — reachability (`T-802`, `FR-017`)

**Landed:** phase 2. **Requirement:** `FR-017`, `RSK-006`. **Decided by:** ADR 0013.

### What changed

The formula gains a sixth factor, R:

```
v1:  risk_score = 100 × clamp01(S × E × X × C × A)
v2:  risk_score = 100 × clamp01(S × E × X × C × A × R)
```

R is **module-level reachability** — whether first-party source imports the
affected package at all:

| State | R | Meaning |
|---|---|---|
| `Referenced` | **1.10** | Scanned source imports the package |
| `Unknown` | **1.00** | Unsupported language, unparseable file, or nothing to resolve — the documented default, recorded in `defaults_applied` |
| `NotReferenced` | **0.65** | Source parsed cleanly and no import was found |

### What this is not

R is **not** a dataflow or taint claim. `NG-2` forbids that permanently.
`Referenced` means "the package is imported", not "the vulnerable symbol is
called" — weaker evidence, and the weights are calibrated to that weakness
rather than allowed to dominate the ranking (ADR 0013, consequences).
Symbol-level reachability is deferred until a symbol-rich ecosystem (Go, Rust)
joins the language set (Q-10).

`Unknown` is **neutral, not pessimistic**. It must never behave like
`NotReferenced`: suppressing a real Finding because the parser did not
understand a file is a far worse failure than carrying noise (`RSK-002`).

Per `RSK-006`, R changes **rank, not existence**. A `NotReferenced` Finding is
still reported and still gateable by `--fail-on`; only its `risk_score` falls.

### Impact on existing users

**Users who get no reachability signal see no score change.** With R = 1.00 the
product is arithmetically identical to v1, so every ranking is preserved — which
is the whole reason `Unknown` is neutral rather than pessimistic. The visible
difference for those users is one new entry, `reachability`, in
`score_explanation.defaults_applied`, and `formula_version` reading `2`.

Users scanning Python or JS/TS with the SAST layer active will see scores move:
up to +10% where the package is imported, down to −35% where it demonstrably is
not. **Baselines are unaffected** — `finding_id` does not include the score.

### Migration

None required. Findings stored under `formula_version: "1"` keep their scores
and remain valid; the field records which formula produced them. A rescan
rewrites them under `2`.

If a comparison across the boundary matters, compare `formula_version` first —
a v1 score and a v2 score are not directly comparable for a Finding whose
reachability is anything other than `Unknown`.
