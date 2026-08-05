# multiscan-risk

Risk scoring formula and explanations. **Pure — no I/O** (spec §8).

```
risk_score = 100 × clamp01(S × E × X × C × A)
```

Severity, Exposure, eXploit likelihood, Confidence, Asset criticality. The score is a pure function of its inputs (RSK-001): no clock, no RNG, no environment, no hash-order dependence. This is why MultiScan ranks by exploitability rather than raw CVSS — a Critical CVE with no exploit path scores below a Medium secret on an internet-reachable asset.

## Key rules

- **Missing input never nulls a score.** Every factor has a documented default, and every applied default is recorded in `score_explanation.defaults_applied` (RSK-002). `ExploitSignal::Unavailable` → 0.50, no-CVE weaknesses → 0.55, KEV-listed → 1.00, EPSS → banded per spec §8.
- **Every score ships an explanation** — `multiscan explain <id>` renders it. If you add a factor, you add its explanation text.
- **`FORMULA_VERSION` bumps with any formula or factor-derivation change** (RSK-003/RSK-004), together with a migration note. Stored scores are never mutated silently.
- No I/O, no `SystemTime` (spec §5.2, DET-004) — enforced by the purity gate. Use `total_cmp` for float ordering, never `partial_cmp().unwrap()` (DET-003).

## Testing

Scoring vectors live in `testdata/vectors/` and run under `cargo xtask golden`. `cargo xtask determinism` and `cargo xtask safety` are mandatory before pushing changes here.

Normative reference: `MULTISCAN-SDD-v1.0.md` §8.
