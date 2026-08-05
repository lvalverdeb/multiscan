# multiscan-report

Renderers: `table`, `json`, `jsonl`, `sarif`, `sbom`, `markdown` (spec §12).

Each renderer takes a slice of Findings **already sorted** by `sort_findings` — `risk_score` descending, then `finding_id` ascending (CLI-003, DET-002) — and returns the complete stdout payload as a `String`. Renderers never print; keeping machine output on stdout, alone, is the caller's contract (CLI-001).

## Formats

| Format | Output |
|---|---|
| `table` | Human terminal table, severity-banded |
| `json` | Full-fidelity JSON array of Findings |
| `jsonl` | One Finding per line — streaming-friendly |
| `sarif` | SARIF 2.1.0 for code-review integration |
| `sbom` | CycloneDX 1.5 |
| `markdown` | PR-comment friendly; no timestamps in the body so re-runs don't churn the diff (OUT-002) |

## Determinism rules

Output must be byte-identical across runs (`cargo xtask determinism`):

- No `HashMap`/`HashSet` iteration anywhere in a render path — `BTreeMap`/`IndexMap` only (DET-001).
- Sort before rendering; engine emit order is meaningless (DET-002).
- Locale and `TZ` must not reach machine output (DET-006).
- Float comparisons use `total_cmp` (DET-003).

Golden fixtures for renderer output live in `testdata/corpus/`; any diff is a reviewable event and every changed line must be explained in the PR.

Normative reference: `MULTISCAN-SDD-v1.0.md` §12.
