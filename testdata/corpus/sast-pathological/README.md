# Pathological TypeScript inputs — a known, unfixed limitation

**These files are not fixtures for a passing test.** They are reproducers for a
denial-of-service in `swc_ecma_parser`'s TypeScript grammar, found by
`cargo +nightly fuzz run sast_parse` (`T-704`) and preserved here so the
evidence is not lost when `fuzz/artifacts/` is cleaned.

## What happens

| File | Bytes | Python | JavaScript | **TypeScript** |
|---|---|---|---|---|
| `ts-backtrack-1.ts` | 111 | fast | fast | **20.1 s** |
| `ts-backtrack-2.ts` | 120 | fast | fast | **30.5 s** |
| `ts-backtrack-3.ts` | 151 | fast | fast | **6.9 s** |

A **120-byte file takes 30 seconds** to parse. `NFR-001` budgets 10 seconds for
a cold scan of a *100k-LOC repo*; one such file exceeds it threefold.

Both front-ends are otherwise fast — ADR 0015 measured 167 MB/s (Python) and
118 MB/s (JS). This is confined to the TypeScript grammar, which backtracks
exponentially on dense ambiguous operator sequences.

## What it is not

Not JSX ambiguity. The obvious hypothesis was that enabling `tsx: true`
unconditionally made `<` maximally ambiguous (type argument vs JSX element vs
less-than). **Tested and disproven**: with `tsx: false` the same inputs take
15.3 s, 30.9 s and 7.2 s. The backtracking is in the TypeScript grammar itself.

Not a memory-safety bug. The fuzzers found no crash: `sast_parse` and
`sast_match` ran 1.05M and 2.33M iterations clean at first, and the longer soak
that produced these units reported slow inputs only.

## Why it is unfixed

The blowup is upstream and cannot be bounded from our side by the usual means:

- `MAX_SOURCE_BYTES` (4 MiB) is irrelevant — these inputs are ~120 bytes.
- `MAX_MATCH_STEPS` bounds *matching*, not *parsing*.
- `ScanContext::deadline` is checked between files, so a scan degrades to
  `Partial` rather than hanging forever — but a single file can still blow the
  budget before the next check.

A real bound needs a per-file parse timeout, which means running the parse on a
worker thread and abandoning it — a design change with its own costs (an
abandoned thread keeps burning CPU until it finishes), and one that should be a
deliberate decision rather than a reflex.

## Open question

Recorded as **Q-12** in `docs/phase-2.md`. It is a cost of ADR 0015's parser
selection that the evaluation did not surface, because the evaluation measured
throughput on real corpora and this is an adversarial input. Options are: raise
it upstream with swc, pin around it if a fixed release appears, bound it with a
worker-thread timeout, or accept it and document the exposure. That choice
belongs to the user, and it is release-relevant for anyone scanning untrusted
repositories.
