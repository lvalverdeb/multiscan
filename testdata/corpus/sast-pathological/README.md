# Pathological TypeScript inputs — contained by ADR 0018

**These now back a passing test** (`crates/engines/multiscan-sast/tests/parse_timeout.rs`):
each must be *abandoned* within the parse budget rather than allowed to run.
They remain reproducers for a
denial-of-service in `swc_ecma_parser`'s TypeScript grammar, found by
`cargo +nightly fuzz run sast_parse` (`T-704`) and preserved here so the
evidence is not lost when `fuzz/artifacts/` is cleaned.

The fuzz soak **aborted on a hard timeout** (libFuzzer wrote a `timeout-*`
artifact and exited 70). It did not merely log slow inputs.

## What happens

| File | Bytes | Python | JavaScript | **TypeScript** |
|---|---|---|---|---|
| `ts-backtrack-1.ts` | 111 | fast | fast | **20.1 s** |
| `ts-backtrack-2.ts` | 120 | fast | fast | **30.5 s** |
| `ts-backtrack-3.ts` | 151 | fast | fast | **6.9 s** |
| `ts-backtrack-4-unbounded.ts` | 203 | fast | fast | **> 10 min — killed, never completed** |

The last one is the important one. A **203-byte file did not finish parsing in
ten minutes**, at which point the run was killed; its true cost is unknown and
may be unbounded in practice. `NFR-001` budgets 10 seconds for a cold scan of a
*100k-LOC repo*.

Stated plainly: **committing a 203-byte `.ts` file to a repository makes any
scan of that repository hang.** That is a denial-of-service reachable by
anyone who can add a file — a pull request, a vendored dependency, a fork.

Both front-ends are otherwise fast — ADR 0015 measured 167 MB/s (Python) and
118 MB/s (JS). This is confined to the TypeScript grammar, which backtracks
exponentially on dense ambiguous operator sequences.

## What it is not

Not JSX ambiguity. The obvious hypothesis was that enabling `tsx: true`
unconditionally made `<` maximally ambiguous (type argument vs JSX element vs
less-than). **Tested and disproven**: with `tsx: false` the same inputs take
15.3 s, 30.9 s and 7.2 s. The backtracking is in the TypeScript grammar itself.

Not a memory-safety bug. No crash, OOM, or sanitizer report in any run —
`sast_parse` and `sast_match` cleared 1.05M and 2.33M iterations before the
soak. The failure mode is time, not memory.

## How it is contained

**ADR 0018** bounds every parse with a 5-second worker-thread timeout; a
timed-out worker is abandoned, and after three timeouts that language is
abandoned for the rest of the scan. Timed-out files degrade the outcome to
`Partial`, so nothing is ever wrongly closed (§7.7.4).

The upstream grammar bug is **not fixed** — it is contained. What remains is
bounded CPU waste on a repo that deliberately ships such files, not a hang.

None of the pre-existing bounds reached it, which is why a new one was needed:

- `MAX_SOURCE_BYTES` (4 MiB) is irrelevant — these inputs are 111–203 bytes.
- `MAX_MATCH_STEPS` bounds *matching*, not *parsing*.
- `ScanContext::deadline` is checked **between** files, never during a parse.
  For the 20–30 s inputs that means the scan degrades to `Partial` late; for
  `ts-backtrack-4-unbounded.ts` it means the deadline is never reached at all,
  because control never returns. Ctrl-C does not help either: `ctx.cancel` is
  read at the same points.

That is exactly what ADR 0018 does, with the abandoned-thread cost accepted
explicitly and capped.

## Open question

Recorded as **Q-12** in `docs/phase-2.md`. It is a cost of ADR 0015's parser
selection that the evaluation did not surface, because the evaluation measured
throughput on real corpora and this is an adversarial input. Options are: raise
it upstream with swc, pin around it if a fixed release appears, bound it with a
worker-thread timeout, or accept it and document the exposure. That choice
belongs to the user.

**Severity note.** This is not a slow-scan annoyance. It is a hang triggerable
by a 203-byte file, in a security scanner whose stated threat model is
"parsing untrusted input", and it is trivially reachable in CI by anyone who
can open a pull request. Treat it as release-blocking for TypeScript scanning
until it is bounded or accepted deliberately.
