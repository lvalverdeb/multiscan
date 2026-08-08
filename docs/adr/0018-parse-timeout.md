# ADR 0018: Bound source parsing with a worker-thread timeout

- Status: Accepted
- Date: 2026-08-08
- Extends: §7.5 (SAST). Resolves `docs/phase-2.md` Q-12. Does not change any
  requirement's text, but takes on a documented tension with P-4 and `DET-007`
  (below).

## Context

The `T-704` fuzz soak found that `swc`'s TypeScript grammar backtracks
exponentially. Measured on the reproducers committed in
`testdata/corpus/sast-pathological/`:

| Bytes | Python | JavaScript | TypeScript |
|---|---|---|---|
| 111 | fast | fast | 20.1 s |
| 120 | fast | fast | 30.5 s |
| 151 | fast | fast | 6.9 s |
| **203** | fast | fast | **> 10 min — killed, never completed** |

A 203-byte file committed to a repository made any scan of that repository
hang. Reachable by anyone who can open a pull request, vendor a dependency, or
push a fork — in a tool whose stated threat model is parsing untrusted input.

Nothing already in the codebase bounded it. `MAX_SOURCE_BYTES` is irrelevant at
203 bytes; `MAX_MATCH_STEPS` bounds matching rather than parsing; and
`ScanContext`'s `deadline` and `cancel` are read **between** files, so on the
unbounded input control never returns to check them. Ctrl-C did not help.

It is not JSX ambiguity — tested with `tsx: false`, which is equally slow — so
it cannot be avoided by configuring the grammar.

## Decision

1. **Every scanned file is parsed on a worker thread with a wall-clock
   budget.** `PARSE_TIMEOUT` is **5 seconds**: roughly 300× the slowest
   legitimate *whole-corpus* parse ADR 0015 measured (554k LOC of Python in
   117 ms). No real single file approaches it.

2. **A timed-out worker is abandoned, not killed.** Rust cannot kill a thread.
   The worker keeps running until it finishes — possibly never. This is the
   unavoidable cost of the approach and is bounded by decision 3, not wished
   away.

3. **After `MAX_PARSE_TIMEOUTS` (3) timeouts, that language is abandoned for
   the rest of the scan.** Without this a repo full of pathological files would
   leak one CPU-burning thread per file; with it the damage is capped at three
   per language regardless of repo contents. Python and JS/TS are tracked
   separately, so a TypeScript blowup never stops Python from being scanned.

4. **A timed-out or skipped file degrades the outcome to `Partial`**, exactly
   as a malformed file does. A file we failed to read cannot close findings
   (§7.7.4).

5. **Both parse paths are bounded** — the Engine's `scan()` and reachability's
   `Index::build` (`T-802`). Leaving either unbounded would leave the hang
   reachable.

## Consequences

- **A wall-clock timeout is machine-dependent, and that is a real tension with
  P-4 ("deterministic or it's a bug") and `DET-007`'s 100-run byte-compare.**
  Three things keep it contained, and none of them is "it probably won't
  happen":
  - A timed-out file yields no tree, exactly as a parse error does, so the
    *finding set* is identical either way. Only the degradation reason differs,
    and outcome reasons do not reach stdout.
  - The budget sits ~300× above any legitimate parse and far below the
    pathological cases (6.9 s at the fastest). The band where the outcome could
    flip is empty for real inputs.
  - Discovery is sorted, so which files are attempted before the cap is reached
    does not depend on scheduling.

  It remains true that on a sufficiently overloaded machine a legitimate file
  could trip the budget. That is an accepted, documented cost of terminating at
  all — not a claim that it cannot happen.

- **Threads enter an engine for the first time.** The architecture is
  deliberately async-free (`deny.toml` bans tokio) and stays so: this is
  `std::thread` plus `mpsc::recv_timeout`, needs no `unsafe`, and
  `#![forbid(unsafe_code)]` is untouched.

- One thread is spawned per scanned file. At ~10–50 µs per spawn this is tens
  of milliseconds across a large repo, against `NFR-001`'s 10-second budget.

- The bound is a backstop for *any* parser pathology, not a patch for one
  grammar. If a future front-end has its own blowup, it is already contained.

- Q-12 is no longer release-blocking. The exposure that remains is bounded
  CPU waste on a repo that deliberately contains such files, not a hang.

## Rejected alternatives

- **Raise it upstream with swc and wait.** Correct to do anyway, but it leaves
  users exposed until a fix ships and is adopted — and the fix would need a
  version bump past the exact pin ADR 0015 chose deliberately.
- **Drop TypeScript support.** Discards a language ADR 0013 selected on
  prevalence, to avoid a bug that a timeout contains.
- **Skip `.ts` files above some size.** The inputs are 111–203 bytes. Size
  carries no signal here.
- **Detect the pathological shape and refuse it.** A heuristic on adversarial
  input is a losing game: it would both miss variants and reject real code.
- **Rely on `ScanContext::deadline`.** It is checked between files, so on the
  unbounded input it is never reached. Making the parse itself deadline-aware
  is the same worker-thread change under another name.
