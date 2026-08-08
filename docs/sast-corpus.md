# SAST corpus audit (`T-705`)

The record of which community corpora were examined, what their licences
actually permit, and what survived translation into `MS-PAT-1`. Per ADR 0014
decision 4 the licence check is blocking, so this audit is a prerequisite to
shipping anything — not documentation written after the fact.

**Nothing here is shipped yet.** Publishing a pack to the feed channel is a
distribution decision, and it is the user's.

## Licence audit

| Corpus | Licence | Admissible |
|---|---|---|
| [`semgrep/semgrep-rules`](https://github.com/semgrep/semgrep-rules) | "Semgrep Rules License v1.0" — a bespoke licence, not OSI/SPDX | **No** |
| [`trailofbits/semgrep-rules`](https://github.com/trailofbits/semgrep-rules) | AGPL-3.0 | **No** |
| [`elttam/semgrep-rules`](https://github.com/elttam/semgrep-rules) | MIT | Yes |
| [`gitlab-org/security-products/sast-rules`](https://gitlab.com/gitlab-org/security-products/sast-rules) | MIT Expat (compound `LICENSE`) | **Yes — selected** |

The Semgrep community registry is the landmine ADR 0014 named, and the gate
caught it: its `LICENSE` is a bespoke "Semgrep Rules License v1.0", which is
not on the redistributable list and cannot be added without its own review.
AGPL-3.0 is excluded for the same reason — redistributing derived rule content
under it would impose AGPL obligations on MultiScan.

GitLab's `LICENSE` is compound: `doc/`, `ee/` and `jh/` carry other terms, and
everything else is MIT Expat. **That repository contains none of those three
directories**, so the entire corpus falls under the MIT clause. Verified, not
assumed.

Attribution is carried: `--license-file` is mandatory, and the licence text and
copyright notice ride verbatim in `provenance.license_text` of every pack. An
SPDX identifier alone is identification, not attribution.

## Reproducing the translation

```bash
cargo xtask translate-rules \
  --from        <checkout of sast-rules> \
  --source      https://gitlab.com/gitlab-org/security-products/sast-rules \
  --license     MIT \
  --license-file <checkout>/LICENSE \
  --date        2026-08-08 \
  --out         <pack>.json
```

## What survived

Of 645 rule files: **135 translated, 480 dropped**, and of those 135, **61
compile and run**.

| Stage | Dropped | Why |
|---|---|---|
| Translate | 324 | Language out of scope — Java, Go, C#, Scala, C (ADR 0013 covers Python and JS/TS) |
| Translate | 123 | Taint mode — forbidden permanently (`NG-2`) |
| Translate | 27 | `metavariable-*` operators — out of subset |
| Translate | 6 | Autofix and regex operators — out of subset |
| Load | 10 | Over the ellipsis cap, plus one duplicate rule id in the corpus |
| Compile | 64 | Leaf pattern text did not parse — **see below** |

**61 working rules across Python and JavaScript/TypeScript**, and they fire
zero times against the quiet corpus (`FP-006`) — the false-positive gate
holding against real community rules rather than a synthetic fixture.

## The one gap worth closing

Almost all 64 compile failures are the same thing: **multi-statement leaf
patterns**, which `MS-PAT-1` currently rejects. Real rules routinely write

```yaml
pattern: |
  $X = require('buffer')
  ...
  new $X(...)
```

Semgrep matches that as a *statement subsequence* anywhere in a block. We
compile a leaf pattern into a single construct, so a two-statement pattern
becomes a whole-module pattern that could only ever match at file root — which
is why it is rejected rather than silently mismatching.

Supporting it means a new pattern form that matches a contiguous run of
statements inside any block, regardless of that block's kind. That is a
**widening of `MS-PAT-1`**, and ADR 0014's consequences are explicit that
widening the subset "is a new ADR, not a translator patch". So it is recorded
here rather than done.

The remaining handful are genuine Semgrep syntax we do not implement — typed
metavariables, deep-expression operators — and one JSX-valued pattern.

## Notes for whoever ships this

- 61 rules is a real starting corpus, not a placeholder; but the dropped-rule
  count is the metric ADR 0014 asks us to watch, and at 480/645 it is
  dominated by out-of-scope languages, which is expected and benign.
- `elttam/semgrep-rules` was translated too and yielded **2** usable rules: its
  content is overwhelmingly Java and Go. Admissible, but not worth shipping.
- Re-running the translator over the same checkout produces a byte-identical
  pack; the date is injected rather than read from the clock.
