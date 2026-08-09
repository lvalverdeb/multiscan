# Translated rule packs

`sast.json` is a **mechanically translated** community corpus, not authored
content — §1.2 forbids MultiScan authoring vulnerability knowledge, so this is
consumed from upstream and filtered to the `MS-PAT-1` subset (ADR 0014).

| | |
|---|---|
| Upstream | [`gitlab-org/security-products/sast-rules`](https://gitlab.com/gitlab-org/security-products/sast-rules) |
| Licence | MIT Expat — full text carried in `provenance.license_text` |
| Translated | 2026-08-08 by `cargo xtask translate-rules` |
| Rules | 135 translated from 645 files; 480 dropped, counted by reason in `provenance` |

Every rule carries its own `provenance` naming the upstream id, source and
licence, so a Finding can be traced back to the rule that produced it.

**Regenerate, never hand-edit.** The exact command and the licence audit for
every corpus considered are in [`docs/sast-corpus.md`](../docs/sast-corpus.md).
Re-running over the same checkout produces a byte-identical pack.

## Serving it

The pack reaches a scan through the feed channel, not the binary: set
`sast_rules_url` in the feed sources and `multiscan db update` fetches it into
the snapshot as `rules/sast.json`. With no pack configured the SAST layer is
inert by design — there is no embedded fallback corpus.
