# ADR 0006: Opt-in git-history scanning in the secrets engine

- Status: Accepted
- Date: 2026-08-06
- Deviates from: `MULTISCAN-SDD-v1.0.md` §7.2, which scopes the secrets
  engine to files under the scan root; and §4.5, whose config sample has no
  `history` key. Adds an opt-in capability; the default scan is unchanged.

## Context

A secret that was committed and later "removed" is not gone: it sits in the
object store of every clone, and rotating it is the only real fix.
Working-tree-only scanning gives a false clean bill after such a removal —
history-aware scanners catch a large share of real leaks precisely there.

## Decision

`multiscan scan --history` (or `[scan.secrets] history = true`) adds a
history pass to the secrets engine:

- **Enumeration via the system `git` CLI** — `rev-list --objects --all`,
  then `cat-file --batch` in bounded chunks. No git library dependency: gix
  is a large tree, libgit2 is C. The git binary is required only when the
  flag is used; it is never a dependency of a default scan.
- **Bounded like all untrusted input**: 20k-blob cap, 8 MiB per blob (the
  tree-scan cap), 256 MiB cumulative, size headers never trusted past the
  cap, chunked batch I/O that cannot deadlock. Hitting a cap ends the pass
  and the scan reports `Partial` — truncation is never silent.
- **Deduplicated**: blobs are keyed by object id; content still in the index
  is skipped (the tree scan covers it), and identical content under many
  historical paths is scanned once.
- **Same rules, same gating**: the full pack plus the entropy fallback run
  against each blob, with excludes and the ADR 0005 noise rules applied to
  the blob's historical path.
- **Identity untouched**: a history finding uses the same
  `ExposedSecret{rule_id, path, fingerprint}` identity as a tree finding, so
  a secret still present in the tree merges with its history sighting rather
  than duplicating, and baselines keep matching. Provenance (`in git
  history, blob <short-oid>`) goes in evidence only — the oid is public
  object metadata, never the secret (SEC-101 holds).
- **Honest degradation**: `--history` on a non-repo root, or with git
  missing, yields `Partial` (exit 3) with the reason on stderr. The user
  asked for coverage that could not be provided; that must not look clean.

## Consequences

- Opt-in only: default scans spawn no processes and need no git.
- `rev-list --all` covers reachable objects; dangling (unreferenced) blobs
  are out of scope until a future `--history=unreachable` mode.
- Line numbers refer to the historical blob content, not any current file.
