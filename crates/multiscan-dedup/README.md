# multiscan-dedup

`finding_id` construction and `Finding` merge. **Pure — no I/O** (spec §7.7).

One weakness, one Finding (P-2). This crate owns the two operations that define identity across the whole product:

- **`finding_id`** — computed from an identity tuple. Paths are normalized to POSIX, root-relative form *before* identity computation, so a Windows checkout and a Linux checkout of the same repo produce the same IDs (DET-005).
- **`merge`** — folds attributed engine emissions (including Bridge imports) into one deduplicated set, preserving every contributing source in `sources[]`.

## Why purity matters here

`finding_id` is the key for baselines, suppressions, and history. If it drifts, every user's stored state silently invalidates. Consequently:

- No I/O, no clocks, no randomness (spec §5.2, DET-004) — enforced by clippy config, the purity gate, and CI.
- No `HashMap`/`HashSet` anywhere iteration can reach output — `BTreeMap`/`BTreeSet` only (DET-001).
- **Any change to `finding_id` construction requires explicit sign-off.** Do not refactor identity encoding casually; see "When to stop and ask" in `CLAUDE.md`.

## Testing rules

- `cargo xtask determinism` (100-run byte-compare) and `cargo xtask safety` are **mandatory** before pushing changes to this crate.
- Every merge case needs an adversarial near-miss pair that must **not** merge. False-merge and false-split are tracked separately; they trade off, and both matter.

Normative reference: `MULTISCAN-SDD-v1.0.md` §7.7.
