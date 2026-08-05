# multiscan-secrets

Secrets engine: regex rules, entropy analysis, truncated fingerprints (spec §7.2).

## The load-bearing invariant: SEC-101

A detected secret **value never leaves the `fingerprint` function**. Findings carry only:

- the rule id and secret type,
- the location,
- a truncated **keyed** fingerprint (enough to correlate the same secret across files and scans, useless for recovery),
- a heavily-masked preview (`mask`).

No code path may persist, print, or log a raw value — not in Evidence, not in debug output, not in errors. Treat any change that widens what leaves this crate as release-blocking review.

## Detection

- **Rule-based**: regex patterns for known credential shapes (`rules` module). Community-corpus format; rules are data, not code.
- **Entropy-based**: generic high-entropy token detection (`shannon_bits`), gated on `ENTROPY_MIN_LEN`/`ENTROPY_MIN_BITS`. Entropy-only detections are capped at **Medium severity / Heuristic confidence** (SEC-103) — a random-looking string is a hint, not proof.

## Untrusted-input discipline

Scanned files are attacker-controllable: per-file cap 8 MB (secrets live in source and config, not multi-GB blobs), per-line cap 64 KB, tree-walk cap on files visited. Oversized input is skipped with a warning, and the Scan continues.

## Testing

Golden fixtures go in `testdata/corpus/secrets/` — including negatives that must **not** match (UUIDs, hashes, minified JS). Fixture "secrets" are synthetic, never real revoked credentials.

Normative reference: `MULTISCAN-SDD-v1.0.md` §7.2.
