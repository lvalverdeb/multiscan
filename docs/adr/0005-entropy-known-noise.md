# ADR 0005: Known-noise handling for the entropy fallback

- Status: Accepted
- Date: 2026-08-06
- Deviates from: `MULTISCAN-SDD-v1.0.md` §7.2, which specifies the entropy
  detector's threshold behaviour (SEC-103) but no exemptions; and §4.5, whose
  config sample has no `entropy_exclude` key. Adds behaviour and config the
  spec does not define; SEC-101/SEC-103 are untouched.

## Context

The generic high-entropy detector fires on any ≥20-char `[A-Za-z0-9+/_\-]`
run at ≥4.0 bits/symbol. Two content classes dominate its false positives:

1. **Content-addresses**: hex digests sit *exactly* at the 4.0 bits/symbol
   ceiling (hex has 16 symbols), and the candidate charset includes `/`, so a
   registry URL's whole path arrives as one token. A real scan of a Python
   workspace produced 1,586 findings — 100% false positives, 1,550 of them
   checksum URLs in `uv.lock`.
2. **Machine-written files**: lockfiles, IDE state, minified bundles — noise
   by construction.

Flood at this scale is a detection failure, not a cosmetic one: a real leaked
key ranked #1,551 in a report is effectively undetected.

## Decision

Narrow the entropy **fallback only** — the precise provider rules (AWS,
GitHub, Slack, Google, private-key, JWT) run on every file, always. A real
credential pasted into a lockfile is still caught by them.

**Path level** (`noise.rs::entropy_noise_path`): the fallback is silenced for
a built-in list of known-noise files — lockfile basenames (`uv.lock`,
`Cargo.lock`, `package-lock.json`, `yarn.lock`, `go.sum`, …), `.idea/` and
`.vscode/` segments, `*.min.js`/`*.min.css`/`*.map` suffixes. Extensible via
a new `[scan.secrets] entropy_exclude` glob list (compiled with the other
excludes at config resolution; bad globs exit 2). `[scan.secrets]` gets its
own schema type (`SecretsScanConfig`) to carry the extra key; `[scan.sca]`
and `[scan.iac]` keep the plain `LayerScanConfig`.

**Token level** (`noise.rs`): in ordinary files, a candidate token is exempt
from the fallback when its shape identifies it as a content-address:

- pure-hex at a standard digest length (32/40/56/64/96/128);
- an RFC 4122 UUID (8-4-4-4-12);
- embedded in a URL — a `://` earlier on the line with no URL-terminating
  delimiter before the token.

## Accepted trade-offs

- A **hex-encoded** credential at a digest length is indistinguishable from a
  digest by shape and will be missed by the fallback. Hex-encoded secrets at
  exactly these lengths are rare; provider-issued tokens are mixed-case
  base62/base64 and unaffected.
- A secret passed as a **URL query parameter** is exempted with the URL.
  Provider-shaped tokens in URLs are still caught by the precise rules.
- Both are heuristic-tier losses (the fallback is already capped at
  Medium/Heuristic, SEC-103) bought against the elimination of the dominant
  false-positive classes. Rejected alternative: downgrading these tokens to
  `low`/`info` instead of skipping — it keeps the flood, just quieter, and
  `--min-severity` is a display filter, not a gate.

## Consequences

- Zero-config scans of real repositories start clean: the 1,586-finding
  workspace above reports 0 secrets findings with no `multiscan.toml` at all.
- `finding_id`s of suppressed-class findings disappear from scan output;
  baselines carrying them simply stop matching (they gated nothing real).
- Golden corpus unchanged (skeleton fixtures contain none of these shapes).
