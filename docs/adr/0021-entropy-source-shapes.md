# ADR 0021: Source shapes are exempt from the entropy fallback

- Status: Accepted
- Date: 2026-08-10
- Extends: ADR 0005, which narrowed the same detector for content-addresses.
- Deviates from: `MULTISCAN-SDD-v1.0.md` §7.2 (SEC-103), which specifies the
  entropy detector's threshold behaviour and no exemptions. SEC-101 and the
  Medium/Heuristic cap are untouched. FP-001 (§13.3) bounds the fallback on
  *machine-generated* content; this widens it to hand-written source, which
  FP-001 does not contemplate. FP-002 holds unchanged — the exemptions are
  heuristic-tier only and never silence a provider rule.

## Context

ADR 0005 removed the content-address flood. A scan of a 15-package Python and
Rust workspace afterwards returned **799 findings, 697 of them
`high-entropy-string`** — and of those 697, all but a handful were ordinary
source text:

| shape | example |
|---|---|
| `snake_case` test name | `test_parquet_reader_supports_lazy_dask_with_explicit_pyarrow_fs` |
| `PascalCase` class | `PafActionsTrackerCube`, `_HybridEngineBoundDataset` |
| `SCREAMING_SNAKE` constant | `MAGIC_NUMBER_WELL_KNOWN_PORTS` |
| filesystem path | `/var/folders/j1/T/boti_sql_manager/warehouse/events` |
| `/`-joined prose | `Postgres/MySQL/ClickHouse`, `SQL/Parquet/field-map` |

The cause is structural, not incidental. Shannon entropy measures symbol
variety, and a 20-character identifier drawn from mixed-case letters plus `_`
clears 4.0 bits/symbol as easily as a base62 key does. The candidate charset
`[A-Za-z0-9+/_\-]` includes the joiners — `_`, `-`, `/` — so a whole path or
a whole test name arrives as one token.

The consequence is the one ADR 0005 already named: the workspace *did* contain
credential-shaped strings — a registry token in a gitignored `.env`, password
hashes pasted into a notebook — and they were ranked among 697 identifiers,
which is indistinguishable from not reporting them.

## Decision

Add a third token-level class to `noise.rs`, alongside digests and UUIDs:
`source_shaped`, the union of two shapes. As with ADR 0005 this narrows the
**fallback only** — precise provider rules run on every file, always.

**`word_shaped`** — the token splits on `_`, `-`, `/` and then at `camelCase`
boundaries into segments where:

- every segment is letters with at most 3 trailing digits (`s3`, `utf8`,
  `sha256`), or a pure number of at most 4 digits;
- the segments average ≥ 3.0 characters — the discriminator. Identifiers
  decompose into words; credential alphabets shred into 1–3 character
  fragments (`zqR4tL8vNb2xJd6…` → `zq`, `R4`, `t`, `L8`, `v`, `Nb2`, `x`,
  `Jd6`, …);
- an all-caps run produced by a `camelCase` split is at most 8 characters, so
  `AKIAIOSFODNN7EXAMPLE` is not a name. `SCREAMING_SNAKE` words arrive already
  delimited and are not capped;
- there are at least 2 segments. A token that does not decompose at all is a
  key shape, however alphabetic;
- the token contains no `+`. It is not an identifier character in any language
  we scan, and it is in the base64 alphabet.

**`path_shaped`** — a `/`-joined token of ≥ 2 components where no component
independently trips the detector's own length-and-entropy bar, and the
components average ≤ 10 characters. Real paths have many short components;
a credential's slashes are sparse, so its components are long. The documented
AWS secret-key shape `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` averages 13.3
and stays in scope.

## Accepted trade-offs

- A credential that decomposes into word-shaped segments averaging ≥ 3
  characters is exempted — a passphrase-style secret such as
  `correct-horse-battery-staple` is missed by the fallback. Such strings
  rarely clear 4.0 bits in the first place, and provider-issued tokens are
  mixed-case base62 with scattered digits, which cannot pass the segment test.
- A `/`-joined chain of pure-alphabetic runs with short components is read as
  a word chain (`Postgres/MySQL/ClickHouse`), so a hypothetical secret of that
  exact shape is missed. Every real provider format mixes case and digits.
- An identifier carrying more than 3 consecutive digits stays flagged
  (`test_sc001_sql_load_benchmark`). Tightening further would start to admit
  credential shapes; this is left as residual noise rather than fixed.
- All three are heuristic-tier losses (SEC-103 caps the fallback at
  Medium/Heuristic) bought against a 95% cut in false positives. The
  alternative — telling users to write `entropy_exclude` globs for their own
  source tree — makes zero-config scanning useless on any real codebase.

## Consequences

- The workspace above drops from 697 entropy findings to ~40, and the
  credential-shaped strings it contains rank at the top rather than the middle.
- As in ADR 0005, `finding_id`s of the suppressed class disappear from scan
  output and baselines carrying them stop matching. `finding_id` construction
  is unchanged.
- Golden corpus unchanged: the fixtures contain no identifier-shaped tokens
  above the entropy floor.
