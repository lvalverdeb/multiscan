# ADR 0015: Phase-2 source parsers — `ruff_python_parser` and `swc_ecma_parser`, at MSRV 1.95

- Status: Accepted
- Date: 2026-08-07
- Supersedes: ADR 0001 (workspace MSRV 1.85). Resolves `docs/phase-2.md` Q-07
  and amends the evaluation gate ADR 0013 §3 defined. Binds nothing in v1 scope.

## Context

ADR 0013 narrowed Q-07 rather than resolving it: pure-Rust parser families are
evaluated first against an explicit gate — no `unsafe` in our crates,
dependency `unsafe` surveyed and judged wrappable, parse time within `NFR-001`,
fuzz-clean per `NFR-010` — and tree-sitter returns only if both families fail.
It named the Ruff/RustPython family for Python and the Biome/swc families for
JS/TS.

That evaluation was run. One spike crate per candidate declaring
`rust-version = "1.85"`, resolved by cargo's MSRV-aware resolver, built under
`cargo +1.85` and `cargo +stable` (1.97); `unsafe` counted over vendored
registry sources and split into each project's own crates versus shared
foundational dependencies; binary size measured as a stripped LTO release
binary that actually calls the parser, minus a 302,736-byte empty baseline;
throughput measured in-process, single-threaded.

| Candidate | Language | Effective MSRV | Last release | `unsafe` (own crates) | Size Δ | Throughput |
|---|---|---|---|---|---|---|
| `ruff_python_parser` 0.0.8 | Python | **1.95** | 2026-08-07 | **2** | 1.31 MiB | 167 MB/s |
| `rustpython-parser` 0.4.0 | Python | 1.85 | **2024-08-06** | 3 | — | — |
| `biome_js_parser` 0.5.7 | JS/TS | — | **2024-03-12** | — | — | — |
| `swc_ecma_parser` 43.0.0 | JS/TS | **1.88** | 2026-07-29 | **164** | 1.09 MiB | 118 MB/s |
| `oxc_parser` 0.75.x | JS/TS | **1.86** | 2026-08-03 | **621** | 0.55 MiB | 258 MB/s |

Corpora: 1394 Python files / 554k LOC / 19.6 MB, and 1391 JavaScript files /
131k LOC / 4.2 MB. Every surviving candidate parsed its corpus with zero
errors.

Four findings drive the decision.

**The performance and size criteria discriminate nothing.** Parsing 554k LOC —
5.5× the `NFR-001` reference repo — takes 117 ms single-threaded against a 10 s
budget. The two selected parsers add ~2.4 MiB to a 9.8 MiB binary against the
30 MB `NFR-004` cap. ADR 0013's concern that grammars would threaten the cap,
and its Q-09 hedge about downloadable packs, are both moot for pure-Rust
parsers.

**MSRV 1.85 is the binding constraint, and it eliminates every candidate at its
current release.** `swc` fails transitively (`ar_archive_writer` 1.88, `icu_*`
1.86); `ruff_python_parser` declares 1.95 outright. `oxc` is the near miss:
`oxc_parser` 0.75.0 declares 1.85, but its siblings resolve to 0.75.1 requiring
1.86. Exact-pinning the whole family — 11 crates at `=0.75.0` — does build at
1.85, verified, but 0.75.0 is ~68 minor versions behind current (0.143.0) and
the very next patch requires 1.86. The only candidate that builds at 1.85
unpinned is `rustpython-parser`, which has had no release in two years. Both
1.85-compatible options are the same thing: a parser frozen in the past.

**`biome_js_parser` is not a candidate.** Last published 2024-03-12, and it
does not compile standalone on 1.85 or on stable 1.97. ADR 0013 named a family
that is not consumable as an external dependency.

**The `unsafe` ranking is the reverse of the speed ranking.** `oxc` carries 621
`unsafe` sites in its own crates — arena allocator plus parser hot path, which
is to say directly on attacker-controlled input, the threat model CLAUDE.md
names explicitly. `swc` carries 164, `ruff` carries 2. For context the existing
tree already carries 8403 `unsafe` sites across 182 crates (`rustix` 1591,
`libc` 474, `hashbrown` 471), so the meaningful question was never tree-wide
count but how much sits in the parse path.

## Decision

1. **Q-07 resolves to `ruff_python_parser` for Python and `swc_ecma_parser` for
   JavaScript/TypeScript.** These are the two maintained candidates with the
   lowest `unsafe` exposure in the code that parses untrusted input.

2. **The workspace MSRV rises to 1.95, superseding ADR 0001.** The bump lands
   with `T-702` (the language front-ends), not before — raising the floor ahead
   of the capability that needs it would break installs for no benefit. At that
   commit: `[workspace.package] rust-version`, the `clippy.toml` `msrv` keys,
   and the CI `msrv` job toolchain all move together, and the `globset 0.4.19`
   pin (which exists only to hold 1.85) is lifted.

3. **ADR 0013's gate gains two criteria, applied above the existing four.**
   *Candidate MSRV ≤ the workspace floor*, and *actively maintained*. The
   second is not taste: a frozen parser of an evolving language degrades
   silently — new syntax becomes a parse error, which becomes `NotApplicable`
   for SAST and reachability `Unknown`, so the Engine quietly stops covering the
   newest code while still reporting `Complete`. Ranked by how much they
   actually separated candidates, the full gate is: maintenance > MSRV >
   own-`unsafe` > size ≫ speed.

4. **The `NFR-010` fuzz criterion is deferred to `T-704`, not waived.** It is
   only meaningful against the selected parsers. Until `T-704` lands, this gate
   is partially evaluated, and that is a release-blocking obligation, not a
   footnote.

5. **The parser AST never crosses the front-end boundary.**
   `ruff_python_parser` is a `0.0.x` crate published weekly (0.0.6 → 0.0.8 in
   three weeks) as internal Astral infrastructure with no semver guarantee.
   Both parsers are pinned exactly, and each language front-end lowers its
   parser's AST into the common tree the `MS-PAT-1` matcher consumes (`T-701`).
   No `ruff_*` or `swc_*` type appears in a `pub` signature outside its own
   front-end module, so an upstream AST reshaping is a contained edit rather
   than a matcher rewrite.

## Consequences

- **MSRV 1.95 sits within two releases of current stable (1.97), permanently.**
  Astral tracks stable aggressively, so this floor will keep moving. `cargo
  install multiscan` stops working on older toolchains — a user-visible
  regression that the release notes for that version must state plainly. This
  is the accepted cost of the decision, and it is the largest one.
- Pinning both parsers exactly means dependency refreshes become deliberate
  reviewed events rather than resolver drift. The `MS-PAT-1` matcher's golden
  fixtures are the regression net when a pin moves.
- Two parser families means two AST shapes and one common tree. That lowering
  layer is new surface `T-701` must carry, and it is where `DET-001` bites:
  neither front-end may leak `HashMap` iteration order, and node ordering must
  come from source position, not from the parser's internal collections.
- 164 + 2 `unsafe` sites now sit on the untrusted-input path. `T-704`'s fuzz
  target is release-blocking for both front-ends, and the oracle is memory
  safety under malformed source, not merely "returned an error".
- `NFR-004` gains ~2.4 MiB of headroom usage (9.8 → ~12.2 MiB against 30 MB).
  The `T-702` PR states the measured delta, per ADR 0013 Q-09.
- ADR 0001's own rationale (`clap_lex` edition 2024, `ed25519-dalek`,
  `cap-std`) is unaffected and still true; only the floor number changes.

## Rejected alternatives

- **tree-sitter.** ADR 0013's designated fallback, and this evaluation genuinely
  weakened the case against it: the tree already carries thousands of `unsafe`
  sites, `oxc` carries hundreds in its own parse path, and tree-sitter is
  MSRV-insensitive, which would have avoided the treadmill this decision
  accepts. It loses on the non-negotiable #1 review it would require — C in the
  tree, wrapped — being a larger and less reversible commitment than a compiler
  floor. Worth re-examining if the MSRV tax proves intolerable; that would be
  its own ADR, and it should check whether Semgrep's own tree-sitter grammars
  reduce `MS-PAT-1` translation drift.
- **MSRV 1.88, `swc` only, Python deferred.** The smallest MSRV move that
  unlocks a maintained parser, and it avoids ruff's `0.0.x` churn entirely. It
  loses because it ships half of ADR 0013's language set: Python is the larger
  half by both corpus size and SCA prevalence, and deferring it leaves
  workstream B's reachability factor with one ecosystem to evaluate.
- **`oxc_parser` for JS/TS.** Fastest (2.2×) and smallest (half of swc), on the
  lowest MSRV of the maintained JS/TS options. It loses on the only criterion
  that discriminates: 621 `unsafe` sites in its own crates versus swc's 164,
  concentrated in the allocator and parser that consume attacker-controlled
  input. Its speed advantage buys nothing against a budget it beats by two
  orders of magnitude.
- **Hold MSRV 1.85.** Requires either `rustpython-parser` (no release since
  2024-08-06) or an 11-crate exact pin of `oxc` at a version ~68 minors stale.
  Both violate the maintenance criterion this ADR adds, and both would ship an
  Engine that silently stops understanding new syntax.
