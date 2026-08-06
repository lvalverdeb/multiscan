# ADR 0010: Rule-pack distribution through the feed channel

- Status: Accepted
- Date: 2026-08-06
- Builds on: ADR 0005/phase-1 (secrets rules as an embedded versioned pack) and
  the feed/snapshot mechanism (FD-002, T-306 signed air-gap bundles). Extends
  §7.2 and §10; the core principle is CLAUDE.md's "embed the engines, consume
  the community data."

## Context

Phase 1 moved secrets rules into a versioned, blake3-digested pack
(`rules/builtin.json`) advertised via the engine manifest. But the pack was
still *embedded*: a new detector meant a binary release. The whole point of the
feed architecture is that knowledge ships as data — a new CVE is a feed refresh,
never a code change. Detection rules should work the same way.

## Decision

A feed snapshot may **carry** engine rule packs. `SnapshotData.rule_packs`
(name → JSON bytes) is written as `rules/<name>.json`, digest-verified like
every other snapshot file and included in the content-addressed `snapshot_id`.
Because signed air-gap bundles (`db export`/`import`, T-306) already tar every
snapshot file, packs ride the **signed** bundle automatically — that is the
distribution channel.

At scan time the CLI resolves the effective secrets pack:

1. If the pinned snapshot has `rules/secrets.json` and it parses, use it.
2. Otherwise use the embedded builtin.
3. `[rules] secrets_pack = "id@version"` selects the pack that satisfies the
   pin; if neither the snapshot pack nor the builtin matches, the embedded
   baseline is used and a warning is printed.

The resolved pack builds the engine (`SecretsEngine::with_pack`), so the
manifest `rule_set` provenance and the ENG-004 severity map reflect what
actually ran. `--verbose` logs the chosen pack's id, version, digest, and
source.

## Safety

A distributed pack is signed and digest-verified, but still external data,
handled defensively:

- **No ReDoS.** Rust's `regex` is linear-time with no backtracking, so a hostile
  pattern cannot hang the scan — the property that makes data-delivered regexes
  safe at all.
- **Bounded.** At most 10,000 rules; patterns over 4 KiB are skipped. A pattern
  that fails to compile is skipped, never fatal (as with the builtin).
- **Integrity.** `Snapshot::rule_pack` reads through the manifest digest check;
  a tampered pack fails to load and the scan falls back to the builtin.
- **Fail-safe.** Any parse/read failure falls back to the embedded baseline;
  the scan never silently loses secrets detection.

## Consequences

- New/updated detectors ship as a signed feed bundle — no binary release.
- Live `db update` fetches advisory feeds only for now; a dedicated rules-feed
  URL can populate `rule_packs` later without changing the consumer contract.
- The mechanism generalizes: IaC and probe packs can be distributed the same
  way when needed.
