# multiscan-feeds

OSV/EPSS/KEV feed cache, snapshot pinning, and air-gap bundles (spec §10).

MultiScan embeds the engines but consumes community vulnerability data — this crate is where that data arrives, is pinned, and is served to engines. A new CVE ships as a data refresh, never a code release.

## Rules this crate embodies

- **Feed downloads are the only sanctioned network path outside `multiscan-scope`**, restricted to an allow-list of feed hosts (R-6). `FeedError::NotAllowed` fires *before* any connection is attempted.
- **`multiscan db update` is the only command that fetches.** A Scan pins one `FeedSnapshot` for its entire duration and never updates mid-run (FD-002, FD-003), so two engines in the same Scan can never disagree about advisory data.
- **Staleness is never silent.** Too-old feeds warn on stderr; under `--offline` they are a hard exit 5 (FD-004).
- Snapshots and bundles are content-addressed and signed (`signing` module) for provenance (FD-006).

## Modules

| Module | Contents |
|---|---|
| `fetch` | `FeedClient`, `DEFAULT_ALLOWED_HOSTS` — the allow-listed HTTP path |
| `cache` | Snapshot layout on disk: `Snapshot`, `SnapshotManifest`, `write_snapshot`, `current_snapshot` |
| `update` | `multiscan db update` implementation, `FeedSources` |
| `enrich` | `Enrichment` — EPSS/KEV lookups engines and risk scoring consume |
| `bundle` | Signed air-gap bundle export/import (FR-011) |
| `signing` | ed25519 key handling for bundle signatures |

## Testing

`cargo xtask offline` runs the crate under a network-denying sandbox that fails on any network syscall — `--offline` correctness is verified, not assumed. Never point a test at a real feed host; use recorded responses.

Normative reference: `MULTISCAN-SDD-v1.0.md` §10.
