# ADR 0020: OSV API freshness is opt-in; the mirror stays the default

- Status: Accepted
- Date: 2026-08-08
- Extends: §10 (feeds) and §7.1 (SCA). Resolves §17 **Q-01**; realizes
  `FR-018`.

## Context

Q-01 asked: full OSV mirror, or API queries? Its conservative default was
"local mirror; API only as an explicit opt-in for freshness. Offline is the
default posture." This ADR makes that the decision.

The mirror is right as the default for reasons that have not changed: `FD-003`
says a scan never fetches, `--offline` must produce byte-identical output, and
a pinned snapshot is what makes a scan reproducible and auditable. But a
snapshot is a point in time, and an advisory published after it is invisible
until the next `db update`. For a user who cares about that gap — a release
gate, an incident — asking the API is the right answer.

## Decision

1. **Off unless asked.** Without `--freshness`, only the pinned snapshot is
   consulted and no request is made. `FR-018` is satisfied by construction: the
   default path has no new network call in it.

2. **`--freshness` and `--offline` are mutually exclusive**, and the CLI says so
   rather than silently letting one win. Quietly ignoring `--freshness` under
   `--offline` would leave a user believing they had checked something they had
   not; quietly ignoring `--offline` would break the guarantee that matters more.

3. **It is a feed fetch, not a scan-target request.** It asks a well-known
   advisory service about package coordinates and stays on the allow-listed
   `multiscan-feeds` path (R-6). `api.osv.dev` joins `DEFAULT_ALLOWED_HOSTS`,
   which is a reviewable addition. Nothing may route a scan target through it.

4. **Only package coordinates leave the machine.** purl strings, already public
   in any lockfile. No repository content, file path, or source text. This is
   the property that makes the feature acceptable at all, and it is why the
   query is built from the resolved inventory rather than from findings.

5. **Results merge, never duplicate.** An API-derived finding is emitted with
   the *same* identity a native SCA finding would carry — same purl, same
   advisory id, same lockfile path — and enters the same dedup pass, so the two
   merge and `sources[]` shows both (`FR-004`). Getting this wrong would show a
   user one weakness twice, which is precisely what this product exists to stop.

6. **The API answers "affected", not "how bad".** Freshness findings carry
   `Informational` severity and are ranked by enrichment downstream. Inferring
   severity from an API that did not state one is the passthrough `ENG-004`
   forbids.

7. **Bounded and honest about it.** At most `MAX_QUERIED_PACKAGES` (2,000)
   packages per pass, batched; anything beyond is **reported on stderr, never
   silently dropped**, because a truncated pass that reads as a clean one is
   worse than no pass.

## Consequences

- The default posture is unchanged, so nobody gets new network traffic they did
  not ask for, and `--offline` remains byte-identical (`FR-018`).
- A freshness pass costs one round trip per 100 packages and re-reads lockfiles
  to build the inventory. That is why it is opt-in rather than always-on.
- API answers are positional per batch. A response longer than its query is
  rejected outright rather than zipped, because misalignment would attribute an
  advisory to a package that does not have it — a silent, confident wrong
  answer, the worst failure this code could produce.
- `resolve_inventory_with_paths` is new, and `resolve_inventory` is now a thin
  wrapper over it. The path was already computed and discarded; keeping it is
  what lets freshness findings merge instead of splitting.
- Tests run against a **loopback fixture server**, never a real host
  (CLAUDE.md). The allow-list refusal is tested by pointing at a
  non-allow-listed host and asserting the error arrives before any connection.

## Rejected alternatives

- **Always query the API.** Breaks `FD-003` (a scan never fetches), makes every
  scan non-reproducible, and sends package coordinates for users who never
  asked. The mirror exists precisely so this is not necessary.
- **Drop the mirror and query only the API.** Kills offline operation (`P-6`),
  air-gap bundles, and reproducibility, and puts a third-party service on the
  critical path of every scan.
- **Let `--freshness` silently no-op under `--offline`.** The user would
  believe they had checked for fresh advisories when they had not. A flag that
  lies about what it did is worse than a flag that refuses.
- **Query from findings rather than from the inventory.** Cheaper, but it can
  only confirm what the snapshot already found — it could never surface a new
  advisory against a package the snapshot considers clean, which is the entire
  point of the feature.
