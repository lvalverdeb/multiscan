# ADR 0024: An absolute symlink target is skipped, not hostile

- Status: Accepted
- Date: 2026-08-14
- Extends: `MULTISCAN-SDD-v1.0.md` §7.1 and `SCA-005` (hardened layer
  extraction). The escape invariant is unchanged; what changes is the
  classification of one entry shape that is not an escape.

## Context

`link_target_ok` rejected any symlink whose target was absolute, and the
extractor turned that rejection into `ExtractError::Unsafe`, which aborts the
whole extraction and exits 3. The intent was right — tar extraction is the
most-exploited surface in image scanners (RUSTSEC-2026-0148) — but the rule
caught ordinary content.

Measured against the stock `debian:12` layer pulled on 2026-08-14:

| entry kind | count |
|---|---|
| regular files | 5,237 |
| directories | 778 |
| symlinks | 637 — of which **49 have absolute targets** |
| hardlinks | 2 (both relative) |
| relative targets climbing above the root | **0** |

The 49 are Debian's alternatives system: `etc/alternatives/awk ->
/usr/bin/mawk`, `etc/alternatives/pager -> /bin/more`, and so on. The first one
encountered aborted the scan:

```
multiscan: error: extracting image layers: unsafe layer entry:
  symlink `etc/alternatives/awk` escapes root          → exit 3
```

Every Debian-family image ships these, so image scanning did not work on any
mainstream base image. The synthetic layers in our own tests contain two
regular files and no symlinks, which is why the test suite was green while
nothing real could be scanned.

An absolute target is not an escape. It cannot be honoured inside an extraction
root — there is no `/usr/bin/mawk` there — and it cannot be followed out of
one, because every file operation goes through a cap-std `Dir` that refuses to
resolve outside it. It is simply meaningless in this context. The genuinely
hostile shape is different: a *relative* target that climbs above the root
(`../../../etc/passwd`), which is what an attacker plants to be traversed by a
later entry.

## Decision

1. **Three classes, one of them fatal.** A symlink target is `Contained`
   (created), `Absolute` (skipped and counted), or `Escapes` — relative and
   climbing above the root — which stays `ExtractError::Unsafe`, aborting the
   layer so the caller learns the image was hostile.

2. **Skipped links are counted and reported, never silent.**
   `Stats::skipped_absolute_links` carries the count, separate from `skipped`
   (special files, whiteouts), and `scan image` prints it: `49 symlink(s) with
   absolute targets skipped during extraction`.

3. **This is not a `Partial` outcome.** The package databases are regular
   files, so a dropped `/etc/alternatives` link costs the inventory nothing.
   Marking it Partial would be both untrue and destructive: `scan.partial`
   maps to `Exit::ScanError`, so every Debian-family image would exit 3
   forever, and `FR-015` would refuse to close findings on a scan that was in
   fact complete.

4. **Hardlinks keep the stricter rule.** Their targets are archive-relative by
   construction, and the real layer contains no absolute ones.

## Consequences

- Debian-family images scan. `mirror.gcr.io/library/debian:12` now completes:
  88 packages, 49 links skipped, 24 findings, exit 0.
- A dangling link that a distro *did* intend is absent from the extracted tree.
  Nothing in the OS package path reads through one: `detect_os` already falls
  back from `etc/os-release` to `usr/lib/os-release`, and `read_packages` tries
  each database location directly.
- The escape signal is narrower and therefore more meaningful: an
  `ExtractError::Unsafe` from a symlink now means a target that climbs above
  the root, which no legitimate layer contains.
- Extraction tests gain the shapes a real layer has, including a
  Debian-shaped fixture. The fuzz oracle is unchanged — the canary must survive
  any input — and the target still exercises both classes.

## Rejected alternatives

- **Create the absolute link as a dangling symlink.** cap-std blocks traversal
  through it, so this is arguably safe, but "safe because the next layer of
  defence catches it" is the wrong posture for the most-exploited surface in
  this class of tool, and the link has no meaning in the extracted tree anyway.
- **Skip, and degrade the scan to `Partial`.** Rejected on rule 3: it maps to
  exit 3 and would fail CI on every normal image, which is a worse failure than
  the one being fixed.
- **Rewrite the target to be root-relative** (`/usr/bin/mawk` →
  `usr/bin/mawk`). Invents a link the image never contained, and would make the
  extracted tree disagree with the image it claims to represent.
