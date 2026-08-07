---
name: adr
description: Author an Architecture Decision Record for MultiScan following the repo's ADR conventions — numbering, front-matter, index update, SDD amendment pointers. Use whenever a change deviates from, extends, or amends MULTISCAN-SDD-v1.0.md, resolves an open question (Q-nn), or lands on the CLAUDE.md stop-and-ask list.
---

# Write an ADR

An ADR is the only sanctioned record of a deviation from the spec: when spec
and code disagree, the code is wrong **unless an ADR says otherwise**. Write
one whenever a decision deviates from, extends, or amends the SDD, resolves an
open question (`Q-nn`), or is on the CLAUDE.md stop-and-ask list.

## Steps

1. **Number and duplicates.** List `docs/adr/` — next number is the highest
   `NNNN` + 1, zero-padded. Check no existing ADR already covers the decision;
   ADRs are append-only, so a changed decision gets a *new* ADR that
   supersedes the old one (set the old one's Status to `Superseded by ADR
   NNNN`) — never rewrite history.
2. **Read for voice.** Read `docs/adr/README.md` (conventions section) and the
   two most recent ADRs. Match their tone: concrete, evidence-first context;
   decisions stated as rules; consequences that admit costs.
3. **Write `docs/adr/NNNN-kebab-title.md`:**
   - Title line: `# ADR NNNN: <decision as a statement, not a topic>`
   - Front-matter list:
     - `Status:` `Proposed` when it is a product-direction call the user has
       not explicitly made — the user flips it to `Accepted`. `Accepted` only
       when recording a decision the user already made or directed.
     - `Date:` today, absolute (YYYY-MM-DD).
     - Relationship line: `Deviates from` / `Extends` / `Amends`, naming the
       exact SDD section (`§n.n`) or requirement ID. Amending a normative
       requirement is the strongest claim — use it only when requirement text
       changes.
   - Sections, in order: `## Context` (the evidence and forces — cite
     requirement IDs, measurements, and real examples, not vibes),
     `## Decision` (numbered rules, testable where possible),
     `## Consequences` (including costs and new obligations, e.g. golden-vector
     or `formula_version` fallout), `## Rejected alternatives` (each with the
     reason it lost — this section is what makes the ADR useful in a year).
4. **Update the index.** Add a row to the table in `docs/adr/README.md`:
   `| [NNNN](NNNN-file.md) | Title | Status | Relationship |`. Bold the verb
   in the relationship column only for `**Amends**`.
5. **If a normative requirement changed:** also edit the requirement's text in
   `MULTISCAN-SDD-v1.0.md` and append an inline `(Amended by ADR NNNN — one
   clause summary)` pointer, so the normative document reads true on its own.
6. **If the ADR resolves or narrows a `Q-nn`:** update that question's row
   where it lives (spec §17 or `docs/phase-2.md`) to point at the ADR.

## Rules that bite

- Use spec §2 vocabulary (`Finding`, `Engine`, `RuleSet`, …) — `make
  lint-vocab` enforces it. Never `vuln`, `issue`, `plugin`, `scanner`.
- Per R-7, when the underlying question is genuinely the user's call, the ADR
  documents the *conservative default* and goes out as `Proposed` — do not
  launder a guess into `Accepted`.
- One decision per ADR. Two decisions that could be ratified separately are
  two ADRs.
- Commit as `docs: ADR NNNN — <short title>`; include the ADR number in any
  related implementation commits, e.g. `[T-nnn] engine: ... (ADR NNNN)`.
