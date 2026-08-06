# ADR 0007: Dockerfile checks in the IaC engine

- Status: Accepted
- Date: 2026-08-06
- Extends: `MULTISCAN-SDD-v1.0.md` §7.3, which scopes the IaC engine to
  Terraform HCL and Kubernetes YAML/JSON. Adds a third input class; the
  normalized-resource + data-policy architecture is unchanged.

## Context

Dockerfile misconfigurations — running as root, `ADD`-ing a remote URL,
piping `curl | sh`, baking secrets into `ENV`, floating base tags — are a
standard, high-signal class the engine did not cover. `classify()` handled
only `.tf` and `.yaml`/`.yml`.

## Decision

A Dockerfile is not declarative: it is an ordered instruction list with build
stages, so the ordering-sensitive facts (the *effective* final `USER`, which
stage is final) must be computed before policy evaluation. `dockerfile.rs`
folds each build stage into one `Resource` of kind `dockerfile_stage`,
exposing normalized boolean attributes:

- `is_final_stage` — only the last stage becomes the runtime image.
- `effective_user_root` — the stage's last `USER` is root/`0`, or none is set
  (per CIS-DOCKER-4.1, an image should declare a non-root user).
- `adds_remote_url`, `curl_pipe_shell`, `secret_in_env`, `base_image_floating`.

The evaluator is untouched: five new pack policies (`cis-docker-*`, pack bumped
to 1.1.0) match `dockerfile_stage` with the existing closed condition set.
`run-as-root` is `all[is_final_stage, effective_user_root]`, so a builder
stage running as root does not flag — only the final image's user matters.
Each policy carries a CWE and ≥1 compliance control (no `mapping_gaps`).

Parsing is bounded (line-continuation aware, comment-stripped, stage cap) as
untrusted input. `secret_in_env` fires only on literal values, never on
`$ARG` references, to avoid flagging legitimate build-time injection.

## Consequences

- `Dockerfile`, `Dockerfile.<env>`, `*.Dockerfile`, and `Containerfile` are
  scanned; `Dockerfile.md`/`.txt`/… (documentation) are not.
- Findings share the `IacMisconfiguration` identity and the normal severity
  map, so they dedup, gate, and render like any IaC finding.
- Semantic depth stops at static instruction analysis: base-image contents
  (a non-root `USER` set by the base) are unknown, so an absent `USER` is
  treated as root — a deliberate, CIS-aligned false-positive-leaning choice
  documented in the remediation text.
