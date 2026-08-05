# Getting Started with MultiScan

MultiScan is a single static binary that scans a **repository, an OCI image, or an
authorized web target** with built-in engines, merges everything into one
deduplicated set of **Findings**, ranks them by *exploitability* (not raw CVSS),
and exits with a policy-driven status code you can gate CI on.

One binary, one vocabulary, one exit contract. This guide walks you from install
to a gated CI scan, step by step.

> Throughout, the tool calls a detected problem a **Finding**, a scanned thing an
> **Asset**, and a built-in checker an **Engine**. That shared vocabulary is the
> whole point — five scanners stop meaning five different things.

---

## 1. Install

### Option A — from crates.io (once published)

```bash
cargo install multiscan
multiscan --version
```

### Option B — build from source

```bash
git clone <this-repo> && cd security-scanner
cargo build --release -p multiscan
./target/release/multiscan --version
```

Optionally put it on your `PATH`:

```bash
cp target/release/multiscan ~/.local/bin/    # or anywhere on PATH
```

The rest of this guide assumes `multiscan` is on your `PATH`.

---

## 2. Load advisory data first

MultiScan **embeds the engines but consumes community data** (OSV, EPSS, KEV).
Software-composition (SCA) scanning needs that feed data locally. Fetch it once
up front — `db update` is the *only* command that touches feed servers:

```bash
multiscan db update       # fetch/refresh OSV + EPSS + KEV snapshots
multiscan db status       # show snapshot ages and digests
```

Re-run `db update` periodically. A new CVE reaches you as a **data refresh**, not
a tool upgrade. If you skip this, secrets and IaC scanning still work, but SCA
will warn that its advisory data is missing.

*(Air-gapped? See §10 for signed offline bundles.)*

---

## 3. Your first scan

Scan the current directory:

```bash
multiscan scan .
```

That runs the full local pipeline — auto-detect applicable layers → run engines in
parallel → dedup into one Finding set → risk-rank → render a table — and exits `0`
if nothing crossed your gate (you have no gate yet, so it exits `0`).

Point it at any path:

```bash
multiscan scan ~/code/my-service
```

### Choose which engines run

By default MultiScan auto-detects applicable layers. To force a subset:

```bash
multiscan scan . --layers sca,secrets,iac
```

Local layers: **`sca`** (dependency/lockfile & OS-package vulnerabilities),
**`secrets`** (hardcoded credentials), **`iac`** (Terraform/YAML/JSON
misconfiguration), **`sast`** (structural scaffold only in v1 — no rules).
`probe` is a web-only layer (see §11).

### Pick a depth profile

```bash
multiscan scan . --profile quick       # fast, shallow
multiscan scan . --profile standard    # default
multiscan scan . --profile thorough    # deepest
```

---

## 4. Read the output — and pick a format

By default you get a human table on your terminal. For machines, choose a format:

```bash
multiscan scan . --format json      # one JSON array — for tools/jq
multiscan scan . --format jsonl     # one Finding per line — for streaming
multiscan scan . --format sarif     # GitHub code scanning, IDEs
multiscan scan . --format sbom      # CycloneDX SBOM of detected components
multiscan scan . --format markdown  # paste into a PR/issue
multiscan scan . --format table     # the default human view
```

**Output discipline (important for scripting):** machine output goes to
**stdout, alone**. All progress, warnings, and diagnostics go to **stderr**. So
this always yields clean JSON:

```bash
multiscan scan . --format json > findings.json      # stdout: pure JSON
multiscan scan . --format json | jq '.[].finding_id'
```

Findings are always sorted deterministically (risk score DESC, then id) — the same
scan produces byte-identical output every time.

To reduce noise in the *human* view (this is a display filter, **not** a gate):

```bash
multiscan scan . --min-severity high
```

---

## 5. Understand a single Finding

Every Finding has a stable `finding_id`. Get the full breakdown — score factors,
evidence, and remediation — for one:

```bash
multiscan explain a3f9c1e0            # id, or any unique prefix
multiscan explain a3f9c1e0 --history  # + its append-only history (needs the DB)
```

The risk score is explained factor-by-factor (severity × exploitability ×
exposure × confidence × asset), and every default that was applied is recorded —
scores are never silently nulled.

---

## 6. Gate your CI — the exit-code contract

This is what makes MultiScan CI-friendly. Exit codes are **distinct and stable**:

| Code | Meaning |
|---|---|
| `0` | Scan completed; nothing met your gate |
| `1` | **Gate threshold met** — the normal "you have findings" CI failure |
| `2` | Usage error (bad flags/config) |
| `3` | Scan error or partial completion (an Engine failed) |
| `4` | Authorization denied or missing (web scans) |
| `5` | Feed data unavailable or too stale under `--offline` |

**Code `3` is never conflated with `1`** — your pipeline can always tell "you have
vulnerabilities" apart from "the scanner broke."

Set a gate with `--fail-on`, using either a risk-score number (0–100) or a
severity name:

```bash
multiscan scan . --fail-on 80         # exit 1 if any Finding scores >= 80
multiscan scan . --fail-on high       # exit 1 if any Finding is >= High
```

A minimal CI step:

```bash
multiscan db update
multiscan scan . --fail-on high --format sarif > results.sarif
# exit 1 => fail the build; exit 3 => the scan itself broke (investigate)
```

### Gate only on *new* findings (baselines)

Accept today's known Findings, fail only on regressions:

```bash
multiscan scan . --format json > baseline.json     # capture a baseline once
multiscan scan . --baseline baseline.json --fail-on high
```

Or compare an existing result set against a baseline directly:

```bash
multiscan diff baseline.json
```

---

## 7. Manage suppressions (with accountability)

You cannot silently or permanently mute a Finding. Every suppression **requires a
justification, an approver, and an expiry** — permanent suppression does not exist:

```bash
multiscan suppress add a3f9c1e0 \
  --justification "Vendored test fixture, not shipped" \
  --approver "sec-team" \
  --expires 2026-11-01

multiscan suppress list        # active and expired
multiscan suppress expire a3f9c1e0   # end one early
```

Omitting any of the three fields is a usage error (exit `2`).

---

## 8. Configure with `multiscan.toml`

Instead of repeating flags, drop a `multiscan.toml` at your repo root (it's
discovered by walking upward from the scan path; `--config <file>` overrides).
Precedence is **flag > config file > default**.

```toml
[scan]
layers  = ["sca", "secrets", "iac"]
profile = "standard"
exclude = ["vendor/**", "**/testdata/**", "*.min.js"]

[gate]
fail_on          = 80.0
baseline         = ".multiscan/baseline.json"
ignore_unfixable = false

[risk]
asset_criticality   = "high"       # tunes exposure/asset factors
data_classification = "sensitive"

[feeds]
max_age = "7d"                      # warn/degrade if advisory data is older
offline = false

[[suppress]]                        # all three fields are mandatory
finding_id    = "a3f9c1e0"
justification = "Vendored test fixture, not shipped"
approver      = "sec-team"
expires       = "2026-11-01"
```

A malformed config — including a `[[suppress]]` entry missing a required field —
fails fast with exit `2`.

---

## 9. Scan a container image

Scan an OCI image by tag or digest (SCA over its OS packages and app dependencies):

```bash
multiscan scan image alpine:3.20
multiscan scan image myregistry.example.com/app@sha256:abcd...
multiscan scan image alpine:3.20 --format sarif --fail-on high
```

Image layers are extracted inside a hardened, path-confined sandbox — malicious
tar entries (absolute paths, `..`, symlink escapes) cannot write outside the
extraction root.

---

## 10. Work offline / air-gapped

`--offline` forbids **all** network access and fails loudly (exit `5`) if the feed
data is missing or older than allowed:

```bash
multiscan scan . --offline --max-feed-age 7d
```

To run in an air-gapped environment, move a **signed** feed snapshot across the gap:

```bash
# On a connected machine:
multiscan db update
multiscan db export --out bundle.tar.zst

# On the air-gapped machine (verify authenticity with the publisher's key):
multiscan db import bundle.tar.zst --trusted-key <ed25519-pubkey-hex>
multiscan scan . --offline
```

Without `--trusted-key`, the bundle's signature proves only integrity, not
authenticity — always pass the key you trust.

---

## 11. Scan an authorized web target (advanced)

Active web probing is **authorization-gated by design**: every request to a scan
target passes through a scope check, redirects out of scope are refused, and
targets can only ever be probed **safely** (read-only or non-destructive — there is
no "destructive" mode, by construction).

`scan web` therefore requires a **signed `ScopeAuthorization` file** plus the
public key its signature must verify against:

```bash
multiscan scan web https://app.example.com \
  --authorization scope-auth.json \
  --authorization-key <ed25519-pubkey-hex>
```

If the authorization is absent, expired, or unverifiable, the scan is **denied**
(exit `4`) — fail-closed. The probe layer only sends declarative,
template-defined, idempotent requests; it never executes scripts or shells out.

> Note: in this build the `multiscan authorize` helper (which would scaffold and
> sign the authorization file) is not yet wired up. Until it lands, the signed
> `ScopeAuthorization` file must be produced out-of-band. Only ever scan targets
> you are explicitly authorized to test.

---

## 12. Bring in other scanners' output

Already run Trivy, Semgrep, Checkov, or ZAP? Import their reports so their results
land in the **same deduplicated Finding set** as MultiScan's native engines:

```bash
multiscan import trivy-report.json            # standalone import
multiscan import results.sarif --format json

# or fold external reports into a live scan's dedup pass (repeatable):
multiscan scan . --import trivy.json --import semgrep.sarif --format json
```

Re-rendering the stored Findings later, in any format, without re-scanning:

```bash
multiscan report --format markdown
```

---

## 13. Shell completions & man page

```bash
multiscan completions bash > /etc/bash_completion.d/multiscan
multiscan completions zsh  > "${fpath[1]}/_multiscan"
multiscan completions fish > ~/.config/fish/completions/multiscan.fish

multiscan manpage > /usr/local/share/man/man1/multiscan.1
```

---

## Quick reference

```bash
# scan
multiscan scan .                              # local repo
multiscan scan image alpine:3.20              # OCI image
multiscan scan web <url> --authorization ...  # authorized web target

# shape the run
--layers sca,secrets,iac,sast     --profile quick|standard|thorough
--format table|json|jsonl|sarif|sbom|markdown
--fail-on <score|severity>        --baseline <file>     --min-severity <sev>
--offline  --max-feed-age 7d      --no-store  --jobs N  --quiet  --verbose

# understand & manage
multiscan explain <id> [--history]
multiscan report --format <fmt>
multiscan diff <baseline>
multiscan suppress add|list|expire ...
multiscan import <file>

# advisory data
multiscan db update|status|export --out <f>|import <bundle> [--trusted-key <k>]|path
```

Exit codes: `0` clean · `1` gate met · `2` usage · `3` scan broke · `4` auth denied
· `5` feeds stale/offline.

For the normative details behind any of this, see `MULTISCAN-SDD-v1.0.md`.
