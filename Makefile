# MultiScan — build, verify, and publish to crates.io.
#
# Publishing order is topological: a crate is published only after every
# workspace crate it depends on is already on crates.io. `cargo publish` waits
# for each crate to appear in the index before returning, so the next crate can
# resolve it.
#
#   make check         # cargo xtask ci — the full gate ladder
#   make publish-dry   # dry-run each crate (see the note below)
#   make publish       # publish every crate to crates.io, in order
#   make publish-<crate-suffix>   # e.g. make publish-core, make publish-cli
#
# Requirements before `make publish`:
#   - `cargo login` (or CARGO_REGISTRY_TOKEN in the environment)
#   - each crate name must be available on crates.io
#   - the working tree should be clean and tagged for the release
#
# Note on `publish-dry`: crates.io resolves a crate's dependencies against the
# registry even for a dry run, so a dependent crate can only be dry-run once the
# crates it depends on are already published. `make publish-dry` therefore fully
# validates only `core` up front; the remaining crates become dry-runnable as
# their dependencies go live. The real `make publish` avoids this entirely by
# publishing in dependency order and waiting for each crate to index.

# Topological publish order (crate-name suffixes). Do not reorder without
# re-checking the dep graph: core → (crates depending only on core) →
# (engines) → cli.
CRATES := \
	core \
	engine \
	dedup \
	risk \
	feeds \
	store \
	report \
	scope \
	sca \
	secrets \
	iac \
	bridge \
	sast \
	probe \
	cli

# Extra flags passed to every `cargo publish` (e.g. PUBLISH_FLAGS=--allow-dirty).
PUBLISH_FLAGS ?=

.PHONY: all check build publish publish-dry $(addprefix publish-,$(CRATES)) \
	$(addprefix dry-,$(CRATES)) clean

all: check

## Run the full gate ladder (fmt, clippy, tests, determinism, safety, size, deny).
check:
	cargo xtask ci

## Release build of the CLI.
build:
	cargo build --release -p multiscan-cli

## Dry-run publish of every crate, in dependency order (no upload).
publish-dry: $(addprefix dry-,$(CRATES))

dry-%:
	cargo publish -p multiscan-$* --locked --dry-run $(PUBLISH_FLAGS)

## Publish every crate to crates.io, in dependency order.
## cargo waits for each crate to land in the index before the next resolves it.
publish: $(addprefix publish-,$(CRATES))

publish-%:
	cargo publish -p multiscan-$* --locked $(PUBLISH_FLAGS)

clean:
	cargo clean
