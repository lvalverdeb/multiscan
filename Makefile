# MultiScan — build, verify, and publish to crates.io.
#
# Publishing order is topological: a crate is published only after every
# workspace crate it depends on is already on crates.io. `cargo publish` waits
# for each crate to appear in the index before returning, so the next crate can
# resolve it.
#
#   make check         # cargo xtask ci — the full gate ladder
#   make bump TO=x.y.z # bump the workspace version, refresh the lock, commit
#   make tag           # annotated git tag v<current-version>
#   make release TO=x.y.z  # bump → check → tag, in one step
#   make publish-dry   # dry-run each crate (see the note below)
#   make publish       # publish every crate to crates.io, in order
#   make publish-<crate>   # e.g. make publish-multiscan-core, make publish-multiscan
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

# Topological publish order (full crate names). Do not reorder without
# re-checking the dep graph: core → (crates depending only on core) →
# (engines) → the multiscan binary crate last.
CRATES := \
	multiscan-core \
	multiscan-engine \
	multiscan-dedup \
	multiscan-risk \
	multiscan-feeds \
	multiscan-store \
	multiscan-report \
	multiscan-scope \
	multiscan-sca \
	multiscan-secrets \
	multiscan-iac \
	multiscan-bridge \
	multiscan-sast \
	multiscan-probe \
	multiscan

# Extra flags passed to every `cargo publish` (e.g. PUBLISH_FLAGS=--allow-dirty).
PUBLISH_FLAGS ?=

# Current workspace version, read from [workspace.package] (the single source of
# truth; every crate inherits it via version.workspace = true).
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

.PHONY: all check build version bump tag release publish publish-dry \
	$(addprefix publish-,$(CRATES)) $(addprefix dry-,$(CRATES)) clean

all: check

## Print the current workspace version.
version:
	@echo $(VERSION)

## Run the full gate ladder (fmt, clippy, tests, determinism, safety, size, deny).
check:
	cargo xtask ci

## Release build of the CLI.
build:
	cargo build --release -p multiscan

## Bump the workspace version. Usage: make bump TO=0.2.0
## Updates [workspace.package] and every internal path-dep version (they must
## match), refreshes Cargo.lock, and commits. Refuses a dirty tree.
bump:
	@test -n "$(TO)" || { echo "usage: make bump TO=<x.y.z>"; exit 2; }
	@test -z "$$(git status --porcelain)" || { echo "working tree is dirty; commit or stash first"; exit 2; }
	@echo "bumping $(VERSION) -> $(TO)"
	# workspace.package version (the lone top-level `version = "..."`).
	sed -i.bak 's/^version = "$(VERSION)"/version = "$(TO)"/' Cargo.toml
	# internal path-dep versions must track the workspace version.
	sed -i.bak -E 's/(multiscan-[a-z]+ = \{ path = "[^"]+", version = )"$(VERSION)"/\1"$(TO)"/' Cargo.toml
	rm -f Cargo.toml.bak
	cargo update --workspace --quiet
	git add Cargo.toml Cargo.lock
	git commit -m "release: v$(TO)"
	@echo "committed v$(TO); tag it with: make tag"

## Create an annotated tag for the current version. Reads the version fresh from
## Cargo.toml so it is correct even right after `make bump`.
tag:
	@v=$$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1); \
	git tag -a "v$$v" -m "MultiScan v$$v"; \
	echo "created tag v$$v — push with: git push origin v$$v"

## One-step release: bump the version, run the full gate ladder, then tag.
## Usage: make release TO=0.2.0
release:
	@test -n "$(TO)" || { echo "usage: make release TO=<x.y.z>"; exit 2; }
	$(MAKE) bump TO=$(TO)
	$(MAKE) check
	git tag -a "v$(TO)" -m "MultiScan v$(TO)"
	@echo "released v$(TO). next: git push && git push origin v$(TO) && make publish"

## Dry-run publish of every crate, in dependency order (no upload).
## Static pattern rule (not an implicit `%` rule): implicit-rule search is
## skipped for .PHONY targets, so a plain `dry-%:` would silently no-op.
publish-dry: $(addprefix dry-,$(CRATES))

$(addprefix dry-,$(CRATES)): dry-%:
	cargo publish -p $* --locked --dry-run $(PUBLISH_FLAGS)

## Publish every crate to crates.io, in dependency order.
## cargo waits for each crate to land in the index before the next resolves it.
publish: $(addprefix publish-,$(CRATES))

$(addprefix publish-,$(CRATES)): publish-%:
	cargo publish -p $* --locked $(PUBLISH_FLAGS)

clean:
	cargo clean
