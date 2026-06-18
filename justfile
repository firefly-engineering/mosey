# mosey — development tasks
#
# All recipes assume the Nix dev shell is active. Run `nix develop`
# first, or rely on direnv (the .envrc loads the flake automatically).

# Show available recipes by default.
default:
    @just --list

# ──────────────────────────────────────────────────────────────────────
# Build
# ──────────────────────────────────────────────────────────────────────

# Build the mosey binary into ./bin/mosey.
build:
    @mkdir -p bin
    go build -o bin/mosey ./cmd/mosey

# Install the mosey binary into the user's GOBIN (defaults to ~/go/bin).
install:
    go install ./cmd/mosey

# Run the binary against arbitrary args. `just run launch --help`.
run *ARGS:
    go run ./cmd/mosey {{ARGS}}

# ──────────────────────────────────────────────────────────────────────
# Test
# ──────────────────────────────────────────────────────────────────────

# Run the full Go test suite.
#
# -race is deliberately off: the libp2p-backed vterm tests
# spawn enough goroutines that the race detector reliably
# deadlocks on macOS. Use `just test-race` when you specifically
# want the race detector — it's still on the menu, just not the
# default gate.
test:
    @if command -v gotestsum >/dev/null 2>&1; then \
        gotestsum --format=pkgname-and-test-fails -- -timeout=120s ./...; \
    else \
        go test -timeout=120s ./...; \
    fi

# Race-detector run. Slower and flakier on macOS (see `test`
# above); use sparingly.
test-race:
    go test -race -timeout=180s ./...

# Stress-run the suite three times; useful for chasing flakes.
test-stress:
    go test -timeout=180s -count=3 ./...

# Verbose run — full per-test output, useful when investigating a failure.
test-verbose:
    @if command -v gotestsum >/dev/null 2>&1; then \
        gotestsum --format=standard-verbose -- -timeout=120s ./...; \
    else \
        go test -v -timeout=120s ./...; \
    fi

# Run tests with coverage and print the total.
test-cover:
    go test -coverprofile=coverage.out -covermode=count ./...
    @echo
    @go tool cover -func=coverage.out | awk '/total:/ || NR==1'

# ──────────────────────────────────────────────────────────────────────
# Lint and format
# ──────────────────────────────────────────────────────────────────────

# Format Go + Nix sources in-place.
fmt:
    gofmt -s -w .
    @nix fmt -- . 2>/dev/null || true

# Verify formatting without writing — used in CI.
fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    diff=$(gofmt -s -l .)
    if [ -n "$diff" ]; then
        echo "gofmt issues:"
        echo "$diff"
        exit 1
    fi
    nix fmt -- . --check 2>/dev/null || true

# Run go vet.
vet:
    go vet ./...

# Run golangci-lint when available.
lint:
    @if command -v golangci-lint >/dev/null 2>&1; then \
        golangci-lint run ./...; \
    else \
        echo "(golangci-lint not on PATH — skipping)"; \
    fi

# ──────────────────────────────────────────────────────────────────────
# Code generation
# ──────────────────────────────────────────────────────────────────────

# Regenerate proto-generated Go from api/*.proto.
proto:
    protoc \
        --go_out=. --go_opt=module=github.com/firefly-engineering/mosey \
        api/auth.proto \
        api/cert.proto \
        api/control.proto \
        api/wallet.proto

# Verify the committed *.pb.go matches what protoc would regenerate.
# Catches drift between .proto sources and checked-in Go in CI.
proto-check:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/api"
    cp api/*.proto "$tmp/api/"
    (cd "$tmp" && protoc \
        --go_out=. --go_opt=module=github.com/firefly-engineering/mosey \
        api/auth.proto api/cert.proto api/control.proto api/wallet.proto)
    for f in auth.pb.go cert.pb.go control.pb.go wallet.pb.go; do
        diff -u "$tmp/api/$f" "api/$f"
    done

# ──────────────────────────────────────────────────────────────────────
# On-chain program (wallet auth, Track B)
# ──────────────────────────────────────────────────────────────────────

# Build the mosey-session Anchor program (target/deploy/mosey_session.so).
# Run from the dev shell: the toolbox solana-toolchain provides a wrapped
# cargo-build-sbf that handles the pinned offline SBF SDK, an isolated
# RUSTUP_HOME, and the platform-tools toolchain — no download, no host
# rustup. Not in `just check`.
#
# --arch v3 is required: enabling SBPFv3 on the public clusters
# (SIMD-0178/0189/0377) raised the *minimum* deployable version to v3, so
# the default v0 stamp is rejected at deploy time as "sbpf_version ... not
# enabled". v3 is active on devnet (epoch 1069), testnet, and mainnet.
anchor-build:
    cd programs/mosey-session && cargo-build-sbf --arch v3

# Behavioral test of the program with litesvm — an in-process Solana VM
# (no validator, no network, no SOL). Builds the .so, then loads it into
# litesvm and exercises register/grant/bump-epoch/revoke/transfer plus the
# rejection paths (invalid caps, non-owner). The harness lives in its own
# crate (programs/mosey-session-litesvm) so litesvm's Solana version stays
# isolated from the program's anchor build. Not in `just check` (host-heavy
# build). solana-test-validator is avoided: it crashes in RocksDB on
# aarch64-darwin in our toolbox.
anchor-test:
    # litesvm's embedded VM doesn't accept SBPFv3; build the baseline arch
    # for the in-process test (devnet deploys still use --arch v3 via
    # anchor-build). The arch only changes bytecode encoding, not logic.
    cd programs/mosey-session && cargo-build-sbf --arch v0
    cd programs/mosey-session-litesvm && cargo test --tests

# ──────────────────────────────────────────────────────────────────────
# TypeScript reference client (clients/typescript/)
#
# Assumes Node 22+ on PATH. The flake doesn't pin nodejs — the
# clients/typescript/ tree is auxiliary, not a hard build dep.
# ──────────────────────────────────────────────────────────────────────

# Install npm dependencies for the TS client.
ts-install:
    cd clients/typescript && npm install --no-audit --no-fund

# Type-check the TS sources.
ts-typecheck:
    cd clients/typescript && npm run typecheck

# Run the TS test suite (unit + e2e). The e2e test requires
# ./bin/mosey — run `just build` first.
ts-test:
    cd clients/typescript && npx vitest run

# Compile TS sources into clients/typescript/dist/.
ts-build:
    cd clients/typescript && npm run build

# Aggregate TS gate: typecheck → test. Use after the Go gate to
# verify wire-format parity.
ts-check: ts-typecheck ts-test
    @echo "✔ just ts-check ok"

# ──────────────────────────────────────────────────────────────────────
# Documentation
# ──────────────────────────────────────────────────────────────────────

# Serve mdbook documentation locally and open it.
docs:
    cd docs && mdbook serve --open

# Build mdbook documentation into docs/book/.
docs-build:
    cd docs && mdbook build

# ──────────────────────────────────────────────────────────────────────
# Aggregate gate
# ──────────────────────────────────────────────────────────────────────

# Full pre-commit gate: format, vet, test, proto-drift.
check: fmt-check vet test proto-check
    @echo "✔ just check ok"

# Nix flake evaluation check (no build).
flake-check:
    nix flake check --no-build

# ──────────────────────────────────────────────────────────────────────
# Maintenance
# ──────────────────────────────────────────────────────────────────────

# Remove build artifacts.
clean:
    rm -rf bin/ coverage.out coverage.html docs/book/ result result-*
