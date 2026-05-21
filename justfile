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

# Regenerate proto-generated Go from internal/api/*.proto.
proto:
    protoc \
        --go_out=. --go_opt=module=github.com/firefly-engineering/mosey \
        internal/api/auth.proto \
        internal/api/cert.proto \
        internal/api/control.proto

# Verify the committed *.pb.go matches what protoc would regenerate.
# Catches drift between .proto sources and checked-in Go in CI.
proto-check:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/internal/api"
    cp internal/api/*.proto "$tmp/internal/api/"
    (cd "$tmp" && protoc \
        --go_out=. --go_opt=module=github.com/firefly-engineering/mosey \
        internal/api/auth.proto internal/api/cert.proto internal/api/control.proto)
    for f in auth.pb.go cert.pb.go control.pb.go; do
        diff -u "$tmp/internal/api/$f" "internal/api/$f"
    done

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
