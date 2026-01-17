# M2M Protocol - Rust Makefile
#
# Usage:
#   make         - Build release binary
#   make check   - Run all checks (fmt, clippy, test)
#   make test    - Run tests
#   make lint    - Run clippy with strict lints
#   make clean   - Clean build artifacts

.PHONY: all build check test lint fmt doc clean install bench ci help setup

# Default target
all: build

# =============================================================================
# Quick Start
# =============================================================================

## Full setup: build + download Hydra model
setup: build model-download
	@echo ""
	@echo "✓ Setup complete!"
	@echo "  Binary: target/release/m2m"
	@echo "  Model:  ./models/hydra/model.safetensors"
	@echo ""
	@echo "Try: cargo test test_load_hydra_model -- --ignored --nocapture"

# =============================================================================
# Build Targets
# =============================================================================

## Build release binary
build:
	cargo build --release

## Build with ONNX support for Hydra model
build-onnx:
	cargo build --release --features onnx

## Build debug binary
build-debug:
	cargo build

## Install binary to ~/.cargo/bin
install:
	cargo install --path .

# =============================================================================
# Quality Checks
# =============================================================================

## Run all checks (format, lint, test, doc)
check: fmt-check lint test doc-check
	@echo "✓ All checks passed"

## Run CI checks (stricter, for GitHub Actions)
ci: fmt-check lint-strict test-all doc-check audit
	@echo "✓ CI checks passed"

## Check formatting without modifying
fmt-check:
	cargo fmt --all -- --check

## Format code
fmt:
	cargo fmt --all

## Run clippy with standard lints
lint:
	cargo clippy --all-targets --all-features -- -D warnings

## Run clippy with strict lints (pedantic)
lint-strict:
	cargo clippy --all-targets --all-features -- \
		-D warnings \
		-D clippy::pedantic \
		-D clippy::nursery \
		-A clippy::module_name_repetitions \
		-A clippy::must_use_candidate \
		-A clippy::missing_errors_doc \
		-A clippy::missing_panics_doc \
		-A clippy::doc_markdown

## Fix clippy warnings automatically
lint-fix:
	cargo clippy --all-targets --all-features --fix --allow-dirty

# =============================================================================
# Testing
# =============================================================================

## Run tests
test:
	cargo test

## Run all tests including ignored (integration tests)
test-all:
	cargo test -- --include-ignored

## Run tests with output
test-verbose:
	cargo test -- --nocapture

## Run specific test
test-one:
	@read -p "Test name: " name; \
	cargo test $$name -- --nocapture

## Run benchmarks
bench:
	cargo bench

## Run tests with coverage (requires cargo-tarpaulin)
coverage:
	cargo tarpaulin --out Html --output-dir target/coverage
	@echo "Coverage report: target/coverage/tarpaulin-report.html"

# =============================================================================
# Documentation
# =============================================================================

## Build documentation
doc:
	cargo doc --no-deps --all-features

## Build and open documentation
doc-open:
	cargo doc --no-deps --all-features --open

## Check documentation for errors
doc-check:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# =============================================================================
# Security & Audit
# =============================================================================

## Run security audit (requires cargo-audit)
audit:
	cargo audit

## Check for outdated dependencies
outdated:
	cargo outdated

## Update dependencies
update:
	cargo update

## Check for unused dependencies (requires cargo-udeps)
udeps:
	cargo +nightly udeps --all-targets

# =============================================================================
# Release
# =============================================================================

## Prepare for release (all checks + version bump reminder)
release-check: ci
	@echo ""
	@echo "Release checklist:"
	@echo "  1. Update version in Cargo.toml"
	@echo "  2. Update CHANGELOG.md"
	@echo "  3. Run: make release-build"
	@echo "  4. Run: cargo publish --dry-run"

## Build release artifacts for all platforms
release-build:
	cargo build --release
	@echo "Binary: target/release/m2m"
	@ls -lh target/release/m2m 2>/dev/null || true

## Publish to crates.io (dry run)
publish-dry:
	cargo publish --dry-run

## Publish to crates.io
publish:
	cargo publish

# =============================================================================
# Development Helpers
# =============================================================================

## Watch for changes and run tests
watch:
	cargo watch -x test

## Watch for changes and run clippy
watch-lint:
	cargo watch -x clippy

## Run the server (development)
run-server:
	RUST_LOG=info cargo run -- server --port 8080

## Run the proxy (development)
run-proxy:
	RUST_LOG=info cargo run -- proxy --upstream https://openrouter.ai/api/v1

## Show dependency tree
tree:
	cargo tree

## Show binary size breakdown (requires cargo-bloat)
bloat:
	cargo bloat --release --crates

## Generate flamegraph (requires cargo-flamegraph)
flamegraph:
	cargo flamegraph --bin m2m -- compress '{"test": true}'

# =============================================================================
# Cleanup
# =============================================================================

## Clean build artifacts
clean:
	cargo clean

## Clean and rebuild
rebuild: clean build

## Remove all generated files
distclean: clean
	rm -rf target/
	rm -f Cargo.lock

# =============================================================================
# Hydra Model
# =============================================================================

## Download Hydra model from HuggingFace
model-download:
	@mkdir -p models
	huggingface-cli download infernet/hydra --local-dir ./models/hydra
	@echo "✓ Model downloaded to ./models/hydra"

## Verify Hydra model
model-verify:
	@test -d ./models/hydra && echo "✓ Model found" || echo "✗ Model not found (run: make model-download)"

# =============================================================================
# Help
# =============================================================================

## Show this help
help:
	@echo "M2M Protocol - Makefile Commands"
	@echo ""
	@echo "Quick Start:"
	@echo "  make setup        - Build + download Hydra model (recommended)"
	@echo ""
	@echo "Build:"
	@echo "  make build        - Build release binary"
	@echo "  make build-onnx   - Build with ONNX support (optional)"
	@echo "  make install      - Install to ~/.cargo/bin"
	@echo ""
	@echo "Quality:"
	@echo "  make check        - Run all quality checks"
	@echo "  make ci           - Run CI checks (stricter)"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Run clippy"
	@echo "  make lint-strict  - Run clippy with pedantic lints"
	@echo ""
	@echo "Testing:"
	@echo "  make test         - Run tests"
	@echo "  make test-all     - Run all tests (including integration)"
	@echo "  make coverage     - Generate coverage report"
	@echo ""
	@echo "Documentation:"
	@echo "  make doc          - Build documentation"
	@echo "  make doc-open     - Build and open documentation"
	@echo ""
	@echo "Security:"
	@echo "  make audit        - Security audit dependencies"
	@echo "  make outdated     - Check for outdated dependencies"
	@echo ""
	@echo "Hydra Model:"
	@echo "  make model-download - Download from HuggingFace"
	@echo ""
	@echo "Development:"
	@echo "  make watch        - Watch and run tests"
	@echo "  make run-server   - Start development server"
	@echo "  make run-proxy    - Start development proxy"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make distclean    - Remove all generated files"
