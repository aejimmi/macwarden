# Project task runner — run `just --list` for available recipes

# Run all tests
test:
    cargo test --workspace --no-fail-fast

# Run tests for a specific crate
test-crate crate:
    cargo test -p {{crate}}

# Run clippy lints
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Check formatting
fmt:
    cargo fmt --all -- --check

# Fix formatting
fmt-fix:
    cargo fmt --all

# Run cargo-deny checks (licenses, advisories, bans, sources)
deny:
    cargo deny check

# Run test coverage
coverage:
    cargo llvm-cov --all --ignore-filename-regex '_test\.rs$'

# Run test coverage and open HTML report
coverage-html:
    cargo llvm-cov --all --ignore-filename-regex '_test\.rs$' --html --open

# Run benchmarks
bench:
    cargo bench --workspace

# Run benchmarks for a specific crate
bench-crate crate:
    cargo bench -p {{crate}}

# Run all checks (lint, fmt, test, deny)
check-all: lint fmt test deny
