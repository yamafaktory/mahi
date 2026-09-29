set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt:
    cargo +nightly fmt --all

fmt-check:
    cargo +nightly fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test *args:
    cargo nextest run --workspace --locked --no-tests=pass {{args}}

test-git *args:
    cargo nextest run --workspace --locked --ignore-default-filter -E 'binary(/^git_/) | test(/(^|::)git_tests::/)' {{args}}

deny:
    cargo deny --locked check

build:
    cargo build --workspace --locked

run *args:
    cargo run --locked -p mahi -- {{args}}

check: fmt-check clippy test deny
