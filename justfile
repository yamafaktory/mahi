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

[positional-arguments]
mutants crate *args:
    cargo mutants --test-tool nextest --cargo-arg=--locked --package "$1" "${@:2}"

fuzz target seconds="60":
    cd fuzz && cargo +nightly fuzz run --target "$(rustc +nightly -vV | sed -n 's/^host: //p')" {{target}} -- -max_total_time={{seconds}} -timeout=10

fuzz-all seconds="30":
    #!/usr/bin/env bash
    set -euo pipefail
    cd fuzz
    host=$(rustc +nightly -vV | sed -n 's/^host: //p')
    targets=$(cargo +nightly fuzz list)
    test -n "$targets"
    for target in $targets; do
        cargo +nightly fuzz run --target "$host" "$target" -- -max_total_time={{seconds}} -timeout=10
    done
