set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt:
    cargo +nightly fmt --all

fmt-check:
    cargo +nightly fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy --workspace --all-targets --locked --features mahi-identity/fuzzing,mahi-live/fuzzing,mahi-proxy/fuzzing,mahi-ssh/fuzzing,mahi-store/fuzzing,mahi-thread/fuzzing -- -D warnings

test *args:
    cargo nextest run --workspace --locked --no-tests=pass {{args}}

test-git *args:
    cargo nextest run --workspace --locked --ignore-default-filter -E 'binary(/^git_/) | test(/(^|::)git_tests::/)' {{args}}

test-wsl *args:
    cargo nextest run --workspace --locked --ignore-default-filter -E 'binary(/^wsl_/)' {{args}}

apparmor-parse:
    cargo run --locked -q -p mahi -- apparmor | sudo apparmor_parser --skip-kernel-load

deb:
    cargo deb --locked -p mahi

deb-check:
    test "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" = 1
    sudo apt-get install -y ./target/debian/mahi_*.deb
    sudo grep -qx 'usr.bin.mahi (unconfined)' /sys/kernel/security/apparmor/profiles
    MAHI_TEST_BINARY=/usr/bin/mahi cargo nextest run --locked -p mahi -E 'test(run_starts_a_thread_and_the_agent_in_its_own_worktree)'
    cp /usr/bin/mahi "$RUNNER_TEMP/mahi"
    ! MAHI_TEST_BINARY="$RUNNER_TEMP/mahi" cargo nextest run --locked -p mahi -E 'test(run_starts_a_thread_and_the_agent_in_its_own_worktree)' > "$RUNNER_TEMP/refused.log" 2>&1
    grep -q 'AppArmor stops mahi' "$RUNNER_TEMP/refused.log"

deny:
    cargo deny --locked check

build:
    cargo build --workspace --locked

run *args:
    cargo run --locked -p mahi -- {{args}}

sweep max_gib="40":
    #!/usr/bin/env bash
    set -euo pipefail
    if ! [[ "{{max_gib}}" =~ ^[0-9]+$ ]]; then
        echo "sweep takes a whole number of GiB, not {{max_gib}}" >&2
        exit 2
    fi
    for dir in target fuzz/target; do
        test -d "$dir" || continue
        used=$(du -sk "$dir" | cut -f1)
        if [ "$used" -gt $(( {{max_gib}} * 1024 * 1024 )) ]; then
            echo "removing $dir: $(( used / 1024 / 1024 )) GiB is over {{max_gib}} GiB"
            rm -rf "$dir"
        fi
    done

check: sweep fmt-check clippy test deny

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
