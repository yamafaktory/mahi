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

# The real Claude Code and Codex through mahi; needs both signed in, see crates/mahi/tests/dogfood_agents.rs
dogfood *args:
    cargo nextest run -p mahi --locked --ignore-default-filter -E 'binary(/^dogfood_/)' --no-capture {{args}}

# Bump every crate to the version, commit, tag v<version> and push, which starts the release (a dry run unless --execute)
release version *args: check
    cargo release {{version}} --no-publish {{args}}

apparmor-parse:
    cargo run --locked -q -p mahi -- apparmor | sudo apparmor_parser --skip-kernel-load

# Build the .deb, with a pre-release such as 0.1.0-rc.1 versioned 0.1.0~rc.1 so Debian sorts it before 0.1.0
deb:
    cargo deb --locked -p mahi --deb-version "$(cargo pkgid -p mahi | sed 's/.*[#@]//; s/-/~/')"

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

# Build mahi and run it in a scratch git repository with its own config and data, kept until try-reset
[positional-arguments]
try *args:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --locked -p mahi
    target=$(cargo metadata --locked --format-version 1 --no-deps | grep -o '"target_directory":"[^"]*"' | cut -d '"' -f 4)
    binary="$target/debug/mahi"
    root="${XDG_CACHE_HOME:-$HOME/.cache}/mahi-try"
    mkdir -p "$root/project" "$root/config" "$root/data"
    cd "$root/project"
    if ! git rev-parse -q --verify HEAD > /dev/null 2>&1; then
        git init -q
        git -c user.name=mahi -c user.email=try@mahi.social -c commit.gpgsign=false commit -q --allow-empty -m init
    fi
    if [ "$(uname -s)" = Darwin ]; then
        mkdir -p "$root/home"
        export HOME="$root/home"
    fi
    XDG_CONFIG_HOME="$root/config" XDG_DATA_HOME="$root/data" exec "$binary" "$@"

# Remove the scratch repository, config and data that try uses
try-reset:
    rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/mahi-try"

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

fuzz-all seconds="30": (fuzz-shard "0" "1" seconds)

fuzz-shard index count seconds="30":
    #!/usr/bin/env bash
    set -euo pipefail
    host=$(rustc +nightly -vV | sed -n 's/^host: //p')
    targets=$(just fuzz-list {{index}} {{count}})
    cd fuzz
    for target in $targets; do
        cargo +nightly fuzz run --target "$host" "$target" -- -max_total_time={{seconds}} -timeout=10
    done

fuzz-list index="0" count="1":
    #!/usr/bin/env bash
    set -euo pipefail
    if ! [[ "{{index}}" =~ ^[0-9]+$ && "{{count}}" =~ ^[0-9]+$ ]] || (( {{index}} >= {{count}} )); then
        echo "fuzz-list: index must be a number from 0 to count - 1" >&2
        exit 2
    fi
    cd fuzz
    all=$(cargo +nightly fuzz list)
    targets=$(for target in $all; do
        hash=$(printf %s "$target" | cksum | cut -d ' ' -f 1)
        if (( hash % {{count}} == {{index}} )); then echo "$target"; fi
    done)
    test -n "$targets"
    echo "$targets"
