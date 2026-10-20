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

# Check every shell script: the ones in scripts/ and the .deb's maintainer scripts
shellcheck:
    shellcheck -x scripts/*.sh packaging/deb/postinst packaging/deb/postrm packaging/deb/prerm

build:
    cargo build --workspace --locked

run *args:
    cargo run --locked -p mahi -- {{args}}

# Build mahi and run it in a scratch git repository with its own config and data, kept until try-reset; MAHI_TRY_REMOTE names a shared git remote
[positional-arguments]
try *args:
    @scripts/try.sh "$@"

# Run mahi as a second user, bob, with a key, config, data and clone of its own, to try mahi with two terminals
[positional-arguments]
try-teammate *args:
    @scripts/try-teammate.sh "$@"

# Remove the scratch repositories, config and data that try and try-teammate use
try-reset:
    @scripts/try-reset.sh

[positional-arguments]
sweep max_gib="40":
    @scripts/sweep.sh "$1"

check: sweep fmt-check clippy test deny shellcheck

[positional-arguments]
mutants crate *args:
    cargo mutants --test-tool nextest --cargo-arg=--locked --package "$1" "${@:2}"

fuzz target seconds="60":
    cd fuzz && cargo +nightly fuzz run --target "$(rustc +nightly -vV | sed -n 's/^host: //p')" {{target}} -- -max_total_time={{seconds}} -timeout=10

fuzz-all seconds="30": (fuzz-shard "0" "1" seconds)

[positional-arguments]
fuzz-shard index count seconds="30":
    @scripts/fuzz-shard.sh "$1" "$2" "$3"

[positional-arguments]
fuzz-list index="0" count="1":
    @scripts/fuzz-list.sh "$1" "$2"
