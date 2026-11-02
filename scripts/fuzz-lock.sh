#!/usr/bin/env bash
set -euo pipefail
mode=${1:-}
case "$mode" in
    check | sync) ;;
    *)
        echo "fuzz-lock takes check or sync, not '$mode'" >&2
        exit 2
        ;;
esac
cd "$(dirname "$0")/.."

hint="run just fuzz-lock-sync"

packages() {
    awk '/^\[\[package\]\]/ { name = "" } /^name = / { name = $3 } /^version = / && name != "" { print name, $3 }' "$1" | tr -d '"' | sort -u
}

apart() {
    awk 'NR == FNR { names[$1] = 1; locked[$1 " " $2] = 1; next } ($1 in names) && !(($1 " " $2) in locked)' \
        <(packages Cargo.lock) <(packages fuzz/Cargo.lock)
}

if [ "$mode" = sync ]; then
    if [ "${DRY_RUN:-false}" = true ]; then
        echo "dry run: fuzz/Cargo.lock left as it is"
        exit 0
    fi
    cp Cargo.lock fuzz/Cargo.lock
    cargo update --workspace --offline --quiet --manifest-path fuzz/Cargo.toml
fi
if ! cargo update --workspace --locked --quiet --manifest-path fuzz/Cargo.toml; then
    echo "fuzz/Cargo.lock is out of date: $hint" >&2
    exit 1
fi
mismatched=$(apart)
if [ -n "$mismatched" ]; then
    echo "fuzz/Cargo.lock locks these crates at versions Cargo.lock does not: $hint" >&2
    echo "$mismatched" >&2
    exit 1
fi
