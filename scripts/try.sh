#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
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
