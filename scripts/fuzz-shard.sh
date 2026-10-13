#!/usr/bin/env bash
set -euo pipefail
index=$1
count=$2
seconds=${3:-30}
scripts=$(dirname "$0")
host=$(rustc +nightly -vV | sed -n 's/^host: //p')
targets=$("$scripts/fuzz-list.sh" "$index" "$count")
cd "$scripts/../fuzz"
for target in $targets; do
    cargo +nightly fuzz run --target "$host" "$target" -- -max_total_time="$seconds" -timeout=10
done
