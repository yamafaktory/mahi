#!/usr/bin/env bash
set -euo pipefail
max_gib=${1:-40}
if ! [[ "$max_gib" =~ ^[0-9]+$ ]]; then
    echo "sweep takes a whole number of GiB, not $max_gib" >&2
    exit 2
fi
cd "$(dirname "$0")/.."
for dir in target fuzz/target; do
    test -d "$dir" || continue
    used=$(du -sk "$dir" | cut -f1)
    if [ "$used" -gt $(( max_gib * 1024 * 1024 )) ]; then
        echo "removing $dir: $(( used / 1024 / 1024 )) GiB is over $max_gib GiB"
        rm -rf "$dir"
    fi
done
