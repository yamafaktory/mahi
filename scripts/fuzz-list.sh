#!/usr/bin/env bash
set -euo pipefail
index=${1:-0}
count=${2:-1}
if ! [[ "$index" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]] || (( index >= count )); then
    echo "fuzz-list: index must be a number from 0 to count - 1" >&2
    exit 2
fi
cd "$(dirname "$0")/../fuzz"
all=$(cargo +nightly fuzz list)
targets=$(for target in $all; do
    hash=$(printf %s "$target" | cksum | cut -d ' ' -f 1)
    if (( hash % count == index )); then echo "$target"; fi
done)
test -n "$targets"
echo "$targets"
