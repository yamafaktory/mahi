#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/try-lib.sh

version=0.7.10
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
        asset="bombadil-x86_64-linux"
        sum=6f2664ca7d4067017b4efb26db5c29d6dcfecdc78131f96989d336f12420cc1b
        ;;
    Darwin-arm64)
        asset="bombadil-aarch64-darwin"
        sum=3d7866e2e8356390a0f2560853e3c775839f8c8ff648c9552c0105f7f78d1d72
        ;;
    *)
        echo "bombadil $version has no release binary for $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac

limit=${1:-1m}
case "$limit" in
    *s) seconds=${limit%s} ;;
    *m) seconds=$((${limit%m} * 60)) ;;
    *h) seconds=$((${limit%h} * 3600)) ;;
    *)
        echo "the time limit takes a unit, such as 30s, 5m or 1h: $limit" >&2
        exit 1
        ;;
esac
if ! [[ $seconds =~ ^[0-9]+$ ]] || [ "$seconds" -eq 0 ]; then
    echo "the time limit is not a whole number of seconds, minutes or hours: $limit" >&2
    exit 1
fi

cache="${XDG_CACHE_HOME:-$HOME/.cache}/mahi-bombadil"
bombadil="$cache/$version/bombadil"
if [ ! -x "$bombadil" ]; then
    mkdir -p "$cache/$version"
    curl -fsSL -o "$bombadil.download" \
        "https://github.com/antithesishq/bombadil/releases/download/v$version/$asset"
    if ! echo "$sum  $bombadil.download" | shasum -a 256 -c - > /dev/null; then
        rm -f "$bombadil.download"
        echo "the downloaded bombadil $version does not match its pinned checksum" >&2
        exit 1
    fi
    chmod +x "$bombadil.download"
    mv "$bombadil.download" "$bombadil"
fi

cargo build --locked -p mahi
binary=$(mahi_binary)
check_binary "$binary"
specification="$PWD/tests/bombadil/home.ts"
output="$PWD/work/scratch/bombadil"
root="$cache/run"
rm -rf "$root" "$output"
mkdir -p "$root/config" "$root/data" "$root/home" "$output"
make_project "$root/project" ""

deadline=$((SECONDS + seconds))
run=0
while [ "$SECONDS" -lt "$deadline" ]; do
    run=$((run + 1))
    (
        cd "$root/project"
        env -i HOME="$root/home" PATH=/usr/bin:/bin TERM=xterm-256color \
            XDG_CONFIG_HOME="$root/config" XDG_DATA_HOME="$root/data" MAHI_LIVE=off \
            "$bombadil" terminal test --specification "$specification" --exit-on-violation \
            --time-limit "$((deadline - SECONDS))s" --output-path "$output/$run" "$binary" \
            > "$output/$run.log" 2>&1
    ) || {
        tail -n 40 "$output/$run.log" >&2
        grep -h 'was violated' "$output/$run.log" >&2 || true
        echo "bombadil found a violation in run $run, logged in $output/$run.log; replay it with:" >&2
        echo "  $bombadil terminal test --specification $specification --reproduce $output/$run $binary" >&2
        echo "  (in $root/project, with the environment this script sets)" >&2
        exit 1
    }
done
echo "bombadil: $run runs over $limit found no violation"
