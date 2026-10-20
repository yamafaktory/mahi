#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/try-lib.sh
cargo build --locked -p mahi
binary=$(mahi_binary)
check_binary "$binary"
root=$(try_root)
url=${MAHI_TRY_REMOTE:-}
if [ -n "$url" ]; then
    https_url "$url" > /dev/null
fi
mkdir -p "$root/config" "$root/data"
if [ ! -d "$root/project/.git" ]; then
    make_project "$root/project" "$url"
fi
check_origin "$root/project" "$url"
cd "$root/project"
if [ "$(uname -s)" = Darwin ]; then
    mkdir -p "$root/home"
    export HOME="$root/home"
fi
export XDG_CONFIG_HOME="$root/config" XDG_DATA_HOME="$root/data"
if [ -n "$url" ]; then
    choose_origin "$binary"
fi
exec "$binary" "$@"
