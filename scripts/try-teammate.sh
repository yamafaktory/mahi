#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/try-lib.sh
cargo build --locked -p mahi
binary=$(mahi_binary)
check_binary "$binary"
root=$(try_root)
state="$root/teammate"
name=${MAHI_TRY_TEAMMATE:-bob}
url=
if [ -n "${MAHI_TRY_REMOTE:-}" ]; then
    url=$(https_url "$MAHI_TRY_REMOTE")
fi
mkdir -p "$state/config" "$state/data"
if [ ! -f "$state/key" ]; then
    ssh-keygen -q -t ed25519 -N '' -C "$name@try.mahi.social" -f "$state/key"
fi
socket="$state/agent.sock"
reachable=0
SSH_AUTH_SOCK=$socket ssh-add -l > /dev/null 2>&1 || reachable=$?
if [ "$reachable" = 2 ]; then
    rm -f "$socket"
    ssh-agent -a "$socket" -s | sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p' > "$state/agent.pid"
else
    SSH_AUTH_SOCK=$socket ssh-add -q -D
fi
SSH_AUTH_SOCK=$socket ssh-add -q "$state/key"
if [ ! -d "$state/project/.git" ]; then
    if [ -n "$url" ]; then
        GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='' \
            GIT_CONFIG_KEY_1=credential.helper GIT_CONFIG_VALUE_1='!gh auth git-credential' \
            make_project "$state/project" "$url"
    elif [ -d "$root/project/.git" ]; then
        git clone -q "$root/project" "$state/project"
    else
        echo "run just try first: the teammate clones its project" >&2
        exit 1
    fi
fi
check_origin "$state/project" "$url"
cd "$state/project"
teammate=(USER="$name" SSH_AUTH_SOCK="$socket" XDG_CONFIG_HOME="$state/config" XDG_DATA_HOME="$state/data")
if [ "$(uname -s)" = Darwin ]; then
    mkdir -p "$state/home"
    teammate+=(HOME="$state/home")
fi
if [ -n "$url" ]; then
    credential=$(credential_name "$url")
    credentials=$(env "${teammate[@]}" "$binary" credential list)
    if ! grep -qx "$credential" <<< "$credentials"; then
        gh auth token --hostname "$(url_host "$url")" | env "${teammate[@]}" "$binary" credential add "$credential"
    fi
    choose_origin env "${teammate[@]}" "$binary"
fi
exec env "${teammate[@]}" "$binary" "$@"
