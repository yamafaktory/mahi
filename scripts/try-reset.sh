#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/try-lib.sh
root=$(try_root)
socket="$root/teammate/agent.sock"
pid_file="$root/teammate/agent.pid"
reachable=0
SSH_AUTH_SOCK=$socket ssh-add -l > /dev/null 2>&1 || reachable=$?
if [ "$reachable" != 2 ] && [ -s "$pid_file" ]; then
    SSH_AGENT_PID=$(cat "$pid_file") ssh-agent -k > /dev/null
fi
rm -f "$socket"
rm -rf "$root"
