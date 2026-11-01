#!/usr/bin/env bash
set -euo pipefail
action=${1:-}
issue=${2:-}
if ! [[ "$issue" =~ ^[0-9]{4}-[a-z0-9-]+$ ]]; then
    echo "worktree takes an issue name such as 0001-one-agent-per-person, not '$issue'" >&2
    exit 2
fi
cd "$(dirname "$0")/.."
path=.worktrees/$issue
case "$action" in
    add)
        git fetch --quiet origin main
        git worktree add -b "issue/$issue" "$path" refs/remotes/origin/main
        echo "worktree $path on branch issue/$issue; it builds into its own $path/target"
        ;;
    remove)
        git worktree remove --force "$path"
        git branch --quiet --delete --force "issue/$issue"
        ;;
    *)
        echo "worktree takes add or remove, not '$action'" >&2
        exit 2
        ;;
esac
