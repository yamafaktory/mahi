#!/usr/bin/env bash
set -euo pipefail
branch=${1:-}
if [ -z "$branch" ]; then
    echo "merge-pr takes the branch of the pull request" >&2
    exit 2
fi
cd "$(dirname "$0")/.."
git fetch --quiet origin main "$branch"
tip=$(git rev-parse "refs/remotes/origin/$branch")
if ! git merge-base --is-ancestor refs/remotes/origin/main "$tip"; then
    echo "$branch does not hold origin/main: rebase it onto origin/main, push it and wait for its checks" >&2
    exit 1
fi
if ! checks=$(gh pr checks "$branch" --required 2>&1); then
    echo "$checks" >&2
    echo "the required checks of $branch have not all passed" >&2
    exit 1
fi
git push --quiet origin "$tip:refs/heads/main"
git push --quiet origin --delete "$branch"
git fetch --quiet --prune origin
echo "origin/main is at $(git rev-parse --short "$tip"), merged from $branch"
