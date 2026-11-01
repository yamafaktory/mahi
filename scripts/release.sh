#!/usr/bin/env bash
set -euo pipefail
version=${1:-}
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
    echo "release takes the version, such as 0.2.0 or 0.2.0-rc.1, not '$version'" >&2
    exit 2
fi
shift
execute=false
for argument in "$@"; do
    case "$argument" in
        --execute) execute=true ;;
        *)
            echo "release takes the version and --execute, not $argument" >&2
            exit 2
            ;;
    esac
done
cd "$(dirname "$0")/.."
branch="release/v$version"
tag="v$version"
if ! $execute; then
    cargo release "$version" --no-publish --no-push
    echo "with --execute: commit on $branch, open its pull request, wait for its checks, merge it, then tag $tag and push the tag"
    exit 0
fi
if [ -n "$(git status --porcelain)" ]; then
    echo "release needs a checkout without changes" >&2
    exit 1
fi
if git ls-remote --exit-code --heads origin "$branch" > /dev/null; then
    git fetch --quiet origin "$branch"
    echo "$branch is on origin already: resuming from its pull request"
else
    git fetch --quiet origin main
    git switch --quiet -c "$branch" refs/remotes/origin/main
    cargo release "$version" --no-publish --no-push --no-confirm --execute
    git push --quiet -u origin "$branch"
    gh pr create --base main --head "$branch" --title "Release mahi $version" \
        --body "Bumps every crate to $version. Once it merges, the tag $tag starts the release."
fi
commit=$(git rev-parse "refs/remotes/origin/$branch")
waited=0
while true; do
    status=0
    checks=$(gh pr checks "$branch" --required 2>&1) || status=$?
    if [ "$status" -ne 1 ] || ! grep -q "no checks reported" <<< "$checks"; then
        break
    fi
    if [ "$waited" -ge 300 ]; then
        echo "no checks were reported on $branch within 5 minutes; run this again to resume" >&2
        exit 1
    fi
    sleep 10
    waited=$((waited + 10))
done
gh pr checks "$branch" --required --watch --interval 30
scripts/merge-pr.sh "$branch"
git switch --quiet --detach "$commit"
if git show-ref --verify --quiet "refs/heads/$branch"; then
    git branch --quiet --delete --force "$branch"
fi
git tag --sign "$tag" --message "mahi $version" "$commit"
git push --quiet origin "$tag"
echo "pushed $tag on $(git rev-parse --short "$commit"), which starts the release"
