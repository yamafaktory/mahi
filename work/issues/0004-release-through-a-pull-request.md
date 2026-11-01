# 0004 Release through a pull request

status: done
depends: none
touches: justfile, Cargo.toml, crates/*/Cargo.toml, AGENTS.md
design: none

## Goal
Make `just release` work with the ruleset on `main`, which requires the CI checks before a
commit reaches `main`. Today cargo-release commits the version bump and pushes it straight to
`main`, and the ruleset refuses that commit, because no check ran on it.

## Acceptance
- `just release <version> --execute` brings the version bump to `main` through a pull request
  whose checks pass, then tags `v<version>` on that commit.
- Without `--execute`, it still only shows what it would do.
- AGENTS.md describes the new flow.

## Log
- 2026-11-01: opened when the required checks were added to the ruleset "Protect main".
- 2026-11-01: `scripts/release.sh` commits the bump on `release/v<version>`, opens its pull
  request, waits for its required checks, merges it with `merge-pr.sh`, then signs and pushes
  `v<version>`. The tag's name and message moved from the manifests into the script, so they
  have one source; cargo-release no longer tags. The dry run was tried on a throwaway
  `release/` branch. `--execute` was not run, since it would publish a release.

- 2026-11-01: review. The script refuses a level such as `patch`, which would have pushed a
  tag `vpatch` that the ruleset keeps for good; tags the release commit itself, not
  `origin/main` after the merge; waits until the checks are reported; resumes from the branch
  on `origin` when run again.

## Follow-ups
- The pre-release hook (`cargo update --workspace --offline` on `fuzz/Cargo.lock`) runs in
  the dry run too, and changes `fuzz/Cargo.lock` (it moved tokio from 1.53.1 to 1.54.1).
  This was true before this change.

## Result
`just release <version> --execute` releases through a pull request. Not yet run for real.
