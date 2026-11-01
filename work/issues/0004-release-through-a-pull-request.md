# 0004 Release through a pull request

status: open
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

## Follow-ups

## Result
