# 0003 Remove mahi land

status: blocked
depends: 0002
touches: crates/mahi/src/land.rs, crates/mahi/src/cli.rs, crates/mahi/src/main.rs, crates/mahi/tests/run.rs, DESIGN.md
design: DESIGN.md "Landing" (which milestone 9 replaces), "One agent each, kept in sync (milestone 9)": Steps

## Goal
Build the last milestone 9 step, "removing `mahi land`", once the `land` tool replaces it,
with its design text in the same commit.

## Acceptance
- `mahi land` is gone, with the design text of what it removes. The trailers stay, as
  DESIGN.md's Landing says.
- The Steps line lists the step as built.

## Log
- 2026-11-01: opened from the milestone 9 Steps line.

## Follow-ups

## Result
