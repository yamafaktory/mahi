# 0002 The land tool and its confirmation

status: blocked
depends: 0001
touches: crates/mahi/src/mcp.rs, crates/mahi/src/land.rs, crates/mahi/tests/run.rs, DESIGN.md
design: DESIGN.md "One agent each, kept in sync (milestone 9)": Tools, Landing, Steps; "Landing"

## Goal
Build the step "the `land` tool and its confirmation": the owner lands the thread by asking
their own agent, which calls the `land` tool, as DESIGN.md's Landing describes.

## Acceptance
- The `land` tool behaves as DESIGN.md's Tools and Landing describe.
- The Steps line lists the step as built.

## Log
- 2026-11-01: opened from the milestone 9 Steps line. Blocked: the wording of the landing
  confirmation is an open question in DESIGN.md. Ask the user for it before building it.

## Follow-ups

## Result
