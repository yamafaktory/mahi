# 0001 One agent per person

status: open
depends: none
touches: crates/mahi/src/home.rs, crates/mahi/src/workspace.rs, crates/mahi-term/src/home.rs, crates/mahi/src/handoff.rs, crates/mahi/src/run.rs, crates/mahi-thread/src/handoff.rs, crates/mahi/src/cli.rs, crates/mahi/src/main.rs, crates/mahi/tests/run.rs, DESIGN.md
design: DESIGN.md "One agent each, kept in sync (milestone 9)": One agent per person, Steps; "Multi-engineer, multi-agent"

## Goal
Build the step "one agent per person, removing add and handoff" from the milestone 9 Steps
line. A collaborator has one agent in a thread, so adding a second agent and handing work
off to another agent go away, with their design text in the same commit.

## Acceptance
- The behaviour that DESIGN.md's "One agent per person" describes is built.
- The add agent and handoff actions are gone, with their design text.
- The Steps line lists the step as built.

## Log
- 2026-11-01: opened from the milestone 9 Steps line.

## Follow-ups

## Result
