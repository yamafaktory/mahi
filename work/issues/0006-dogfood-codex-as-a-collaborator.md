# 0006 Bring Codex back into the dogfood test as a collaborator

status: open
depends: 0001
touches: crates/mahi/tests/dogfood_agents.rs, justfile, README.md, AGENTS.md
design: DESIGN.md "One agent each, kept in sync (milestone 9)": Joining, Sync

## Goal
The dogfood test (`just dogfood`) ran the real Codex by handing Claude Code's thread to it.
Handoff is gone (0001, D015), so the test runs Claude Code alone. Bring Codex back as a
collaborator: a second user in the dogfood world joins Claude Code's thread with Codex, and
the two agents' work is kept in sync.

## Acceptance
- `just dogfood` runs the real Claude Code and Codex, each as its own participant, in one
  thread.
- The user runs it with their sign-ins, since CI cannot.

## Log
- 2026-11-01: opened from 0001 (D015).

## Follow-ups

## Result
