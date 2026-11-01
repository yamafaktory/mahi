# 0001 One agent per person

status: in-progress
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
- 2026-11-01: the step has three pieces. (1) and (2), in one PR because `start_new_agent`
  served both: remove `mahi agent add` and `mahi handoff`, their home screen keys, menu
  entries and palette actions. (3) Not built yet: refuse to invite a collaborator while the
  owner's agent runs without a built-in profile that reports turn ends.
- 2026-11-01: the briefing code stays: `mahi land --with` quotes it as "the record of an
  agent's work". It goes with `mahi land` in 0003. The notes mechanism (`MAHI_HANDOFF`, the
  notes file, the first prompt) also stays for the draft rewrite, as one optional `Notes` value
  of `Launch`.
- 2026-11-01: the user's choices: D013 (the `(running here)` mark goes, and the running lock
  with it), D014 (the landing test of two agents becomes a git test with bob), D015 (the
  dogfood test keeps Claude Code alone, Codex comes back in 0006).
- 2026-11-01: `the_users_agents_share_one_host_and_the_next_takes_over_when_it_ends` keeps its
  second agent of the user by writing a `tester.codex` snapshots ref, as a thread from before
  one agent per person holds, then resuming it.

- 2026-11-01: review. Fixed: stale text about the running lock and the `(running here)` mark,
  including the `list_agents` description every agent reads; `launch` takes the config its
  callers hold; the notes became a plain path; the dead `g` key went. Coverage restored: the
  tools test reads another agent's work; the draft rewrite test checks the notes prompt as the
  last argument; two tests click `+` in a tab (declining keeps the tab, an agent that cannot
  start shows why); a unit test of `merge::merge_base` with trailers, which a judge found no
  test covered.

## Follow-ups
- 0006: bring Codex back into the dogfood test as a collaborator.
- 0003: the notes file is still named `mahi-handoff.md` and the variable `MAHI_HANDOFF`, though
  only the draft rewrite uses them now.

## Result
