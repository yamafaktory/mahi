# 0005 Cut milestone 9's Steps line down to built and next

status: open
depends: none
touches: DESIGN.md, docs/decisions.md
design: DESIGN.md "One agent each, kept in sync (milestone 9)": Steps

## Goal
Milestone 9's Steps line is one paragraph thousands of words long. It repeats the behaviour of
each built step in detail. Cut it down to what is built and what is next. Keep each detail
the specification needs in the section that describes the behaviour. Record in
`docs/decisions.md` each choice of the user's that it holds and that the file lacks.

## Acceptance
- No behaviour the Steps line describes is lost: each detail it drops is in another section
  of DESIGN.md.
- Each step the line calls "built so far" (serving and fetching, merging when idle, the note,
  the one view) is either listed as built or has an issue for what is left. Compare the
  design with the code to tell which.
- The user reviews the cut before it lands, because DESIGN.md is the specification.

## Log
- 2026-11-01: opened when the work log moved into the repository (D011).

## Follow-ups

## Result
