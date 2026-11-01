# Decisions

Decisions made during the work, oldest first. Append a new entry at the end, and never
rewrite one: a later entry replaces an earlier one by naming it. DESIGN.md stays the
specification. An entry says what was chosen, who chose it and why, and names its commits.

The entries before D012 were moved here on 2026-11-01 from an agent's private notes.

## D001 · 2026-10-23 · Build milestone 9's sync steps in the design's order

Chosen by the user. A teammate who joined as a collaborator saw nothing of the owner's work
until they switched to the owner's agent, because the sync steps were not built. Each step is
its own commit: turn-end snapshots, their announcement, serving and fetching them, merging
when idle, then the one view and the status line.

## D002 · 2026-10-23 · The owner's pairing confirmation names the role

Chosen by the user: `Add bob (SHA256:…) to thread <thread-id> as a collaborator?`, or
`… as a watcher?`. Commit dbe39f1.

## D003 · 2026-10-26 · What counts as an agent settings path

Chosen by the user. `CLAUDE.local.md` and `AGENTS.override.md` are settings paths (a9ff343).
mahi reads through the settings links of the agent's tree (3b5246b). It folds lookalike
names as the filesystems do: the characters HFS+ ignores, NFD, lowercase, `ſ` as `s`, NTFS
`:` and trailing dots, and `~digit` short names (da83760). `@path` imports in `CLAUDE.md`
stay out: links only.

## D004 · 2026-10-26 · Wording of a held turn in the palette

Chosen by the user: `changes agent settings`, and the keys `Enter takes · Ctrl-X skips`.
Commit 8d7dced.

## D005 · 2026-10-26 · One sync state per teammate stays an open question

Chosen by the user: one `SyncState` enum per teammate stays in DESIGN.md's Open questions,
to be done after the settings keypress.

## D006 · 2026-10-27 · The palette of held turns is titled `Held turns`

Chosen by the user. Commit 98cfb9a.

## D007 · 2026-10-27 · One view follows the design

Chosen by the user: build the one view as DESIGN.md describes it, not a modal agents picker.
bob's list of agents was hidden because the workspace decided once, when the first tab
opened, whether to show it.

## D008 · 2026-10-29 · A teammate's agent that asks reads `! asks`

Chosen by the user, from DESIGN.md's word "asks". The user's own agent keeps `! asks you`.

## D009 · 2026-10-29 · Wording of the status line

Chosen by the user. A held turn reads
`bob.claude done · a turn waits for you: changes agent settings`. Conflicts read
`conflicts from bob.claude: src/a.rs, src/b.rs` and come first. When the line overflows,
mahi drops the lists of merged files first, then ends the line with `+N more`.

## D010 · 2026-11-01 · The joiner's pairing line names the role

Chosen by the user, worded as D002: `alice added you to thread <thread-id> as a
collaborator.`, or `… as a watcher.`. `mahi join` prints it. The home screen tells it on the
last line of the thread's tab, with the thread's 8-digit short id, so that the role fits an
80-column terminal.

## D011 · 2026-11-01 · The work log lives in the repository

Chosen by the user, after reading the AGENTS.md of earendil-works/djs. The issues, their logs
and this file live in the repository (`work/`, `docs/decisions.md`), so that every agent and
reviewer reads the same context. While iterating, an agent runs only the tests its change can
break. The full local gate runs once before the pull request, and CI's required checks run
on it before it reaches `main`. Every change reaches `main` through a pull request that merges
once its checks pass, with no approval from the user.

## D012 · 2026-11-01 · The coordinator mode is opt-in, with at most two sub-agents

Chosen by the user. Each sub-agent starts cold and reads the design and the code again, so
parallel agents use several times the tokens of one session. Most of milestone 9's steps also
build on each other. The user starts the coordinator mode only for issues that touch separate
code. At most two sub-agents run at once.
