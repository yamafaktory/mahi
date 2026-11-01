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

## D013 · 2026-11-01 · The list_agents mark of agents running here goes

Chosen by the user. `list_agents` marked the user's other agents in the thread as `(running
here)`. Only several agents of one person in a thread give the mark a meaning, and one agent
per person removes them. The running lock that only the mark read goes with it.

## D014 · 2026-11-01 · Landing two agents is tested with a collaborator

Chosen by the user. The test that lands two agents' work used `mahi agent add`. It becomes a
git test in which bob joins as a collaborator through the test SSH remote, so the second
agent is a teammate's, as one agent per person has it.

## D015 · 2026-11-01 · The dogfood test keeps Claude Code alone for now

Chosen by the user. The dogfood test handed Claude Code's thread to Codex. Without handoff,
Codex cannot enter that thread as the same person, and a thread of its own cannot get its
sign-in before it starts. Claude Code's part stays, and issue 0006 brings Codex back as a
collaborator, with a second user in the dogfood world.

## D016 · 2026-11-01 · A collaborator needs the owner's agent to report its turn ends

Chosen by the user. `mahi invite --collaborator` refuses while an agent of the owner in the
thread, running or not, has no built-in profile that reports its turn ends, since a resume
would bring the same agent back. The check runs before a pairing code is shown.

## D017 · 2026-11-01 · Wording of that refusal

Chosen by the user: `tester.sh does not report when its turns end, so a collaborator's work
could not be kept in sync with it; run the thread with Claude Code or Codex, or invite a
--watcher`.

## D018 · 2026-11-01 · The join dialog lists only agents that report their turn ends

Chosen by the user, as DESIGN.md's Joining says. With none on `PATH`, the dialog says
`neither Claude Code nor Codex, the agents that report when their turns end, is on PATH`.
That sentence was written by the agent from D017's wording, for the user to check.

## D019 · 2026-11-01 · GitHub issues hold the work log

Chosen by the user. D011 put the log in `work/`, and D019 replaces that. The issue files in
`work/issues/` and `work/BOARD.md` moved to GitHub issues #10 to #19 (0001 to 0006 became
#10 to #15), and new work starts as an issue. An issue's comments are its log, the labels
`in progress` and `blocked` give its state, and a pull request closes its issue with
`Closes #<number>`.

In this repository, the agent creates issues, comments on them and opens pull requests
without asking the user, on issues and pull requests whose author is the user's account, as
the user already allowed for pull requests. A comment on one that another person opened, or
outside this repository, needs the user's approval for each comment. This file stays in the
repository, because the user's choices belong with the design.
