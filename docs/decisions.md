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

## D020 · 2026-11-02 · The tls-open fuzz target expects a sealed change_cipher_spec record to be refused

Chosen by the user (#27). rustls 0.23.46 refuses a TLS 1.3 record whose inner type is
change_cipher_spec, as RFC 8446 section 5 requires. The `tls-open` target asserted that every
sealed record opens. It now asserts that such a record fails with
`IllegalMiddleboxChangeCipherSpec`, and every other type keeps the round trip. mahi's minimum
rustls becomes 0.23.46.
||||||| parent of 0719547 (Refuse in mahi join an agent without turn ends and the other role's way in)

## D021 · 2026-11-02 · Wording of the join refusals for the other role

Chosen by the user (#16), from the agent's proposals:

- `mahi join <ticket> -- <agent>` for a watcher: `alice added you to thread 3f2a91c as a
  watcher, so you cannot run an agent in it; watch it with mahi join <ticket>, or ask alice to
  invite you as a --collaborator`.
- `mahi join <ticket>` for a collaborator: `alice added you to thread 3f2a91c as a
  collaborator, so you join it with your agent: mahi join <ticket> -- claude, or -- codex`.

## D022 · 2026-11-02 · Wording of the join refusal for an agent without turn ends

Chosen by the user (#16), from the agent's proposal after D017: `tester.sh does not report
when its turns end, so your work could not be kept in sync with your teammates'; join with
Claude Code or Codex`.

## D023 · 2026-11-02 · Wording of the landing confirmation

Chosen by the user (#11), from the agent's proposal, for the open question in DESIGN.md:

```
Land thread 3f2a91c on mahi/3f2a91c

  Retry failed requests in the client
    src/client.rs
    src/retry.rs
  Test the retry
    tests/retry.rs

Pull request: Retry failed requests

Not merged yet, so not in this landing:
  bob.claude  turn ended 4m ago

Enter pushes  Esc cancels
```

## D024 · 2026-11-02 · Wording of the land tool's answers

Chosen by the user (#11), from the agent's proposal:

```
only alice, the thread's owner, lands this thread; ask them to

not landed: each changed path goes in exactly one commit
  in no commit: src/a.rs, src/b.rs
  in more than one commit: src/c.rs
  did not change: README.md

not landed: resolve the conflict markers first, in src/a.rs

nothing changed since the last landing

mahi shows the landing to alice to push or cancel; your next note says which
```

## D025 · 2026-11-02 · Wording of the landing's outcome in the agent's note

Chosen by the user (#11), from the agent's proposal:

```
alice pushed your landing: 2 commits on mahi/3f2a91c to origin.

alice cancelled your landing; nothing was pushed.

your landing was not pushed: origin refused mahi/3f2a91c: <reason>
```

## D026 · 2026-11-02 · Wording of the confirmation after a push

Chosen by the user (#11), from the agent's proposal:

```
Pushed 2 commits on mahi/3f2a91c to origin.
Open the pull request: https://github.com/…/pull/new/mahi/3f2a91c
Its description is in <state>/PR.md and on your clipboard.

Esc closes
```

## D027 · 2026-11-02 · The land tool's description

Chosen by the user (#11), from the agent's proposal: `Lands the thread: mahi commits the
changed files of your worktree as the commits you list, each a message and the paths it holds,
and asks the thread's owner to push them as a pull request with the title and description you
give. Every changed path goes in exactly one commit. Only the owner's agent can land. Do not
commit or push yourself.`

## D028 · 2026-11-02 · The landing commits carry the owner's git identity

Chosen by the user (#11): the land tool's commits carry `user.name` and `user.email` from the
repository's git config as author and committer, read once when the run starts, and the time
they are built. mahi refuses to land when either is not set, and says which one is missing.

## D029 · 2026-11-02 · Wording of the land tool's other refusals

Chosen by the user (#11), from the agent's proposal:

```
not landed: more than 10000 paths changed since the last landing

not landed: git's user.name is not set in this repository; ask alice to set it with git config user.name

not landed: no remote is chosen for this clone; ask alice to choose one with mahi remote <name> --private or --public
```

The same as the second line for `user.email`.

## D030 · 2026-11-02 · Wording of the confirmation while a push runs and when it fails

Chosen by the user (#11), from the agent's proposal: the hint reads `Pushing to origin…` while
the push runs, and a failure replaces the confirmation with `Not pushed: origin refused
mahi/3f2a91c: <reason>`, then `Esc closes`.

## D031 · 2026-11-02 · The owner's run that cannot land

Chosen by the user (#41). When the owner's own run cannot land, because it has no palette on a
terminal, no thread key, or `meta` cannot be read, its agent is told `not landed: this run of
alice's agent cannot show the landing to push or cancel; resume the thread in a terminal with
mahi resume <thread>`.

## D032 · 2026-11-02 · The land tool reads the chosen remote at each call

Chosen by the user (#41). `mahi remote` takes effect on the next `land` call, without a
restart. The git identity stays read once (D028).

## D033 · 2026-11-02 · Control characters in a landing's commit message

Chosen by the user (#41). A call whose commit message holds control characters other than a
newline and a tab is refused: `not landed: the message of commit 2 holds control characters;
write it without them`.

## D034 · 2026-11-02 · The landing shows the branch in full

Chosen by the user (#41). The confirmation, the outcome and the note show `mahi/<thread-id>`
in full, the branch's real name; the title shows the thread short.

## D035 · 2026-11-02 · A branch the forge deleted refuses the landing for now

Chosen by the user (#41). Until the three-way landing on the forge's branch is built, the
tool refuses while the branch record says gone: `not landed: the forge deleted
mahi/<thread-id>, and mahi cannot yet land on top of what it merged`. The fix is built next.

## D036 · 2026-11-02 · PR.md lives in its own folder

Chosen by the user (#41). The description goes to `mahi/state/<thread>/landing/PR.md`, whose
folder name cannot be an agent slot.

## D037 · 2026-11-02 · Two outcome lines after a push

Chosen by the user (#41): `Its description is in <path>.` when the description is over 64 KiB
and not copied, and `cannot keep the pull request draft in <path>: <error>` when PR.md cannot
be written.

## D038 · 2026-11-02 · Where the unremembered branch line goes

Chosen by the user (#41). `cannot remember the pushed branch: <error>` comes last in the
outcome, after D026's lines.

## D039 · 2026-11-02 · mahi end keeps the turn-end record

Chosen by the user (#36). `mahi end` keeps the record of whether the last run reported its
turn ends, so an ended thread still refuses a collaborator after a run without them.

## D040 · 2026-11-02 · The invite refusal for a run without its profile

Chosen by the user (#36). When the owner's agent has a built-in profile that reports turn ends
but its last run went without it: `tester.claude last ran without its profile, so it did not
report when its turns end; resume the thread without --no-profile, or invite a --watcher`.

## D041 · 2026-11-02 · A run without turn ends is refused once there is another collaborator

Chosen by the user (#36, #34). While `meta` lists another collaborator, `mahi run` and `mahi
resume`, by the owner or a collaborator, refuse an agent that would not report its turn ends,
before anything starts: `tester.sh does not report when its turns end, so your teammates' work
could not be kept in sync with it; run Claude Code or Codex, with its profile`.

## D042 · 2026-11-02 · A join by pairing code joins as the role allows

Chosen by the user (#32). A collaborator who joined by code without an agent watches. A
watcher who joined by code with an agent is told `alice added you to thread <id> as a watcher,
so your agent does not run; you watch alice's agents`, and watches.

## D043 · 2026-11-02 · The resume refusal for a watcher

Chosen by the user (#34): `alice made you a watcher in thread <id>, so you cannot run an agent
in it; watch it with mahi join <ticket>, or ask alice to invite you as a --collaborator`.

## D044 · 2026-11-02 · Turn-end frames are ordered per run

Chosen by the user (#19). Turn-end frames are ordered within each run, as claims frames are, so
learning a teammate's turn ends needs no anchoring.

## D045 · 2026-11-02 · A failed take says why

Chosen by the user (#19). When taking a held turn fails, the palette shows `Not taken:
<reason>` under it.

## D046 · 2026-11-02 · The held turns palette in a run without sync

Chosen by the user (#19). A run without sync shows `This run takes in no teammates' work`.

## D047 · 2026-11-02 · A settings path that would not change holds no turn

Chosen by the user (#19). A teammate's turn waits for the keypress only for a settings path
the merge would change.

## D048 · 2026-11-02 · The pager flake gets an issue

Chosen by the user (#19). The one failure of
`git_works_for_the_agent_without_showing_the_repositorys_secrets` is tracked in an issue.

## D049 · 2026-11-02 · The join dialog's message when no agent fits

Chosen by the user (#19), replacing D018's text: `no agent on PATH reports when its turns end; a
collaborator needs Claude Code or Codex with its built-in profile`.

## D050 · 2026-11-02 · No docs on new private items

Chosen by the user (#19). New private and `pub(crate)` items get no `///` docs; only what
`missing_docs` requires is documented. Existing private docs stay unless a change touches them.

## D051 · 2026-11-02 · Snapshots carry a signed thread trailer

Chosen by the user (DESIGN.md open question). Each snapshot names its thread in a signed
trailer, and a fetched snapshot without the right one is refused.

## D052 · 2026-11-02 · One sync state per teammate

Chosen by the user (DESIGN.md open question, D005). What sync holds for a teammate becomes one
enum per teammate, kept in one record.

## D053 · 2026-11-02 · Codex's hooks may carry the note

Chosen by the user (DESIGN.md open question). Find out whether Codex's hooks can add the merge
note as context, and use them when they can.

## D054 · 2026-11-03 · Wording of the refusal when the landing branch changed a path too

Chosen by the user (#11). When the forge deleted `mahi/<thread-id>`, the next landing starts
from the landing branch's tip on the remote. A path that the landing branch changed since the
last landing, and that conflicts with the worktree, refuses the landing: `not landed: main on
up changed these paths since the last landing too: src/a.rs, src/b.rs`. The refusal gives no
advice.

## D055 · 2026-11-03 · Wording when the remote has no landing branch

Chosen by the user (#11). When the forge deleted `mahi/<thread-id>` and the chosen remote has
no landing branch to build on, the land tool fails with `the landing branch main does not
exist on up`, in the shape of `mahi land`'s `the landing branch main does not exist here`.

## D056 · 2026-11-03 · A closed pull request counts as merged for now

Chosen by the user (#11). mahi cannot tell a pull request closed without a merge from a squash
merge without the forge's API. The landing after a deleted branch builds on the landing branch
as DESIGN.md says, so the work of a landing whose pull request was closed is not landed again.
The case is an open question (#62).

## D057 · 2026-11-03 · The worktree takes the tip a landing on the landing branch pushed

Chosen by the user (#11). After a landing that builds on the landing branch's tip, because the
forge deleted `mahi/<thread-id>`, mahi merges the pushed tip into the owner's worktree once the
agent is idle, as it merges a teammate's turn, and the agent's note says so. The worktree then
holds what the landing branch brought, and the next landing finds its changed paths from the
last landed commit's tree, as before.

## D058 · 2026-11-03 · The landing branch's agent settings wait for the user

Chosen by the user (#64). When the merge of a pushed tip into the owner's worktree (D057)
brings a change from the landing branch to an agent settings path, it waits for the user's
keypress, as a teammate's turn does. The palette lists it as a held teammate turn, for example
`main  3m · changes agent settings`. Enter takes it and Ctrl-X skips it.

## D059 · 2026-11-03 · The landing branch's conflict markers

Chosen by the user (#64). The conflict markers of that merge carry the label `mahi main`: the
landing branch's name after `mahi`, as a teammate's carry `mahi bob.claude`.

## D060 · 2026-11-03 · The note after the landing branch's merge

Chosen by the user (#64). The note keeps a teammate merge's header and lines, with `main on
up` as the source. The line for a path where the agent's version was kept points to no tool,
since read_diff cannot show the landing branch's side:

```
mahi merged your teammates' work into your worktree since your last prompt.
Resolve these conflicts before anything else.
Resolve the conflict markers in (from main on up): `m.txt`
Your version was kept, but main on up changed these too: `logo.png`
merged main on up: `upstream.txt`, `m.txt`
```

## D061 · 2026-11-03 · The landing branch's held merge has no skip

Chosen by the user (#64). The merge of the landing branch's changes that waits for the user
(D058) has no Ctrl-X: the palette shows only `Enter takes`, and the merge waits until the user
takes it. Landings meanwhile measure from the tree the last landing recorded, so nothing of the
landing branch's is reverted.

## D062 · 2026-11-03 · The profile key first-prompt-arg goes with mahi land

Chosen by the user (#12). `first-prompt-arg` only told mahi where the first prompt asking an
agent to read its notes goes, which only `mahi land --with` gave. It goes from the profile
format with `mahi land`, so a profile that still sets it is refused as an unknown key is.

## D063 · 2026-11-04 · A kept-ours settings change still waits

Chosen by the user (#55), narrowing D047. A teammate's turn does not wait for a settings path
the worktree already holds as that turn left it. It still waits for a settings path where the
merge keeps the agent's side over the teammate's, so a teammate's instructions do not reach
the agent through `read_diff` without the user.

## D064 · 2026-11-04 · The thread trailer and older snapshots

Chosen by the user (#57), building D051. The trailer is `Mahi-Thread: <thread-id>`, shaped like
`Mahi-Turn-End`. A fetch checks only what can carry it: the newest snapshot it takes must name
the thread, and no snapshot it brings may name another. Older snapshots without the trailer
are taken, since the signed newest one fixes its whole history.

## D065 · 2026-11-04 · Resume names an older snapshot's thread

Chosen by the user (#57). When `mahi resume` starts an agent whose newest snapshot names no
thread, it first adds a snapshot of the same tree that keeps that snapshot's trailers and adds
`Mahi-Thread`, so teammates fetch it again after one run of the new mahi, before any turn.

## D066 · 2026-11-05 · One sync record per teammate holds the held and the skipped snapshot

Chosen by the user (#58), building D052. A teammate can be held and skipped at once: after a
skip of X, a held Y still merges from X as its base. So one record per teammate, at
`sync/<participant>.<agent>/teammates/<teammate's slot>`, holds the skipped snapshot next to
what waits, free or held. It replaces the `held` and `skipped` files. The `conflicts` record,
the run's set of snapshots tried and the agent's turn flags stay where they are. No release
wrote the old files, so mahi does not read them: a held or skipped snapshot an older build
kept is held again at the teammate's next merge, and the user is asked again.

## D067 · 2026-11-05 · A landing refuses file names that are not UTF-8

Chosen by the user (#38). The land tool takes its paths as JSON strings, so the agent cannot
name a file whose name is not UTF-8. A landing whose changes hold such a name is refused with
`not landed: rename these files, whose names are not UTF-8: <paths>`. Paths stay strings
elsewhere: `read_diff` and the note show such names with U+FFFD, for display only.

## D068 · 2026-11-05 · A landing deletes a file name that is not UTF-8 in its last commit

Chosen by the user (#38), narrowing D067. A landing refuses only the names that are not UTF-8
it would write: files added or changed. Such a file the worktree deleted, as after a rename to
a UTF-8 name, goes out in the landing's last commit without the agent naming it, so the
landing branch matches the worktree and the refusal can always be cleared. The confirmation
lists each such deletion under the last commit as `<path> (deleted, name not UTF-8)`.

## D069 · 2026-11-09 · A fetch from the remote skips a watcher's agent refs

Chosen by the user (#87). A fetch from the remote treats a watcher's agent refs (snapshots,
transcript, session) as those of a participant `meta` does not list: they go in `skipped` and
never move. Refs already accepted stay. A teammate who never fetched them then does not see a
former collaborator's past work. The other choices were to keep taking them, since sync never
merges a watcher's work, or to refuse and report them.

## D070 · 2026-11-09 · A joining collaborator's agent starts before the merges

Chosen by the user (#88). `mahi join` starts the collaborator's agent at once, in a worktree at
the thread's base, after its fetch from the remote. Sync counts the agent as idle from its
start, so it merges the teammates' latest turn ends that it holds before the first turn, unless
the user prompts first, and the next prompt carries the note. The join no longer asks the host
for the snapshots, retrying for about 30 s, and merges them before the agent starts, as the
design said before. The code already worked this way, so only the design text changed.

## D071 · 2026-11-09 · Invisible and text direction characters in a landing's commit message

Chosen by the user (#61). The land tool refuses a commit message that holds invisible or text
direction characters, such as U+200B (zero width space) or U+202E (right to left override), as
D033 refuses control characters, with a refusal of its own: `not landed: the message of commit
2 holds invisible or text direction characters; write it without them`. The other choices were
to remove them, to show them escaped in the confirmation, or to keep them.

## D072 · 2026-11-09 · Ask whether a deleted thread branch's pull request was merged

Chosen by the user (#62), replacing D056. When a fetch finds that `mahi/<thread-id>` is gone
from the remote since the last landing, the landing confirmation first asks the owner about that
pull request. Body: `The last landing's branch is gone from <remote>. If its pull request was closed
without a merge, its changes can land again.` Hint: `y lands them again  n they were merged  Esc
cancels`. On `y`, the changes of the last landing land again. On `n`, the landing goes on as it
does today. How `y` finds those changes is open. The other choice was to find the changed paths
from the tree of `mahi/<thread-id>`.

## D073 · 2026-11-09 · The status line shows a held merge of the landing branch

Chosen by the user (#65). A merge of the landing branch into the owner's worktree that waits
for the keypress shows as the status line's first item, before the conflicts: `main · a merge
waits for you: changes agent settings`, with the landing branch's name in place of `main`. This
changes DESIGN.md's One view, where the conflicts came first, once #65 is built.

## D074 · 2026-11-09 · The D040 refusal names the agent instead of --no-profile

Chosen by the user (#71), replacing D040's advice. D040's invite refusal ends with `resume the
thread with Claude Code and its profile, or invite a --watcher`, with the agent the slot's
profile names, so it holds after a run of another program in the slot too. DESIGN.md quotes
D040's text and changes with it. Which name a profile without a known agent shows is open.

## D075 · 2026-11-09 · A code join refuses when the role turned to watcher during its fetch

Chosen by the user (#72), narrowing D042. A join by pairing code with an agent reads `meta` again after its
fetch, as a ticket join does, and refuses before the agent starts when the user is now a
watcher: `alice made you a watcher in thread <id> while you joined, so your agent does not run;
ask alice for a new code to watch`. The other choice was to watch, as D042 does, which needs the
live node again.

## D076 · 2026-11-09 · The reasons a held turn's take fails before a merge

Chosen by the user (#76), building on D045. Under a held turn whose take fails before any merge,
the palette shows one reason per case, with the teammate's name in place of `bob`:

- `meta` cannot be read: `Not taken: cannot read the thread's members`.
- The user is no longer a collaborator: `Not taken: you are no longer a collaborator`.
- The teammate is no longer a collaborator: `Not taken: bob is no longer a collaborator`.
- The teammate did not sign the snapshot: `Not taken: bob did not sign this turn`.

## D077 · 2026-11-09 · Report a host address that cannot be published

Chosen by the user (#98). A host that cannot publish its address reports the first failure
once on standard error: `mahi: mahi invite cannot find this thread's live address: <error>`.

## D078 · 2026-11-09 · An agent in raw mode is not told that mahi's input ended

Chosen by the user (#102). Nothing changes: when mahi's input ends, mahi sends one end of file,
and only while the agent's terminal is in line mode, as it does today. An agent that reads its terminal in raw mode waits, as it
would with no keys typed. The other choices were to hang up the terminal, or to send the end of
file once line mode comes back.

## D079 · 2026-11-09 · When the host prints the unpublished address report

Chosen by the user (#98). The report of D077 prints at once while no agent runs, such as in the
workspace. `mahi run` holds the report from the moment its host starts and prints it after the
agent exits, so it never lands on the agent's screen. A later publish that succeeds resets the
report: the next failure is reported again, once.

## D080 · 2026-11-09 · A landing records the tree it measured from

Chosen by the user (#62), settling D072's open point. Each landing's record keeps one more tree:
the worktree tree that landing measured its changed paths from. On `y`, the next landing measures
from that tree again, so the last landing's paths count as changed and merge onto the landing
branch's tip. The other choice was to walk back `mahi/<thread-id>` to the commit the last landing
built on and measure from its tree, which could land paths that landing did not hold.

## D081 · 2026-11-10 · `y` cancels the landing and tells the agent to land again

Chosen by the user (#62), settling how D072's `y` lands the changes again. The agent's pending
`land` call names commits for the new paths only, so `y` cancels it. The record notes the answer,
and the agent's note reads: `<owner> cancelled your landing: the last landing's pull request was
closed without a merge, so its paths count as changed again; call land again with commits that
place them.` The next `land` call measures from the last landing's tree (D080). The other choice
was to measure again at once and refuse the call with the paths its commits do not place.

## D082 · 2026-11-10 · mahi remembers an `n` answer

Chosen by the user (#62). On `n`, the record notes that the pull request was merged. Later `land`
calls then skip the question until a landing pushes. A push writes a new record without the
answer. A fetch that finds the branch back on the remote also clears the answer. The other choice
was to ask on each call until a push.

## D083 · 2026-11-10 · The question shows after the landing is built

Chosen by the user (#62). A `land` call builds its landing first, with the fetch of the landing
branch, and shows the question after. A refusal or a failed fetch therefore shows without the
question. The other choice was to show the question at once and build the landing after `n`.

## D084 · 2026-11-10 · A home screen code join refuses with D075's text

Chosen by the user (#109). A code join from the home screen starts its agent as
`mahi join <ticket> -- <agent>`. When the owner makes the user a watcher during that join, the
agent's tab refuses with D075's text: `alice made you a watcher in thread <id> while you joined,
so your agent does not run; ask alice for a new code to watch`. The other choice was to keep
D021's ticket text, which names a ticket the user never saw.

## D085 · 2026-11-10 · Codex keeps calling `list_agents` for the note

Chosen by the user (#59), building on D053. Codex's prompt hook now adds the note to the user's
prompt, as Claude Code's does. Codex runs a changed hook only once the user approves it again, so
its server instructions keep asking it to call `list_agents` at the start of each turn, and
whichever comes first takes the note. The other choice was to give Codex Claude Code's
instructions, which say that the user's next prompt carries the note, so the note would wait
until the user approved the hook.

## D087 · 2026-11-10 · A Codex subagent's prompt is left out

Chosen by the user (#115). Codex fires its prompt hook for each subagent it spawns, with an
`agent_id` in the payload. mahi leaves such a prompt out: it is not recorded as the user's ask,
changes no state and gets no note. The agent's own turn covers the subagent's work. The other choice
was to record it marked as the subagent's prompt, which would change the transcript format.

## D088 · 2026-11-10 · The note after `y` when the branch came back

Chosen by the user (#111). A fetch can find the last landing's branch back on the remote while
the landing confirmation asks about it. When the owner then answers `y`, the last landing's paths
do not land again, and the agent's note reads `alice cancelled your landing: the last landing's
branch is on up again, so its paths do not land again; call land again.`, with the owner's name
and the remote. The other choice was to keep the plain line `alice cancelled your landing; nothing
was pushed.`.

## D089 · 2026-11-11 · No fix for an `n` answer after the branch came back

Chosen by the user (#120). Only a fetch while the landing confirmation asks can find the gone
branch back. Only a second mahi process in the same clone that starts another of the owner's
agents fetches then, through `mahi join` or `mahi resume --agent`. mahi leaves `n` as it is in
that case. The other choices were to cancel the landing with a note, as D088 does for `y`, or to
refuse such a second process before it fetches.

## D090 · 2026-11-11 · The Codex dogfood signs in through ChatGPT in the browser

Chosen by the user (#15). The dogfood test runs `codex login` with `CODEX_HOME` set to the
teammate's thread state directory. Codex prints a URL and opens it in the browser, and the user
signs in with ChatGPT, so each run needs the user. Nothing is read from `~/.codex`, and the sign
in stays in the test's throwaway directory. The user first chose an OpenAI API key read from a
file, but an API key needs a paid OpenAI Platform account. A ChatGPT device code then failed:
OpenAI's device page kept asking to turn device codes on after the user turned them on. The other
choice was to copy `~/.codex/auth.json` into the thread, which a token refresh could sign out.

## D091 · 2026-11-11 · The Codex dogfood prompts Codex once Claude's work is merged

Chosen by the user (#15). The test starts `mahi join` with Codex and no task. It waits until
Claude's turn is merged into Codex's worktree, then types the task. Codex then starts from
Claude's work, without a conflict, and the test checks D070's merge before the first turn. The
other choice was to pass the task on the command line, as the user prompting first, and to type
a second prompt so that mahi's note makes Codex resolve the conflict markers.

## D092 · 2026-11-11 · Transcript turns travel live with the turn-end snapshots

Chosen by the user (#125). A host's answer to a request for an agent's turn-end snapshots also
holds that agent's transcript turns since the last one the asker holds, so `read_transcript`
shows a teammate's turns during the session. The protocol becomes `mahi/snapshots/2`, and turn-end
and claims frames gain a field, so a peer on an older mahi gets no live sync, and its claims frames
are refused, until both sides upgrade. The other choice was a separate protocol,
`mahi/transcript/1`, which keeps live snapshot sync with an older peer but adds a second handler
with its own limits and checks.

## D093 · 2026-11-11 · Turn-end frames name the transcript's newest commit

Chosen by the user (#125). A turn that changes no file adds no turn-end snapshot, so nothing would
ask for its transcript turns. Turn-end and claims frames now name the agent's newest transcript
commit beside its latest turn-end snapshot, and the asker asks when it lacks either one. A
transcript that moved without a turn end is named in the next claims frame, within 10 s, rather
than in a turn-end frame of its own, so a turn that ends with a snapshot is fetched once. The
other choice was to add a turn-end snapshot at every turn end, even with no file change, which adds
an empty commit for each question and still sends nothing while conflicts are unresolved.

## D094 · 2026-11-12 · mahi gets a theme of its own, inspired by delta.dev

Chosen by the user (#129). mahi's views take a palette inspired by https://delta.dev/ but not
the same: its cool greys pulled toward plum, Royal Plum kept as the accent for titles, the
selected row and the badge, and green, red, amber and orange for added lines, removed lines, what
waits for the user and conflicts. mahi paints its own surfaces only (the side panel, the tab bar
and the dialogs), and the agent's pane keeps the terminal's background, since the agent draws its
colours against it. Dark terminals only for now. Each participant gets a colour of their own, from
plum, teal, amber, blue, coral and green, by their place in `meta`, so the colour is the same on
every teammate's screen. The other choices were delta's palette with its blue accent, which drops
Royal Plum, and the terminal's own colours with delta's text and diff colours only.


## D097 · 2026-11-12 · Participant colours that no status colour uses

Chosen by the user (#129). D094's amber, coral and green look like the colours of what waits for
the user, removed lines and added lines, so a teammate's name could read as a status. They are
replaced by lavender #A98BE0, sky #6CC7E0 and sand #BFB09C, beside plum, teal and blue. Conflicts
take a brighter orange, #F0883C, which stays apart from every participant colour on a terminal of
256 colours too. The other choices were to keep the six, or to use only plum, teal and blue.

## D095 · 2026-11-12 · Every participant's status shows in a panel at the right of the agent

Chosen by the user (#130). The status line under a thread's pane is hard to see, and every
participant should always see the status of everything. A thread's tab shows a panel at the
right of the agent's pane, and the status line comes back only on a terminal too narrow for the
panel. The other choices were the same panel hidden by a key, and several rows under the pane.

## D096 · 2026-11-12 · The panel lists the agents, then the changes since the base

Chosen by the user (#130). The panel lists each agent of the thread, the user's own first, with
its state and the files merged from it since the user's last prompt. Below them, it lists the
files of the user's worktree that changed since the thread's base or its last landing, with the
added and removed line counts: what a landing would hold. The other choices were each agent's
own changes since the base, read from its latest turn-end snapshot, or the merged files only.

## D098 · 2026-11-12 · Each agent reports the changes it sees, when asked and on its own

Chosen by the user (#133, #134). A new MCP tool, `read_status`, gives the agent what the panel
shows, so it answers when the user asks what changed. And after a merge that brought a
teammate's files or left conflicts, mahi types a prompt into the agent, so it reports at once in
its own pane, at the cost of one turn for each such merge. The other choices were the tool alone,
or the prompt alone.

## D099 · 2026-11-12 · The prompt after a merge names the teammates whose work merged

Chosen by the user (#134). mahi types `mahi merged bob.claude's work. Tell me what changed.`,
naming each teammate's agent whose work the merge brought, as `bob.claude's and carol.codex's`
for two. The note, with the files, reaches the agent with the prompt. The other choices were
`mahi merged your teammates' work. Tell me what changed.` and `mahi merged your teammates' work.
Read what changed and tell me whether it affects your work.`

## D100 · 2026-11-12 · A held turn taken in the palette prompts no report

Chosen by the user (#134). A teammate's turn held for the user's keypress, because it changes
agent settings, and taken in the palette, merges with no report prompt after it: the user just
chose to take it, and the note still reaches the agent with their next prompt. The other choice
was to prompt the agent as after an automatic merge.

## D101 · 2026-11-13 · A new agent's session start lets the report after a merge in

Chosen by the user (#137). After a teammate's work merges, mahi types the report into the agent
once its `SessionStart` hook ran, with no key of the user's since, as after a reported turn end.
So a new agent reports a merge before its first turn. Claude Code runs hooks only in a trusted
folder, so its trust dialog is closed by then. The other choices were an agent quiet and
untouched since it started, which could type into a startup dialog, or waiting for the agent's
first turn end.

## D102 · 2026-11-13 · A Codex agent with no dialog at launch takes the report at once

Chosen by the user (#137). Codex 0.168 fires `SessionStart` only with the first prompt, so it
cannot tell mahi that a new Codex agent is ready. mahi takes the launch as a reported turn end,
once Codex first writes, when Codex can open no dialog: it starts with no argument or its resume
arguments, it is signed in, it trusts the worktree or its repository's root, each hook of
mahi's is approved with the hash Codex computes for the hook mahi installs now, and neither
folder holds a `.codex` entry. A popup that a later Codex adds is not covered. The other choices
were text on Codex's screen that shows only at an empty composer, which each release can
change, or the fix for Claude Code alone, with Codex waiting for its first turn.

## D103 · 2026-11-13 · The workspace shows the terminal's background and text colour

Chosen by the user (#143), in place of part of D094. The agent's pane kept the terminal's
background while mahi painted its own surface on the tab bar and the side panel, so two
backgrounds showed side by side. mahi now paints no background on the tab bar and the side
panel: they and the agent's pane show the terminal's background, and their plain text takes the
terminal's own colour, so it reads on a light terminal too. Borders and colours keep the parts
apart. The badge and the selection keep Royal Plum (D094), and dialogs and the palette keep
mahi's surface, so they stand out. The other choices were mahi's background everywhere, painting
it on every cell the agent leaves at the default background, and, for the text, keeping mahi's
light grey #E2DEE6.

## D104 · 2026-11-13 · The note groups a merge's files by what was done to them

Chosen by the user (#142). After a teammate's work merged, the note listed its files with no word
for what happened, so an agent could not tell that a merge deleted a file. The note now groups
each teammate's files by kind, in one clause each: `merged davy.claude: added src/new.rs,
docs/a.md; changed src/lib.rs; deleted README.md`. The other choices were a verb on each file,
`added src/new.rs, added docs/a.md, …`, and signs like a diff, `+src/new.rs ~src/lib.rs
-README.md`.

## D105 · 2026-11-13 · read_diff keeps comparing with the thread's base

Chosen by the user (#142). After a teammate reverted their own change, their tree matched the
thread's base again, so `read_diff` showed no change although the merge deleted the user's copy.
The note's kinds (D104) now tell the agent what the merge did, and `read_diff` keeps one meaning:
what a teammate changed since the base. The other choice was to make `read_diff` also show what
the last merge of a teammate's work changed in the user's own worktree.

## D106 · 2026-11-13 · A file added then deleted before the next prompt leaves the note

Chosen by the user (#142). Several merges from one teammate can land before the agent's next
prompt, and the note shows what they came to together. A file a teammate added and then deleted
in that time leaves the note, since the agent never saw it; when it was the teammate's only
file, the teammate leaves the note and no report is typed for them. The other choice was to show
it as deleted, the latest kind.

## D107 · 2026-11-13 · A file the agent was shown as added reads deleted when it goes

Chosen by the user (#142), narrowing D106. The prompt hook can show the note, then a merge lands
before mahi takes it, so the note stays. mahi then marks the added files the shown note named,
and puts back as deleted any of them that a merge deleted while the hook read it. From then on,
such a file added and then deleted reads `deleted` in the note, so the agent learns that a file
it read about is gone; any other file added then deleted still leaves the note. The other
choice was to keep dropping it.

## D108 · 2026-11-14 · An escape byte before another one leaves the line unfinished

Chosen by the user (#150). Terminals that send Alt as an escape prefix send Alt+Up as
`ESC ESC [A`. Codex reads those bytes as Escape, and an agent that reads them as Alt+Up keeps
working. mahi counts an escape byte right before another one as a key that leaves the agent's
input line unfinished, in one read or across two. Merges wait until Enter, Ctrl-C, Ctrl-U or
Escape empties the line again, and never land in a running turn. The other choices were to read it as the Escape key, which ends
the turn for mahi while such an agent still works, or as an Alt prefix that changes nothing,
which lets a merge run while Escape pressed twice holds a picker open.

## D109 · 2026-11-14 · The side panel lists a teammate's merged files in a row per kind

Chosen by the user (#147). The panel listed each teammate's merged files as `merged: <files>`,
with no word for what the merge did. It now shows one row per kind, deleted first, as the note
groups them (D104): `deleted: <files>`, `changed: <files>`, then `added: <files>`. The rows read
without colour, and the deleted files show first when the panel cuts the list short. The other
choices were a sign before each file, a sign with colour, and colour alone.

## D110 · 2026-11-14 · mahi gets a palette for light terminals

Chosen by the user (#144), in place of D094's dark terminals only. Since D103 the tab bar and the
side panel show the terminal's background, and on a white one some of mahi's colours read
poorly. mahi asks the terminal for its background with OSC 11 at start and picks a dark or a
light palette from it. Dark stays the default when the terminal does not answer. The light
palette's colours are still to be chosen. The other choice was to keep the theme for dark
terminals only.

## D111 · 2026-11-14 · An agent can trace a line of code back to its thread, after a plan

Chosen by the user (#148). A tool lets an agent go from a line of code to the thread, the agent
and the turns that wrote it. A plan in the issue comes first: the tool's shape, how it finds the
turn, what a user outside the thread gets, and what happens after a squash or a rebase. The user
approves the plan before any code. The other choices were to keep the idea for later, or to
close it.

## D112 · 2026-11-14 · A second Escape soon after the first leaves the line unfinished

Chosen by the user (#153), widening D108. Escape pressed twice opens Claude Code's rewind picker
and Codex's backtrack picker, and each press arrives as a read of its own. A second Escape soon
after the first now leaves the agent's input line unfinished, so no merge runs while a picker is
open. Merges wait until Enter, Ctrl-C, Ctrl-U or a later single Escape. The window follows the
agents' own double-press window. The other choice was to leave each Escape as the Escape key.

## D113 · 2026-11-14 · The light palette keeps the dark palette's hues, darkened

Chosen by the user (#144), completing D110. Each light colour keeps the hue of its dark colour
and is darkened until it reaches 4.5:1 contrast on white, on #FDF6E3 and on the light surface:
ACCENT #C1318E, MUTED #736B80, ADDED #4F783D, REMOVED #CF2D3B, WARN #8D671F, CONFLICT #B1520E,
teal #367974, blue #2D68D9, lavender #7F53D1, sky #1E7790, sand #7E6B51, the surface #F6F3F8
with text #2A2630, and pane borders #D3CDD9. Royal Plum stays behind the selection and the badge,
with its text in #E2DEE6. Dialogs and the palette take the light surface on a light terminal.
Teal is #367974 rather than the proposed #367973, so it stays apart from ADDED on a terminal of
256 colours. The other choices were to keep dialogs dark in both palettes, or to adjust colours.

## D114 · 2026-11-14 · A second Escape follows each agent's own picker

Chosen by the user (#153), completing D112. Claude Code opens its picker on a second Escape
within 800 ms of the first, and Codex opens its backtrack preview on any Escape after an Escape
with no other key between. mahi follows each: for Claude Code a second Escape within 800 ms
leaves the line unfinished and a third counts as Escape again, and for Codex every Escape after
an Escape, with no other key between, leaves it unfinished. The other choices were 800 ms for
every agent, or no window for every agent. During the work, not by the user, an agent mahi does
not know is taken as Codex, so no merge runs while a picker may be open.

## D115 · 2026-11-15 · The home screen joins with J

Chosen by the user (#160), with the key left to the agent. `c` for join was confusing, and `j`
stays the vim motion down. The agent chose `J` (Shift-J): it keeps the letter of join, and
every other letter it could take had no link to join. The other choices were `o`, `a` and `w`.
With Caps Lock on, `j` on most terminals sends `J` and opens the join dialog. The user keeps
`J` anyway, since Escape closes the dialog and nothing joins without a code.

## D116 · 2026-11-15 · The palette ends with e and invites with i

Asked for by the user (#161). The workspace's palette listed End this thread and Invite a
teammate with no key. The agent proposed `i` for invite, the home screen's key, and the user
chose `e` for end as well, also the home screen's key. Each key acts only while the palette
lists its action, once the shown tab knows its thread. The other choice was to leave End this
thread without a key.

## D117 · 2026-11-15 · Adding a teammate who paired selects Yes first

Chosen by the user (#162). When a teammate pairs, the owner's question `Add <name>
(<fingerprint>) to thread <thread-id> as a <role>?` selected No first. The owner gave the code
to that teammate, so the question now ends in `[Y/n]`: its dialog selects Yes first, and on
lines an empty answer adds the teammate. Every other confirmation keeps No first. The No default
came from the generic confirmation, not from an earlier choice. During the work, not by the
user: a question asked on lines now drops the keys typed before it, so an Enter pressed while
the owner waits for the teammate cannot add them. Then, chosen by the user: a question that
selects Yes first takes no key for its first 500 ms, as the land question does, so an Enter
pressed just as it shows cannot add the teammate either. A question that selects No first takes
keys at once, since Enter there declines.

## D118 · 2026-11-16 · An erased line counts as empty again

Chosen by the user (#166). In a run with two terminals, the owner typed in their agent's line
and erased it with Backspace. mahi counted the line as unfinished until Enter, Ctrl-C, Ctrl-U
or Escape, so the collaborator's merge waited almost four minutes, and the report prompt never
came. mahi now counts the ASCII characters typed and the Backspaces, and a count back to zero
empties the line. Any other cursor or edit key, a character outside ASCII or an Alt chord makes
the count unsure, so the line stays unfinished. Every mistake leaves the line unfinished, never
empty. The other choices were to keep the rule and say on the status line that a merge waits
for the line, or both. Also chosen by the user: the report prompt comes once the line is
counted back to empty, not only when no key came since the turn end. The user first included
Enter, Escape, Ctrl-C and Ctrl-U. The review then found that Enter can send a built-in command
such as `/model`, which opens a picker no hook reports, that Escape can keep a draft or step
back only one level of a nested dialog, and that Ctrl-U clears one line of a multi-line draft.
So the user chose Backspace back to zero only. Those keys still empty the line for merges, and
a prompt hook clears it for the report. An arrow or Tab on an empty line also leaves it not
clear for the report.

## D119 · 2026-11-16 · Real times, sealed in the transcript turns

Chosen by the user (#177, #178). mahi kept no time at all: thread commits carry the time zero
to limit metadata leakage, and ages counted from when a run first saw a turn. The user wants
real times. They chose to seal them in the records only the thread's participants read, so
each transcript event now carries the time the host took it in, as a `jiff` `Timestamp`, in
version 2 of the turn record. Thread commits keep the time zero. The other choice was a real
commit date on snapshots and turns, which anyone who reads the remote would see. During the
work, not by the user: version 1 turns still read, with no time, and a time that goes back
within a turn is accepted, since a clock can step back.

## D120 · 2026-11-16 · Times read as how long ago, then as a day and time

Chosen by the user (#178). A time under a day old shows as how long ago it was, such as `3m ago`,
and an older one as its day and time in the local time zone, such as `Nov 14 14:05`. The other
choices were always an absolute local time, or always UTC. During the work, not by the user: a
time from another year adds the year (`Jul 1 2025 10:30`); a time after now, from a teammate
whose clock runs ahead, shows its day and time; without a time zone mahi shows UTC and writes
`UTC` after the time; `read_transcript` heads a turn as `Turn 3 (2h ago):`; the JSON of
`mahi threads search` carries `time` in RFC 3339, in UTC; the workspace's record of an offline
teammate always shows days and times, since it stays on screen as it was made; and an empty `TZ`
counts as unset.

## D121 · 2026-11-16 · Last activity behind a flag, and on the home screen once unlocked

Chosen by the user (#178). A thread's last activity comes from its turns' times, which are
sealed, so reading them needs the passphrase, and plain `mahi threads` asks none. So
`mahi threads --activity` asks once and adds each thread's last activity, and the home screen
shows it while the mahi key is unlocked, leaving it blank otherwise. The other choices were the
home screen alone, or no last activity. During the work, not by the user: the text reads
`last active 3m ago`, the JSON field is `last_active` and appears only with `--activity`, and
each agent's turns are read back at most 64 turns for a time; on the home screen, the column
goes when the agents would get fewer than 16 cells, before the whole thread id does.
