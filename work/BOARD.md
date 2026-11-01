# Board

The coordinator owns this file. When no coordinator runs, the agent that works an issue keeps
its line current.

| Issue | Status | Depends | Note |
|---|---|---|---|
| [0001 One agent per person](issues/0001-one-agent-per-person.md) | in-progress | none | add and handoff removed in a PR; the invite refusal is left |
| [0002 The land tool and its confirmation](issues/0002-land-tool.md) | blocked | 0001 | needs the user's wording for the confirmation |
| [0003 Remove mahi land](issues/0003-remove-mahi-land.md) | blocked | 0002 | |
| [0004 Release through a pull request](issues/0004-release-through-a-pull-request.md) | open | none | `just release` pushes to `main`, which the ruleset now refuses |
| [0005 Cut milestone 9's Steps line down](issues/0005-steps-line-to-built-and-next.md) | open | none | the user reviews the cut |
| [0006 Codex in the dogfood test as a collaborator](issues/0006-dogfood-codex-as-a-collaborator.md) | open | 0001 | the user runs it with their sign-ins |

## Open questions for the user

DESIGN.md's Open questions list the questions the design leaves open. Milestone 9 has four
there: the thread a snapshot names, the landing confirmation's wording (0002), one state per
teammate (D005 put it after the settings keypress, which is now built) and whether Codex's
hooks can add the note. These came up during the work and are not in DESIGN.md:

- Anchoring makes a teammate broadcast full screens that the requester drops. Ordering
  `TurnEnded` per run, as claims frames are ordered, would avoid it. (Raised in review of
  531f097.)
- A failed take in the held turns palette reopens the palette but gives no reason.
- The held turns palette says `No teammate's turn waits for you` even in a run without sync.
- A settings path can wait for a keypress when ours already equals theirs.
- `git_works_for_the_agent_without_showing_the_repositorys_secrets` failed once in four full
  `just test-git` runs (the git pager said "terminal is not fully functional"). Not reproduced.
