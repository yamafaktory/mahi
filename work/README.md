# Work tracking

The log of mahi's work lives here, in the repository, so that context survives from one
session or agent to the next. A private memory of one agent is no substitute: no other agent
and no reviewer can read it.

- `BOARD.md` lists the issues and their state. The coordinator owns it. When no coordinator
  runs, the agent that works the issue keeps it current.
- `issues/NNNN-slug.md` holds one issue: its goal, its acceptance criteria, its log and its
  result. The number is the next free one, four digits.
- `../docs/decisions.md` records each decision made during the work, oldest first. Append to
  it, never rewrite an entry.
- `scratch/<issue>/` holds logs, large outputs and temporary files. Git ignores it.

## An issue file

```markdown
# NNNN Title in a few words

status: open | in-progress | blocked | done
depends: NNNN, … (or none)
touches: the files and directories the change is expected to change
design: the DESIGN.md sections to read for this issue

## Goal
What the issue achieves, and why.

## Acceptance
- What must be true when it is done.

## Log
- YYYY-MM-DD: what was done, what was found, open questions.

## Follow-ups
- Work found on the way, for the coordinator to turn into issues.

## Result
What landed (commits), how to use it, known gaps.
```

## Working an issue

1. Read the issue and the DESIGN.md sections it names. Set `status: in-progress`.
2. Work in small steps. Each commit adds one piece with its tests, as AGENTS.md says.
3. Keep the `## Log` current. Write the user's choices and their wording in it, and add each
   one to `docs/decisions.md`.
4. List follow-up work under `## Follow-ups`. In coordinator mode, only the coordinator turns
   it into issue files.
5. When the acceptance criteria hold, set `status: done` and fill in `## Result`.

## Coordinator mode

One session working the issues in order is the default. The coordinator mode is opt-in. The
user starts it for issues that touch separate code (fuzz targets, packaging or docs, for
example), because each sub-agent starts cold and uses several times the tokens of one session
(D012).

- At most two sub-agents run at once.
- The coordinator runs `just worktree <issue>`, which makes the worktree `.worktrees/<issue>`
  on the branch `issue/<issue>`. Git ignores `.worktrees/`.
- A sub-agent's shell starts in the main checkout. It works only under its worktree's path,
  and passes that path to every review it starts.
- Each worktree builds into its own `target/`. Never point two checkouts at one
  `CARGO_TARGET_DIR`, or the main checkout's tests run the worktree's older `mahi` binary.
- A sub-agent commits on its branch and never pushes. It reports back what landed, the
  commits, the follow-ups and anything surprising.
- The coordinator reviews the branch, pushes it, opens its pull request and merges it with
  `just merge-pr issue/<issue>` once its checks pass. Then it runs
  `just worktree-remove <issue>`, which removes the worktree with its `target/` and its
  branch.
- The coordinator alone edits `BOARD.md`, creates issue files and merges.
