# mahi — design

> *mahi* (te reo Māori): work.

mahi is a single Rust binary that lets multiple engineers collaborate in real time with **any** terminal coding agent (Claude Code, Codex, Gemini CLI, …), peer-to-peer, with the full history of the work stored encrypted in the project's own git remote.

## Thesis

Review shouldn't be a gate at the end. When teammates watch, steer and prompt each other's agents while the work happens, design problems are caught at turn 3 instead of in a finished PR. By the time a branch lands, the discussion has already happened; the PR on GitHub/GitLab becomes a quick skim of changes people already saw being made.

## Principles

- **Agent-agnostic.** Wrap the agent's own terminal UI; never require a specific agent or editor.
- **Peer-to-peer.** No mahi server. Realtime traffic goes directly between peers.
- **Git-native.** All durable state lives in git refs on the project's existing remote. The result of a thread is one ordinary remote branch.
- **Private by default.** Rich history (transcripts, agent state) is end-to-end encrypted before it becomes a git object.
- **Sandboxed.** Every agent runs inside an OS-level sandbox, so teammates can prompt each other's agents safely.
- **Use the forge for what it's good at.** Final diff viewing and approval happen in GitHub/GitLab. mahi does not rebuild review tooling.

## Non-goals (decided)

- Signed review attestations / `allowed_signers` trust roots: overhead with little value when repo access already defines the team. May return later as an optional compliance layer built on forge identities.
- Implicit review-coverage tracking: dropped; the forge's PR diff covers the final look.
- Multiple agents editing the same worktree simultaneously.

## Architecture

### Core (agent-independent)

- **PTY wrapper**: launches the agent in a pseudo-terminal (`portable-pty`), passes it through to the user's terminal, and maintains a virtual screen (`vt100`) for late joiners and crude text snapshots.
- **Sandbox**: the whole agent process runs inside bubblewrap (Linux, WSL2) or Seatbelt (macOS). Same pattern as Anthropic's sandbox-runtime (`srt`), implemented natively in Rust.
- **Proxies**: a network allowlist proxy, and an LLM API proxy that injects the API key (the key never enters the sandbox) and meters tokens per participant.
- **Worktree watcher** (`notify`): debounced snapshots of the agent's worktree into hidden refs.
- **Git storage**: `gix` for local object/ref writes; the `git` CLI for network operations.
- **Live layer**: iroh (QUIC, hole punching, relay fallback) + iroh-gossip, one topic per thread.
- **Shared state**: a CRDT (Automerge or Loro) for multi-writer data: human chat, claims, comments.
- **Prompt queue**: remote prompts are held and injected into the agent's PTY only when it's idle.
- **MCP server**: exposes the thread to every agent (list agents, read others' transcripts/diffs, merge a branch, claim a file/task).

### Adapters (agent-specific)

An adapter answers: how to launch, where state lives and how to relocate it per thread, what the sandbox must allow, how to get structured events, how to detect idle, and how to resume.

```rust
trait Adapter {
    fn launch(&self, ctx: &ThreadCtx) -> LaunchSpec;          // argv, env, config dir
    fn sandbox_needs(&self) -> SandboxNeeds;                   // domains, paths
    fn install_capture(&self, ctx: &ThreadCtx) -> Result<()>;  // hooks, config
    fn events(&self, ctx: &ThreadCtx) -> EventStream;          // normalized events
    fn idle(&self) -> IdleSignal;                              // hook, pattern, or quiet
    fn resume(&self, session: &SessionRef) -> Option<LaunchSpec>;
}
```

Support is a gradient:

1. **No profile**: sandbox, live terminal view, worktree snapshots. Idle = output quiet + optional prompt regex on the virtual screen.
2. **Declarative profile (TOML)**: state relocation, sandbox rules, resume command, idle signal.
3. **Parser / external adapter**: structured transcript. External adapters are separate executables speaking JSON lines over stdio, so anyone can add an agent in any language.

Example profile:

```toml
[agent]
name = "claude-code"
command = ["claude"]
resume = ["claude", "--resume", "{session_id}"]

[state]
env = { CLAUDE_CONFIG_DIR = "{thread_dir}/claude" }

[sandbox]
domains = ["api.anthropic.com"]

[capture]
hooks = "claude-code"
transcript = "{thread_dir}/claude/projects/**/*.jsonl"
parser = "claude-jsonl"

[idle]
signal = "hook:Stop"
```

Canonical event format: the ACP (Agent Client Protocol) session-update schema. Adapters normalize into it. Agents with a headless streaming-JSON mode can be driven that way when no human is at the terminal (e.g. agents hosted on an always-on peer).

Notes for Claude Code: a per-thread `CLAUDE_CONFIG_DIR` lets mahi inject hooks without touching the user's global config, and tells it exactly where transcripts land. Hooks run inside the sandbox, so the hook handler (`mahi hook`) talks to the host binary over a bind-mounted Unix socket. Hook handlers must never block or fail the agent: log and exit 0.

## Storage layout

```
refs/threads/<id>/meta                     # title, base, participants, wrapped keys, landing branch
refs/threads/<id>/<agent>/snapshots        # one commit per edit (worktree trees)
refs/threads/<id>/<agent>/transcript       # one commit per agent turn (encrypted)
refs/threads/<id>/<agent>/session          # native agent session files (encrypted)
refs/threads/<id>/state                    # CRDT blob (encrypted)
```

- Each author only writes their own refs, so the layout is append-only and conflict-free.
- Thread refs are pushed to the project's remote (the durable backing store) after every turn. They are not in the default refspec, so normal clones never see them.
- Thread IDs are random, and thread commits use a generic committer identity, to limit metadata leakage.

## Encryption

- Encrypt at write time, before content becomes a git object: serialize → zstd → encrypt → write blob.
- `age` (Rust `age` crate): a random per-thread data key, wrapped for each participant as an age recipient (SSH ed25519 keys supported).
- Always encrypted: transcripts, native session files, CRDT state, screen captures.
- Code snapshots: plaintext for private remotes (keeps dedup and diffs), encrypted bundles per checkpoint for public remotes. Ask when unsure.
- Removing a participant rotates the data key for future content.
- Optional team recovery recipient (an offline key).

## Session lifecycle

`mahi run -- claude` (or any agent):

1. Create the thread: ID, data key, `meta` ref (base commit, creator key, participants, landing branch). Optionally snapshot uncommitted changes as the real starting point.
2. `git worktree add` on `threads/<id>/<agent>` from the base. The worktree's git dir and the common git dir are read-only inside the sandbox (git config and hooks can execute code).
3. Start the proxies and watcher (snapshot zero = base).
4. Create the per-thread agent config dir and install capture hooks.
5. Launch the agent in the sandbox → PTY → the user's terminal.
6. Join the gossip topic; print an invite ticket (node address, topic, key), bound to participant public keys.
7. Each turn: events get host sequence numbers, are broadcast live, and are flushed as an encrypted turn commit at turn end, then pushed to the remote.

Joining: `mahi join <ticket>` fetches `refs/threads/<id>/*`, decrypts, renders history, subscribes live, and dedupes by sequence number. The teammate can then watch, queue prompts to others' agents, or `mahi agent add` to run their own agent in the thread.

Ending and restarting: `mahi end` waits for idle, commits final turns, compacts, pushes, and stops sandboxes. `mahi resume <id>` fetches, decrypts, restores worktrees at their latest snapshots, restores agent config, and relaunches (native resume if the adapter supports it, otherwise a handoff bundle).

Host migration: if an agent's host leaves, another peer restores from the latest snapshot and resumes the session (native or handoff).

## Multi-engineer, multi-agent

- Every teammate runs their own agent, on their own machine, with their own worktree branch, sandbox and API key.
- Agents never write into each other's worktrees. Work flows by merge ("merge Alice's agent's fix into my worktree"), and agents resolve conflicts. Forking = starting a new agent from another agent's snapshot.
- Remote prompts go into the host's queue; permission requests always route to the host, never the sender. Default: the host accepts each remote prompt with a keypress.
- Advisory claims (file/task) live in the CRDT and are exposed via MCP so agents avoid overlap.
- Cross-agent handoff bundle: goal, decision summary, current diff, transcript as reference.

## Landing

- A thread results in **one remote branch**. The remote serializes it: only fast-forward pushes; a rejected push → fetch, merge, retry.
- The integrator (thread owner by default; needs push access) merges agent branches locally, curates them into clean commits, rebases onto main, and pushes.
- Commit trailers link back to the thread:

  ```
  Thread: 7f3a9c2e
  Agent: claude-code (alice)
  Session: 01J8...
  ```

- mahi generates the PR description from the thread: summary, key decisions and why, agents and people involved, link to the thread. The final look and approval happen in the forge.

## Compaction and cleanup

Compaction tiers:

- **Live**: every snapshot.
- **Rolling**: older turns collapse to one snapshot per turn.
- **Landed**: one encrypted transcript blob per agent, one or zero snapshots per turn (per policy).
- **Expired**: thread refs deleted; only the trailers remain.

Compaction is done by one peer (owner or integrator), only when agents are idle, pushed with `--force-with-lease`. A compaction marker in `meta` makes the rewrite authoritative.

Branch deletion triggers cleanup:

- Detected via `git fetch --prune` on any `mahi` command, and optionally by a CI job on the forge's branch-delete event.
- Merged (check with patch IDs or the forge API, since squash merges break ancestry): compact to the Landed tier or delete, per policy.
- Deleted unmerged: tombstone in `meta`, grace period (~2 weeks); restoring the branch cancels it; then delete.
- Purge: delete remote refs; locally remove worktrees, config dirs, sandbox state, refs **and reflogs**, prune objects, and destroy the data key (crypto-shredding covers forge caches). Peers clean up on their next fetch. Limit: purging can't be forced on a machine that never runs mahi again.

## Serverless caveats

- NAT traversal: hole punching works for most networks; symmetric NATs need a relay, which can be any peer with a public IP (it only forwards ciphertext).
- Discovery: invite tickets shared out of band, or DHT (pkarr / Mainline); mDNS on a LAN.
- Async work across time zones goes through the remote; realtime needs peers online together.
- The LLM itself is a hosted API unless a local model is used.

## Milestones

1. `mahi run -- <agent>`: sandbox, snapshots, encrypted transcript refs, local `mahi resume`.
2. P2P live layer: iroh gossip, invite tickets, live terminal view for teammates.
3. Remote backing store: push/fetch thread refs, cross-machine resume, handoff bundles.
4. Multi-agent threads: remote prompt queue, `mahi agent add`, merges, MCP coordination tools.
5. Landing: integration, curated commits with trailers, PR description generation.
6. Compaction and branch-deletion cleanup.

## Open questions

- Automerge vs Loro for shared state.
- Windows support (WSL2 only?).
- Subscription-login agents: credentials must live inside the sandbox, which loses the key-injection property.
- Default snapshot encryption policy when the remote's visibility is unknown.
- Name: the `mahi` crate looked unclaimed on crates.io (Sept 2026); confirm GitHub and other registries. Be thoughtful about using a te reo Māori word if this becomes commercial.
