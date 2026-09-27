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

- **PTY wrapper**: launches the agent in a pseudo-terminal, passes it through to the user's terminal, and maintains a virtual screen (`vt100`) for late joiners and crude text snapshots. The pseudo-terminal is opened with `rustix` and the agent is spawned by `mahi-sandbox` itself, not by `portable-pty`, because the sandbox must act between fork and exec on the same spawn. The agent starts with an empty environment plus what mahi passes on, in its own session and process group, and killing it kills the whole group.
- **Sandbox**: the whole agent process runs inside an OS sandbox: namespaces, Landlock and seccomp on Linux (and WSL2), Seatbelt through `sandbox_init` on macOS. Same pattern as Anthropic's sandbox-runtime (`srt`), implemented natively in Rust with no helper program such as `bwrap`. All `unsafe` code in mahi lives in this one crate. On Linux the agent starts in new user and mount namespaces, mapped to the user's own effective uid and gid, with an empty read-only root: only the paths its policy binds (read-only, recursively, or read-write), a private `/tmp`, and a minimal `/dev` (null, zero, full, random, urandom, tty, a private `devpts` and `/dev/shm`). Each bound path is opened with `openat2` and `RESOLVE_NO_SYMLINKS` after the namespaces exist, so a planted symbolic link cannot redirect a bind, and is cloned with `open_tree` and made read-only with `mount_setattr`, which also covers mounts below it. Mount points are created and reached component by component with `openat2`, so a symbolic link placed in a writable path cannot move a mount elsewhere. Before exec the child locks the securebits (`NOROOT`, `NO_SETUID_FIXUP`), empties the capability bounding and ambient sets, sets `no_new_privs` and marks every inherited descriptor close-on-exec, so the agent holds no capability even when mahi runs as root, and cannot reopen the host through a leaked descriptor. The agent's terminal comes from the host's `devpts`, while `/dev/pts` in the sandbox is a new instance, so `ttyname` cannot name it yet. `/proc` comes with the PID namespace. On Ubuntu, unprivileged user namespaces must be allowed (`kernel.apparmor_restrict_unprivileged_userns=0`).
- **Proxies**: a network allowlist proxy, and an LLM API proxy that injects the API key (the key never enters the sandbox) and meters tokens per participant.
- **Snapshot scheduler**: snapshots of the agent's worktree into hidden refs, taken when the agent's hooks report that a tool ran or a turn ended, and otherwise on a timer that runs every second while the worktree keeps changing and backs off to 30 s while it does not. There is no file-system watcher: a worktree belongs to an agent, and a watcher can be made to follow a swapped-in symbolic link out of the tree, exhaust the user's watch limit, or queue events without bound, all of which were demonstrated against `notify`. The timer is the safety net for changes no hook reports (a background process, a person editing the worktree, an agent without hooks): they show up at the next tick, within a second while the worktree is busy and within 30 s after a long idle spell. Pokes never bring snapshots closer together than one second. With the snapshot cache a tick costs about 10 ms on 5,000 files and 170 ms on 100,000, in a release build.
- **Git storage**: `gix` for objects, refs and worktrees, and for fetch. mahi never runs the `git` program. Push is not in `gix` yet, so mahi implements send-pack itself, over a pure-Rust SSH client (`russh`) and HTTPS.
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
refs/threads/<id>/meta                              # title, base, participants, wrapped keys, landing branch
refs/threads/<id>/state                             # CRDT blob (encrypted)
refs/threads/<id>/agents/<participant>.<agent>/snapshots   # one commit per edit (worktree trees)
refs/threads/<id>/agents/<participant>.<agent>/transcript  # one commit per agent turn (encrypted)
refs/threads/<id>/agents/<participant>.<agent>/session     # native agent session files (encrypted)
```

- Each author only writes their own refs, so the layout is append-only and conflict-free.
- Agents live under `agents/`, named `<participant>.<agent>`, so an agent can never be called `meta` or `state`, and two people can run the same agent in one thread.
- Thread refs are pushed to the project's remote (the durable backing store) after every turn. They are not in the default refspec, so normal clones never see them.
- Thread IDs are random, and thread commits use a generic committer identity, to limit metadata leakage.

## Encryption

- Encrypt at write time, before content becomes a git object: serialize → LZ4 → encrypt → write blob. The encrypted payload is the plaintext length (`u32`, little-endian) followed by one LZ4 block, so a reader checks the length against its limit before allocating, and a hostile blob cannot expand without bound. (zstd was the first choice; the only pure-Rust decoder, `ruzstd`, does not bound how much one block expands to.)
- Each participant has two keys. Their SSH ed25519 key ties them to their forge identity and signs (the owner signs `meta` with it, through ssh-agent, so no prompt). Their mahi key, an age X25519 identity, is what thread keys are wrapped to: ssh-agent can sign but not decrypt, so decrypting with the SSH key would need its passphrase every time, and a separate key also keeps a stolen SSH key from opening every thread.
- The mahi key lives in `identity.age` in the user's config directory (`~/Library/Application Support/mahi` on macOS, `$XDG_CONFIG_HOME/mahi` or `~/.config/mahi` elsewhere), encrypted with a passphrase (age scrypt, work factor 18; files asking for more than 19 are refused, which caps scrypt at 512 MiB). It is written to a temporary file and hard-linked into place, so it is either complete or absent and never overwritten. The file (600) and its directory (700) must be owned by the user, and a file others can read, or a directory others can write, is refused. It works the same on Linux and macOS, with or without a desktop keyring.
- SSH keys other than ed25519 are refused, `ssh-rsa` included. Since thread keys are wrapped to mahi keys, not SSH keys, mahi does not build `age`'s SSH support at all, and with it the `rsa` crate and its unfixed timing advisory (RUSTSEC-2023-0071) are gone.
- `age` (Rust `age` crate): each thread has its own age X25519 identity, the thread key. Content is encrypted to the thread key's recipient. The thread key's secret is itself encrypted to each participant's mahi key and stored in `meta`. Adding a participant wraps the existing thread key once more; nothing else is re-encrypted.
- Always encrypted: transcripts, native session files, CRDT state, screen captures.
- Code snapshots: plaintext for private remotes (keeps dedup and diffs), encrypted bundles per checkpoint for public remotes. Ask when unsure.
- Removing a participant rotates the thread key for future content: a new thread identity, wrapped for the remaining participants. Content written before the removal stays readable to the removed participant.
- Optional team recovery recipient (an offline key).

### The `meta` document

- Encoded with `postcard`, in a versioned envelope: `{ version, body, signature }`.
- The body holds, in plain text: the thread ID, the base commit, the owner's name, the thread recipient, and each participant's name, SSH ed25519 public key, mahi key (age X25519 recipient) and the thread key wrapped to that mahi key. The title and the landing branch are sealed to the thread key.
- The owner signs the body with their SSH key (SSHSIG, namespace `mahi-meta`, SHA-512).
- A reader verifies the signature against an owner key it already trusts: its own key when it created the thread, or the key in the invite ticket when it joins. Never against the key the document names. This is what stops someone who can push to the remote from replacing `meta` with a thread key they control.
- After unwrapping, a participant checks that their thread key matches the recipient in the body, so the owner cannot give different participants different keys.
- The body names its thread and carries a generation: 0 for a new thread, one higher for each later version. A reader refuses a document whose thread is not the ref's. It also keeps, per thread and outside git, the highest generation it has accepted and that document's body hash. It refuses a lower generation (a rolled-back `meta` that still lists a removed participant or an old key), and a different body with the same generation. Checking that the ref only fast-forwards is not enough, since a force-push can rewrite it. An invite ticket carries the generation the joiner must accept at least. Pins live in each clone's git directory (`mahi/pins/`), so a fresh clone starts without one, and that minimum is what protects its first load.
- A `meta` document is identified by the hash of its body, not by its git blob id: the envelope around a signed body can be re-encoded without breaking the signature.
- Keys that are points of small order are refused: an SSH ed25519 key of small order lets anyone forge its signatures, and a mahi key of small order gives an all-zero shared secret (age panics on it).
- Reading is bounded: 256 KiB per document, 256 participants, and a 256-byte title.

### Transcripts

- Each agent turn is one commit on `refs/threads/<id>/agents/<participant>.<agent>/transcript`, whose tree holds a single file, `turn`: the turn sealed to the thread key.
- A turn is `postcard` in a versioned record: its number, counted from 0, and its events, each a host-assigned sequence number and an opaque payload (the ACP session update, as the adapter produced it).
- Each sealed turn also stores the running last sequence number of the whole transcript, so an empty turn carries it forward.
- Turn numbers go up by one from commit to commit, and sequence numbers strictly increase within and across turns. Appending checks the new turn against the transcript's tip (its newest commit, turn number and running last sequence number), which the host keeps in memory or recovers by opening only the newest commit; it never opens earlier turns. Reading walks newest first, holds one turn at a time, and checks every commit it walks, which also has to have at most one parent.
- Reading is bounded: 1 MiB per event, 100,000 events and 64 MiB per encoded turn (plus the sealing overhead for the stored blob), and the caller chooses how many turns to read back.

## Session lifecycle

`mahi run -- claude` (or any agent):

1. Create the thread: ID, thread key, `meta` ref (base commit, creator key, participants, landing branch). Optionally snapshot uncommitted changes as the real starting point.
2. Add a linked worktree at the base with a detached `HEAD`, so no branch appears in the user's branch list; the agent's work is recorded in its `snapshots` ref. mahi writes git's linked-worktree layout itself and checks files out with gix. `.gitattributes` conversions (`text`, `eol`, `ident`, `working-tree-encoding`) apply as in git, so `git status` stays clean, but no filter driver is configured, so no filter program (such as git-lfs) runs: filtered files are checked out as stored. The worktree's git dir and the common git dir are read-only inside the sandbox (git config and hooks can execute code).
3. Start the proxies and the snapshot scheduler (snapshot zero = base).
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
- Purge: delete remote refs; locally remove worktrees, config dirs, sandbox state, refs **and reflogs**, prune objects, and destroy the thread keys (crypto-shredding covers forge caches). Peers clean up on their next fetch. Limit: purging can't be forced on a machine that never runs mahi again.

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

- Authorship: anyone who has a thread's public recipient can seal content to it, so encryption alone does not say who wrote a blob. Turn commits (or their content) should be signed with the author's key if mahi needs to know who wrote what.
- Automerge vs Loro for shared state.
- Windows support (WSL2 only?).
- Subscription-login agents: credentials must live inside the sandbox, which loses the key-injection property.
- Default snapshot encryption policy when the remote's visibility is unknown.
- Name: the `mahi` crate looked unclaimed on crates.io (Sept 2026); confirm GitHub and other registries. Be thoughtful about using a te reo Māori word if this becomes commercial.
