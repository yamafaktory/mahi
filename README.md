# mahi

> *mahi* (te reo Māori): work.

> [!WARNING]
> mahi is preview software. Commands, configuration and the formats it keeps in git may
> change between releases without a migration, and its sandbox and encryption have not been
> audited by a third party. Try it on repositories whose work you can redo, and keep your own
> branches and backups.

mahi lets several engineers work together in real time with any terminal coding agent, such as
Claude Code or Codex. Each agent runs in a sandbox, in a git worktree of its own. Teammates
watch it live and can hand it prompts, take over its work or merge it. Peers connect directly,
with no mahi server, and a thread's history is kept in the project's own git remote, with what
the agents were asked and replied encrypted.

mahi is a single Rust binary for Linux and macOS, and for Windows through WSL 2. Its home is
[mahi.social](https://mahi.social).

## Status

mahi is a preview. Every part [DESIGN.md](DESIGN.md) specifies is built and tested, on Linux,
macOS and WSL 2, and with the real Claude Code and Codex, but it has had few users so far:
expect rough edges, and changes that need you to start threads again. DESIGN.md is the
specification and lists what is still open. Please report what breaks in the
[issues](https://github.com/yamafaktory/mahi/issues).

## Install

On Linux (x86_64 and arm64, glibc 2.35 or later: Ubuntu 22.04, Debian 12 and newer), macOS
(Apple silicon and Intel) and WSL 2, the installer script of the latest
[release](https://github.com/yamafaktory/mahi/releases) puts `mahi` in `~/.local/bin`, or in
`$MAHI_INSTALL_DIR` when it is set, and adds that directory to your shell's `PATH`
(`MAHI_NO_MODIFY_PATH=1` leaves your shell files alone):

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/yamafaktory/mahi/releases/latest/download/mahi-installer.sh | sh
```

Each release also has the archive for every platform, `mahi-<target>.tar.xz`, with the binary,
its license and this README, and `.deb` packages for Ubuntu 24.04 and later. Each archive has
a `.sha256` checksum, also listed in `sha256.sum`, and GitHub's build provenance attestation:
`gh attestation verify mahi-<target>.tar.xz --repo yamafaktory/mahi`. The macOS binaries are not
notarized yet: if a browser downloaded the archive, macOS refuses to run `mahi` until you remove
its quarantine with `xattr -d com.apple.quarantine mahi` (the installer script is not affected).

To build it from source instead, use the Rust toolchain pinned in `rust-toolchain.toml`:

```sh
cargo install --locked --path crates/mahi
```

On Ubuntu 23.10 and later, AppArmor denies unprivileged programs what the sandbox needs inside
its user namespaces, so a `mahi` installed by the script, from an archive or from source needs
the profile `mahi apparmor` prints for it, as mahi explains when it meets the restriction.
The release's `.deb` (or one built with `just deb`, into `target/debian/`) installs mahi in
`/usr/bin` with that profile instead.

### Windows (WSL 2)

mahi runs on Windows inside a WSL 2 distribution. In PowerShell:

```powershell
wsl --update                    # WSL's own kernel has what the sandbox needs (6.1 or later)
wsl --install -d Ubuntu-24.04   # or wsl --set-version <distribution> 2 for an existing one
```

Then, inside the distribution, download a Linux release as above, or install Rust with
[rustup](https://rustup.rs) and build mahi. Keep your repositories in the distribution's Linux file system (`~/`) rather than under
`/mnt/c`, which is much slower and lets Windows programs run what an agent leaves there. WSL's
kernel does not have Ubuntu's AppArmor restriction on user namespaces, so the `.deb` and
`mahi apparmor` are not needed there. mahi refuses to run under WSL 1, and an agent in the
sandbox cannot start Windows programs. CI runs mahi's tests inside WSL 2.

## Quick start

```sh
mahi init                     # create your mahi key and choose the SSH key that signs threads
cd my-project                 # any git repository
mahi run claude               # run an agent in a sandbox, in a new thread
mahi threads                  # list this repository's threads
mahi resume <thread>          # pick a thread up again, with the same agent
mahi land <thread>            # bring the thread's work back as a branch to curate into commits
```

To work with teammates, `mahi remote` chooses the remote a thread is pushed to, `mahi id`
prints the card a thread's owner needs, `mahi invite` turns it into a ticket, and
`mahi join <ticket>` watches the thread live. `mahi handoff`, `mahi agent` and `mahi merge`
move work between agents.

## Agents

Any terminal agent runs in mahi. For an agent it has a profile for, mahi also knows which hosts
the agent may reach, gives it a state directory of its own in each thread, records its turns
through its hooks, and serves it the thread's tools (`mahi mcp`). mahi chooses the profile by
the agent program's file name and says at start which one it uses. Profiles for Claude Code and
Codex are built in, and mahi also reads their session logs: a `mahi handoff` briefing quotes
the agent's latest replies, and `mahi resume` on another machine restores its session.

The sandbox reaches the network only through mahi's proxy, to the hosts the profile or
`--allow-host` names. Options for `mahi run` go before the agent; everything after the agent is
passed to it unchanged.

### Claude Code

Store a subscription token once, so no shell has to export it, then run `claude`:

```sh
claude setup-token | mahi credential add claude
mahi run claude
```

The profile reaches only `api.anthropic.com` and hands Claude Code the `claude` credential as
`CLAUDE_CODE_OAUTH_TOKEN`. Claude Code asks once per thread whether to trust the folder.

### Codex

```sh
mahi run codex
```

Codex keeps its sign-in in the thread's own state directory, so it asks to sign in once in each
thread. The browser sign-in cannot reach back into the sandbox: choose **Sign in with Device
Code** (turn on device code sign-in for Codex in ChatGPT's security settings first), or an API
key. The first time, Codex also asks you to approve mahi's three hooks, which report each
prompt, tool call and turn end to mahi; mahi remembers the approval for later threads. Codex's
own sandbox is turned off, since mahi's replaces it, so do not pass it `--sandbox`,
`--full-auto` or a `--profile` that sets one.

### Any other agent

Without a profile, an agent gets the sandbox, the live view and snapshots, and no network
unless you allow it:

```sh
mahi run --allow-host api.example.com --pass-env EXAMPLE_API_KEY my-agent --some-flag
```

To give it its hosts, variables and a state directory of its own in each thread, write a
profile in `profiles/` in mahi's configuration directory (`~/.config/mahi`, or
`~/Library/Application Support/mahi` on macOS), for example `profiles/my-agent.toml`:

```toml
name = "my-agent"
program = "my-agent"
hosts = ["api.example.com"]
pass-env = ["EXAMPLE_API_KEY"]
state-env = "MY_AGENT_HOME"
resume-args = ["--continue"]
```

A profile can also write the files that wire the agent's hooks to `mahi hook`, so its turns
are recorded, and give it `mahi mcp`, so it gets the thread's tools. A profile for `claude` or
`codex` replaces the built-in one; `reader = "claude-code"` or `reader = "codex"`, with a
`state-env`, keeps mahi reading its sessions. Every field is described in
[DESIGN.md](DESIGN.md#adapters-agent-specific); `mahi run --no-profile` runs an agent bare.

## Commands

| Command | What it does |
|---|---|
| `mahi init` | Creates your mahi key and chooses the SSH key that signs your threads |
| `mahi run <agent> [args…]` | Runs an agent in a sandbox, in a new thread and worktree |
| `mahi resume <thread>` | Runs the thread's agent again, continuing its latest session |
| `mahi threads` | Lists the repository's threads and their agents |
| `mahi agent add <thread> -- <agent>` | Runs another of your agents in a thread |
| `mahi handoff <thread> --from <p.agent> -- <agent>` | Starts an agent on another agent's work, with a briefing |
| `mahi merge <thread> --from <p.agent>` | Merges another agent's work into your agent's worktree |
| `mahi land <thread>` | Brings the thread's work back as a branch to curate into commits |
| `mahi end <thread>` | Ends a thread: records a last snapshot and removes its worktree |
| `mahi purge <thread>` | Deletes a thread here and on its remote |
| `mahi remote [name]` | Shows or chooses the remote threads are pushed to |
| `mahi id` | Prints your participant card |
| `mahi invite <thread> <card>` | Invites a teammate and prints the ticket they join with |
| `mahi join <ticket>` | Watches a thread live from a ticket |
| `mahi credential add\|list\|remove` | Keeps the tokens agents sign in with |
| `mahi apparmor` | Prints the AppArmor profile Ubuntu needs for the sandbox |

`mahi help <command>` shows every option.

## Architecture

mahi is one binary with no server. Everything a thread holds lives in the project's own git
repository, encrypted, and travels through its existing remote; teammates who are online at
the same time also connect to each other directly. [DESIGN.md](DESIGN.md) specifies every part.

- **Threads in git.** A thread is a set of refs under `refs/threads/<id>/` in the project's
  repository, read and written with [gitoxide](https://github.com/GitoxideLabs/gitoxide): each
  agent's worktree snapshots, the transcript of its turns, its own session files, and a `meta`
  document listing the participants. mahi pushes and fetches them with its own SSH and HTTPS
  transports, so nothing else on the remote changes.
- **Encryption.** Each thread has its own key, wrapped for every participant's
  [age](https://age-encryption.org) key, and what the agents were asked and replied is
  compressed ([LZ4](https://github.com/PSeitz/lz4_flex)) and sealed with it before it becomes a
  git object. `meta` and every commit are signed with the participant's SSH key, through
  ssh-agent.
- **Sandbox.** The agent runs in a pseudo-terminal inside an OS sandbox mahi builds itself, with
  no helper program: user, mount, PID and network namespaces,
  [Landlock](https://landlock.io) and a [seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
  filter on Linux, Seatbelt on macOS. Its only way out is mahi's proxy, to the hosts its
  profile allows.
- **Live layer.** Peers connect directly over QUIC with [iroh](https://www.iroh.computer)
  (hole punching, with relays as a fallback) and share the live terminal, prompts and claims
  over [iroh-gossip](https://github.com/n0-computer/iroh-gossip), one topic per thread, sealed
  with a key derived from the thread key so only its participants can read them. TLS is
  [rustls](https://github.com/rustls/rustls) with mahi's own pure-Rust crypto provider, built
  on [RustCrypto](https://github.com/RustCrypto). An invite ticket carries the host's address
  and the key a joiner must trust.
- **Agents.** A profile tells mahi how to launch an agent, which hosts it may reach and where
  its state lives. Its hooks report each prompt, tool call and turn end to `mahi hook`, and
  `mahi mcp` serves it the thread's tools over the
  [Model Context Protocol](https://modelcontextprotocol.io). Built-in readers parse Claude
  Code's and Codex's session logs for handoff briefings and pull request drafts.
- **Terminal.** The live view and the in-session palette render the agent's screen with
  [vt100](https://crates.io/crates/vt100), on [tokio](https://tokio.rs).

The workspace is split where a part has a clear boundary:

| Crate | What it holds |
|---|---|
| `mahi` | The binary: commands, the run loop, profiles, merge, handoff and landing |
| `mahi-core` | Thread ids, names and the ref layout |
| `mahi-crypto` | Thread keys and the sealed blob format |
| `mahi-identity` | The passphrase-protected age key, ssh-agent signing and stored credentials |
| `mahi-store` | Thread refs, snapshots, worktrees and merges in the project's git repository |
| `mahi-thread` | The signed `meta` document, participants and transcripts |
| `mahi-sandbox` | The pseudo-terminal and the sandbox, the only crate with `unsafe` code |
| `mahi-proxy` | The allowlist proxy that is the sandbox's only network |
| `mahi-schedule` | When to snapshot: on a hook's poke or an adaptive timer |
| `mahi-agent` | Hook messages, profiles and the Claude Code and Codex session readers |
| `mahi-live` | iroh endpoints, invite tickets and the live layer |
| `mahi-tls` | The pure-Rust rustls crypto provider for QUIC and TLS 1.3 |
| `mahi-ssh` | The SSH client for git remotes, with `known_hosts` checks |
| `mahi-http` | The HTTPS transport for git remotes |
| `mahi-term` | The terminal side of the in-session palette |

## Development

The commands are in the `justfile`, and [AGENTS.md](AGENTS.md) describes how the project is
worked on. `just check` runs formatting, lints, tests and the dependency policy;
`just test-git` runs the tests that need the `git` program, and `just test-wsl` the ones that
need WSL 2. `just dogfood` runs the real Claude Code and Codex through mahi end to end (a
thread, a handoff, a resume and a landing) in a throwaway home, with your own sign-ins:

```sh
MAHI_DOGFOOD_CLAUDE_TOKEN=path/to/claude-setup-token \
MAHI_DOGFOOD_CODEX_AUTH=~/.codex/auth.json just dogfood
```

## License

[MIT](LICENSE)
