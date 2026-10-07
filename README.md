# mahi

> *mahi* (te reo Māori): work.

mahi lets several engineers work together in real time with any terminal coding agent, such as
Claude Code or Codex. Each agent runs in a sandbox, in a git worktree of its own. Teammates
watch it live and can hand it prompts, take over its work or merge it. Peers connect directly,
with no mahi server, and a thread's history is kept in the project's own git remote, with what
the agents were asked and replied encrypted.

mahi is a single Rust binary for Linux and macOS, and for Windows through WSL 2. Its home is
[mahi.social](https://mahi.social).

## Status

mahi is early and in active development: the first milestone is being built, and commands and
formats may still change. [DESIGN.md](DESIGN.md) is the specification and says what is built
and what is planned.

## Install

Build it from source with the Rust toolchain pinned in `rust-toolchain.toml`:

```sh
cargo install --locked --path crates/mahi
```

On Ubuntu 23.10 and later, AppArmor denies unprivileged programs what the sandbox needs inside
its user namespaces. Install the `.deb` (`just deb` builds it into `target/debian/`), which puts
mahi in `/usr/bin` with an AppArmor profile that allows exactly that, or install the profile
`mahi apparmor` prints, as mahi explains when it meets the restriction.

### Windows (WSL 2)

mahi runs on Windows inside a WSL 2 distribution. In PowerShell:

```powershell
wsl --update                    # WSL's own kernel has what the sandbox needs (6.1 or later)
wsl --install -d Ubuntu-24.04   # or wsl --set-version <distribution> 2 for an existing one
```

Then, inside the distribution, install Rust with [rustup](https://rustup.rs) and build mahi as
above. Keep your repositories in the distribution's Linux file system (`~/`) rather than under
`/mnt/c`, which is much slower and lets Windows programs run what an agent leaves there. WSL's
kernel does not have Ubuntu's AppArmor restriction on user namespaces, so the `.deb` and
`mahi apparmor` are not needed there. mahi refuses to run under
WSL 1, and an agent in the sandbox cannot start Windows programs. CI runs mahi's tests inside
WSL 2.

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
