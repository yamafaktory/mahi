# mahi

> *mahi* (te reo Māori): work.

mahi lets several engineers work together in real time with any terminal coding agent, such as
Claude Code or Codex. Each agent runs in a sandbox, in a git worktree of its own. Teammates
watch it live and can hand it prompts, take over its work or merge it. Peers connect directly,
with no mahi server, and a thread's history is kept in the project's own git remote, with what
the agents were asked and replied encrypted.

mahi is a single Rust binary for Linux and macOS. Its home is [mahi.social](https://mahi.social).

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

## Quick start

```sh
mahi init                     # create your mahi key and choose the SSH key that signs threads
cd my-project                 # any git repository
mahi run claude               # run an agent in a sandbox, in a new thread
mahi threads                  # list this repository's threads
mahi resume <thread>          # pick a thread up again, with the same agent
mahi land <thread>            # bring the thread's work back as a branch to curate into commits
```

To work with teammates, `mahi remote` chooses the remote a thread is pushed to, `mahi id` prints the card a thread's owner needs, `mahi invite` turns
it into a ticket, and `mahi join <ticket>` watches the thread live. `mahi handoff`, `mahi
agent` and `mahi merge` move work between agents. `mahi help <command>` explains each one.

## Agents

Any terminal agent runs in mahi. For an agent mahi has a profile for, it also knows which hosts
the agent may reach, keeps its state per thread, records its turns through its hooks, and
serves it the thread's tools. Profiles for Claude Code (`claude`) and Codex (`codex`) are built
in, and you can write your own in TOML (see [DESIGN.md](DESIGN.md#adapters-agent-specific)).

The sandbox reaches the network only through mahi's proxy, to the hosts the profile or
`--allow-host` names. Tokens agents sign in with can be stored with `mahi credential add`, so
no shell has to export them.

## Development

The commands are in the `justfile`, and [AGENTS.md](AGENTS.md) describes how the project is
worked on. `just check` runs formatting, lints, tests and the dependency policy.

## License

[MIT](LICENSE)
