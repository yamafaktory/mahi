# AGENTS.md

Instructions for coding agents that work in this repository.

## Project

mahi is a single Rust binary. It lets several engineers work together in real time with any
terminal coding agent. Read [DESIGN.md](DESIGN.md) before you make a change. The design is the
specification. If a change goes against it, update the design in the same commit, or ask first.

## Toolchain

- Latest stable Rust, pinned in `rust-toolchain.toml`. `rust-version` in `Cargo.toml` is the
  same version. Update both together when a new stable is released.
- Edition 2024, resolver 3.
- `rustfmt.toml` uses options that only nightly rustfmt has (`group_imports`,
  `imports_granularity`, `imports_layout`). Formatting uses `cargo +nightly fmt`. Everything
  else uses stable.
- Tests run with [cargo-nextest](https://nexte.st), not `cargo test`.
- Commands are in the `justfile`. Use `just <recipe>` instead of calling cargo directly, so
  every agent and person runs the same flags.

## Commands

```sh
just            # list recipes
just fmt        # format in place (nightly rustfmt)
just fmt-check  # check formatting
just clippy     # clippy on all targets, warnings are errors
just test       # cargo nextest run; extra args pass through, e.g. just test -p mahi
just build
just run -- …   # run the mahi binary
just check      # fmt-check + clippy + test
```

CI (`.github/workflows/checks.yml`) runs `just fmt-check`, `just clippy` and
`just test --profile ci` as separate jobs. Change a check in the `justfile`, not in the
workflow, so that CI and local runs stay the same.

After every change, run `just fmt && just check`. A change is not done until `just check`
passes. Do not silence a failure: fix the cause.

## Workspace

- Every crate is in `crates/<name>` and is a member through `crates/*`.
- Put shared metadata in `[workspace.package]`, and use `field.workspace = true` in each crate.
- Declare every dependency once in `[workspace.dependencies]`, with a full version and its
  features. A crate refers to it with `dep = { workspace = true }`.
- Every crate has `[lints] workspace = true`. Change lints only in the workspace manifest.
- `Cargo.lock` is committed. Commands use `--locked`.
- Split code into a new crate only when it has a clear boundary (for example, logic that is
  pure and needs no I/O). Do not make a crate for each module.

## Lints

The workspace lint table is the rule. A summary:

- `clippy::pedantic` is `deny`, and so are `unwrap_used`, `panic`, `todo`, `unimplemented`,
  `dbg_macro` and `allow_attributes`. `clippy.toml` allows `unwrap`, `panic` and `dbg!` in tests.
- `unsafe_code` is `deny`. If unsafe code is really necessary, ask first. Put it in the
  smallest possible module with `#[expect(unsafe_code, reason = "…")]` and a `// SAFETY:`
  comment.
- `missing_docs`, `missing_debug_implementations` and `unreachable_pub` are errors through
  `just clippy`.
- To allow a lint, use `#[expect(lint, reason = "…")]` on the smallest item possible. Do not
  use `#[allow]`, and do not use crate-level allows.

## Rust style

Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) and the
[Rust Style Guide](https://doc.rust-lang.org/style-guide/). Specifically:

- **Names.** `UpperCamelCase` for types and traits, `snake_case` for functions and modules,
  `SCREAMING_SNAKE_CASE` for constants. Conversions use `as_`, `to_` and `into_` with their
  usual cost meaning. Getters have no `get_` prefix. Acronyms are words: `PtyWrapper`, not
  `PTYWrapper`.
- **Errors.** Library code returns typed errors (`thiserror`), one error enum per module or
  boundary, and does not panic on input. Error messages are lowercase with no trailing
  period. Only the binary's top level may flatten errors into a report.
- **No panics in production code.** Do not use `unwrap()`, `expect()`, `panic!`, `todo!` or
  indexing that can go out of bounds outside tests. Use `?`, `let … else`, or return an error.
  `expect("…")` is allowed only when the invariant is local and its message states the
  invariant.
- **Types over strings.** Use newtypes for identifiers (`ThreadId`, `AgentName`) and enums for
  closed sets. Make invalid states impossible to represent. Parse at the boundary, then pass
  typed values inward.
- **Ownership.** Take `&str`, `&[T]` and `&Path` in arguments. Take ownership only when the
  function stores the value. Do not clone to satisfy the borrow checker without a reason.
- **Visibility.** Make items private by default. Use `pub(crate)` inside a crate, and `pub`
  only for the crate API.
- **Imports.** Put `use` declarations at the top of the module, in the groups that rustfmt
  makes. Do not use glob imports, except `use super::*;` in test modules.
- **Configuration.** Read the environment once at startup into a typed struct. Do not call
  `std::env::var` deep in the code. `std::env::set_var` is `unsafe` in edition 2024 and is not
  used.
- **Async and blocking.** Do not block inside async code. Use `spawn_blocking` or a dedicated
  thread for PTY, filesystem and git work that blocks.
- **Dependencies.** Prefer well-maintained crates that DESIGN.md already names (`gix`,
  `portable-pty`, `vt100`, `notify`, `iroh`, `age`, …). Ask before you add a large dependency
  that the design does not name.

## Comments and docs

- Every public item has a `///` doc comment, because `missing_docs` requires it. Each crate
  root has a `//!` comment. The first line is one sentence that says what the item is.
- Do not add other comments. Use clear names and small functions instead. If a comment
  seems necessary, ask first. `// SAFETY:` on unsafe blocks is the only exception.

## Tests

- Put unit tests in a `#[cfg(test)] mod tests` at the end of the file. Put integration tests
  in `crates/<name>/tests/`.
- A test name says the behaviour, for example `resume_restores_latest_snapshot`, not
  `test_resume`.
- In tests, `unwrap()` and `expect()` are allowed.
- A test that needs an external tool (bubblewrap, a git remote, network) must fail if the tool
  is missing. It must not pass by skipping. Put it behind a nextest filter or a separate
  recipe.

## Commits

- One logical change per commit. The subject line says what changed and why, in the
  imperative, with no type prefix.
- Do not commit generated files, `target/` or local paths.
- Never add a `Co-Authored-By` trailer or any other agent attribution to a commit, and never
  add a "Generated with …" line to a pull request description.
