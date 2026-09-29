//! The `mahi` binary.

mod cli;
mod credentials;
mod end;
mod environment;
mod hook;
mod id;
mod init;
mod invite;
mod join;
mod live;
mod network;
mod profile;
mod prompt;
mod recorder;
mod remote;
mod run;
mod session;
mod terminal;
mod thread_lock;
mod threads;
mod turns;

use std::{
    error::Error,
    fmt::Write,
    io::{
        self,
        Write as _,
    },
    process,
};

use clap::Parser;

use crate::{
    cli::{
        Cli,
        Command,
        CredentialCommand,
    },
    environment::Environment,
    init::InitError,
    profile::Profile,
    prompt::TerminalPrompt,
    run::Outcome,
};

fn main() {
    let cli = Cli::parse();
    let required = match &cli.command {
        Command::Run(command) => command.options.pass_env().to_vec(),
        Command::Resume(command) => command.options.pass_env().to_vec(),
        Command::Join(command) if command.agent().is_some() => command.options.pass_env().to_vec(),
        _ => Vec::new(),
    };
    let optional: Vec<_> = Profile::optional_env_of_all()
        .filter_map(|name| name.parse().ok())
        .collect();
    let environment = Environment::read(&required, &optional);
    let code = match cli.command {
        Command::Init => match TerminalPrompt::open()
            .map_err(InitError::Prompt)
            .and_then(|mut prompt| init::init(&environment, &mut prompt))
        {
            Ok(()) => 0,
            Err(error) => {
                report(&error);
                1
            }
        },
        Command::End(command) => match end::end(&command, &environment) {
            Ok(end::Ended::Done(done)) => {
                eprint!("{done}");
                0
            }
            Ok(end::Ended::Stopped(signal)) => {
                signal.reraise();
                128 + signal.number()
            }
            Err(error) => {
                report(&error);
                1
            }
        },
        Command::Credential(command) => match credentials::credential(&command, &environment) {
            Ok(done) if command == CredentialCommand::List => print_out(&done),
            Ok(done) => {
                eprint!("{done}");
                0
            }
            Err(error) => {
                report(&error);
                1
            }
        },
        Command::Join(command) => match join::join(&command, &environment) {
            Ok(Outcome::Exited(code)) => code,
            Ok(Outcome::Stopped(signal)) => {
                signal.reraise();
                128 + signal.number()
            }
            Err(error) => {
                report(&error);
                1
            }
        },
        Command::Invite(command) => {
            exit_code(invite::invite(&command, &environment).map(|ticket| print_out(&ticket)))
        }
        Command::Remote(command) => {
            exit_code(remote::remote(&command).map(|done| print_out(&done)))
        }
        Command::Id => exit_code(id::id(&environment).map(|card| print_out(&card))),
        Command::Threads => exit_code(threads::threads().map(|listing| print_out(&listing))),
        Command::Hook(hook) => {
            if let Some(socket) = &environment.hook_socket {
                let _ = hook::send(socket, hook.kind, io::stdin().lock());
            }
            0
        }
        Command::Resume(command) => match run::resume(&command, &environment) {
            Ok(Outcome::Exited(code)) => code,
            Ok(Outcome::Stopped(signal)) => {
                signal.reraise();
                128 + signal.number()
            }
            Err(error) => {
                report(&error);
                1
            }
        },
        Command::Run(command) => match run::run(&command, &environment) {
            Ok(Outcome::Exited(code)) => code,
            Ok(Outcome::Stopped(signal)) => {
                signal.reraise();
                128 + signal.number()
            }
            Err(error) => {
                report(&error);
                1
            }
        },
    };
    process::exit(code);
}

/// Returns the exit code of a command's `result`, reporting its error.
fn exit_code<E: Error>(result: Result<i32, E>) -> i32 {
    result.unwrap_or_else(|error| {
        report(&error);
        1
    })
}

/// Writes `text` to standard output, where a reader that stopped early is not an error.
fn print_out(text: &str) -> i32 {
    match io::stdout().lock().write_all(text.as_bytes()) {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => {
            report(&error);
            1
        }
        _ => 0,
    }
}

fn report(error: &dyn Error) {
    let mut message = format!("mahi: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        let _ = write!(message, ": {cause}");
        source = cause.source();
    }
    eprintln!("{message}");
}
