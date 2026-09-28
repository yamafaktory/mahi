//! The `mahi` binary.

mod cli;
mod environment;
mod hook;
mod init;
mod network;
mod profile;
mod prompt;
mod recorder;
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
        Command::Threads => match threads::threads() {
            Ok(listing) => match io::stdout().lock().write_all(listing.as_bytes()) {
                Err(error) if error.kind() != io::ErrorKind::BrokenPipe => {
                    report(&error);
                    1
                }
                _ => 0,
            },
            Err(error) => {
                report(&error);
                1
            }
        },
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

fn report(error: &dyn Error) {
    let mut message = format!("mahi: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        let _ = write!(message, ": {cause}");
        source = cause.source();
    }
    eprintln!("{message}");
}
