//! The `mahi` binary.

mod cli;
mod environment;
mod hook;
mod init;
mod network;
mod prompt;
mod recorder;
mod run;
mod session;
mod terminal;
mod turns;

use std::{
    error::Error,
    fmt::Write,
    io,
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
    prompt::TerminalPrompt,
    run::Outcome,
};

fn main() {
    let cli = Cli::parse();
    let pass_env = match &cli.command {
        Command::Run(command) => command.pass_env(),
        _ => &[],
    };
    let environment = Environment::read(pass_env);
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
        Command::Hook(hook) => {
            if let Some(socket) = &environment.hook_socket {
                let _ = hook::send(socket, hook.kind, io::stdin().lock());
            }
            0
        }
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
