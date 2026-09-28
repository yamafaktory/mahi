//! The `mahi` binary.

mod cli;
mod environment;
mod init;
mod prompt;
mod recorder;
mod run;
mod session;
mod terminal;

use std::{
    error::Error,
    fmt::Write,
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
    let environment = Environment::read();
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
