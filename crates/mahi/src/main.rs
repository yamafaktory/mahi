//! The `mahi` binary.

mod cli;
mod run;
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
    run::Outcome,
};

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Run(command) => match run::run(&command) {
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
