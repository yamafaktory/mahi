//! The `mahi` binary.

mod cli;
mod run;
mod terminal;

use std::{
    env,
    error::Error,
    fmt::Write,
    process,
};

use crate::{
    cli::{
        Command,
        USAGE,
    },
    run::Outcome,
};

fn main() {
    let code = match cli::parse(env::args_os()) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            0
        }
        Ok(Command::Version) => {
            println!("mahi {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(Command::Run(command)) => match run::run(&command) {
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
        Err(error) => {
            eprintln!("mahi: {error}\n{USAGE}");
            2
        }
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
