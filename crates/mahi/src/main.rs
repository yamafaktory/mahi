//! The `mahi` binary.

mod claims;
mod cli;
mod compose;
mod credentials;
mod end;
mod environment;
mod handoff;
mod hook;
mod hub;
mod id;
mod init;
mod inject;
mod invite;
mod join;
mod land;
mod landed_branch;
mod live;
mod mcp;
mod merge;
mod merge_door;
mod merged;
mod network;
mod palette;
mod profile;
mod prompt;
mod prompts;
mod purge;
mod recorder;
mod remote;
mod run;
mod session;
mod session_sync;
mod settings;
mod sync;
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
use mahi_identity::ConfigDir;

use crate::{
    cli::{
        AgentCommand,
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

/// Makes mahi's configuration directory private when its group or others may write to it, as
/// an installer creating it with the user's umask can leave it, and says so.
fn make_config_private(environment: &Environment) {
    let Ok(config) = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    ) else {
        return;
    };
    match config.make_private() {
        Ok(true) => eprintln!(
            "mahi: made {} private (mode 700), since its group or others could write to it",
            config.path().display()
        ),
        Ok(false) => {}
        Err(error) => eprintln!(
            "mahi: could not make {} private: {error}",
            config.path().display()
        ),
    }
}

fn main() {
    let cli = Cli::parse();
    let required = match &cli.command {
        Command::Run(command) => Some(command.options.pass_env().to_vec()),
        Command::Resume(command) => Some(command.options.pass_env().to_vec()),
        Command::Handoff(command) => Some(command.options.pass_env().to_vec()),
        Command::Agent(AgentCommand::Add(command)) => Some(command.options.pass_env().to_vec()),
        Command::Land(command) => Some(command.options.pass_env().to_vec()),
        Command::Join(command) if command.agent().is_some() => {
            Some(command.options.pass_env().to_vec())
        }
        _ => None,
    };
    let mut environment = Environment::read(required.as_deref().unwrap_or_default(), &[]);
    make_config_private(&environment);
    if required.is_some() {
        let loaded = ConfigDir::resolve(
            environment.home.as_deref(),
            environment.xdg_config_home.as_deref(),
        )
        .map_err(|error| Box::new(error) as Box<dyn Error>)
        .and_then(|config| {
            profile::load(&config).map_err(|error| Box::new(error) as Box<dyn Error>)
        });
        if let Err(error) = loaded {
            report(error.as_ref());
            process::exit(1);
        }
    }
    let optional: Vec<_> = Profile::optional_env_of_all()
        .filter_map(|name| name.parse().ok())
        .collect();
    environment.read_optional(&optional);
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
        Command::Purge(command) => purged(&command, &environment),
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
        Command::Join(command) => outcome_code(join::join(&command, &environment)),
        Command::Invite(command) => {
            exit_code(invite::invite(&command, &environment).map(|ticket| print_out(&ticket)))
        }
        Command::Remote(command) => {
            exit_code(remote::remote(&command).map(|done| print_out(&done)))
        }
        Command::Id => exit_code(id::id(&environment).map(|card| print_out(&card))),
        Command::Apparmor => apparmor(&environment),
        Command::Threads => exit_code(threads::threads().map(|listing| print_out(&listing))),
        Command::Hook(hook) => {
            if let Some(socket) = &environment.hook_socket {
                let _ = hook::send(socket, hook.kind, io::stdin().lock());
            }
            0
        }
        Command::Mcp => serve_mcp(&environment),
        Command::Land(command) => landed(&command, &environment),
        Command::Merge(command) => merged(&command, &environment),
        Command::Handoff(command) => outcome_code(run::handoff(&command, &environment)),
        Command::Agent(AgentCommand::Add(command)) => {
            outcome_code(run::agent_add(&command, &environment))
        }
        Command::Resume(command) => outcome_code(run::resume(&command, &environment)),
        Command::Run(command) => outcome_code(run::run(&command, &environment)),
    };
    process::exit(code);
}

/// Returns the exit code of a command that ran an agent: the agent's, or 128 plus the signal
/// that stopped it, reraised; or 1, reporting the error.
fn outcome_code<E: Error>(result: Result<Outcome, E>) -> i32 {
    match result {
        Ok(Outcome::Exited(code)) => code,
        Ok(Outcome::Stopped(signal)) => {
            signal.reraise();
            128 + signal.number()
        }
        Err(error) => {
            report(&error);
            1
        }
    }
}

/// Returns the exit code of a command's `result`, reporting its error.
fn exit_code<E: Error>(result: Result<i32, E>) -> i32 {
    result.unwrap_or_else(|error| {
        report(&error);
        1
    })
}

/// Prints the AppArmor profile for this mahi's own path, and returns the exit code.
fn apparmor(environment: &Environment) -> i32 {
    let profile = environment
        .mahi_exe
        .as_deref()
        .and_then(mahi_sandbox::apparmor_profile);
    if let Some(profile) = profile {
        return print_out(&profile.text);
    }
    eprintln!(
        "mahi: cannot write a profile for this mahi: its path is unknown or holds a character \
         AppArmor reads as a pattern"
    );
    1
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
    report_message(format!("mahi: {error}"), error);
}

/// Reports `error` and its causes after `context`.
fn report_with(context: &str, error: &dyn Error) {
    report_message(format!("mahi: {context}: {error}"), error);
}

fn report_message(mut message: String, error: &dyn Error) {
    causes(&mut message, error);
    eprintln!("{message}");
}

/// Runs `mahi merge`, prints its report, and returns its exit code.
fn merged(command: &cli::MergeCommand, environment: &Environment) -> i32 {
    match merge::merge(command, environment) {
        Ok(merge::Outcome::Done(report)) => {
            eprint!("{report}");
            0
        }
        Ok(merge::Outcome::Stopped(signal, report)) => {
            if let Some(report) = report {
                eprint!("{report}");
            }
            signal.reraise();
            128 + signal.number()
        }
        Err(error) => {
            report(&error);
            1
        }
    }
}

/// Runs `mahi purge`, prints its report, and returns its exit code.
fn purged(command: &cli::PurgeCommand, environment: &Environment) -> i32 {
    match purge::purge(command, environment) {
        Ok(purge::Purged::Done(done)) => {
            eprint!("{done}");
            0
        }
        Ok(purge::Purged::Kept) => {
            eprintln!("mahi: nothing was purged");
            1
        }
        Ok(purge::Purged::Failed(done, error)) => {
            eprint!("{done}");
            report(&error);
            1
        }
        Ok(purge::Purged::Stopped(signal, done)) => {
            eprint!("{done}");
            signal.reraise();
            128 + signal.number()
        }
        Err(error) => {
            report(&error);
            1
        }
    }
}

/// Runs `mahi land`, prints its report, and returns its exit code.
fn landed(command: &cli::LandCommand, environment: &Environment) -> i32 {
    match land::land(command, environment) {
        Ok(land::Outcome::Done(report)) => {
            eprint!("{report}");
            0
        }
        Ok(land::Outcome::Incomplete(report)) => {
            eprint!("{report}");
            1
        }
        Ok(land::Outcome::Failed(told, error)) => {
            eprint!("{told}");
            report(&error);
            1
        }
        Ok(land::Outcome::Stopped(signal, report)) => {
            eprint!("{report}");
            signal.reraise();
            128 + signal.number()
        }
        Err(error) => {
            report(&error);
            1
        }
    }
}

/// Relays `mahi mcp` to the mahi that runs the agent, and returns its exit code.
fn serve_mcp(environment: &Environment) -> i32 {
    let Some(socket) = &environment.mcp_socket else {
        eprintln!("mahi: mahi mcp serves an agent that mahi runs; it has none here");
        return 1;
    };
    match mcp::relay(socket) {
        Ok(()) => 0,
        Err(error) => {
            report(&error);
            1
        }
    }
}

/// Returns `error` followed by its causes, each after a colon.
pub(crate) fn describe(error: &dyn Error) -> String {
    let mut message = error.to_string();
    causes(&mut message, error);
    message
}

fn causes(message: &mut String, error: &dyn Error) {
    let mut source = error.source();
    while let Some(cause) = source {
        let _ = write!(message, ": {cause}");
        source = cause.source();
    }
}
