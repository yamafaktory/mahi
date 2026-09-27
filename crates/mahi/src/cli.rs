use std::ffi::OsString;

use thiserror::Error;

pub(crate) const USAGE: &str = "\
usage: mahi run [--] <agent> [<argument>...]
       mahi --help
       mahi --version

mahi run exits with the agent's exit code, or 128 plus the signal that ended it.
It exits with 1 when it cannot run the agent and 2 on a usage error.
Piped input reaches the agent through its terminal, as lines of text.";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Run(RunCommand),
    Help,
    Version,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RunCommand {
    pub(crate) agent: OsString,
    pub(crate) arguments: Vec<OsString>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum UsageError {
    #[error("no command given")]
    MissingCommand,
    #[error("unknown command {0:?}")]
    UnknownCommand(OsString),
    #[error("no agent given to run")]
    MissingAgent,
}

pub(crate) fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, UsageError> {
    let mut arguments = arguments.into_iter().skip(1);
    let Some(command) = arguments.next() else {
        return Err(UsageError::MissingCommand);
    };
    match command.to_str() {
        Some("run") => parse_run(arguments),
        Some("help" | "--help" | "-h") => Ok(Command::Help),
        Some("--version" | "-V") => Ok(Command::Version),
        _ => Err(UsageError::UnknownCommand(command)),
    }
}

fn parse_run(mut arguments: impl Iterator<Item = OsString>) -> Result<Command, UsageError> {
    let mut agent = arguments.next().ok_or(UsageError::MissingAgent)?;
    if agent == "--" {
        agent = arguments.next().ok_or(UsageError::MissingAgent)?;
    }
    Ok(Command::Run(RunCommand {
        agent,
        arguments: arguments.collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(arguments: &[&str]) -> Result<Command, UsageError> {
        parse(
            std::iter::once("mahi")
                .chain(arguments.iter().copied())
                .map(OsString::from),
        )
    }

    #[test]
    fn run_takes_the_agent_and_passes_every_later_argument_through() {
        let expected = Command::Run(RunCommand {
            agent: "claude".into(),
            arguments: vec!["--model".into(), "--".into(), "x".into()],
        });
        assert_eq!(
            parse_all(&["run", "--", "claude", "--model", "--", "x"]),
            Ok(expected)
        );
        assert_eq!(
            parse_all(&["run", "claude"]),
            Ok(Command::Run(RunCommand {
                agent: "claude".into(),
                arguments: Vec::new(),
            }))
        );
    }

    #[test]
    fn missing_and_unknown_commands_are_usage_errors() {
        assert_eq!(parse_all(&[]), Err(UsageError::MissingCommand));
        assert_eq!(parse_all(&["run"]), Err(UsageError::MissingAgent));
        assert_eq!(parse_all(&["run", "--"]), Err(UsageError::MissingAgent));
        assert_eq!(
            parse_all(&["jump"]),
            Err(UsageError::UnknownCommand("jump".into()))
        );
    }

    #[test]
    fn help_and_version_are_recognised() {
        assert_eq!(parse_all(&["--help"]), Ok(Command::Help));
        assert_eq!(parse_all(&["-V"]), Ok(Command::Version));
    }
}
