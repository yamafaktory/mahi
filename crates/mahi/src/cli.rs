use std::ffi::{
    OsStr,
    OsString,
};

use clap::{
    Args,
    Parser,
    Subcommand,
};

const EXIT_CODES: &str = "\
Exit codes: mahi run exits with the agent's exit code, or 128 plus the signal that ended it.
It exits with 1 when it cannot run the agent and 2 on a usage error.";

/// Real-time, peer-to-peer collaboration around any terminal coding agent.
#[derive(Debug, Parser, PartialEq, Eq)]
#[command(name = "mahi", version, after_help = EXIT_CODES)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum Command {
    /// Runs an agent in a sandbox on the current directory.
    Run(RunCommand),
}

#[derive(Debug, Args, PartialEq, Eq)]
#[command(after_help = "Piped input reaches the agent through its terminal, as lines of text.")]
pub(crate) struct RunCommand {
    /// The agent to run, looked up on PATH unless it contains a slash, then the arguments
    /// passed to it unchanged.
    #[arg(
        value_names = ["AGENT", "ARGUMENT"],
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    command: Vec<OsString>,
}

impl RunCommand {
    pub(crate) fn agent(&self) -> &OsStr {
        self.command
            .first()
            .expect("clap requires at least one value for the agent")
    }

    pub(crate) fn arguments(&self) -> &[OsString] {
        self.command.get(1..).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use clap::{
        CommandFactory,
        error::ErrorKind,
    };

    use super::*;

    fn parse(arguments: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("mahi").chain(arguments.iter().copied()))
    }

    fn run(agent: &str, arguments: &[&str]) -> Cli {
        Cli {
            command: Command::Run(RunCommand {
                command: std::iter::once(agent)
                    .chain(arguments.iter().copied())
                    .map(OsString::from)
                    .collect(),
            }),
        }
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_takes_the_agent_and_passes_every_later_argument_through() {
        assert_eq!(
            parse(&["run", "--", "claude", "--model", "--", "x"]).unwrap(),
            run("claude", &["--model", "--", "x"])
        );
        assert_eq!(
            parse(&["run", "claude", "--help"]).unwrap(),
            run("claude", &["--help"])
        );
        assert_eq!(parse(&["run", "claude"]).unwrap(), run("claude", &[]));
    }

    #[test]
    fn flag_like_agents_and_bytes_that_are_not_utf8_pass_through() {
        use std::os::unix::ffi::OsStringExt;

        assert_eq!(
            parse(&["run", "--", "--weird-agent"]).unwrap(),
            run("--weird-agent", &[])
        );
        let odd = OsString::from_vec(vec![b'a', 0xff]);
        let parsed = Cli::try_parse_from([
            OsString::from("mahi"),
            OsString::from("run"),
            odd.clone(),
            odd.clone(),
        ])
        .unwrap();
        let Command::Run(command) = parsed.command;
        assert_eq!(command.agent(), odd.as_os_str());
        assert_eq!(command.arguments(), [odd]);
    }

    #[test]
    fn missing_and_unknown_commands_are_usage_errors() {
        assert_eq!(
            parse(&[]).unwrap_err().kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
        assert_eq!(
            parse(&["run"]).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            parse(&["jump"]).unwrap_err().kind(),
            ErrorKind::InvalidSubcommand
        );
    }

    #[test]
    fn help_and_version_are_recognised() {
        assert_eq!(
            parse(&["--help"]).unwrap_err().kind(),
            ErrorKind::DisplayHelp
        );
        assert_eq!(
            parse(&["run", "--help"]).unwrap_err().kind(),
            ErrorKind::DisplayHelp
        );
        assert_eq!(
            parse(&["--version"]).unwrap_err().kind(),
            ErrorKind::DisplayVersion
        );
    }
}
