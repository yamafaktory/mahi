use std::ffi::{
    OsStr,
    OsString,
};

use clap::{
    Args,
    Parser,
    Subcommand,
};
use mahi_core::{
    AgentName,
    NameError,
    ThreadId,
};
use mahi_identity::{
    CredentialName,
    CredentialNameError,
};
use mahi_proxy::HostName;

use crate::{
    environment::{
        EnvName,
        EnvNameError,
    },
    hook::HookKind,
    profile::Profile,
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
    /// Creates your mahi key and chooses the SSH key that signs your threads.
    Init,
    /// Runs an agent in a sandbox on the current directory.
    Run(RunCommand),
    /// Resumes a thread you started, in its worktree, with the same agent.
    Resume(ResumeCommand),
    /// Ends a thread you started that is not running: records its worktree in a last
    /// snapshot, then removes the worktree and the agent's state. Its history stays.
    End(EndCommand),
    /// Lists the threads of this repository, with their agents and whether their worktree is
    /// still there.
    Threads,
    /// Keeps the tokens agents sign in with, so no shell has to export them.
    #[command(subcommand)]
    Credential(CredentialCommand),
    /// Reports an agent event, with its details on standard input, to the mahi run that
    /// started the agent. Agent hooks call it; it always exits with 0.
    Hook(HookCommand),
}

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct HookCommand {
    /// What happened.
    #[arg(value_enum)]
    pub(crate) kind: HookKind,
}

/// What the agent may reach and receive, for `mahi run` and `mahi resume`.
#[derive(Debug, Args, Default, PartialEq, Eq)]
pub(crate) struct LaunchOptions {
    /// A host the agent may reach over HTTPS, through mahi's proxy; repeat it for several.
    /// Without one, the agent has no network.
    #[arg(long = "allow-host", value_name = "HOST")]
    allow_hosts: Vec<HostName>,
    /// An environment variable passed on to the agent unchanged, such as the token it signs
    /// in with; repeat it for several. mahi never interprets or shows its value.
    #[arg(long = "pass-env", value_name = "NAME")]
    pass_env: Vec<EnvName>,
    /// Runs the agent bare, without the profile mahi has for it (such as claude-code for
    /// `claude`): no hosts, variables, settings or hooks beyond what the options give.
    #[arg(long = "no-profile")]
    no_profile: bool,
    /// A stored credential handed to the agent as an environment variable, written
    /// NAME=VARIABLE, such as `claude=CLAUDE_CODE_OAUTH_TOKEN`; repeat it for several.
    #[arg(long = "credential", value_name = "NAME=VARIABLE", value_parser = parse_binding)]
    credentials: Vec<CredentialBinding>,
}

/// A stored credential and the variable it becomes in the agent's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialBinding {
    pub(crate) name: CredentialName,
    pub(crate) variable: EnvName,
}

fn parse_binding(text: &str) -> Result<CredentialBinding, String> {
    let (name, variable) = text
        .split_once('=')
        .ok_or_else(|| format!("{text:?} is not NAME=VARIABLE"))?;
    Ok(CredentialBinding {
        name: name
            .parse()
            .map_err(|error: CredentialNameError| error.to_string())?,
        variable: variable
            .parse()
            .map_err(|error: EnvNameError| error.to_string())?,
    })
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub(crate) enum CredentialCommand {
    /// Stores a token under NAME, read hidden from the terminal or from standard input, such
    /// as `claude setup-token | mahi credential add claude`. An existing one is never replaced.
    Add {
        /// The name to store it under.
        name: CredentialName,
    },
    /// Lists the names of the stored credentials, never their values.
    List,
    /// Removes the credential stored under NAME.
    Remove {
        /// The name it is stored under.
        name: CredentialName,
    },
}

impl LaunchOptions {
    pub(crate) fn allow_hosts(&self) -> &[HostName] {
        &self.allow_hosts
    }

    pub(crate) fn pass_env(&self) -> &[EnvName] {
        &self.pass_env
    }

    pub(crate) fn credentials(&self) -> &[CredentialBinding] {
        &self.credentials
    }

    /// Returns the profile for the agent program `program`, unless `--no-profile` was given.
    pub(crate) fn profile_for(&self, program: &OsStr) -> Option<&'static Profile> {
        if self.no_profile {
            return None;
        }
        Profile::for_agent(program)
    }
}

#[derive(Debug, Args, PartialEq, Eq)]
#[command(after_help = "Piped input reaches the agent through its terminal, as lines of text.")]
pub(crate) struct RunCommand {
    #[command(flatten)]
    pub(crate) options: LaunchOptions,
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

    /// Returns the profile for the agent, unless `--no-profile` was given.
    pub(crate) fn profile(&self) -> Option<&'static Profile> {
        self.options.profile_for(self.agent())
    }
}

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct ResumeCommand {
    /// The thread to resume, as `mahi threads` lists it.
    pub(crate) thread: ThreadId,
    /// Which of your agents in the thread to resume, when it has several.
    #[arg(long, value_name = "NAME", value_parser = parse_agent)]
    pub(crate) agent: Option<AgentName>,
    #[command(flatten)]
    pub(crate) options: LaunchOptions,
    /// A command to run instead of the thread's agent and its profile's resume arguments,
    /// after `--`.
    #[arg(last = true, value_name = "COMMAND")]
    pub(crate) command: Vec<OsString>,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct EndCommand {
    /// The thread to end, as `mahi threads` lists it.
    pub(crate) thread: ThreadId,
    /// Which of your agents in the thread to record last, when it has several.
    #[arg(long, value_name = "NAME", value_parser = parse_agent)]
    pub(crate) agent: Option<AgentName>,
    /// Removes the worktree even when its last snapshot leaves out paths it cannot record,
    /// such as files too large or unreadable, which are then lost.
    #[arg(long)]
    pub(crate) force: bool,
}

fn parse_agent(text: &str) -> Result<AgentName, NameError> {
    AgentName::new(text)
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
                options: LaunchOptions::default(),
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
        let Command::Run(command) = parsed.command else {
            panic!("expected the run command");
        };
        assert_eq!(command.agent(), odd.as_os_str());
        assert_eq!(command.arguments(), [odd]);
    }

    #[test]
    fn hosts_and_passed_variables_come_before_the_agent() {
        let parsed = parse(&[
            "run",
            "--allow-host",
            "api.example.com",
            "--pass-env",
            "TOKEN",
            "--allow-host",
            "b.example.com",
            "claude",
            "--allow-host",
            "x",
        ])
        .unwrap();
        let Command::Run(command) = parsed.command else {
            panic!("expected the run command");
        };
        let hosts: Vec<&str> = command
            .options
            .allow_hosts()
            .iter()
            .map(HostName::as_str)
            .collect();
        assert_eq!(hosts, ["api.example.com", "b.example.com"]);
        assert_eq!(command.options.pass_env()[0].as_str(), "TOKEN");
        assert_eq!(command.agent(), "claude");
        assert_eq!(command.arguments(), ["--allow-host", "x"]);
        let Command::Run(claude) = parse(&["run", "claude"]).unwrap().command else {
            panic!("expected the run command");
        };
        assert_eq!(claude.profile().unwrap().name, "claude-code");
        let Command::Run(bare) = parse(&["run", "--no-profile", "claude"]).unwrap().command else {
            panic!("expected the run command");
        };
        assert!(bare.profile().is_none());
        for bad in [
            ["run", "--allow-host", "127.0.0.1", "claude"],
            ["run", "--allow-host", "localhost", "claude"],
            ["run", "--pass-env", "HOME", "claude"],
            ["run", "--pass-env", "A=B", "claude"],
        ] {
            assert_eq!(
                parse(&bad).unwrap_err().kind(),
                ErrorKind::ValueValidation,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn resume_takes_a_thread_its_options_and_an_optional_command() {
        let thread = "0123456789abcdef0123456789abcdef";
        let parsed = parse(&[
            "resume",
            thread,
            "--agent",
            "claude",
            "--allow-host",
            "api.example.com",
            "--",
            "claude",
            "--resume",
        ])
        .unwrap();
        let Command::Resume(resume) = parsed.command else {
            panic!("expected the resume command");
        };
        assert_eq!(resume.thread.to_string(), thread);
        assert_eq!(resume.agent.unwrap().as_str(), "claude");
        assert_eq!(resume.options.allow_hosts().len(), 1);
        assert_eq!(resume.command, ["claude", "--resume"]);
        let Command::Resume(bare) = parse(&["resume", thread]).unwrap().command else {
            panic!("expected the resume command");
        };
        assert!(bare.command.is_empty() && bare.agent.is_none());
        for bad in [
            vec!["resume"],
            vec!["resume", "not-an-id"],
            vec!["resume", thread, "--agent", "Bad Name"],
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn credentials_are_named_and_bound_to_a_variable() {
        let Command::Run(run) = parse(&[
            "run",
            "--credential",
            "claude=CLAUDE_CODE_OAUTH_TOKEN",
            "sh",
        ])
        .unwrap()
        .command
        else {
            panic!("expected the run command");
        };
        let binding = &run.options.credentials()[0];
        assert_eq!(binding.name.as_str(), "claude");
        assert_eq!(binding.variable.as_str(), "CLAUDE_CODE_OAUTH_TOKEN");
        for bad in ["claude", "Claude=TOKEN", "claude=HOME", "claude=A-B"] {
            assert!(parse(&["run", "--credential", bad, "sh"]).is_err(), "{bad}");
        }
        assert_eq!(
            parse(&["credential", "add", "claude"]).unwrap().command,
            Command::Credential(CredentialCommand::Add {
                name: "claude".parse().unwrap()
            })
        );
        assert!(parse(&["credential", "add", "Bad"]).is_err());
    }

    #[test]
    fn hook_takes_one_known_event() {
        assert_eq!(
            parse(&["hook", "turn-end"]).unwrap(),
            Cli {
                command: Command::Hook(HookCommand {
                    kind: HookKind::TurnEnd
                })
            }
        );
        assert_eq!(
            parse(&["hook", "reboot"]).unwrap_err().kind(),
            ErrorKind::InvalidValue
        );
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
