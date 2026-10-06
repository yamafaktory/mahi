use std::{
    env,
    ffi::OsString,
    fmt,
    fs,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    str::FromStr,
};

use mahi_store::GlobalPatterns;
use thiserror::Error;
use zeroize::Zeroizing;

/// The variables of the user's environment every agent gets.
pub(crate) const PASSED_ON: [&str; 10] = [
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "PATH",
    "USER",
    "LOGNAME",
    "TZ",
];

/// The variable that tells `mahi hook` where the `mahi run` that started the agent listens.
pub(crate) const HOOK_SOCKET: &str = "MAHI_HOOK_SOCKET";

/// The variable that tells `mahi mcp` where the mahi that started the agent serves its tools.
pub(crate) const MCP_SOCKET: &str = "MAHI_MCP_SOCKET";

/// The variable that tells the agent's hooks where the mahi binary is.
pub(crate) const MAHI_BIN: &str = "MAHI_BIN";

/// The variables that tell the agent where its proxy is.
pub(crate) const PROXY_VARIABLES: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];

const LONGEST_ENV_NAME: usize = 128;
const RESERVED: [&str; 14] = [
    "HOME",
    "MAHI_HANDOFF",
    "TMPDIR",
    HOOK_SOCKET,
    MCP_SOCKET,
    MAHI_BIN,
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// The environment variables mahi reads, read once at startup.
#[derive(Default)]
pub(crate) struct Environment {
    pub(crate) home: Option<PathBuf>,
    pub(crate) xdg_config_home: Option<PathBuf>,
    pub(crate) xdg_data_home: Option<PathBuf>,
    pub(crate) xdg_runtime_dir: Option<PathBuf>,
    pub(crate) ssh_auth_sock: Option<PathBuf>,
    pub(crate) hook_socket: Option<PathBuf>,
    pub(crate) mcp_socket: Option<PathBuf>,
    pub(crate) mahi_exe: Option<PathBuf>,
    pub(crate) path: Option<OsString>,
    pub(crate) user: Option<String>,
    pub(crate) temp_dir: PathBuf,
    pub(crate) passed_on: Vec<(&'static str, OsString)>,
    pub(crate) pass_env: Vec<Passed>,
    pub(crate) live: LiveMode,
    pub(crate) https_proxy: Option<String>,
    pub(crate) no_proxy: Option<String>,
    pub(crate) term: Option<String>,
    pub(crate) term_program: Option<String>,
    pub(crate) tmux: bool,
    pub(crate) kitty: bool,
    pub(crate) vte: bool,
}

/// Whether `mahi run` and `mahi resume` let teammates watch, from `MAHI_LIVE`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum LiveMode {
    /// `off`: no live layer at all.
    Off,
    /// `local`: the live layer without relays, reachable only at direct addresses.
    Local,
    /// `public`, or unset: the live layer with n0's public relays.
    #[default]
    Public,
    /// Any other value, which `mahi run` refuses rather than guess.
    Unknown,
}

impl LiveMode {
    fn parse(value: Option<&OsString>) -> Self {
        match value.map(|value| value.to_str()) {
            None | Some(Some("public")) => Self::Public,
            Some(Some("off")) => Self::Off,
            Some(Some("local")) => Self::Local,
            Some(_) => Self::Unknown,
        }
    }
}

/// A variable passed on to the agent: its value, if set, and whether a missing one is an error
/// (named with `--pass-env`) or is simply left out (named by a profile).
pub(crate) struct Passed {
    pub(crate) name: EnvName,
    pub(crate) value: Option<Zeroizing<Vec<u8>>>,
    pub(crate) required: bool,
}

impl fmt::Debug for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Environment")
            .field("home", &self.home)
            .field("xdg_config_home", &self.xdg_config_home)
            .field("xdg_data_home", &self.xdg_data_home)
            .field("xdg_runtime_dir", &self.xdg_runtime_dir)
            .field("ssh_auth_sock", &self.ssh_auth_sock)
            .field("hook_socket", &self.hook_socket)
            .field("mcp_socket", &self.mcp_socket)
            .field("mahi_exe", &self.mahi_exe)
            .field("user", &self.user)
            .field("temp_dir", &self.temp_dir)
            .field("live", &self.live)
            .field(
                "pass_env",
                &self
                    .pass_env
                    .iter()
                    .map(|passed| &passed.name)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// The name of an environment variable the user passes on to the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvName(String);

/// A name that cannot be passed on to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum EnvNameError {
    #[error("{0:?} is not an environment variable name")]
    Invalid(String),
    #[error("{0} is set by mahi and cannot be passed on")]
    Reserved(String),
}

impl FromStr for EnvName {
    type Err = EnvNameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut bytes = text.bytes();
        let valid = text.len() <= LONGEST_ENV_NAME
            && bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !valid {
            return Err(EnvNameError::Invalid(text.to_owned()));
        }
        if RESERVED.contains(&text) {
            return Err(EnvNameError::Reserved(text.to_owned()));
        }
        Ok(Self(text.to_owned()))
    }
}

impl EnvName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Environment {
    /// Reads the environment, including the variables named in `required` and `optional`.
    pub(crate) fn read(required: &[EnvName], optional: &[EnvName]) -> Self {
        let value = |name| env::var_os(name).filter(|value| !value.is_empty());
        let path = |name| value(name).map(PathBuf::from);
        let text = |name| value(name).and_then(|value| value.into_string().ok());
        Self {
            home: path("HOME"),
            xdg_config_home: path("XDG_CONFIG_HOME"),
            xdg_data_home: path("XDG_DATA_HOME").filter(|path| path.is_absolute()),
            xdg_runtime_dir: path("XDG_RUNTIME_DIR"),
            ssh_auth_sock: path("SSH_AUTH_SOCK"),
            hook_socket: path(HOOK_SOCKET),
            mcp_socket: path(MCP_SOCKET),
            mahi_exe: env::current_exe().and_then(fs::canonicalize).ok(),
            path: value("PATH"),
            user: value("USER").and_then(|user| user.into_string().ok()),
            temp_dir: env::temp_dir(),
            live: LiveMode::parse(value("MAHI_LIVE").as_ref()),
            https_proxy: text("https_proxy").or_else(|| text("HTTPS_PROXY")),
            no_proxy: text("no_proxy").or_else(|| text("NO_PROXY")),
            term: text("TERM"),
            term_program: text("TERM_PROGRAM"),
            tmux: value("TMUX").is_some(),
            kitty: value("KITTY_WINDOW_ID").is_some(),
            vte: value("VTE_VERSION").is_some(),
            passed_on: PASSED_ON
                .iter()
                .filter_map(|&name| value(name).map(|value| (name, value)))
                .collect(),
            pass_env: required
                .iter()
                .map(|name| (name, true))
                .chain(optional.iter().map(|name| (name, false)))
                .map(|(name, required)| Passed {
                    name: name.clone(),
                    value: env::var_os(name.as_str()).map(|value| Zeroizing::new(value.into_vec())),
                    required,
                })
                .collect(),
        }
    }

    /// Reads the variables named in `optional` too, which profiles pass on when they are set,
    /// leaving those already read alone.
    pub(crate) fn read_optional(&mut self, optional: &[EnvName]) {
        for name in optional {
            if self.pass_env.iter().any(|passed| passed.name == *name) {
                continue;
            }
            self.pass_env.push(Passed {
                name: name.clone(),
                value: env::var_os(name.as_str()).map(|value| Zeroizing::new(value.into_vec())),
                required: false,
            });
        }
    }

    /// Returns where thread worktrees live: `$XDG_DATA_HOME/mahi/worktrees`, or
    /// `~/.local/share/mahi/worktrees`, on macOS too, since mahi keeps agents out of
    /// `~/Library`.
    pub(crate) fn worktree_root(&self) -> Option<PathBuf> {
        self.xdg_data_home
            .clone()
            .or_else(|| {
                self.home
                    .as_ref()
                    .map(|home| home.join(".local").join("share"))
            })
            .map(|data| data.join("mahi").join("worktrees"))
    }

    /// Returns the directory mahi keeps its sockets in: `XDG_RUNTIME_DIR`, or else the
    /// temporary directory.
    pub(crate) fn runtime_dir(&self) -> PathBuf {
        self.xdg_runtime_dir
            .clone()
            .unwrap_or_else(|| self.temp_dir.clone())
    }

    /// Returns the user's git ignore and attributes files, where git looks for them.
    pub(crate) fn git_patterns(&self) -> GlobalPatterns {
        let git = self
            .xdg_config_home
            .clone()
            .or_else(|| self.home.as_ref().map(|home| home.join(".config")))
            .map(|config| config.join("git"));
        GlobalPatterns {
            excludes: git.as_ref().map(|git| git.join("ignore")),
            attributes: git.map(|git| git.join("attributes")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_names_mahi_does_not_set_can_be_passed_on() {
        assert_eq!(
            "CLAUDE_CODE_OAUTH_TOKEN"
                .parse::<EnvName>()
                .unwrap()
                .as_str(),
            "CLAUDE_CODE_OAUTH_TOKEN"
        );
        assert!("_x1".parse::<EnvName>().is_ok());
        let long = "A".repeat(LONGEST_ENV_NAME + 1);
        for text in ["", "1A", "A-B", "A=B", "A B", "É", long.as_str()] {
            assert!(
                matches!(text.parse::<EnvName>(), Err(EnvNameError::Invalid(_))),
                "{text:?}"
            );
        }
        for text in [
            "HOME",
            "https_proxy",
            "NO_PROXY",
            "MAHI_HOOK_SOCKET",
            "MAHI_MCP_SOCKET",
            "MAHI_BIN",
        ] {
            assert!(
                matches!(text.parse::<EnvName>(), Err(EnvNameError::Reserved(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn debug_shows_passed_names_but_never_their_values() {
        let environment = Environment {
            pass_env: vec![Passed {
                name: "TOKEN".parse().unwrap(),
                value: Some(Zeroizing::new(b"s3cret".to_vec())),
                required: true,
            }],
            ..Environment::default()
        };
        let shown = format!("{environment:?}");
        assert!(shown.contains("TOKEN"), "{shown}");
        assert!(!shown.contains("s3cret"), "{shown}");
    }

    #[test]
    fn worktrees_live_in_the_user_data_directory() {
        let mut environment = Environment {
            home: Some(PathBuf::from("/home/alice")),
            ..Environment::default()
        };
        assert_eq!(
            environment.worktree_root(),
            Some(PathBuf::from("/home/alice/.local/share/mahi/worktrees"))
        );
        environment.xdg_data_home = Some(PathBuf::from("/data"));
        assert_eq!(
            environment.worktree_root(),
            Some(PathBuf::from("/data/mahi/worktrees"))
        );
        assert_eq!(Environment::default().worktree_root(), None);
    }

    #[test]
    fn git_pattern_files_follow_xdg_config_home_then_home() {
        let mut environment = Environment {
            home: Some(PathBuf::from("/home/alice")),
            ..Environment::default()
        };
        assert_eq!(
            environment.git_patterns().excludes,
            Some(PathBuf::from("/home/alice/.config/git/ignore"))
        );
        environment.xdg_config_home = Some(PathBuf::from("/xdg"));
        let patterns = environment.git_patterns();
        assert_eq!(patterns.excludes, Some(PathBuf::from("/xdg/git/ignore")));
        assert_eq!(
            patterns.attributes,
            Some(PathBuf::from("/xdg/git/attributes"))
        );
        assert_eq!(Environment::default().git_patterns().excludes, None);
    }

    #[test]
    fn mahi_live_is_off_local_or_public_and_anything_else_is_refused() {
        let parse = |value: Option<&str>| LiveMode::parse(value.map(OsString::from).as_ref());
        assert_eq!(parse(None), LiveMode::Public);
        assert_eq!(parse(Some("public")), LiveMode::Public);
        assert_eq!(parse(Some("off")), LiveMode::Off);
        assert_eq!(parse(Some("local")), LiveMode::Local);
        for typo in ["of", "0", "false", "OFF", "Local"] {
            assert_eq!(parse(Some(typo)), LiveMode::Unknown, "{typo}");
        }
    }
}
