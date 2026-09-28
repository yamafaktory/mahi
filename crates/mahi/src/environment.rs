use std::{
    env,
    ffi::OsString,
    fs,
    path::PathBuf,
};

use mahi_store::GlobalPatterns;

const PASSED_ON: [&str; 10] = [
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

/// The variable that tells the agent's hooks where the mahi binary is.
pub(crate) const MAHI_BIN: &str = "MAHI_BIN";

/// The environment variables mahi reads, read once at startup.
#[derive(Debug, Default)]
pub(crate) struct Environment {
    pub(crate) home: Option<PathBuf>,
    pub(crate) xdg_config_home: Option<PathBuf>,
    pub(crate) xdg_runtime_dir: Option<PathBuf>,
    pub(crate) ssh_auth_sock: Option<PathBuf>,
    pub(crate) hook_socket: Option<PathBuf>,
    pub(crate) mahi_exe: Option<PathBuf>,
    pub(crate) path: Option<OsString>,
    pub(crate) user: Option<String>,
    pub(crate) temp_dir: PathBuf,
    pub(crate) passed_on: Vec<(&'static str, OsString)>,
}

impl Environment {
    pub(crate) fn read() -> Self {
        let value = |name| env::var_os(name).filter(|value| !value.is_empty());
        let path = |name| value(name).map(PathBuf::from);
        Self {
            home: path("HOME"),
            xdg_config_home: path("XDG_CONFIG_HOME"),
            xdg_runtime_dir: path("XDG_RUNTIME_DIR"),
            ssh_auth_sock: path("SSH_AUTH_SOCK"),
            hook_socket: path(HOOK_SOCKET),
            mahi_exe: env::current_exe().and_then(fs::canonicalize).ok(),
            path: value("PATH"),
            user: value("USER").and_then(|user| user.into_string().ok()),
            temp_dir: env::temp_dir(),
            passed_on: PASSED_ON
                .iter()
                .filter_map(|&name| value(name).map(|value| (name, value)))
                .collect(),
        }
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
}
