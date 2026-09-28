use std::{
    env,
    ffi::OsString,
    path::PathBuf,
};

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

/// The environment variables mahi reads, read once at startup.
#[derive(Debug, Default)]
pub(crate) struct Environment {
    pub(crate) home: Option<PathBuf>,
    pub(crate) xdg_config_home: Option<PathBuf>,
    pub(crate) xdg_runtime_dir: Option<PathBuf>,
    pub(crate) ssh_auth_sock: Option<PathBuf>,
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
            path: value("PATH"),
            user: value("USER").and_then(|user| user.into_string().ok()),
            temp_dir: env::temp_dir(),
            passed_on: PASSED_ON
                .iter()
                .filter_map(|&name| value(name).map(|value| (name, value)))
                .collect(),
        }
    }
}
