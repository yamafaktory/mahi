use std::{
    env,
    path::PathBuf,
};

/// The environment variables mahi reads, read once at startup.
#[derive(Debug, Default)]
pub(crate) struct Environment {
    pub(crate) home: Option<PathBuf>,
    pub(crate) xdg_config_home: Option<PathBuf>,
    pub(crate) ssh_auth_sock: Option<PathBuf>,
}

impl Environment {
    pub(crate) fn read() -> Self {
        let path = |name| {
            env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        Self {
            home: path("HOME"),
            xdg_config_home: path("XDG_CONFIG_HOME"),
            ssh_auth_sock: path("SSH_AUTH_SOCK"),
        }
    }
}
