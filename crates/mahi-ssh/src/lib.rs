//! mahi's SSH transport: git remotes over SSH, with host keys checked against `known_hosts` and
//! logins through ssh-agent.

mod known_hosts;
mod remote;
mod session;

pub use known_hosts::{
    HostKeyStatus,
    KnownHosts,
    KnownHostsError,
};
pub use remote::{
    GitService,
    RemoteError,
    SshRemote,
};
pub use session::{
    Exec,
    SshError,
    SshSession,
};
