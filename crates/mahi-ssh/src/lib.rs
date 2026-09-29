//! mahi's SSH transport: git remotes over SSH, with host keys checked against `known_hosts` and
//! logins through ssh-agent.

mod exec;
mod git;
mod known_hosts;
mod remote;
mod session;

pub use exec::{
    Exec,
    ExecInput,
    ExecOutput,
    RemoteFailure,
};
pub use git::SshTransport;
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
    SshError,
    SshSession,
};
