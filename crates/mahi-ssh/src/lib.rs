//! mahi's SSH transport: git remotes over SSH, with host keys checked against `known_hosts` and
//! logins through ssh-agent.

mod exec;
#[cfg(any(fuzzing, feature = "fuzzing"))]
pub mod fuzzing;
mod git;
mod known_hosts;
mod proto;
mod remote;
mod session;

pub use exec::{
    Exec,
    ExecInput,
    ExecOutput,
    Interrupted,
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
