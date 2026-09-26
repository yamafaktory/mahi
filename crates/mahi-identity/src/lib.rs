//! The local mahi identity: a passphrase-protected age key in the user's config directory.

#[cfg(not(unix))]
compile_error!("mahi supports Linux and macOS only");

mod config;
mod identity;
mod ssh_agent;

pub use config::{
    ConfigDir,
    ConfigError,
};
pub use identity::{
    IdentityError,
    LocalIdentity,
};
pub use ssh_agent::{
    AgentError,
    AgentSigner,
    SshAgent,
};
