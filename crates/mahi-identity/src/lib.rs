//! The local mahi identity: a passphrase-protected age key in the user's config directory.

#[cfg(not(unix))]
compile_error!("mahi supports Linux and macOS only");

mod config;
mod credential;
mod identity;
mod node;
mod private_file;
mod public;
mod ssh_agent;

pub use config::{
    ConfigDir,
    ConfigError,
};
pub use credential::{
    Credential,
    CredentialError,
    CredentialName,
    CredentialNameError,
    credential_names,
    remove_credential,
};
pub use identity::{
    IdentityError,
    LocalIdentity,
};
pub use node::NodeKey;
pub use public::{
    PublicIdentity,
    SigningKey,
};
pub use ssh_agent::{
    AgentError,
    AgentSigner,
    SshAgent,
};
