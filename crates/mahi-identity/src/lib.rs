//! The local mahi identity: a passphrase-protected age key in the user's config directory.

#[cfg(not(unix))]
compile_error!("mahi supports Linux and macOS only");

mod config;
mod credential;
#[cfg(any(fuzzing, feature = "fuzzing"))]
pub mod fuzzing;
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
pub use private_file::{
    check_owned_dir,
    read_owned_file,
};
pub use public::{
    PublicIdentity,
    SigningKey,
};
pub use ssh_agent::{
    AgentError,
    AgentSigner,
    SshAgent,
};
