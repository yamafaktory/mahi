use std::{
    fmt::Write as _,
    io::{
        self,
        Read,
    },
};

use age::secrecy::ExposeSecret;
use mahi_identity::{
    ConfigDir,
    ConfigError,
    Credential,
    CredentialError,
    CredentialName,
    IdentityError,
    credential_names,
    remove_credential,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    cli::CredentialCommand,
    environment::Environment,
    prompt::{
        Prompt,
        TerminalPrompt,
    },
};

const LONGEST_INPUT: usize = 16 * 1024 + 2;

#[derive(Debug, Error)]
pub(crate) enum CredentialsError {
    #[error("cannot find mahi's configuration directory")]
    Config(#[from] ConfigError),
    #[error("cannot read the credential")]
    Read(#[source] io::Error),
    #[error(transparent)]
    Invalid(#[from] CredentialError),
    #[error("a credential named {0} exists; remove it first to replace it")]
    Exists(CredentialName),
    #[error("cannot keep the credential")]
    Store(#[source] IdentityError),
    #[error("cannot read or change the stored credentials")]
    Manage(#[source] IdentityError),
}

/// Runs `mahi credential …` and returns what to show the user.
pub(crate) fn credential(
    command: &CredentialCommand,
    environment: &Environment,
) -> Result<String, CredentialsError> {
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    match command {
        CredentialCommand::Add { name } => {
            let credential = Credential::new(read_secret(name)?)?;
            match credential.save(&config, name) {
                Ok(()) => Ok(format!("stored the credential {name}\n")),
                Err(IdentityError::Exists(_)) => Err(CredentialsError::Exists(name.clone())),
                Err(error) => Err(CredentialsError::Store(error)),
            }
        }
        CredentialCommand::List => {
            let names = credential_names(&config).map_err(CredentialsError::Manage)?;
            Ok(names.iter().fold(String::new(), |mut listing, name| {
                let _ = writeln!(listing, "{name}");
                listing
            }))
        }
        CredentialCommand::Remove { name } => {
            if remove_credential(&config, name).map_err(CredentialsError::Manage)? {
                Ok(format!("removed the credential {name}\n"))
            } else {
                Ok(format!("there is no credential named {name}\n"))
            }
        }
    }
}

fn read_secret(name: &CredentialName) -> Result<Zeroizing<Vec<u8>>, CredentialsError> {
    let stdin = io::stdin();
    if rustix::termios::isatty(&stdin) {
        let secret = TerminalPrompt::open()
            .and_then(|mut prompt| prompt.secret(&format!("Token for {name}: ")))
            .map_err(CredentialsError::Read)?;
        return Ok(Zeroizing::new(secret.expose_secret().as_bytes().to_vec()));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(LONGEST_INPUT + 1));
    stdin
        .lock()
        .take(u64::try_from(LONGEST_INPUT + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(CredentialsError::Read)?;
    if bytes.len() > LONGEST_INPUT {
        return Err(CredentialError::TooLarge.into());
    }
    Ok(bytes)
}
