use mahi_core::NameError;
use mahi_identity::{
    ConfigDir,
    ConfigError,
    IdentityError,
    PublicIdentity,
    SigningKey,
};
use mahi_thread::{
    InvalidMeta,
    KeyError,
    Participant,
    ParticipantCard,
    ParticipantKey,
};
use thiserror::Error;

use crate::{
    environment::Environment,
    session,
};

#[derive(Debug, Error)]
pub(crate) enum IdError {
    #[error("cannot find mahi's configuration directory")]
    Config(#[from] ConfigError),
    #[error("mahi is not set up; run mahi init first")]
    NotInitialised(#[source] IdentityError),
    #[error("USER does not give a participant name")]
    ParticipantName(#[source] NameError),
    #[error("your signing key is not usable")]
    Key(#[from] KeyError),
    #[error("your keys cannot describe a participant")]
    Participant(#[from] InvalidMeta),
}

/// Returns the user's participant card, the line a thread's owner needs to invite them.
pub(crate) fn id(environment: &Environment) -> Result<String, IdError> {
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let public = PublicIdentity::load(&config.recipient_file()).map_err(IdError::NotInitialised)?;
    let signing = SigningKey::load(&config.signing_key_file()).map_err(IdError::NotInitialised)?;
    let node = session::own_node(&config).map_err(IdError::NotInitialised)?;
    let name =
        session::participant_from(environment.user.as_deref()).map_err(IdError::ParticipantName)?;
    let participant = Participant::new(
        name,
        ParticipantKey::from_public_key(signing.public_key())?,
        public.recipient().clone(),
        node,
    )?;
    Ok(format!("{}\n", ParticipantCard::new(participant)))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
    };

    use mahi_identity::{
        LocalIdentity,
        NodeKey,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;

    #[test]
    fn the_card_holds_the_users_name_and_public_keys() {
        let dir = tempfile::tempdir().unwrap();
        let environment = Environment {
            home: Some(dir.path().to_path_buf()),
            user: Some("Alice Smith".to_owned()),
            ..Environment::default()
        };
        assert!(matches!(id(&environment), Err(IdError::NotInitialised(_))));

        let config = ConfigDir::resolve(Some(dir.path()), None).unwrap();
        fs::create_dir_all(config.path()).unwrap();
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = LocalIdentity::generate();
        PublicIdentity::from(&identity)
            .save(&config.recipient_file())
            .unwrap();
        let ssh = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        SigningKey::try_from(ssh.public_key().clone())
            .unwrap()
            .save(&config.signing_key_file())
            .unwrap();
        NodeKey::generate()
            .unwrap()
            .save(&config.node_key_file())
            .unwrap();

        let line = id(&environment).unwrap();
        assert!(line.ends_with('\n'));
        let card: ParticipantCard = line.parse().unwrap();
        let participant = card.participant();
        assert_eq!(participant.name().as_str(), "alice-smith");
        assert_eq!(
            participant.recipient().to_string(),
            identity.recipient().to_string()
        );
        assert_eq!(participant.node(), &session::own_node(&config).unwrap());
        assert_eq!(
            participant.key().to_openssh(),
            ParticipantKey::from_public_key(ssh.public_key())
                .unwrap()
                .to_openssh()
        );
    }
}
