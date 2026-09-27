use std::io;

use age::secrecy::ExposeSecret;
use mahi_identity::{
    AgentError,
    ConfigDir,
    ConfigError,
    IdentityError,
    LocalIdentity,
    PublicIdentity,
    SigningKey,
    SshAgent,
};
use ssh_key::HashAlg;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::{
    environment::Environment,
    prompt::Prompt,
};

const MIN_PASSPHRASE_CHARS: usize = 8;

#[derive(Debug, Error)]
pub(crate) enum InitError {
    #[error("cannot find mahi's configuration directory")]
    ConfigDir(#[from] ConfigError),
    #[error("cannot ask the user")]
    Prompt(#[source] io::Error),
    #[error("the passphrase must have at least {MIN_PASSPHRASE_CHARS} characters")]
    ShortPassphrase,
    #[error("the two passphrases differ")]
    PassphraseMismatch,
    #[error("cannot set up your mahi key")]
    Identity(#[from] IdentityError),
    #[error("SSH_AUTH_SOCK is not set; start ssh-agent and add an ed25519 key (ssh-add)")]
    NoAgent,
    #[error("cannot list the keys in ssh-agent")]
    Agent(#[from] AgentError),
    #[error("ssh-agent holds no ed25519 key; add one with ssh-add")]
    NoEd25519Key,
    #[error("choose a number from 1 to {count}")]
    NoSuchKey { count: usize },
    #[error("{} exists without identity.age; remove it and run mahi init again", .0.display())]
    OrphanPublicIdentity(std::path::PathBuf),
}

pub(crate) fn init(environment: &Environment, prompt: &mut dyn Prompt) -> Result<(), InitError> {
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let public = public_identity(&config, prompt)?;
    let signing = signing_key(&config, environment, prompt)?;
    prompt
        .say(&format!("mahi key:    {}", public.recipient()))
        .map_err(InitError::Prompt)?;
    prompt
        .say(&format!(
            "signing key: {}",
            signing.public_key().fingerprint(HashAlg::Sha256)
        ))
        .map_err(InitError::Prompt)?;
    Ok(())
}

fn public_identity(
    config: &ConfigDir,
    prompt: &mut dyn Prompt,
) -> Result<PublicIdentity, InitError> {
    let identity_file = config.identity_file();
    let recipient_file = config.recipient_file();
    let identity_exists = identity_file.symlink_metadata().is_ok();
    match PublicIdentity::load(&recipient_file) {
        Ok(_) if !identity_exists => {
            return Err(InitError::OrphanPublicIdentity(recipient_file));
        }
        Ok(public) => return Ok(public),
        Err(IdentityError::NotFound(_)) => {}
        Err(error) => return Err(error.into()),
    }
    let identity = if identity_exists {
        let passphrase = prompt
            .secret("Passphrase for your mahi key: ")
            .map_err(InitError::Prompt)?;
        LocalIdentity::load(&identity_file, &passphrase)?
    } else {
        prompt
            .say("Creating your mahi key; it is encrypted with a passphrase.")
            .map_err(InitError::Prompt)?;
        let passphrase = prompt
            .secret("New passphrase: ")
            .map_err(InitError::Prompt)?;
        if passphrase.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(InitError::ShortPassphrase);
        }
        let again = prompt.secret("Repeat it: ").map_err(InitError::Prompt)?;
        let same: bool = passphrase
            .expose_secret()
            .as_bytes()
            .ct_eq(again.expose_secret().as_bytes())
            .into();
        if !same {
            return Err(InitError::PassphraseMismatch);
        }
        let identity = LocalIdentity::generate();
        identity.save(&identity_file, &passphrase)?;
        identity
    };
    let public = PublicIdentity::from(&identity);
    public.save(&recipient_file)?;
    Ok(public)
}

fn signing_key(
    config: &ConfigDir,
    environment: &Environment,
    prompt: &mut dyn Prompt,
) -> Result<SigningKey, InitError> {
    let path = config.signing_key_file();
    match SigningKey::load(&path) {
        Ok(key) => {
            warn_if_not_in_agent(&key, environment, prompt)?;
            return Ok(key);
        }
        Err(IdentityError::NotFound(_)) => {}
        Err(error) => return Err(error.into()),
    }
    let socket = environment
        .ssh_auth_sock
        .as_deref()
        .ok_or(InitError::NoAgent)?;
    let mut keys = SshAgent::new(socket).ed25519_keys()?;
    let chosen = match keys.len() {
        0 => return Err(InitError::NoEd25519Key),
        1 => {
            let key = keys.remove(0);
            prompt
                .say(&format!(
                    "Signing with {} {}",
                    key.fingerprint(HashAlg::Sha256),
                    key.comment()
                ))
                .map_err(InitError::Prompt)?;
            key
        }
        _ => {
            prompt
                .say("Which SSH key should sign your threads?")
                .map_err(InitError::Prompt)?;
            for (number, key) in keys.iter().enumerate() {
                prompt
                    .say(&format!(
                        "  {}) {} {}",
                        number + 1,
                        key.fingerprint(HashAlg::Sha256),
                        key.comment()
                    ))
                    .map_err(InitError::Prompt)?;
            }
            let answer = prompt.answer("Number: ").map_err(InitError::Prompt)?;
            let index = answer
                .parse::<usize>()
                .ok()
                .and_then(|number| number.checked_sub(1))
                .filter(|&index| index < keys.len())
                .ok_or(InitError::NoSuchKey { count: keys.len() })?;
            keys.swap_remove(index)
        }
    };
    let key = SigningKey::try_from(chosen)?;
    key.save(&path)?;
    Ok(key)
}

fn warn_if_not_in_agent(
    key: &SigningKey,
    environment: &Environment,
    prompt: &mut dyn Prompt,
) -> Result<(), InitError> {
    let Some(socket) = environment.ssh_auth_sock.as_deref() else {
        return Ok(());
    };
    let Ok(keys) = SshAgent::new(socket).ed25519_keys() else {
        return Ok(());
    };
    if !keys
        .iter()
        .any(|held| held.key_data() == key.public_key().key_data())
    {
        prompt
            .say("warning: ssh-agent does not hold your signing key; add it with ssh-add")
            .map_err(InitError::Prompt)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::{
            Read,
            Write,
        },
        os::unix::net::UnixListener,
        path::{
            Path,
            PathBuf,
        },
        thread,
    };

    use age::secrecy::SecretString;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        PublicKey,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;

    #[derive(Default)]
    struct Script {
        secrets: VecDeque<&'static str>,
        answers: VecDeque<&'static str>,
        said: Vec<String>,
    }

    impl Prompt for Script {
        fn say(&mut self, line: &str) -> io::Result<()> {
            self.said.push(line.to_owned());
            Ok(())
        }

        fn secret(&mut self, _: &str) -> io::Result<SecretString> {
            let secret = self
                .secrets
                .pop_front()
                .expect("an unexpected passphrase question");
            Ok(SecretString::from(secret.to_owned()))
        }

        fn answer(&mut self, _: &str) -> io::Result<String> {
            Ok(self
                .answers
                .pop_front()
                .expect("an unexpected question")
                .to_owned())
        }
    }

    struct Setup {
        _dir: TempDir,
        environment: Environment,
        config: ConfigDir,
    }

    fn setup(keys: &[PublicKey]) -> Setup {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let socket = dir.path().join("agent.sock");
        serve_keys(&socket, keys.to_vec());
        let environment = Environment {
            home: Some(home.clone()),
            xdg_config_home: None,
            ssh_auth_sock: Some(socket),
        };
        let config = ConfigDir::resolve(Some(&home), None).unwrap();
        Setup {
            _dir: dir,
            environment,
            config,
        }
    }

    fn serve_keys(socket: &Path, keys: Vec<PublicKey>) {
        let listener = UnixListener::bind(socket).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut request = [0_u8; 5];
                if stream.read_exact(&mut request).is_err() {
                    continue;
                }
                let mut body = vec![12];
                body.extend_from_slice(&u32::try_from(keys.len()).unwrap().to_be_bytes());
                for key in &keys {
                    let blob = key.to_bytes().unwrap();
                    body.extend_from_slice(&u32::try_from(blob.len()).unwrap().to_be_bytes());
                    body.extend_from_slice(&blob);
                    body.extend_from_slice(&4_u32.to_be_bytes());
                    body.extend_from_slice(b"note");
                }
                let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
                frame.extend_from_slice(&body);
                let _ = stream.write_all(&frame);
            }
        });
    }

    fn ed25519() -> PublicKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    fn files(config: &ConfigDir) -> [PathBuf; 3] {
        [
            config.identity_file(),
            config.recipient_file(),
            config.signing_key_file(),
        ]
    }

    #[test]
    fn a_first_run_creates_the_key_and_uses_the_only_agent_key() {
        let key = ed25519();
        let setup = setup(std::slice::from_ref(&key));
        let mut script = Script {
            secrets: ["correct horse", "correct horse"].into(),
            ..Script::default()
        };
        init(&setup.environment, &mut script).unwrap();
        for file in files(&setup.config) {
            assert!(file.is_file(), "{}", file.display());
        }
        let signing = SigningKey::load(&setup.config.signing_key_file()).unwrap();
        assert_eq!(signing.public_key().key_data(), key.key_data());
        let identity = LocalIdentity::load(
            &setup.config.identity_file(),
            &SecretString::from("correct horse".to_owned()),
        )
        .unwrap();
        assert!(
            PublicIdentity::load(&setup.config.recipient_file())
                .unwrap()
                .belongs_to(&identity)
        );

        let mut again = Script::default();
        init(&setup.environment, &mut again).unwrap();
        assert!(again.said.iter().any(|line| line.starts_with("mahi key:")));
    }

    #[test]
    fn short_and_mismatched_passphrases_are_refused_before_anything_is_written() {
        let setup = setup(&[ed25519()]);
        let mut short = Script {
            secrets: ["short"].into(),
            ..Script::default()
        };
        assert!(matches!(
            init(&setup.environment, &mut short),
            Err(InitError::ShortPassphrase)
        ));
        let mut mismatch = Script {
            secrets: ["first passphrase", "second passphrase"].into(),
            ..Script::default()
        };
        assert!(matches!(
            init(&setup.environment, &mut mismatch),
            Err(InitError::PassphraseMismatch)
        ));
        for file in files(&setup.config) {
            assert!(!file.exists(), "{}", file.display());
        }
    }

    #[test]
    fn the_user_chooses_among_several_agent_keys() {
        let keys = [ed25519(), ed25519(), ed25519()];
        let setup = setup(&keys);
        let mut wrong = Script {
            secrets: ["correct horse", "correct horse"].into(),
            answers: ["7"].into(),
            ..Script::default()
        };
        assert!(matches!(
            init(&setup.environment, &mut wrong),
            Err(InitError::NoSuchKey { count: 3 })
        ));
        for answer in ["0", "abc"] {
            let mut script = Script {
                answers: [answer].into(),
                ..Script::default()
            };
            assert!(matches!(
                init(&setup.environment, &mut script),
                Err(InitError::NoSuchKey { count: 3 })
            ));
        }
        let mut right = Script {
            answers: ["2"].into(),
            ..Script::default()
        };
        init(&setup.environment, &mut right).unwrap();
        let signing = SigningKey::load(&setup.config.signing_key_file()).unwrap();
        assert_eq!(signing.public_key().key_data(), keys[1].key_data());
        assert!(right.said.iter().any(|line| line.contains("SHA256:")));
    }

    #[test]
    fn an_unfinished_setup_is_completed_with_the_existing_key() {
        let setup = setup(&[ed25519()]);
        let identity = LocalIdentity::generate();
        identity
            .save(
                &setup.config.identity_file(),
                &SecretString::from("correct horse".to_owned()),
            )
            .unwrap();
        let mut script = Script {
            secrets: ["correct horse"].into(),
            ..Script::default()
        };
        init(&setup.environment, &mut script).unwrap();
        assert!(
            PublicIdentity::load(&setup.config.recipient_file())
                .unwrap()
                .belongs_to(&identity)
        );
    }

    #[test]
    fn a_public_identity_without_its_secret_half_is_refused() {
        let setup = setup(&[ed25519()]);
        PublicIdentity::from(&LocalIdentity::generate())
            .save(&setup.config.recipient_file())
            .unwrap();
        assert!(matches!(
            init(&setup.environment, &mut Script::default()),
            Err(InitError::OrphanPublicIdentity(_))
        ));
    }

    #[test]
    fn a_wrong_passphrase_on_an_unfinished_setup_writes_nothing() {
        let setup = setup(&[ed25519()]);
        LocalIdentity::generate()
            .save(
                &setup.config.identity_file(),
                &SecretString::from("correct horse".to_owned()),
            )
            .unwrap();
        let mut script = Script {
            secrets: ["wrong horse"].into(),
            ..Script::default()
        };
        assert!(matches!(
            init(&setup.environment, &mut script),
            Err(InitError::Identity(IdentityError::WrongPassphrase))
        ));
        assert!(!setup.config.recipient_file().exists());
    }

    #[test]
    fn a_missing_agent_or_ed25519_key_is_reported() {
        let setup = setup(&[]);
        let mut script = Script {
            secrets: ["correct horse", "correct horse"].into(),
            ..Script::default()
        };
        assert!(matches!(
            init(&setup.environment, &mut script),
            Err(InitError::NoEd25519Key)
        ));
        let environment = Environment {
            home: setup.environment.home.clone(),
            xdg_config_home: None,
            ssh_auth_sock: None,
        };
        assert!(matches!(
            init(&environment, &mut Script::default()),
            Err(InitError::NoAgent)
        ));
    }
}
