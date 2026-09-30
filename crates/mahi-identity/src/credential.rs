use std::{
    fmt,
    fs,
    io,
    path::PathBuf,
    str::FromStr,
};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    ConfigDir,
    IdentityError,
    private_file,
};

const CREDENTIALS: &str = "credentials";
const LONGEST_NAME: usize = 128;
const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;

/// The name a credential is stored under: 1 to 128 lowercase letters, digits and inner hyphens.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialName(String);

/// A text is not a credential name.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0:?} is not a credential name; use lowercase letters, digits and inner hyphens")]
pub struct CredentialNameError(String);

impl FromStr for CredentialName {
    type Err = CredentialNameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let valid = !text.is_empty()
            && text.len() <= LONGEST_NAME
            && !text.starts_with('-')
            && !text.ends_with('-')
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(CredentialNameError(text.to_owned()))
        }
    }
}

impl CredentialName {
    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A secret an agent signs in with, such as a subscription token, kept in mahi's configuration
/// directory under the same rules as the identity files and handed to the agent unread.
///
/// It is never shown in `Debug` output and is zeroed when dropped.
pub struct Credential(Zeroizing<Vec<u8>>);

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(..)")
    }
}

/// A credential is empty, too large, or cannot go into an environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CredentialError {
    /// Nothing was given, or only a line ending.
    #[error("the credential is empty")]
    Empty,
    /// It is larger than 16 KiB.
    #[error("the credential is larger than 16 KiB")]
    TooLarge,
    /// It holds a NUL byte or a line break, which an environment variable cannot carry.
    #[error("the credential holds a NUL byte or a line break")]
    Unfit,
}

impl Credential {
    /// Makes a credential from `bytes`, as typed or piped: one trailing line ending is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] if what is left is empty, larger than 16 KiB, or holds a
    /// NUL byte or a line break.
    pub fn new(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, CredentialError> {
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        if bytes.is_empty() {
            return Err(CredentialError::Empty);
        }
        if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
            return Err(CredentialError::TooLarge);
        }
        if bytes.iter().any(|&byte| matches!(byte, 0 | b'\n' | b'\r')) {
            return Err(CredentialError::Unfit);
        }
        Ok(Self(bytes))
    }

    /// Returns the secret, to hand it to the agent.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Stores the credential as `name`, once: an existing one is never overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Exists`] if a credential of that name exists, or another
    /// [`IdentityError`] if the directory is not private or writing fails.
    pub fn save(&self, config: &ConfigDir, name: &CredentialName) -> Result<(), IdentityError> {
        private_file::write_new(&credential_file(config, name), &self.0)
    }

    /// Loads the credential stored as `name`, or returns `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an [`IdentityError`] if the file is not a private regular file of the user's in
    /// a private directory, or holds no valid credential.
    pub fn load(config: &ConfigDir, name: &CredentialName) -> Result<Option<Self>, IdentityError> {
        let path = credential_file(config, name);
        match private_file::read(&path, MAX_CREDENTIAL_BYTES) {
            Ok(bytes) => Self::new(Zeroizing::new(bytes))
                .map(Some)
                .map_err(|_| IdentityError::Malformed),
            Err(IdentityError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// Removes the credential stored as `name`. Returns whether there was one.
///
/// # Errors
///
/// Returns [`IdentityError::Io`] if it cannot be removed.
pub fn remove_credential(config: &ConfigDir, name: &CredentialName) -> Result<bool, IdentityError> {
    let directory = config.path().join(CREDENTIALS);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
        Ok(metadata) if !metadata.is_dir() => return Err(IdentityError::NotPrivate(directory)),
        Ok(_) => private_file::check_private_dir(&directory)?,
    }
    match fs::remove_file(credential_file(config, name)) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Lists the names of the stored credentials, in order; files that are not valid names are left
/// out.
///
/// # Errors
///
/// Returns [`IdentityError::Io`] if the directory exists but cannot be read.
pub fn credential_names(config: &ConfigDir) -> Result<Vec<CredentialName>, IdentityError> {
    let entries = match fs::read_dir(config.path().join(CREDENTIALS)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(name) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn credential_file(config: &ConfigDir, name: &CredentialName) -> PathBuf {
    config.path().join(CREDENTIALS).join(name.as_str())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn config() -> (tempfile::TempDir, ConfigDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        fs::create_dir_all(config.path()).unwrap();
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o700)).unwrap();
        (dir, config)
    }

    fn secret(text: &str) -> Credential {
        Credential::new(Zeroizing::new(text.as_bytes().to_vec())).unwrap()
    }

    #[test]
    fn names_are_short_lowercase_words() {
        for good in ["claude", "codex-2", "a"] {
            assert!(good.parse::<CredentialName>().is_ok(), "{good}");
        }
        let long = "a".repeat(LONGEST_NAME + 1);
        for bad in ["", "Claude", "-a", "a-", "a/b", "..", "a b", long.as_str()] {
            assert!(bad.parse::<CredentialName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn one_line_ending_is_dropped_and_unfit_secrets_are_refused() {
        assert_eq!(secret("token\n").expose(), b"token");
        assert_eq!(secret("token\r\n").expose(), b"token");
        let new = |bytes: &[u8]| Credential::new(Zeroizing::new(bytes.to_vec()));
        assert!(matches!(new(b"\n"), Err(CredentialError::Empty)));
        assert!(matches!(new(b"a\nb"), Err(CredentialError::Unfit)));
        assert!(matches!(new(b"a\0b"), Err(CredentialError::Unfit)));
        let large = vec![b'a'; usize::try_from(MAX_CREDENTIAL_BYTES).unwrap() + 1];
        assert!(matches!(new(&large), Err(CredentialError::TooLarge)));
        assert!(!format!("{:?}", secret("hidden")).contains("hidden"));
    }

    #[test]
    fn a_credential_is_stored_once_listed_loaded_and_removed() {
        let (_dir, config) = config();
        let name: CredentialName = "claude".parse().unwrap();
        assert!(Credential::load(&config, &name).unwrap().is_none());
        secret("t0ken").save(&config, &name).unwrap();
        assert!(matches!(
            secret("other").save(&config, &name),
            Err(IdentityError::Exists(_))
        ));
        let file = config.path().join(CREDENTIALS).join("claude");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            Credential::load(&config, &name).unwrap().unwrap().expose(),
            b"t0ken"
        );
        fs::write(config.path().join(CREDENTIALS).join("Not A Name"), "x").unwrap();
        fs::create_dir(config.path().join(CREDENTIALS).join("adir")).unwrap();
        assert_eq!(
            credential_names(&config).unwrap(),
            std::slice::from_ref(&name)
        );
        assert!(remove_credential(&config, &name).unwrap());
        assert!(!remove_credential(&config, &name).unwrap());
        assert!(Credential::load(&config, &name).unwrap().is_none());
    }

    #[test]
    fn remove_refuses_a_credentials_directory_that_is_a_link() {
        let (dir, config) = config();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::write(elsewhere.join("claude"), "keep").unwrap();
        std::os::unix::fs::symlink(&elsewhere, config.path().join(CREDENTIALS)).unwrap();
        let name: CredentialName = "claude".parse().unwrap();
        assert!(remove_credential(&config, &name).is_err());
        assert!(elsewhere.join("claude").exists());
    }

    #[test]
    fn a_credential_others_can_read_or_a_planted_link_is_refused() {
        let (dir, config) = config();
        let name: CredentialName = "claude".parse().unwrap();
        secret("t0ken").save(&config, &name).unwrap();
        let file = config.path().join(CREDENTIALS).join("claude");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Credential::load(&config, &name),
            Err(IdentityError::NotPrivate(_))
        ));
        fs::remove_file(&file).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "stolen").unwrap();
        std::os::unix::fs::symlink(&outside, &file).unwrap();
        assert!(matches!(
            Credential::load(&config, &name),
            Err(IdentityError::NotAFile(_))
        ));
    }
}
