use std::{
    io,
    path::Path,
    str,
};

use age::x25519;
use ssh_key::{
    Algorithm,
    PublicKey,
};

use crate::{
    IdentityError,
    LocalIdentity,
    private_file,
};

const MAX_PUBLIC_BYTES: u64 = 1024;

/// The public half of the user's mahi key, which thread keys are wrapped to.
///
/// It is kept beside the encrypted identity so mahi can start threads without asking for the
/// passphrase. Its file is private to the user even though its content is public: whoever could
/// replace it could make new threads trust their key.
#[derive(Debug, Clone)]
pub struct PublicIdentity(x25519::Recipient);

/// The ed25519 SSH key that signs the user's thread `meta` documents, without a comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey(PublicKey);

impl PublicIdentity {
    /// Returns the recipient that thread keys are wrapped to.
    #[must_use]
    pub fn recipient(&self) -> &x25519::Recipient {
        &self.0
    }

    /// Says whether `identity` is the secret half of this public identity.
    #[must_use]
    pub fn belongs_to(&self, identity: &LocalIdentity) -> bool {
        identity.recipient().to_string() == self.0.to_string()
    }

    /// Writes the public identity once; an existing file is never replaced.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Exists`] if `path` exists, [`IdentityError::NotPrivate`] if the
    /// parent directory is not private, or [`IdentityError::Io`] if writing fails.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        private_file::write_new(path, format!("{}\n", self.0).as_bytes())
    }

    /// Reads the public identity.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::NotFound`] if there is no file, [`IdentityError::NotPrivate`]
    /// if it or its directory is not private to the user, [`IdentityError::Malformed`] if it
    /// does not hold exactly one age X25519 recipient, or another [`IdentityError`] if it
    /// cannot be read.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        Self::parse(&private_file::read(path, MAX_PUBLIC_BYTES)?)
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, IdentityError> {
        single_line(bytes)?
            .parse()
            .map(Self)
            .map_err(|_| IdentityError::Malformed)
    }
}

impl From<&LocalIdentity> for PublicIdentity {
    fn from(identity: &LocalIdentity) -> Self {
        Self(identity.recipient())
    }
}

impl SigningKey {
    /// Returns the SSH public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }

    /// Writes the key once, as an OpenSSH line; an existing file is never replaced.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Exists`] if `path` exists, [`IdentityError::NotPrivate`] if the
    /// parent directory is not private, or [`IdentityError::Io`] if encoding or writing fails.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let line = self.0.to_openssh().map_err(io::Error::other)?;
        private_file::write_new(path, format!("{line}\n").as_bytes())
    }

    /// Reads a key written by [`SigningKey::save`]. Anything `save` would not write, such as a
    /// comment or trailing spaces, is refused.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::NotFound`] if there is no file, [`IdentityError::NotPrivate`]
    /// if it or its directory is not private to the user, [`IdentityError::UnsupportedKey`] if
    /// the key is not ed25519, [`IdentityError::Malformed`] if it is not a single OpenSSH public
    /// key line, or another [`IdentityError`] if it cannot be read.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        Self::parse(&private_file::read(path, MAX_PUBLIC_BYTES)?)
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, IdentityError> {
        let line = single_line(bytes)?;
        let key = PublicKey::from_openssh(line).map_err(|_| IdentityError::Malformed)?;
        let key = Self::try_from(key)?;
        let written = key.0.to_openssh().map_err(|_| IdentityError::Malformed)?;
        if written != line {
            return Err(IdentityError::Malformed);
        }
        Ok(key)
    }
}

impl TryFrom<PublicKey> for SigningKey {
    type Error = IdentityError;

    fn try_from(mut key: PublicKey) -> Result<Self, IdentityError> {
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(IdentityError::UnsupportedKey);
        }
        key.set_comment("");
        Ok(Self(key))
    }
}

fn single_line(bytes: &[u8]) -> Result<&str, IdentityError> {
    let text = str::from_utf8(bytes).map_err(|_| IdentityError::Malformed)?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() || line.contains(['\n', '\r']) {
        return Err(IdentityError::Malformed);
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{
            PermissionsExt,
            symlink,
        },
        path::PathBuf,
    };

    use ssh_key::{
        PrivateKey,
        public::{
            KeyData,
            SkEd25519,
        },
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;

    fn private_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn private_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn ed25519() -> PublicKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    #[test]
    fn the_public_identity_round_trips_and_is_never_overwritten() {
        let dir = private_dir();
        let path = dir.path().join("identity.pub");
        let identity = LocalIdentity::generate();
        let public = PublicIdentity::from(&identity);
        public.save(&path).unwrap();
        let loaded = PublicIdentity::load(&path).unwrap();
        assert!(loaded.belongs_to(&identity));
        assert!(!loaded.belongs_to(&LocalIdentity::generate()));
        let other = PublicIdentity::from(&LocalIdentity::generate());
        assert!(matches!(other.save(&path), Err(IdentityError::Exists(_))));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn the_signing_key_drops_its_comment_and_round_trips() {
        let dir = private_dir();
        let path = dir.path().join("signing-key.pub");
        let mut key = ed25519();
        key.set_comment("from the agent\nwith a newline");
        let signing = SigningKey::try_from(key.clone()).unwrap();
        signing.save(&path).unwrap();
        let loaded = SigningKey::load(&path).unwrap();
        assert_eq!(loaded.public_key().key_data(), key.key_data());
        assert_eq!(loaded.public_key().comment(), "");
        assert!(matches!(
            SigningKey::try_from(ed25519()).unwrap().save(&path),
            Err(IdentityError::Exists(_))
        ));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fn hardware_key() -> PublicKey {
        let ed25519 = ed25519();
        let inner = *ed25519.key_data().ed25519().unwrap();
        PublicKey::from(KeyData::SkEd25519(SkEd25519::new(inner, "ssh:")))
    }

    #[test]
    fn only_plain_ed25519_keys_can_sign() {
        let other = hardware_key();
        let line = other.to_openssh().unwrap();
        assert!(matches!(
            SigningKey::try_from(other),
            Err(IdentityError::UnsupportedKey)
        ));
        let dir = private_dir();
        let path = private_file(&dir, "hardware.pub", &format!("{line}\n"));
        assert!(matches!(
            SigningKey::load(&path),
            Err(IdentityError::UnsupportedKey)
        ));
    }

    #[test]
    fn files_others_can_change_are_refused() {
        let dir = private_dir();
        let path = dir.path().join("identity.pub");
        PublicIdentity::from(&LocalIdentity::generate())
            .save(&path)
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(
            PublicIdentity::load(&path),
            Err(IdentityError::NotPrivate(_))
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            PublicIdentity::load(&path),
            Err(IdentityError::NotPrivate(_))
        ));
    }

    #[test]
    fn missing_files_and_symbolic_links_are_refused() {
        let dir = private_dir();
        assert!(matches!(
            PublicIdentity::load(&dir.path().join("missing")),
            Err(IdentityError::NotFound(_))
        ));
        let target = dir.path().join("identity.pub");
        PublicIdentity::from(&LocalIdentity::generate())
            .save(&target)
            .unwrap();
        let link = dir.path().join("link.pub");
        symlink(&target, &link).unwrap();
        assert!(matches!(
            PublicIdentity::load(&link),
            Err(IdentityError::NotAFile(_))
        ));
    }

    #[test]
    fn contents_save_would_not_write_are_refused() {
        let dir = private_dir();
        let recipient = LocalIdentity::generate().recipient().to_string();
        let key = SigningKey::try_from(ed25519())
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        let long = "a".repeat(2000);
        let recipients = [
            String::new(),
            format!("{recipient}\n{recipient}\n"),
            format!("{recipient}\r\n"),
            format!(" {recipient}\n"),
            long.clone(),
        ];
        for (index, content) in recipients.iter().enumerate() {
            let path = private_file(&dir, &format!("recipient-{index}"), content);
            assert!(
                matches!(PublicIdentity::load(&path), Err(IdentityError::Malformed)),
                "{content:?}"
            );
        }
        let keys = [
            format!("{key}\n{key}\n"),
            format!("{key}\r\n"),
            format!("{key} \n"),
            format!("{key} a comment\n"),
            long,
        ];
        for (index, content) in keys.iter().enumerate() {
            let path = private_file(&dir, &format!("key-{index}"), content);
            assert!(
                matches!(SigningKey::load(&path), Err(IdentityError::Malformed)),
                "{content:?}"
            );
        }
    }
}
