use std::{
    fmt,
    path::Path,
};

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::{
    IdentityError,
    private_file,
};

const SECRET_BYTES: usize = 32;

/// The secret key of the user's iroh node, which names and authenticates their machine on the
/// live layer.
///
/// It is stored as its 32 raw bytes in a private file, never appears in `Debug` output, and is
/// zeroed when dropped.
pub struct NodeKey(Zeroizing<[u8; SECRET_BYTES]>);

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NodeKey(..)")
    }
}

impl NodeKey {
    /// Draws a new node key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Random`] if the random source is unavailable.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        getrandom::fill(secret.as_mut_slice()).map_err(IdentityError::Random)?;
        Ok(Self(secret))
    }

    /// Returns the secret bytes, to hand them to iroh.
    #[must_use]
    pub fn secret(&self) -> &[u8; SECRET_BYTES] {
        &self.0
    }

    /// Returns the public half, the node id, as ed25519 public key bytes.
    #[must_use]
    pub fn public(&self) -> [u8; SECRET_BYTES] {
        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }

    /// Writes the node key once; an existing file is never replaced.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Exists`] if `path` exists, [`IdentityError::NotPrivate`] if the
    /// parent directory is not private, or [`IdentityError::Io`] if writing fails.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        private_file::write_new(path, self.0.as_slice())
    }

    /// Reads the node key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::NotFound`] if there is no file, [`IdentityError::NotPrivate`] or
    /// [`IdentityError::NotAFile`] if it or its directory is not private to the user, or
    /// [`IdentityError::Malformed`] if it does not hold exactly 32 bytes.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        Self::parse(&Zeroizing::new(private_file::read(
            path,
            SECRET_BYTES as u64,
        )?))
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        if bytes.len() != SECRET_BYTES {
            return Err(IdentityError::Malformed);
        }
        secret.copy_from_slice(bytes);
        Ok(Self(secret))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
    };

    use super::*;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn a_node_key_is_saved_once_and_loads_back_with_the_same_node_id() {
        let dir = private_dir();
        let path = dir.path().join("node.key");
        let key = NodeKey::generate().unwrap();
        key.save(&path).unwrap();
        assert!(matches!(
            NodeKey::generate().unwrap().save(&path),
            Err(IdentityError::Exists(_))
        ));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let loaded = NodeKey::load(&path).unwrap();
        assert_eq!(loaded.secret(), key.secret());
        assert_eq!(loaded.public(), key.public());
        assert_ne!(NodeKey::generate().unwrap().public(), key.public());
        assert_eq!(format!("{loaded:?}"), "NodeKey(..)");
    }

    #[test]
    fn a_node_key_of_the_wrong_size_or_open_to_others_is_refused() {
        let dir = private_dir();
        for (name, len) in [("short", 31), ("long", 33)] {
            let path = dir.path().join(name);
            fs::write(&path, vec![1; len]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                NodeKey::load(&path),
                Err(IdentityError::Malformed)
            ));
        }
        let path = dir.path().join("open");
        fs::write(&path, [1; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            NodeKey::load(&path),
            Err(IdentityError::NotPrivate(_))
        ));
        assert!(matches!(
            NodeKey::load(&dir.path().join("missing")),
            Err(IdentityError::NotFound(_))
        ));
    }
}
