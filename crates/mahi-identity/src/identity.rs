use std::{
    fmt,
    fs::{
        self,
        File,
        Metadata,
        OpenOptions,
    },
    io::{
        self,
        Read,
        Write,
    },
    iter,
    os::unix::fs::{
        DirBuilderExt,
        MetadataExt,
        OpenOptionsExt,
    },
    path::{
        Path,
        PathBuf,
    },
    str,
};

use age::{
    DecryptError,
    Decryptor,
    Encryptor,
    Identity,
    scrypt,
    secrecy::{
        ExposeSecret,
        SecretString,
    },
    x25519,
};
use thiserror::Error;
use zeroize::Zeroizing;

const WORK_FACTOR: u8 = 18;
const MAX_WORK_FACTOR: u8 = 19;
const MAX_FILE_BYTES: u64 = 4096;
const MAX_SECRET_BYTES: usize = 128;
const PRIVATE_FILE: u32 = 0o600;
const PRIVATE_DIR: u32 = 0o700;

/// The user's own mahi key: an age X25519 identity that thread keys are wrapped to.
///
/// It is stored encrypted with a passphrase, and its secret half never appears in `Debug`
/// output.
pub struct LocalIdentity(x25519::Identity);

/// Saving or loading the local identity failed.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// An identity file already exists; mahi never overwrites one.
    #[error("{} already exists", .0.display())]
    Exists(PathBuf),
    /// There is no identity file.
    #[error("{} does not exist", .0.display())]
    NotFound(PathBuf),
    /// The identity file or its directory is not private to the current user.
    #[error(
        "{} must be owned by you and not accessible to others (chmod 600 for the file, 700 for \
         its directory)",
        .0.display()
    )]
    NotPrivate(PathBuf),
    /// The identity path is not a regular file.
    #[error("{} is not a regular file", .0.display())]
    NotAFile(PathBuf),
    /// The passphrase is wrong.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// The file asks for more scrypt work than mahi allows.
    #[error("identity file asks for too much work to decrypt")]
    ExcessiveWork,
    /// The file is not a passphrase-encrypted mahi identity, or it is truncated.
    #[error("identity file is malformed")]
    Malformed,
    /// Reading or writing failed.
    #[error("cannot read or write the identity file")]
    Io(#[from] io::Error),
}

impl LocalIdentity {
    /// Generates a new identity.
    #[must_use]
    pub fn generate() -> Self {
        Self(x25519::Identity::generate())
    }

    /// Returns the public recipient others wrap thread keys to.
    #[must_use]
    pub fn recipient(&self) -> x25519::Recipient {
        self.0.to_public()
    }

    /// Returns the identity for unwrapping thread keys.
    #[must_use]
    pub fn as_age(&self) -> &dyn Identity {
        &self.0
    }

    /// Encrypts the identity with `passphrase` and writes it to `path`.
    ///
    /// The file is written to a temporary name, synced, and then linked into place, so `path`
    /// either holds a complete identity or does not exist, and an existing file is never
    /// overwritten. Once the link exists the identity is saved: removing the temporary name and
    /// syncing the directory afterwards are best effort. Missing parent directories are created with mode 700; the parent must be
    /// owned by the current user and not writable by anyone else.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Exists`] if `path` exists, [`IdentityError::NotPrivate`] if the
    /// parent directory is not private, or [`IdentityError::Io`] if writing fails.
    pub fn save(&self, path: &Path, passphrase: &SecretString) -> Result<(), IdentityError> {
        self.save_with_work_factor(path, passphrase, WORK_FACTOR)
    }

    fn save_with_work_factor(
        &self,
        path: &Path,
        passphrase: &SecretString,
        work_factor: u8,
    ) -> Result<(), IdentityError> {
        let mut recipient = scrypt::Recipient::new(passphrase.clone());
        recipient.set_work_factor(work_factor);
        let encryptor = Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut writer = encryptor.wrap_output(Vec::new())?;
        writer.write_all(self.0.to_string().expose_secret().as_bytes())?;
        let encrypted = writer.finish()?;

        let parent = parent_of(path);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR)
            .create(parent)?;
        check_private_dir(parent)?;
        if fs::symlink_metadata(path).is_ok() {
            return Err(IdentityError::Exists(path.to_path_buf()));
        }

        let temp = temp_path(path);
        if let Err(error) = write_new(&temp, &encrypted) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        let linked = fs::hard_link(&temp, path);
        let _ = fs::remove_file(&temp);
        match linked {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(IdentityError::Exists(path.to_path_buf()))
            }
            Err(error) => Err(error.into()),
            Ok(()) => {
                let _ = File::open(parent).and_then(|dir| dir.sync_all());
                Ok(())
            }
        }
    }

    /// Reads the identity at `path` and decrypts it with `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::NotFound`] if there is no file, [`IdentityError::NotAFile`] if
    /// it is not a regular file, [`IdentityError::NotPrivate`] if it or its directory is not
    /// private to the current user, [`IdentityError::WrongPassphrase`] if the passphrase is
    /// wrong, or another [`IdentityError`] if the file is malformed or unreadable.
    pub fn load(path: &Path, passphrase: &SecretString) -> Result<Self, IdentityError> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(IdentityError::NotFound(path.to_path_buf()));
            }
            Err(error) => return Err(error.into()),
            Ok(metadata) if !metadata.is_file() => {
                return Err(IdentityError::NotAFile(path.to_path_buf()));
            }
            Ok(_) => {}
        }
        check_private_dir(parent_of(path))?;
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(IdentityError::NotAFile(path.to_path_buf()));
        }
        if !is_private(&metadata, PRIVATE_FILE) {
            return Err(IdentityError::NotPrivate(path.to_path_buf()));
        }
        let mut encrypted = Vec::new();
        file.take(MAX_FILE_BYTES + 1).read_to_end(&mut encrypted)?;
        if encrypted.len() as u64 > MAX_FILE_BYTES {
            return Err(IdentityError::Malformed);
        }

        let decryptor =
            Decryptor::new(encrypted.as_slice()).map_err(|_| IdentityError::Malformed)?;
        if !decryptor.is_scrypt() {
            return Err(IdentityError::Malformed);
        }
        let mut identity = scrypt::Identity::new(passphrase.clone());
        identity.set_max_work_factor(MAX_WORK_FACTOR);
        let reader = decryptor
            .decrypt(iter::once(&identity as &dyn Identity))
            .map_err(|error| match error {
                DecryptError::ExcessiveWork { .. } => IdentityError::ExcessiveWork,
                DecryptError::DecryptionFailed => IdentityError::WrongPassphrase,
                _ => IdentityError::Malformed,
            })?;
        let mut secret = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 1));
        reader
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut secret)
            .map_err(|_| IdentityError::Malformed)?;
        if secret.len() > MAX_SECRET_BYTES {
            return Err(IdentityError::Malformed);
        }
        str::from_utf8(&secret)
            .ok()
            .and_then(|secret| secret.parse().ok())
            .map(Self)
            .ok_or(IdentityError::Malformed)
    }
}

impl fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("recipient", &self.recipient().to_string())
            .finish_non_exhaustive()
    }
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn is_private(metadata: &Metadata, allowed: u32) -> bool {
    metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o777 & !allowed == 0
}

fn check_private_dir(dir: &Path) -> Result<(), IdentityError> {
    let metadata = fs::metadata(dir)?;
    let owned = metadata.uid() == rustix::process::geteuid().as_raw();
    if !metadata.is_dir() || !owned || metadata.mode() & 0o022 != 0 {
        return Err(IdentityError::NotPrivate(dir.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::*;

    const FAST: u8 = 10;

    fn passphrase(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn identity_path(dir: &TempDir) -> PathBuf {
        dir.path().join("config").join("mahi").join("identity.age")
    }

    fn saved(dir: &TempDir) -> (LocalIdentity, PathBuf) {
        let identity = LocalIdentity::generate();
        let path = identity_path(dir);
        identity
            .save_with_work_factor(&path, &passphrase("correct horse"), FAST)
            .unwrap();
        (identity, path)
    }

    fn private_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn saves_and_loads_back_the_same_identity() {
        let dir = TempDir::new().unwrap();
        let (identity, path) = saved(&dir);
        let loaded = LocalIdentity::load(&path, &passphrase("correct horse")).unwrap();
        assert_eq!(
            loaded.recipient().to_string(),
            identity.recipient().to_string()
        );
    }

    #[test]
    fn saving_leaves_no_temporary_file() {
        let dir = TempDir::new().unwrap();
        let (_, path) = saved(&dir);
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["identity.age"]);
    }

    #[test]
    fn the_file_is_encrypted() {
        let dir = TempDir::new().unwrap();
        let (_, path) = saved(&dir);
        let bytes = fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"age-encryption.org/v1\n"));
        assert!(
            !bytes
                .windows(b"AGE-SECRET-KEY".len())
                .any(|w| w == b"AGE-SECRET-KEY")
        );
    }

    #[test]
    fn a_wrong_passphrase_is_refused() {
        let dir = TempDir::new().unwrap();
        let (_, path) = saved(&dir);
        assert!(matches!(
            LocalIdentity::load(&path, &passphrase("battery staple")),
            Err(IdentityError::WrongPassphrase)
        ));
    }

    #[test]
    fn an_existing_identity_or_symlink_is_never_overwritten() {
        let dir = TempDir::new().unwrap();
        let (identity, path) = saved(&dir);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            LocalIdentity::generate().save_with_work_factor(&path, &passphrase("x"), FAST),
            Err(IdentityError::Exists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            LocalIdentity::load(&path, &passphrase("correct horse"))
                .unwrap()
                .recipient()
                .to_string(),
            identity.recipient().to_string()
        );

        let link = path.with_file_name("link.age");
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &link).unwrap();
        assert!(matches!(
            LocalIdentity::generate().save_with_work_factor(&link, &passphrase("x"), FAST),
            Err(IdentityError::Exists(_))
        ));
        assert!(!dir.path().join("elsewhere").exists());
    }

    #[test]
    fn a_leftover_temporary_file_does_not_block_saving() {
        let dir = TempDir::new().unwrap();
        let path = identity_path(&dir);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path.parent().unwrap())
            .unwrap();
        fs::write(temp_path(&path), b"left by a crash").unwrap();
        LocalIdentity::generate()
            .save_with_work_factor(&path, &passphrase("p"), FAST)
            .unwrap();
        assert!(LocalIdentity::load(&path, &passphrase("p")).is_ok());
        assert!(!temp_path(&path).exists());
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(
            LocalIdentity::load(&dir.path().join("nope"), &passphrase("x")),
            Err(IdentityError::NotFound(_))
        ));
    }

    #[test]
    fn files_and_new_directories_are_private() {
        let dir = TempDir::new().unwrap();
        let (_, path) = saved(&dir);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn a_file_others_can_read_is_refused() {
        let dir = TempDir::new().unwrap();
        let (_, path) = saved(&dir);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            LocalIdentity::load(&path, &passphrase("correct horse")),
            Err(IdentityError::NotPrivate(_))
        ));
    }

    #[test]
    fn a_directory_others_can_write_is_refused() {
        let dir = TempDir::new().unwrap();
        let (_, path) = saved(&dir);
        let parent = path.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            LocalIdentity::load(&path, &passphrase("correct horse")),
            Err(IdentityError::NotPrivate(p)) if p == parent
        ));
        let other = parent.join("other.age");
        assert!(matches!(
            LocalIdentity::generate().save_with_work_factor(&other, &passphrase("x"), FAST),
            Err(IdentityError::NotPrivate(_))
        ));
        assert!(!other.exists());
    }

    #[test]
    fn a_directory_at_the_path_is_not_a_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.age");
        fs::create_dir(&path).unwrap();
        assert!(matches!(
            LocalIdentity::load(&path, &passphrase("x")),
            Err(IdentityError::NotAFile(_))
        ));
    }

    #[test]
    fn a_file_asking_for_too_much_work_is_refused_before_working() {
        let dir = TempDir::new().unwrap();
        let (_, path) = saved(&dir);
        let bytes = fs::read(&path).unwrap();
        let header_end = bytes.windows(4).position(|w| w == b"\n---").unwrap();
        let header = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let stanza = header
            .lines()
            .find(|l| l.starts_with("-> scrypt "))
            .unwrap();
        let heavy = stanza.replace(&format!(" {FAST}"), " 40");
        let mut tampered = header.replacen(stanza, &heavy, 1).into_bytes();
        tampered.extend_from_slice(&bytes[header_end..]);
        let heavy_path = private_file(&dir, "heavy.age", &tampered);
        assert!(matches!(
            LocalIdentity::load(&heavy_path, &passphrase("correct horse")),
            Err(IdentityError::ExcessiveWork)
        ));
    }

    #[test]
    fn an_age_file_not_encrypted_with_a_passphrase_is_malformed() {
        let dir = TempDir::new().unwrap();
        let recipient = x25519::Identity::generate().to_public();
        let encryptor =
            Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient)).unwrap();
        let mut writer = encryptor.wrap_output(Vec::new()).unwrap();
        writer.write_all(b"AGE-SECRET-KEY-1").unwrap();
        let path = private_file(&dir, "x25519.age", &writer.finish().unwrap());
        assert!(matches!(
            LocalIdentity::load(&path, &passphrase("x")),
            Err(IdentityError::Malformed)
        ));
    }

    #[test]
    fn empty_truncated_garbage_and_oversized_files_are_malformed() {
        let dir = TempDir::new().unwrap();
        let (_, path) = saved(&dir);
        let full = fs::read(&path).unwrap();
        for (name, content) in [
            ("empty", Vec::new()),
            ("truncated", full[..full.len() / 2].to_vec()),
            ("garbage", b"not an age file".to_vec()),
            ("big", vec![b'a'; 5000]),
        ] {
            let path = private_file(&dir, name, &content);
            assert!(
                matches!(
                    LocalIdentity::load(&path, &passphrase("correct horse")),
                    Err(IdentityError::Malformed)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn debug_hides_the_secret() {
        let identity = LocalIdentity::generate();
        let debug = format!("{identity:?}");
        assert!(debug.contains(&identity.recipient().to_string()));
        assert!(!debug.contains("AGE-SECRET-KEY"));
    }
}
