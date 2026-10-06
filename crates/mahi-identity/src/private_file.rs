use std::{
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
    mem,
    os::unix::fs::{
        DirBuilderExt,
        MetadataExt,
        OpenOptionsExt,
    },
    path::{
        Path,
        PathBuf,
    },
};

use zeroize::Zeroizing;

use crate::IdentityError;

const PRIVATE_FILE: u32 = 0o600;
const PRIVATE_DIR: u32 = 0o700;

pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
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
    if let Err(error) = write_temp(&temp, bytes) {
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

pub(crate) fn read(path: &Path, max_bytes: u64) -> Result<Vec<u8>, IdentityError> {
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
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(IdentityError::NotAFile(path.to_path_buf()));
    }
    if !is_private(&metadata) {
        return Err(IdentityError::NotPrivate(path.to_path_buf()));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(max_bytes + 1).unwrap_or(0),
    ));
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(IdentityError::Malformed);
    }
    Ok(mem::take(&mut *bytes))
}

/// Reads the regular file at `path`, at most `max_bytes` long, without following a symbolic
/// link, when it and its directory are the user's own and writable by no one else.
///
/// # Errors
///
/// Returns [`IdentityError::NotFound`] if there is no file, [`IdentityError::NotAFile`] if it
/// is not a regular file, [`IdentityError::WritableByOthers`] if it or its directory is
/// another user's or writable by someone else, [`IdentityError::Malformed`] if it is longer
/// than `max_bytes`, or [`IdentityError::Io`] if it cannot be read.
pub fn read_owned_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, IdentityError> {
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
    check_owned_dir(parent_of(path))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(IdentityError::NotAFile(path.to_path_buf()));
    }
    if !is_owned_unshared(&metadata) {
        return Err(IdentityError::WritableByOthers(path.to_path_buf()));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(IdentityError::Malformed);
    }
    Ok(bytes)
}

/// Checks that `dir` is a directory of the user's own that no one else can write to.
///
/// # Errors
///
/// Returns [`IdentityError::WritableByOthers`] if it is not, or [`IdentityError::Io`] if it
/// cannot be looked at.
pub fn check_owned_dir(dir: &Path) -> Result<(), IdentityError> {
    let metadata = fs::metadata(dir)?;
    if !metadata.is_dir() || !is_owned_unshared(&metadata) {
        return Err(IdentityError::WritableByOthers(dir.to_path_buf()));
    }
    Ok(())
}

fn is_owned_unshared(metadata: &Metadata) -> bool {
    metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o022 == 0
}

fn no_follow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits().cast_signed()
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

fn write_temp(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn is_private(metadata: &Metadata) -> bool {
    metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.mode() & 0o777 & !PRIVATE_FILE == 0
}

pub(crate) fn check_private_dir(dir: &Path) -> Result<(), IdentityError> {
    let metadata = fs::metadata(dir)?;
    let owned = metadata.uid() == rustix::process::geteuid().as_raw();
    if !metadata.is_dir() || !owned || metadata.mode() & 0o022 != 0 {
        return Err(IdentityError::NotPrivate(dir.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{
        PermissionsExt,
        symlink,
    };

    use super::*;

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn an_owned_file_no_one_else_can_write_is_read_whatever_others_may_read() {
        let dir = tempfile::tempdir().unwrap();
        set_mode(dir.path(), 0o755);
        let path = dir.path().join("codex.toml");
        fs::write(&path, b"name = \"codex\"\n").unwrap();
        set_mode(&path, 0o644);
        assert_eq!(read_owned_file(&path, 64).unwrap(), b"name = \"codex\"\n");

        assert!(matches!(
            read_owned_file(&path, 4),
            Err(IdentityError::Malformed)
        ));
        set_mode(&path, 0o664);
        assert!(matches!(
            read_owned_file(&path, 64),
            Err(IdentityError::WritableByOthers(refused)) if refused == path
        ));
        set_mode(&path, 0o600);
        set_mode(dir.path(), 0o775);
        assert!(matches!(
            read_owned_file(&path, 64),
            Err(IdentityError::WritableByOthers(refused)) if refused == dir.path()
        ));
        set_mode(dir.path(), 0o700);
        let link = dir.path().join("link.toml");
        symlink(&path, &link).unwrap();
        assert!(matches!(
            read_owned_file(&link, 64),
            Err(IdentityError::NotAFile(_))
        ));
        assert!(matches!(
            read_owned_file(&dir.path().join("missing.toml"), 64),
            Err(IdentityError::NotFound(_))
        ));
    }
}
