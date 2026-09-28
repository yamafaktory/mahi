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
