use std::{
    fs,
    io::{
        self,
        Read,
        Write,
    },
    path::PathBuf,
    time::Duration,
};

use gix_lock::acquire::Fail;
use mahi_core::ThreadId;
use mahi_store::Store;
use thiserror::Error;

use crate::{
    KeyError,
    ParticipantKey,
};

const MAX_OWNER_BYTES: u64 = 1024;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Remembering or reading a thread's owner key failed.
#[derive(Debug, Error)]
pub enum OwnerError {
    /// Another owner key is already remembered for the thread; it is never replaced.
    #[error("thread {0} is already known with another owner key")]
    Changed(ThreadId),
    /// The remembered key is not a usable key.
    #[error("the remembered owner key of thread {0} is not usable")]
    Corrupt(ThreadId, #[source] KeyError),
    /// Reading or writing failed.
    #[error("cannot read or write the thread's owner key")]
    Io(#[from] io::Error),
}

/// Remembers, in the repository's git directory, the owner key an invite ticket named for
/// `thread`, so a later `mahi resume` checks the thread's `meta` against it and never against
/// the key the document names. Remembering the same key again does nothing; another key is
/// refused.
///
/// # Errors
///
/// Returns [`OwnerError::Changed`] if another key is remembered, or [`OwnerError::Io`] if
/// writing fails.
pub fn remember_owner(
    store: &Store,
    thread: ThreadId,
    owner: &ParticipantKey,
) -> Result<(), OwnerError> {
    let path = owner_path(store, thread);
    let mut lock = gix_lock::File::acquire_to_update_resource(
        &path,
        Fail::AfterDurationWithBackoff(LOCK_TIMEOUT),
        Some(store.common_dir().to_path_buf()),
    )
    .map_err(io::Error::other)?;
    match read_owner(&path, thread)? {
        Some(known) if &known == owner => return Ok(()),
        Some(_) => return Err(OwnerError::Changed(thread)),
        None => {}
    }
    lock.write_all(owner.to_openssh().as_bytes())?;
    lock.with_mut(|file| file.sync_all())?;
    lock.commit()
        .map_err(|error| io::Error::other(error.error))?;
    if let Some(directory) = path.parent() {
        fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

/// Returns the owner key remembered for `thread`, if any.
///
/// # Errors
///
/// Returns [`OwnerError::Corrupt`] if the remembered key is not usable, or
/// [`OwnerError::Io`] if reading fails.
pub fn remembered_owner(
    store: &Store,
    thread: ThreadId,
) -> Result<Option<ParticipantKey>, OwnerError> {
    read_owner(&owner_path(store, thread), thread)
}

fn owner_path(store: &Store, thread: ThreadId) -> PathBuf {
    store
        .common_dir()
        .join("mahi")
        .join("owners")
        .join(thread.to_string())
}

fn read_owner(
    path: &std::path::Path,
    thread: ThreadId,
) -> Result<Option<ParticipantKey>, OwnerError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut line = String::new();
    file.take(MAX_OWNER_BYTES).read_to_string(&mut line)?;
    ParticipantKey::from_openssh(&line)
        .map(Some)
        .map_err(|error| OwnerError::Corrupt(thread, error))
}

#[cfg(test)]
mod tests {
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;

    fn key() -> ParticipantKey {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        ParticipantKey::from_public_key(key.public_key()).unwrap()
    }

    #[test]
    fn an_owner_is_remembered_once_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread = ThreadId::random().unwrap();
        assert!(remembered_owner(&store, thread).unwrap().is_none());
        let owner = key();
        remember_owner(&store, thread, &owner).unwrap();
        remember_owner(&store, thread, &owner).unwrap();
        assert_eq!(
            remembered_owner(&store, thread).unwrap(),
            Some(owner.clone())
        );
        assert!(matches!(
            remember_owner(&store, thread, &key()),
            Err(OwnerError::Changed(changed)) if changed == thread
        ));
        assert_eq!(remembered_owner(&store, thread).unwrap(), Some(owner));
        fs::write(owner_path(&store, thread), "not a key").unwrap();
        assert!(matches!(
            remembered_owner(&store, thread),
            Err(OwnerError::Corrupt(..))
        ));
    }
}
