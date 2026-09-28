use std::{
    io,
    os::fd::OwnedFd,
    path::PathBuf,
};

use mahi_core::ThreadId;
use mahi_identity::ConfigDir;
use rustix::{
    fs::{
        FlockOperation,
        Mode,
        OFlags,
    },
    io::Errno,
};
use thiserror::Error;

use crate::profile;

const LOCKS: &str = "locks";
const ATTEMPTS: usize = 4;

/// The lock that keeps one mahi at a time on a thread, held for as long as it lives.
///
/// It is an advisory `flock` on `locks/<thread-id>` in mahi's configuration directory, which
/// no sandbox ever sees, so an agent cannot hold another thread's lock. The system releases it
/// when mahi exits, however it exits.
#[derive(Debug)]
pub(crate) struct ThreadLock {
    file: OwnedFd,
    path: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum LockError {
    #[error("thread {0} is already running in another mahi")]
    Busy(ThreadId),
    #[error("cannot lock the thread")]
    Io(#[from] io::Error),
}

impl ThreadLock {
    /// Takes the lock of `thread`, or fails at once if another mahi holds it.
    ///
    /// The lock is only held once the file it locked is still the one at its path, since
    /// `mahi end` removes lock files.
    pub(crate) fn acquire(config: &ConfigDir, thread: ThreadId) -> Result<Self, LockError> {
        let directory = config.path().join(LOCKS);
        profile::create_private_dir(&directory)?;
        let path = directory.join(thread.to_string());
        for _ in 0..ATTEMPTS {
            let file = rustix::fs::open(
                &path,
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(io::Error::from)?;
            match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {}
                Err(Errno::WOULDBLOCK) => return Err(LockError::Busy(thread)),
                Err(error) => return Err(io::Error::from(error).into()),
            }
            let lock = Self {
                file,
                path: path.clone(),
            };
            if lock.still_at_its_path()? {
                return Ok(lock);
            }
        }
        Err(LockError::Busy(thread))
    }

    /// Removes the lock file of a thread that has ended, if it is still the one this lock
    /// holds, then releases the lock.
    pub(crate) fn remove(self) -> io::Result<()> {
        if self.still_at_its_path()? {
            match std::fs::remove_file(&self.path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        Ok(())
    }

    fn still_at_its_path(&self) -> io::Result<bool> {
        let held = rustix::fs::fstat(&self.file)?;
        match rustix::fs::lstat(&self.path) {
            Ok(named) => Ok(named.st_dev == held.st_dev && named.st_ino == held.st_ino),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_is_locked_once_until_its_lock_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        let thread = ThreadId::random().unwrap();
        let other = ThreadId::random().unwrap();
        let held = ThreadLock::acquire(&config, thread).unwrap();
        assert!(matches!(
            ThreadLock::acquire(&config, thread),
            Err(LockError::Busy(busy)) if busy == thread
        ));
        let _other = ThreadLock::acquire(&config, other).unwrap();
        drop(held);
        ThreadLock::acquire(&config, thread).unwrap();
    }

    #[test]
    fn an_ended_threads_lock_file_goes_and_a_stale_holder_does_not_count() {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        let thread = ThreadId::random().unwrap();
        let path = config.path().join(LOCKS).join(thread.to_string());
        let first = ThreadLock::acquire(&config, thread).unwrap();
        assert!(path.exists());
        first.remove().unwrap();
        assert!(!path.exists());
        let stale = ThreadLock::acquire(&config, thread).unwrap();
        std::fs::remove_file(&path).unwrap();
        let fresh = ThreadLock::acquire(&config, thread).unwrap();
        stale.remove().unwrap();
        assert!(path.exists());
        drop(fresh);
    }
}
