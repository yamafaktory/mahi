use std::{
    io,
    os::fd::OwnedFd,
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

/// The lock that keeps one mahi at a time on a thread, held for as long as it lives.
///
/// It is an advisory `flock` on `locks/<thread-id>` in mahi's configuration directory, which
/// no sandbox ever sees, so an agent cannot hold another thread's lock. The system releases it
/// when mahi exits, however it exits.
#[derive(Debug)]
pub(crate) struct ThreadLock {
    _file: OwnedFd,
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
    pub(crate) fn acquire(config: &ConfigDir, thread: ThreadId) -> Result<Self, LockError> {
        let directory = config.path().join(LOCKS);
        profile::create_private_dir(&directory)?;
        let file = rustix::fs::open(
            directory.join(thread.to_string()),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io::Error::from)?;
        match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { _file: file }),
            Err(Errno::WOULDBLOCK) => Err(LockError::Busy(thread)),
            Err(error) => Err(io::Error::from(error).into()),
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
}
