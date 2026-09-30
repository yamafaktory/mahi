use std::{
    io,
    os::fd::OwnedFd,
    path::{
        Path,
        PathBuf,
    },
};

use mahi_core::{
    AgentName,
    ThreadId,
};
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

/// The lock that keeps a thread from being ended, or invited to as if it were not running,
/// while one of its agents runs, taken alone by `mahi end` and `mahi invite`.
///
/// It is an advisory `flock` on `locks/<thread-id>` in mahi's configuration directory, which
/// no sandbox ever sees, so an agent cannot hold another thread's lock. The system releases it
/// when mahi exits, however it exits.
#[derive(Debug)]
pub(crate) struct ThreadLock {
    held: Held,
    directory: PathBuf,
    thread: ThreadId,
}

/// The locks a mahi running one agent of a thread holds for as long as it lives: the thread's,
/// shared with the mahis of its other agents, and the agent's own, alone.
#[derive(Debug)]
pub(crate) struct AgentLock {
    _thread: Held,
    _agent: Held,
}

#[derive(Debug)]
struct Held {
    file: OwnedFd,
    path: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum LockError {
    #[error("thread {0} is running in another mahi")]
    Busy(ThreadId),
    #[error("agent {1} of thread {0} is already running in another mahi")]
    AgentBusy(ThreadId, AgentName),
    #[error("cannot lock the thread")]
    Io(#[from] io::Error),
}

impl ThreadLock {
    /// Takes the lock of `thread` alone, or fails at once if a mahi runs one of its agents.
    ///
    /// The lock is only held once the file it locked is still the one at its path, since
    /// `mahi end` removes lock files.
    pub(crate) fn acquire(config: &ConfigDir, thread: ThreadId) -> Result<Self, LockError> {
        let directory = locks_dir(config)?;
        let held = Held::take(&directory.join(thread.to_string()), true)?
            .ok_or(LockError::Busy(thread))?;
        Ok(Self {
            held,
            directory,
            thread,
        })
    }

    /// Removes the lock files of a thread that has ended, its own and its agents', if they
    /// are still the ones at their paths, then releases the lock.
    pub(crate) fn remove(self) -> io::Result<()> {
        let prefix = format!("{}.", self.thread);
        for entry in std::fs::read_dir(&self.directory)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix))
            {
                remove_if_absent_is_fine(&entry.path())?;
            }
        }
        if self.held.still_at_its_path()? {
            remove_if_absent_is_fine(&self.held.path)?;
        }
        Ok(())
    }
}

impl AgentLock {
    /// Takes the lock of `thread` shared, then `agent`'s alone, or fails at once if the thread
    /// is being ended or the agent runs in another mahi.
    pub(crate) fn acquire(
        config: &ConfigDir,
        thread: ThreadId,
        agent: &AgentName,
    ) -> Result<Self, LockError> {
        let directory = locks_dir(config)?;
        let shared = Held::take(&directory.join(thread.to_string()), false)?
            .ok_or(LockError::Busy(thread))?;
        let own = Held::take(&directory.join(format!("{thread}.{agent}")), true)?
            .ok_or_else(|| LockError::AgentBusy(thread, agent.clone()))?;
        Ok(Self {
            _thread: shared,
            _agent: own,
        })
    }
}

impl Held {
    fn take(path: &Path, alone: bool) -> Result<Option<Self>, LockError> {
        let operation = if alone {
            FlockOperation::NonBlockingLockExclusive
        } else {
            FlockOperation::NonBlockingLockShared
        };
        for _ in 0..ATTEMPTS {
            let file = rustix::fs::open(
                path,
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(io::Error::from)?;
            match rustix::fs::flock(&file, operation) {
                Ok(()) => {}
                Err(Errno::WOULDBLOCK) => return Ok(None),
                Err(error) => return Err(io::Error::from(error).into()),
            }
            let held = Self {
                file,
                path: path.to_path_buf(),
            };
            if held.still_at_its_path()? {
                return Ok(Some(held));
            }
        }
        Ok(None)
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

fn locks_dir(config: &ConfigDir) -> io::Result<PathBuf> {
    let directory = config.path().join(LOCKS);
    profile::create_private_dir(&directory)?;
    Ok(directory)
}

fn remove_if_absent_is_fine(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
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

    #[test]
    fn agents_of_a_thread_run_side_by_side_and_keep_it_from_ending() {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        let thread = ThreadId::random().unwrap();
        let claude = AgentName::new("claude").unwrap();
        let codex = AgentName::new("codex").unwrap();
        let first = AgentLock::acquire(&config, thread, &claude).unwrap();
        let second = AgentLock::acquire(&config, thread, &codex).unwrap();
        assert!(matches!(
            AgentLock::acquire(&config, thread, &claude),
            Err(LockError::AgentBusy(busy, agent)) if busy == thread && agent == claude
        ));
        assert!(matches!(
            ThreadLock::acquire(&config, thread),
            Err(LockError::Busy(_))
        ));
        drop(first);
        assert!(ThreadLock::acquire(&config, thread).is_err());
        drop(second);
        let ending = ThreadLock::acquire(&config, thread).unwrap();
        assert!(matches!(
            AgentLock::acquire(&config, thread, &claude),
            Err(LockError::Busy(_))
        ));
        let locks = config.path().join(LOCKS);
        assert!(locks.join(format!("{thread}.claude")).exists());
        let other = ThreadId::random().unwrap();
        let _elsewhere = AgentLock::acquire(&config, other, &claude).unwrap();
        ending.remove().unwrap();
        assert!(!locks.join(thread.to_string()).exists());
        assert!(!locks.join(format!("{thread}.claude")).exists());
        assert!(!locks.join(format!("{thread}.codex")).exists());
        assert!(locks.join(format!("{other}.claude")).exists());
    }
}
