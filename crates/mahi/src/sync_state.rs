use std::{
    fs::{
        self,
        File,
    },
    io::{
        self,
        Read,
    },
    path::{
        Path,
        PathBuf,
    },
};

use mahi_core::{
    AgentSlot,
    ThreadId,
};
use mahi_store::Store;
use rustix::fs::{
    Mode,
    OFlags,
};

use crate::{
    profile,
    session,
};

const SYNC_DIR: &str = "sync";

/// Returns where mahi keeps what sync holds for `slot`'s worktree in `thread`:
/// `<common git dir>/mahi/state/<thread>/sync/<participant>.<agent>`, beside the agent's state
/// directory, out of the agent's reach.
pub(crate) fn dir(store: &Store, thread: ThreadId, slot: &AgentSlot) -> PathBuf {
    session::state_root(store, thread)
        .join(SYNC_DIR)
        .join(slot.to_string())
}

/// Reads `file`, or `None` when it is missing; a file larger than `most` bytes is an error.
pub(crate) fn read(file: &Path, most: u64) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let read = File::open(file).and_then(|opened| {
        opened
            .take(most.saturating_add(1))
            .read_to_end(&mut bytes)
            .map(drop)
    });
    match read {
        Ok(()) if bytes.len() as u64 > most => Err(io::ErrorKind::FileTooLarge.into()),
        Ok(()) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Replaces `file` with `bytes`, atomically, in a directory only the user can use.
pub(crate) fn write(file: &Path, bytes: &[u8]) -> io::Result<()> {
    let (Some(dir), Some(name)) = (file.parent(), file.file_name().and_then(|n| n.to_str())) else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    profile::create_private_dir(dir)?;
    let directory = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    profile::replace(&directory, name, bytes)
}

/// Removes `file`, which may already be gone.
pub(crate) fn remove(file: &Path) -> io::Result<()> {
    match fs::remove_file(file) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Says whether `file` may exist: `false` only when it is surely missing.
pub(crate) fn may_exist(file: &Path) -> bool {
    !matches!(fs::symlink_metadata(file), Err(error) if error.kind() == io::ErrorKind::NotFound)
}
