use std::{
    fs,
    io,
    path::{
        Path,
        PathBuf,
    },
};

use mahi_core::{
    AgentSlot,
    ThreadId,
};
use mahi_store::{
    ObjectId,
    Store,
};
use thiserror::Error;

use crate::{
    merged::MergedFrom,
    sync_state,
};

const HELD_DIR: &str = "held";
const MAX_HELD_BYTES: u64 = 64 * 1024;
const MAX_HELD_PATHS: usize = 20;
const LONGEST_PATH: usize = 200;

/// A teammate's turn-end snapshot that changes agent settings, waiting for the user with that
/// teammate's later turns behind it: the snapshot, the first paths it changes that hold it,
/// and how many such paths there are, none when they could not be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldSettings {
    pub(crate) commit: ObjectId,
    pub(crate) paths: Vec<String>,
    pub(crate) changed: usize,
}

#[derive(Debug, Error)]
pub(crate) enum HeldError {
    #[error("cannot keep the snapshot that waits for the user in {0}")]
    Io(PathBuf, #[source] io::Error),
    #[error("the snapshot kept in {0} cannot be read; remove the file to merge it again")]
    Malformed(PathBuf),
}

/// Returns where the snapshot of `from` that waits for the user is kept, for `into`'s worktree
/// in `thread`: the agent's sync directory, then `held/<participant>.<agent>` of `from`.
pub(crate) fn file(
    store: &Store,
    thread: ThreadId,
    (into, from): (&AgentSlot, &AgentSlot),
) -> PathBuf {
    sync_state::dir(store, thread, into)
        .join(HELD_DIR)
        .join(from.to_string())
}

/// Says whether a snapshot of a teammate waits in `file`, or may: only a file surely missing
/// lets the teammate's turns be merged.
pub(crate) fn waits(file: &Path) -> bool {
    sync_state::may_exist(file)
}

impl HeldSettings {
    /// Returns the snapshot `commit`, held for the agent settings `paths` it changes, of which
    /// the first 20 are kept, each cut to 200 bytes.
    pub(crate) fn new(commit: ObjectId, paths: &[String]) -> Self {
        let cut = |path: &String| {
            let mut end = path.len().min(LONGEST_PATH);
            while !path.is_char_boundary(end) {
                end -= 1;
            }
            path.get(..end).unwrap_or_default().to_owned()
        };
        Self {
            commit,
            paths: paths
                .iter()
                .take(MAX_HELD_PATHS)
                .map(cut)
                .filter(|path| !path.is_empty())
                .collect(),
            changed: paths.len(),
        }
    }

    /// Reads the snapshot kept in `file`, or `None` when none waits.
    pub(crate) fn load(file: &Path) -> Result<Option<Self>, HeldError> {
        let malformed = || HeldError::Malformed(file.to_path_buf());
        let bytes = match sync_state::read(file, MAX_HELD_BYTES) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::FileTooLarge => return Err(malformed()),
            Err(error) => return Err(HeldError::Io(file.to_path_buf(), error)),
        };
        let text = String::from_utf8(bytes).map_err(|_| malformed())?;
        let mut records = text.strip_suffix('\0').ok_or_else(malformed)?.split('\0');
        let commit = records
            .next()
            .and_then(|commit| ObjectId::from_hex(commit.as_bytes()).ok())
            .ok_or_else(malformed)?;
        let changed = records
            .next()
            .and_then(|changed| changed.parse().ok())
            .ok_or_else(malformed)?;
        let paths: Vec<String> = records.map(str::to_owned).collect();
        if paths.len() > MAX_HELD_PATHS
            || paths.len() > changed
            || paths.iter().any(String::is_empty)
        {
            return Err(malformed());
        }
        Ok(Some(Self {
            commit,
            paths,
            changed,
        }))
    }

    /// Writes this snapshot to `file`, unless one already waits there, so the first one held
    /// stays first.
    pub(crate) fn keep(&self, file: &Path) -> Result<(), HeldError> {
        if waits(file) {
            return Ok(());
        }
        let mut text = format!("{}\0{}\0", self.commit.to_hex(), self.changed);
        for path in &self.paths {
            text.push_str(path);
            text.push('\0');
        }
        sync_state::write(file, text.as_bytes())
            .map_err(|error| HeldError::Io(file.to_path_buf(), error))
    }

    /// Stops holding the snapshot kept in `file`.
    pub(crate) fn release(file: &Path) -> Result<(), HeldError> {
        sync_state::remove(file).map_err(|error| HeldError::Io(file.to_path_buf(), error))
    }
}

/// Stops holding each snapshot kept for `into`'s worktree in `thread` that `merged`, what the
/// agent's snapshots record as merged, now holds: the held snapshot or a later one of its
/// agent. A record that cannot be read or removed stays, so its teammate keeps waiting.
pub(crate) fn release_merged(
    store: &Store,
    thread: ThreadId,
    into: &AgentSlot,
    merged: &MergedFrom,
) {
    let dir = sync_state::dir(store, thread, into).join(HELD_DIR);
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(from) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<AgentSlot>().ok())
        else {
            continue;
        };
        let file = dir.join(from.to_string());
        let (Ok(Some(held)), Some(taken)) = (HeldSettings::load(&file), merged.of(&from)) else {
            continue;
        };
        if taken == held.commit || store.descends_from(taken, held.commit).unwrap_or(false) {
            let _ = HeldSettings::release(&file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(byte: u8) -> ObjectId {
        ObjectId::from_bytes_or_panic(&[byte; 20])
    }

    #[test]
    fn a_held_snapshot_reads_back_as_kept_and_the_first_one_kept_stays() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sync/alice.claude/held/bob.codex");
        assert_eq!(HeldSettings::load(&file).unwrap(), None);
        assert!(!waits(&file));
        let paths: Vec<String> = (0..25).map(|index| format!(".claude/{index}")).collect();
        let held = HeldSettings::new(commit(1), &paths);
        assert_eq!(held.paths.len(), 20);
        assert_eq!(held.changed, 25);
        held.keep(&file).unwrap();
        assert!(waits(&file));
        HeldSettings::new(commit(2), &[]).keep(&file).unwrap();
        assert_eq!(HeldSettings::load(&file).unwrap(), Some(held));
        HeldSettings::release(&file).unwrap();
        assert!(!waits(&file));
        HeldSettings::release(&file).unwrap();
    }

    #[test]
    fn a_held_snapshot_with_long_paths_is_kept_short_enough_to_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("held");
        let paths: Vec<String> = (0..20)
            .map(|index| format!(".claude/{index}{}", "\u{e9}".repeat(3000)))
            .collect();
        HeldSettings::new(commit(1), &paths).keep(&file).unwrap();
        let held = HeldSettings::load(&file).unwrap().unwrap();
        assert_eq!(held.paths.len(), 20);
        assert!(held.paths.iter().all(|path| path.len() <= LONGEST_PATH));
    }

    #[test]
    fn a_held_snapshot_file_that_is_not_one_mahi_wrote_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("held");
        let hex = commit(1).to_hex().to_string();
        for text in [
            String::new(),
            format!("{hex}\0"),
            format!("{hex}\0x\0"),
            "not a commit\x000\0".to_owned(),
            format!("{hex}\x000\0CLAUDE.md\0"),
            format!("{hex}\x001\0\0"),
            format!("{hex}\x001"),
        ] {
            fs::write(&file, &text).unwrap();
            assert!(
                matches!(HeldSettings::load(&file), Err(HeldError::Malformed(_))),
                "{text:?}"
            );
        }
        fs::write(&file, format!("{hex}\x002\0CLAUDE.md\0")).unwrap();
        assert!(HeldSettings::load(&file).unwrap().is_some());
    }
}
