use std::{
    fmt::Write as _,
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
    source::Source,
    sync_state,
};

const TEAMMATES_DIR: &str = "teammates";
const LANDING_FILE: &str = "landing";
const MAX_RECORD_BYTES: u64 = 64 * 1024;
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SyncRecord {
    pub(crate) skipped: Option<ObjectId>,
    pub(crate) waits: Waits,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum Waits {
    #[default]
    Free,
    Held(HeldSettings),
}

#[derive(Debug, Error)]
pub(crate) enum HeldError {
    #[error("cannot read or write the sync record {0}")]
    Io(PathBuf, #[source] io::Error),
    #[error("the sync record {0} is not one mahi wrote")]
    Malformed(PathBuf),
}

/// Returns where sync keeps its record of `from` for `into`'s worktree in `thread`: the
/// agent's sync directory, then `teammates/<participant>.<agent>` of `from`.
pub(crate) fn file(
    store: &Store,
    thread: ThreadId,
    (into, from): (&AgentSlot, &AgentSlot),
) -> PathBuf {
    sync_state::dir(store, thread, into)
        .join(TEAMMATES_DIR)
        .join(from.to_string())
}

/// Returns where sync keeps its record of `from` for `into`'s worktree in `thread`: [`file`]
/// for a teammate's agent, and `landing` in the agent's sync directory for the landing branch.
pub(crate) fn file_for(
    store: &Store,
    thread: ThreadId,
    (into, from): (&AgentSlot, &Source),
) -> PathBuf {
    match from {
        Source::Agent(from) => file(store, thread, (into, from)),
        Source::Landing(_) => sync_state::dir(store, thread, into).join(LANDING_FILE),
    }
}

/// Returns the snapshot of a teammate the user skipped, kept in `file`, which their next turns
/// merge from, or `None` when there is none or the record cannot be read.
pub(crate) fn skipped(file: &Path) -> Option<ObjectId> {
    SyncRecord::load(file).ok()?.skipped
}

/// Every snapshot that waits for the user in `into`'s worktree in `thread`, with the teammate
/// it came from, in the order of their slots; a record that cannot be read is left out.
pub(crate) fn list(
    store: &Store,
    thread: ThreadId,
    into: &AgentSlot,
) -> Vec<(AgentSlot, HeldSettings)> {
    let dir = sync_state::dir(store, thread, into).join(TEAMMATES_DIR);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut held: Vec<(AgentSlot, HeldSettings)> = entries
        .flatten()
        .filter_map(|entry| {
            let from: AgentSlot = entry.file_name().to_str()?.parse().ok()?;
            let Waits::Held(record) = SyncRecord::load(&dir.join(from.to_string())).ok()?.waits
            else {
                return None;
            };
            Some((from, record))
        })
        .collect();
    held.sort_by_cached_key(|(from, _)| from.to_string());
    held
}

/// Says whether a snapshot of a teammate waits in `file`, or may: only a record that surely
/// holds none lets the teammate's turns be merged.
pub(crate) fn waits(file: &Path) -> bool {
    !matches!(
        SyncRecord::load(file),
        Ok(SyncRecord {
            waits: Waits::Free,
            ..
        })
    )
}

impl SyncRecord {
    pub(crate) fn load(file: &Path) -> Result<Self, HeldError> {
        let malformed = || HeldError::Malformed(file.to_path_buf());
        let bytes = match sync_state::read(file, MAX_RECORD_BYTES) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(Self::default()),
            Err(error) if error.kind() == io::ErrorKind::FileTooLarge => return Err(malformed()),
            Err(error) => return Err(HeldError::Io(file.to_path_buf(), error)),
        };
        let text = String::from_utf8(bytes).map_err(|_| malformed())?;
        let mut fields = text.strip_suffix('\0').ok_or_else(malformed)?.split('\0');
        let skipped = match fields.next().ok_or_else(malformed)? {
            "" => None,
            hex => Some(ObjectId::from_hex(hex.as_bytes()).map_err(|_| malformed())?),
        };
        let Some(commit) = fields.next() else {
            return Ok(Self {
                skipped,
                waits: Waits::Free,
            });
        };
        let commit = ObjectId::from_hex(commit.as_bytes()).map_err(|_| malformed())?;
        let changed = fields
            .next()
            .and_then(|changed| changed.parse().ok())
            .ok_or_else(malformed)?;
        let paths: Vec<String> = fields.map(str::to_owned).collect();
        if paths.len() > MAX_HELD_PATHS
            || paths.len() > changed
            || paths.iter().any(String::is_empty)
        {
            return Err(malformed());
        }
        Ok(Self {
            skipped,
            waits: Waits::Held(HeldSettings {
                commit,
                paths,
                changed,
            }),
        })
    }

    pub(crate) fn save(&self, file: &Path) -> Result<(), HeldError> {
        let io = |error| HeldError::Io(file.to_path_buf(), error);
        if *self == Self::default() {
            return sync_state::remove(file).map_err(io);
        }
        let mut text = String::new();
        if let Some(skipped) = self.skipped {
            let _ = write!(text, "{}", skipped.to_hex());
        }
        text.push('\0');
        if let Waits::Held(held) = &self.waits {
            let _ = write!(text, "{}\0{}\0", held.commit.to_hex(), held.changed);
            for path in &held.paths {
                text.push_str(path);
                text.push('\0');
            }
        }
        sync_state::write(file, text.as_bytes()).map_err(io)
    }
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

    /// Reads the snapshot that waits in the record kept in `file`, or `None` when none waits.
    pub(crate) fn load(file: &Path) -> Result<Option<Self>, HeldError> {
        Ok(match SyncRecord::load(file)?.waits {
            Waits::Free => None,
            Waits::Held(held) => Some(held),
        })
    }

    /// Makes this snapshot wait in the record kept in `file`, unless one already waits there,
    /// or may, so the first one held stays first.
    pub(crate) fn keep(&self, file: &Path) -> Result<(), HeldError> {
        let Ok(mut record) = SyncRecord::load(file) else {
            return Ok(());
        };
        if record.waits != Waits::Free {
            return Ok(());
        }
        record.waits = Waits::Held(self.clone());
        record.save(file)
    }

    /// Skips this snapshot, which waits in the record kept in `file`: keeps it as skipped, so
    /// the teammate's next turns merge from it and its change stays out, and stops holding it,
    /// in one write.
    pub(crate) fn skip(&self, file: &Path) -> Result<(), HeldError> {
        let mut record = SyncRecord::load(file)?;
        record.skipped = Some(self.commit);
        record.waits = Waits::Free;
        record.save(file)
    }
}

/// Stops holding, or keeping as skipped, each snapshot kept for `into`'s worktree in `thread`
/// that `merged`, what the agent's snapshots record as merged, now holds: that snapshot or a
/// later one of its agent. A record that cannot be read or written stays, so its teammate
/// keeps waiting.
pub(crate) fn release_merged(
    store: &Store,
    thread: ThreadId,
    into: &AgentSlot,
    merged: &MergedFrom,
) {
    let dir = sync_state::dir(store, thread, into).join(TEAMMATES_DIR);
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
        let Some(taken) = merged.of(&from) else {
            continue;
        };
        let file = dir.join(from.to_string());
        let Ok(mut record) = SyncRecord::load(&file) else {
            continue;
        };
        let holds =
            |kept: ObjectId| taken == kept || store.descends_from(taken, kept).unwrap_or(false);
        let mut changed = false;
        if record.skipped.is_some_and(holds) {
            record.skipped = None;
            changed = true;
        }
        if let Waits::Held(held) = &record.waits
            && holds(held.commit)
        {
            record.waits = Waits::Free;
            changed = true;
        }
        if changed {
            let _ = record.save(&file);
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
        let file = dir.path().join("sync/alice.claude/teammates/bob.codex");
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
        SyncRecord::default().save(&file).unwrap();
        assert!(!waits(&file));
        assert!(!file.exists());
        SyncRecord::default().save(&file).unwrap();
    }

    #[test]
    fn a_skipped_snapshot_stays_the_base_beside_a_later_one_held_in_the_same_record() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sync/alice.claude/teammates/bob.codex");
        let first = HeldSettings::new(commit(1), &["CLAUDE.md".to_owned()]);
        first.keep(&file).unwrap();
        first.skip(&file).unwrap();
        assert!(!waits(&file));
        assert_eq!(skipped(&file), Some(commit(1)));
        let later = HeldSettings::new(commit(2), &["AGENTS.md".to_owned()]);
        later.keep(&file).unwrap();
        assert!(waits(&file));
        assert_eq!(
            SyncRecord::load(&file).unwrap(),
            SyncRecord {
                skipped: Some(commit(1)),
                waits: Waits::Held(later.clone()),
            }
        );
        later.skip(&file).unwrap();
        assert_eq!(
            SyncRecord::load(&file).unwrap(),
            SyncRecord {
                skipped: Some(commit(2)),
                waits: Waits::Free,
            }
        );
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
    fn a_merge_releases_only_the_part_of_a_record_it_took() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path().join("repo")).unwrap();
        let store = Store::open(&dir.path().join("repo")).unwrap();
        let thread = ThreadId::random().unwrap();
        let (into, bob): (AgentSlot, AgentSlot) = (
            "alice.claude".parse().unwrap(),
            "bob.codex".parse().unwrap(),
        );
        let kept = file(&store, thread, (&into, &bob));
        let held = HeldSettings::new(commit(2), &["AGENTS.md".to_owned()]);
        SyncRecord {
            skipped: Some(commit(1)),
            waits: Waits::Held(held.clone()),
        }
        .save(&kept)
        .unwrap();
        let mut merged = MergedFrom::default();
        merged.record(bob.clone(), commit(1));
        release_merged(&store, thread, &into, &merged);
        assert_eq!(
            SyncRecord::load(&kept).unwrap(),
            SyncRecord {
                skipped: None,
                waits: Waits::Held(held),
            }
        );
        merged.record(bob, commit(2));
        release_merged(&store, thread, &into, &merged);
        assert!(!kept.exists());
    }

    #[test]
    fn a_sync_record_that_is_not_one_mahi_wrote_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("held");
        let hex = commit(1).to_hex().to_string();
        for text in [
            String::new(),
            "not a commit\0".to_owned(),
            format!("\0{hex}\0"),
            format!("\0{hex}\0x\0"),
            "\0not a commit\x000\0".to_owned(),
            format!("\0{hex}\x000\0CLAUDE.md\0"),
            format!("\0{hex}\x001\0\0"),
            format!("\0{hex}\x001"),
        ] {
            fs::write(&file, &text).unwrap();
            assert!(
                matches!(SyncRecord::load(&file), Err(HeldError::Malformed(_))),
                "{text:?}"
            );
            assert!(waits(&file), "{text:?}");
        }
        fs::write(&file, format!("\0{hex}\x002\0CLAUDE.md\0")).unwrap();
        assert!(HeldSettings::load(&file).unwrap().is_some());
        fs::write(&file, format!("{hex}\0")).unwrap();
        assert_eq!(
            SyncRecord::load(&file).unwrap(),
            SyncRecord {
                skipped: Some(commit(1)),
                waits: Waits::Free,
            }
        );
    }
}
