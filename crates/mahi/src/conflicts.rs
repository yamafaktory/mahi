use std::{
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
    MAX_MERGED_PATHS,
    ObjectId,
    Store,
    StoreError,
};
use thiserror::Error;

use crate::sync_state;

const CONFLICTS_FILE: &str = "conflicts";
const MAX_KEPT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_KEPT_PATHS: usize = 2 * MAX_MERGED_PATHS;
const SHORTEST_MARKER: usize = 7;

/// The paths a merge left with conflict markers in an agent's worktree, the agent they came
/// from, and the tree the worktree had before the merge, kept in the agent's state until the
/// markers are resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeptConflicts {
    from: AgentSlot,
    before: ObjectId,
    paths: Vec<Vec<u8>>,
}

#[derive(Debug, Error)]
pub(crate) enum ConflictsError {
    #[error("cannot keep the conflicts of the merge in {0}")]
    Io(PathBuf, #[source] io::Error),
    #[error("the conflicts kept in {0} cannot be read; resolve them and remove the file")]
    Malformed(PathBuf),
    #[error("the merge left more conflicts than mahi keeps")]
    TooMany,
    #[error("cannot read the worktree's snapshot")]
    Store(#[from] StoreError),
}

/// Returns the label of conflict markers on the side of `slot`: `mahi <participant>.<agent>`.
pub(crate) fn label(slot: &AgentSlot) -> String {
    format!("mahi {slot}")
}

/// Returns where the conflicts of `slot`'s worktree in `thread` are kept:
/// `<common git dir>/mahi/state/<thread>/sync/<participant>.<agent>/conflicts`, beside the
/// agent's state directory, out of the agent's reach.
pub(crate) fn file(store: &Store, thread: ThreadId, slot: &AgentSlot) -> PathBuf {
    sync_state::dir(store, thread, slot).join(CONFLICTS_FILE)
}

impl KeptConflicts {
    /// Returns the conflicts of a merge from `from` into a worktree whose tree was `before`,
    /// which left markers in `paths`, or `None` when it left none.
    pub(crate) fn of_merge<'path, P: AsRef<[u8]> + 'path>(
        (from, before): (&AgentSlot, ObjectId),
        paths: impl Iterator<Item = &'path P>,
    ) -> Option<Self> {
        let paths: Vec<Vec<u8>> = paths.map(|path| path.as_ref().to_vec()).collect();
        (!paths.is_empty()).then(|| Self {
            from: from.clone(),
            before,
            paths,
        })
    }

    #[cfg(test)]
    pub(crate) fn before(&self) -> ObjectId {
        self.before
    }

    /// Reads the conflicts kept in `file`, or `None` when none are kept.
    pub(crate) fn load(file: &Path) -> Result<Option<Self>, ConflictsError> {
        let malformed = || ConflictsError::Malformed(file.to_path_buf());
        let bytes = match sync_state::read(file, MAX_KEPT_BYTES) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::FileTooLarge => return Err(malformed()),
            Err(error) => return Err(ConflictsError::Io(file.to_path_buf(), error)),
        };
        let mut records = bytes
            .strip_suffix(b"\0")
            .ok_or_else(malformed)?
            .split(|byte| *byte == 0);
        let from = records
            .next()
            .and_then(|from| std::str::from_utf8(from).ok())
            .and_then(|from| from.parse().ok())
            .ok_or_else(malformed)?;
        let before = records
            .next()
            .and_then(|before| ObjectId::from_hex(before).ok())
            .ok_or_else(malformed)?;
        let paths: Vec<Vec<u8>> = records.map(<[u8]>::to_vec).collect();
        if paths.is_empty() || paths.len() > MAX_KEPT_PATHS || paths.iter().any(Vec::is_empty) {
            return Err(malformed());
        }
        Ok(Some(Self {
            from,
            before,
            paths,
        }))
    }

    /// Writes these conflicts to `file`, replacing what it held, in a directory only the user
    /// can use.
    pub(crate) fn save(&self, file: &Path) -> Result<(), ConflictsError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.from.to_string().as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.before.to_hex().to_string().as_bytes());
        bytes.push(0);
        for path in &self.paths {
            bytes.extend_from_slice(path);
            bytes.push(0);
        }
        if self.paths.len() > MAX_KEPT_PATHS || bytes.len() as u64 > MAX_KEPT_BYTES {
            return Err(ConflictsError::TooMany);
        }
        sync_state::write(file, &bytes)
            .map_err(|error| ConflictsError::Io(file.to_path_buf(), error))
    }
}

/// Says whether `line` is a conflict marker of a merge between `slots`: at least seven `<` or
/// `>`, then the label of one of them, alone or followed by `:` and a path.
fn is_marker(line: &[u8], slots: &[Vec<u8>; 2]) -> bool {
    let Some(&first) = line.first().filter(|first| matches!(**first, b'<' | b'>')) else {
        return false;
    };
    let run = line.iter().take_while(|byte| **byte == first).count();
    let Some(label) = line.get(run..).filter(|_| run >= SHORTEST_MARKER) else {
        return false;
    };
    slots.iter().any(|slot| {
        label
            .strip_prefix(slot.as_slice())
            .is_some_and(|rest| rest.is_empty() || rest.first() == Some(&b':'))
    })
}

/// Says whether `into`'s worktree, as its snapshot tree `tree` holds it, has no conflict kept
/// in `file` left unresolved: no file that changed since the tree before the merge, at its
/// path or moved to another, holds a marker of that merge. `file` is removed once they are
/// resolved.
pub(crate) fn resolved(
    store: &Store,
    into: &AgentSlot,
    file: &Path,
    tree: ObjectId,
) -> Result<bool, ConflictsError> {
    let Some(kept) = KeptConflicts::load(file)? else {
        return Ok(true);
    };
    let slots = [into, &kept.from].map(|slot| format!(" {}", label(slot)).into_bytes());
    if store.changed_files_hold(kept.before, tree, &|line| is_marker(line, &slots))? {
        return Ok(false);
    }
    sync_state::remove(file).map_err(|error| ConflictsError::Io(file.to_path_buf(), error))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use mahi_store::EntryKind;

    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path().join("repo")).unwrap();
        let store = Store::open(&dir.path().join("repo")).unwrap();
        (dir, store)
    }

    fn tree(store: &Store, files: &[(&str, &str)]) -> ObjectId {
        let entries: Vec<_> = files
            .iter()
            .map(|(name, text)| {
                (
                    *name,
                    EntryKind::Blob,
                    store.write_blob(text.as_bytes()).unwrap(),
                )
            })
            .collect();
        store.write_tree(&entries).unwrap()
    }

    fn slots() -> (AgentSlot, AgentSlot) {
        (
            "alice.claude".parse().unwrap(),
            "bob.codex".parse().unwrap(),
        )
    }

    const MARKED: &str =
        "<<<<<<< mahi alice.claude\nours\n=======\ntheirs\n>>>>>>> mahi bob.codex\n";

    fn kept_from(file: &Path, before: ObjectId, paths: &[&str]) {
        KeptConflicts::of_merge((&slots().1, before), paths.iter())
            .unwrap()
            .save(file)
            .unwrap();
    }

    #[test]
    fn kept_conflicts_read_back_as_written_and_none_are_kept_without_a_file() {
        let (dir, store) = store();
        let file = dir.path().join("state/sync/alice.claude/conflicts");
        assert_eq!(KeptConflicts::load(&file).unwrap(), None);
        let (_, bob) = slots();
        let before = tree(&store, &[("a.txt", "a\n")]);
        let paths = ["a.txt", "dir/b \n\u{e9}.txt"];
        let kept = KeptConflicts::of_merge((&bob, before), paths.iter()).unwrap();
        kept.save(&file).unwrap();
        assert_eq!(KeptConflicts::load(&file).unwrap(), Some(kept));
        assert_eq!(
            KeptConflicts::of_merge::<&str>((&bob, before), [].iter()),
            None
        );
    }

    #[test]
    fn a_kept_conflicts_file_that_is_not_one_mahi_wrote_is_refused() {
        let (dir, _store) = store();
        let file = dir.path().join("conflicts");
        let tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
        let cases = [
            String::new(),
            "bob.codex".to_owned(),
            "bob.codex\0".to_owned(),
            format!("bob.codex\0{tree}\0"),
            format!("not a slot\0{tree}\0a.txt\0"),
            "bob.codex\0not a tree\0a.txt\0".to_owned(),
            format!("bob.codex\0{tree}\0a.txt\0\0"),
        ];
        for bytes in cases {
            fs::write(&file, &bytes).unwrap();
            assert!(
                matches!(
                    KeptConflicts::load(&file),
                    Err(ConflictsError::Malformed(_))
                ),
                "{bytes:?}"
            );
        }
        fs::write(&file, format!("bob.codex\0{tree}\0a.txt\0")).unwrap();
        assert!(KeptConflicts::load(&file).unwrap().is_some());
    }

    #[test]
    fn conflicts_are_resolved_once_no_file_changed_since_the_merge_holds_its_markers() {
        let (dir, store) = store();
        let file = dir.path().join("sync/alice.claude/conflicts");
        let (alice, _) = slots();
        let before = tree(&store, &[("a.txt", "ours\n"), ("b.txt", "b\n")]);
        kept_from(&file, before, &["a.txt", "b.txt"]);
        let marked = tree(&store, &[("a.txt", MARKED), ("b.txt", MARKED)]);
        assert!(!resolved(&store, &alice, &file, marked).unwrap());
        let one_left = tree(&store, &[("a.txt", "ours and theirs\n"), ("b.txt", MARKED)]);
        assert!(!resolved(&store, &alice, &file, one_left).unwrap());
        let moved = tree(&store, &[("a.txt", "ours\n"), ("elsewhere.txt", MARKED)]);
        assert!(!resolved(&store, &alice, &file, moved).unwrap());
        assert!(file.exists());
        let done = tree(&store, &[("a.txt", "ours and theirs\n")]);
        assert!(resolved(&store, &alice, &file, done).unwrap());
        assert!(!file.exists());
        assert!(resolved(&store, &alice, &file, marked).unwrap());
    }

    #[test]
    fn longer_markers_swapped_sides_and_labels_naming_a_path_still_hold_a_conflict() {
        let (dir, store) = store();
        let file = dir.path().join("conflicts");
        let (alice, _) = slots();
        let before = tree(&store, &[]);
        for text in [
            "<<<<<<<<<< mahi alice.claude\nours\n",
            "<<<<<<< mahi bob.codex:src/b.rs\ntheirs\n",
            "x\n>>>>>>> mahi alice.claude:src/a.rs\r\n",
            ">>>>>>> mahi bob.codex\n",
        ] {
            kept_from(&file, before, &["a.txt"]);
            let marked = tree(&store, &[("a.txt", text)]);
            assert!(
                !resolved(&store, &alice, &file, marked).unwrap(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn markers_of_another_merge_or_another_agent_do_not_hold_a_conflict() {
        let (dir, store) = store();
        let file = dir.path().join("conflicts");
        let (alice, _) = slots();
        let before = tree(&store, &[]);
        for text in [
            "<<<<<<< HEAD\nx\n=======\ny\n>>>>>>> carol.claude\n",
            "<<<<<<< mahi carol.claude\n",
            "<<<<<<< mahi alice.claude2\n",
            "<<<<<< mahi alice.claude\n",
            "x <<<<<<< mahi alice.claude\n",
            "<<<<<<<mahi alice.claude\n",
        ] {
            kept_from(&file, before, &["a.txt"]);
            let other = tree(&store, &[("a.txt", text)]);
            assert!(resolved(&store, &alice, &file, other).unwrap(), "{text:?}");
        }
    }
}
