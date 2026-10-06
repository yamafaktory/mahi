use std::{
    collections::{
        BTreeMap,
        HashMap,
    },
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

use gix::{
    ObjectId,
    object::Kind,
    objs::tree::EntryMode,
};

use crate::{
    snapshot::{
        MAX_SNAPSHOT_DEPTH,
        MAX_SNAPSHOT_FILE_BYTES,
    },
    store::{
        MAX_TREE_BYTES,
        Store,
        StoreError,
    },
};

const MAX_DEPTH: usize = 64;
const MAX_TREES: usize = 65_536;
const MAX_TREE_BYTES_READ: u64 = 32 * 1024 * 1024;
/// The most files a tree that mahi checks out into a worktree may hold.
pub(crate) const MAX_CHECKED_OUT_FILES: usize = 2_000_000;
/// The most bytes of files a tree that mahi checks out into a worktree may hold.
pub(crate) const MAX_CHECKED_OUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_CHECKED_OUT_TREES: usize = 262_144;
const MAX_CHECKED_OUT_TREE_BYTES: u64 = 256 * 1024 * 1024;

/// How a path differs from one tree to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The path is only in the newer tree.
    Added,
    /// The path is only in the older tree.
    Deleted,
    /// The path is in both, with other contents or another mode.
    Modified,
}

/// The paths that differ between two trees, in the order the trees are walked, and whether
/// the list was cut short.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Changes {
    /// Each changed file, `/`-separated, with how it changed.
    pub paths: Vec<(String, Change)>,
    /// Whether more paths changed than were listed.
    pub truncated: bool,
}

struct Walk<'a> {
    store: &'a Store,
    limit: usize,
    trees: usize,
    bytes: u64,
    most_trees: usize,
    most_bytes: u64,
    changes: Changes,
}

type Entries = BTreeMap<Vec<u8>, (EntryMode, ObjectId)>;

#[derive(Debug, Clone, Copy)]
struct Counted {
    files: usize,
    bytes: u64,
    dirs: usize,
    height: usize,
}

#[derive(Debug, Clone, Copy)]
struct Budget<'a> {
    files: usize,
    bytes: u64,
    interrupt: &'a AtomicBool,
}

impl Store {
    /// Returns the files that differ between the trees `old` and `new`, at most `limit` of
    /// them, descending only into subtrees whose ids differ; a directory's files come before
    /// a file of the same name. Every tree is size-checked before it is loaded; past 64
    /// levels, 65,536 trees or 32 MiB of trees read in all, the list is marked cut short.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::WrongObject`] if either is not a tree, [`StoreError::TooLarge`] if
    /// a tree is larger than 1 MiB, [`StoreError::DuplicateEntryName`] if a tree names an entry
    /// twice, or [`StoreError::Git`] if reading fails.
    pub fn changed_paths(
        &self,
        old: ObjectId,
        new: ObjectId,
        limit: usize,
    ) -> Result<Changes, StoreError> {
        let mut walk = Walk {
            store: self,
            limit,
            trees: 0,
            bytes: 0,
            most_trees: MAX_TREES,
            most_bytes: MAX_TREE_BYTES_READ,
            changes: Changes::default(),
        };
        walk.compare(Some(old), Some(new), "", 0)?;
        Ok(walk.changes)
    }

    /// Returns whether checking `tree` out would write at most `most_files` files (gitlinks
    /// included) and `most_bytes` bytes and 262,144 directories, counting a subtree's files and
    /// directories each time it is named, with no file over [`MAX_SNAPSHOT_FILE_BYTES`] and no
    /// directory deeper than [`MAX_SNAPSHOT_DEPTH`], within 262,144 distinct trees and 256 MiB
    /// of them read, so a small tree that names the same subtrees or blobs over and over, even
    /// empty ones or ones holding only gitlinks, cannot stand for millions of entries or a full
    /// disk. Each distinct tree is read once.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TooLarge`] if a tree is larger than 1 MiB,
    /// [`StoreError::DuplicateEntryName`] if a tree names an entry twice,
    /// [`StoreError::WrongObject`] if an entry's object is not of its mode's kind,
    /// [`StoreError::Interrupted`] if `interrupt` is set, or [`StoreError::Git`] if reading
    /// fails.
    pub(crate) fn fits_checkout(
        &self,
        tree: ObjectId,
        (most_files, most_bytes): (usize, u64),
        interrupt: &AtomicBool,
    ) -> Result<bool, StoreError> {
        let mut walk = Walk {
            store: self,
            limit: 0,
            trees: 0,
            bytes: 0,
            most_trees: MAX_CHECKED_OUT_TREES,
            most_bytes: MAX_CHECKED_OUT_TREE_BYTES,
            changes: Changes::default(),
        };
        let mut counted = HashMap::new();
        let budget = Budget {
            files: most_files,
            bytes: most_bytes,
            interrupt,
        };
        Ok(walk.count(tree, 0, &mut counted, budget)?.is_some())
    }
}

impl Walk<'_> {
    fn entries(&mut self, tree: Option<ObjectId>) -> Result<Option<Entries>, StoreError> {
        let Some(tree) = tree else {
            return Ok(Some(Entries::new()));
        };
        let size = self.store.bounded_size(tree, Kind::Tree, MAX_TREE_BYTES)?;
        if self.trees >= self.most_trees || self.bytes.saturating_add(size) > self.most_bytes {
            return Ok(None);
        }
        self.trees += 1;
        self.bytes += size;
        let mut entries = Entries::new();
        for entry in self.store.repo.find_tree(tree)?.iter() {
            let entry = entry.map_err(gix::Error::from)?;
            let name = entry.filename().to_vec();
            if entries.contains_key(&name) {
                return Err(StoreError::DuplicateEntryName(
                    String::from_utf8_lossy(&name).into_owned(),
                ));
            }
            entries.insert(name, (entry.mode(), entry.object_id()));
        }
        Ok(Some(entries))
    }

    fn count(
        &mut self,
        tree: ObjectId,
        depth: usize,
        counted: &mut HashMap<ObjectId, Counted>,
        budget: Budget<'_>,
    ) -> Result<Option<Counted>, StoreError> {
        if budget.interrupt.load(Ordering::Relaxed) {
            return Err(StoreError::Interrupted);
        }
        if let Some(&seen) = counted.get(&tree) {
            return Ok((depth + seen.height <= MAX_SNAPSHOT_DEPTH + 1).then_some(seen));
        }
        if depth > MAX_SNAPSHOT_DEPTH {
            return Ok(None);
        }
        let Some(entries) = self.entries(Some(tree))? else {
            return Ok(None);
        };
        let mut sum = Counted {
            files: 0,
            bytes: 0,
            dirs: 1,
            height: 1,
        };
        for (mode, id) in entries.values() {
            if mode.is_tree() {
                let Some(below) = self.count(*id, depth + 1, counted, budget)? else {
                    return Ok(None);
                };
                sum.files = sum.files.saturating_add(below.files);
                sum.bytes = sum.bytes.saturating_add(below.bytes);
                sum.dirs = sum.dirs.saturating_add(below.dirs);
                sum.height = sum.height.max(below.height + 1);
            } else if mode.is_commit() {
                sum.files += 1;
            } else {
                let size = match self
                    .store
                    .bounded_size(*id, Kind::Blob, MAX_SNAPSHOT_FILE_BYTES)
                {
                    Ok(size) => size,
                    Err(StoreError::TooLarge { .. }) => return Ok(None),
                    Err(error) => return Err(error),
                };
                sum.files += 1;
                sum.bytes = sum.bytes.saturating_add(size);
            }
            if sum.files > budget.files
                || sum.bytes > budget.bytes
                || sum.dirs > MAX_CHECKED_OUT_TREES
            {
                return Ok(None);
            }
        }
        counted.insert(tree, sum);
        Ok(Some(sum))
    }

    fn full(&self) -> bool {
        self.changes.truncated
    }

    fn push(&mut self, path: String, change: Change) {
        if self.changes.paths.len() >= self.limit {
            self.changes.truncated = true;
        } else {
            self.changes.paths.push((path, change));
        }
    }

    fn compare(
        &mut self,
        old: Option<ObjectId>,
        new: Option<ObjectId>,
        prefix: &str,
        depth: usize,
    ) -> Result<(), StoreError> {
        if depth >= MAX_DEPTH {
            self.changes.truncated = true;
            return Ok(());
        }
        let (Some(before), Some(after)) = (self.entries(old)?, self.entries(new)?) else {
            self.changes.truncated = true;
            return Ok(());
        };
        let mut olds = before.keys().peekable();
        let mut news = after.keys().peekable();
        loop {
            let name = match (olds.peek(), news.peek()) {
                (Some(old), Some(new)) if old < new => olds.next(),
                (Some(old), Some(new)) if old == new => {
                    news.next();
                    olds.next()
                }
                (_, Some(_)) => news.next(),
                (Some(_), None) => olds.next(),
                (None, None) => None,
            };
            let Some(name) = name else {
                break;
            };
            if self.full() {
                return Ok(());
            }
            let old_entry = before.get(name).copied();
            let new_entry = after.get(name).copied();
            if old_entry == new_entry {
                continue;
            }
            let path = if prefix.is_empty() {
                String::from_utf8_lossy(name).into_owned()
            } else {
                format!("{prefix}/{}", String::from_utf8_lossy(name))
            };
            let subtree = |entry: Option<(EntryMode, ObjectId)>| {
                entry.filter(|(mode, _)| mode.is_tree()).map(|(_, id)| id)
            };
            let file =
                |entry: Option<(EntryMode, ObjectId)>| entry.filter(|(mode, _)| !mode.is_tree());
            let (old_tree, new_tree) = (subtree(old_entry), subtree(new_entry));
            if old_tree.is_some() || new_tree.is_some() {
                self.compare(old_tree, new_tree, &path, depth + 1)?;
            }
            match (file(old_entry), file(new_entry)) {
                (Some(_), Some(_)) => self.push(path, Change::Modified),
                (Some(_), None) => self.push(path, Change::Deleted),
                (None, Some(_)) => self.push(path, Change::Added),
                (None, None) => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gix::objs::tree::EntryKind;
    use tempfile::TempDir;

    use super::*;

    fn store() -> (TempDir, Store) {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn changed_files_are_listed_down_to_the_first_difference() {
        let (_dir, store) = store();
        let blob = |text: &str| store.write_blob(text.as_bytes()).unwrap();
        let same = store
            .write_tree(&[("keep", EntryKind::Blob, blob("k"))])
            .unwrap();
        let src_old = store
            .write_tree(&[
                ("a.rs", EntryKind::Blob, blob("a")),
                ("gone.rs", EntryKind::Blob, blob("g")),
            ])
            .unwrap();
        let src_new = store
            .write_tree(&[
                ("a.rs", EntryKind::Blob, blob("a2")),
                ("new.rs", EntryKind::Blob, blob("n")),
            ])
            .unwrap();
        let old = store
            .write_tree(&[
                ("README", EntryKind::Blob, blob("r")),
                ("same", EntryKind::Tree, same),
                ("src", EntryKind::Tree, src_old),
                ("was-file", EntryKind::Blob, blob("f")),
            ])
            .unwrap();
        let now_dir = store
            .write_tree(&[("inside", EntryKind::Blob, blob("i"))])
            .unwrap();
        let new = store
            .write_tree(&[
                ("README", EntryKind::Blob, blob("r")),
                ("same", EntryKind::Tree, same),
                ("script", EntryKind::BlobExecutable, blob("s")),
                ("src", EntryKind::Tree, src_new),
                ("was-file", EntryKind::Tree, now_dir),
            ])
            .unwrap();
        let changes = store.changed_paths(old, new, 100).unwrap();
        assert_eq!(
            changes.paths,
            [
                ("script".to_owned(), Change::Added),
                ("src/a.rs".to_owned(), Change::Modified),
                ("src/gone.rs".to_owned(), Change::Deleted),
                ("src/new.rs".to_owned(), Change::Added),
                ("was-file/inside".to_owned(), Change::Added),
                ("was-file".to_owned(), Change::Deleted),
            ]
        );
        assert!(!changes.truncated);
        let cut = store.changed_paths(old, new, 2).unwrap();
        assert_eq!(cut.paths.len(), 2);
        assert!(cut.truncated);
        assert_eq!(
            store.changed_paths(old, old, 10).unwrap(),
            Changes::default()
        );
        assert!(matches!(
            store.changed_paths(blob("x"), new, 10),
            Err(StoreError::WrongObject { .. })
        ));
    }

    #[test]
    fn mode_and_submodule_changes_count_and_duplicate_names_are_refused() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        let old = store
            .write_tree(&[
                ("run", EntryKind::Blob, blob),
                ("sub", EntryKind::Commit, blob),
            ])
            .unwrap();
        let other = ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap();
        let new = store
            .write_tree(&[
                ("run", EntryKind::BlobExecutable, blob),
                ("sub", EntryKind::Commit, other),
            ])
            .unwrap();
        assert_eq!(
            store.changed_paths(old, new, 10).unwrap().paths,
            [
                ("run".to_owned(), Change::Modified),
                ("sub".to_owned(), Change::Modified),
            ]
        );
        let mut twice = Vec::new();
        for _ in 0..2 {
            twice.extend_from_slice(b"100644 a\0");
            twice.extend_from_slice(blob.as_bytes());
        }
        let duplicated =
            gix::objs::Write::write_buf(&store.repo.objects, Kind::Tree, &twice).unwrap();
        assert!(matches!(
            store.changed_paths(old, duplicated, 10),
            Err(StoreError::DuplicateEntryName(_))
        ));
    }

    #[test]
    fn one_large_subtree_named_many_times_stops_at_the_read_budget() {
        let (_dir, store) = store();
        let empty = store.write_tree(&[]).unwrap();
        let names: Vec<String> = (0..20_000).map(|index| format!("d{index:05}")).collect();
        let wide: Vec<(&str, EntryKind, ObjectId)> = names
            .iter()
            .map(|name| (name.as_str(), EntryKind::Tree, empty))
            .collect();
        let large = store.write_tree(&wide).unwrap();
        let many: Vec<(&str, EntryKind, ObjectId)> = names
            .iter()
            .take(200)
            .map(|name| (name.as_str(), EntryKind::Tree, large))
            .collect();
        let root = store.write_tree(&many).unwrap();
        let changes = store.changed_paths(empty, root, 10).unwrap();
        assert!(changes.paths.is_empty());
        assert!(changes.truncated);
    }
}
