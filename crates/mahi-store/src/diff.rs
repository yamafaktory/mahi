use gix::{
    ObjectId,
    object::Kind,
    objs::tree::EntryMode,
};
use gix_imara_diff::{
    Algorithm,
    BasicLineDiffPrinter,
    Diff,
    InternedInput,
    UnifiedDiffConfig,
};

use crate::store::{
    MAX_TREE_BYTES,
    Store,
    StoreError,
};

/// The largest file a diff reads, in bytes.
pub const MAX_DIFFED_BYTES: u64 = 1024 * 1024;
const MAX_PATH_DEPTH: usize = 64;

/// How one file differs between two trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDiff {
    /// The file is the same in both, or in neither.
    Same,
    /// The lines that differ, as a unified diff.
    Text(String),
    /// The file is not text in one of the trees.
    Binary,
    /// The file is larger than [`MAX_DIFFED_BYTES`] in one of the trees.
    TooLarge,
    /// The path names something other than a file, or is not a valid path.
    NotAFile,
}

fn as_text(found: &Found) -> Result<Option<&str>, FileDiff> {
    match found {
        Found::File(bytes, _) if bytes.contains(&0) => Err(FileDiff::Binary),
        Found::File(bytes, _) => std::str::from_utf8(bytes)
            .map(Some)
            .map_err(|_| FileDiff::Binary),
        Found::Missing => Ok(None),
        Found::TooLarge => Err(FileDiff::TooLarge),
        Found::NotAFile => Err(FileDiff::NotAFile),
    }
}

enum Found {
    File(Vec<u8>, EntryMode),
    Missing,
    TooLarge,
    NotAFile,
}

impl Store {
    /// Returns how the file at `path`, `/`-separated, differs from the tree `old` to the tree
    /// `new`. Every tree on the way is size-checked before it is loaded, and a file larger than
    /// [`MAX_DIFFED_BYTES`] is not read.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TooLarge`] if a tree on the way is larger than 1 MiB, or
    /// [`StoreError::Git`] if reading fails.
    pub fn file_diff(
        &self,
        old: ObjectId,
        new: ObjectId,
        path: &str,
    ) -> Result<FileDiff, StoreError> {
        let (before, after) = (self.file_at(old, path)?, self.file_at(new, path)?);
        let (before_text, after_text) = match (as_text(&before), as_text(&after)) {
            (Err(why), _) | (_, Err(why)) => return Ok(why),
            (Ok(before), Ok(after)) => (before, after),
        };
        if before_text.is_none() && after_text.is_none() {
            return Ok(FileDiff::Same);
        }
        let side = |found: &Found, prefix: &str| match found {
            Found::File(..) => format!("{prefix}/{path}"),
            _ => "/dev/null".to_owned(),
        };
        let header = format!("--- {}\n+++ {}\n", side(&before, "a"), side(&after, "b"));
        let (before_text, after_text) = (before_text.unwrap_or(""), after_text.unwrap_or(""));
        if before_text == after_text {
            let note = match (&before, &after) {
                (Found::File(_, old_mode), Found::File(_, new_mode)) if old_mode == new_mode => {
                    return Ok(FileDiff::Same);
                }
                (Found::File(..), Found::File(..)) => "(only the file's mode changed)\n",
                _ => "(an empty file)\n",
            };
            return Ok(FileDiff::Text(header + note));
        }
        let input = InternedInput::new(before_text, after_text);
        let mut diff = Diff::compute(Algorithm::Histogram, &input);
        diff.postprocess_lines(&input);
        let printer = BasicLineDiffPrinter(&input.interner);
        let hunks = diff.unified_diff(&printer, UnifiedDiffConfig::default(), &input);
        Ok(FileDiff::Text(format!("{header}{hunks}")))
    }

    fn file_at(&self, tree: ObjectId, path: &str) -> Result<Found, StoreError> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() > MAX_PATH_DEPTH || parts.iter().any(|part| matches!(*part, "" | "." | ".."))
        {
            return Ok(Found::NotAFile);
        }
        let mut current = tree;
        for (index, part) in parts.iter().enumerate() {
            self.bounded_size(current, Kind::Tree, MAX_TREE_BYTES)?;
            let found = self.repo.find_tree(current)?;
            let Some(entry) = found.find_entry(*part) else {
                return Ok(Found::Missing);
            };
            let (mode, id) = (entry.mode(), entry.object_id());
            if index + 1 < parts.len() {
                if !mode.is_tree() {
                    return Ok(Found::Missing);
                }
                current = id;
                continue;
            }
            if !mode.is_blob_or_symlink() {
                return Ok(Found::NotAFile);
            }
            return Ok(match self.read_blob(id, MAX_DIFFED_BYTES) {
                Ok(bytes) => Found::File(bytes, mode),
                Err(StoreError::TooLarge { .. }) => Found::TooLarge,
                Err(StoreError::WrongObject { .. }) => Found::NotAFile,
                Err(error) => return Err(error),
            });
        }
        Ok(Found::NotAFile)
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

    fn nested(store: &Store, text: &[u8]) -> ObjectId {
        let file = store.write_blob(text).unwrap();
        let inner = store
            .write_tree(&[("lib.rs", EntryKind::Blob, file)])
            .unwrap();
        store
            .write_tree(&[("src", EntryKind::Tree, inner)])
            .unwrap()
    }

    #[test]
    fn a_changed_file_gives_a_unified_diff_of_its_lines() {
        let (_dir, store) = store();
        let old = nested(&store, b"one\ntwo\nthree\n");
        let new = nested(&store, b"one\n2\nthree\nfour\n");
        let FileDiff::Text(text) = store.file_diff(old, new, "src/lib.rs").unwrap() else {
            panic!("no diff");
        };
        assert!(
            text.starts_with("--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ "),
            "{text}"
        );
        assert!(text.contains("-two\n+2\n"), "{text}");
        assert!(text.contains("+four\n"), "{text}");
        assert_eq!(
            store.file_diff(old, old, "src/lib.rs").unwrap(),
            FileDiff::Same
        );
        assert_eq!(
            store.file_diff(old, new, "src/none.rs").unwrap(),
            FileDiff::Same
        );
        let empty = store.write_tree(&[]).unwrap();
        let FileDiff::Text(added) = store.file_diff(empty, new, "src/lib.rs").unwrap() else {
            panic!("no diff");
        };
        assert!(added.contains("+one\n+2\n"), "{added}");
    }

    #[test]
    fn binary_large_odd_or_missing_paths_are_said_rather_than_diffed() {
        let (_dir, store) = store();
        let old = nested(&store, b"text\n");
        let binary = nested(&store, b"bin\0ary");
        assert_eq!(
            store.file_diff(old, binary, "src/lib.rs").unwrap(),
            FileDiff::Binary
        );
        let large = nested(
            &store,
            &vec![b'a'; usize::try_from(MAX_DIFFED_BYTES).unwrap() + 1],
        );
        assert_eq!(
            store.file_diff(old, large, "src/lib.rs").unwrap(),
            FileDiff::TooLarge
        );
        for path in ["src", "src/../src/lib.rs", "/src/lib.rs", "src//lib.rs", ""] {
            assert_eq!(
                store.file_diff(old, binary, path).unwrap(),
                FileDiff::NotAFile,
                "{path}"
            );
        }
        assert_eq!(
            store.file_diff(old, binary, "src/lib.rs/x").unwrap(),
            FileDiff::Same
        );
    }

    #[test]
    fn an_added_or_deleted_empty_file_and_a_mode_change_are_not_the_same() {
        let (_dir, store) = store();
        let empty_tree = store.write_tree(&[]).unwrap();
        let empty = store.write_blob(b"").unwrap();
        let script = store.write_blob(b"echo\n").unwrap();
        let with_empty = store.write_tree(&[("e", EntryKind::Blob, empty)]).unwrap();
        assert_eq!(
            store.file_diff(empty_tree, with_empty, "e").unwrap(),
            FileDiff::Text("--- /dev/null\n+++ b/e\n(an empty file)\n".to_owned())
        );
        assert_eq!(
            store.file_diff(with_empty, empty_tree, "e").unwrap(),
            FileDiff::Text("--- a/e\n+++ /dev/null\n(an empty file)\n".to_owned())
        );
        let plain = store
            .write_tree(&[("run", EntryKind::Blob, script)])
            .unwrap();
        let executable = store
            .write_tree(&[("run", EntryKind::BlobExecutable, script)])
            .unwrap();
        assert_eq!(
            store.file_diff(plain, executable, "run").unwrap(),
            FileDiff::Text("--- a/run\n+++ b/run\n(only the file's mode changed)\n".to_owned())
        );
        let FileDiff::Text(added) = store.file_diff(empty_tree, plain, "run").unwrap() else {
            panic!("no diff");
        };
        assert!(added.starts_with("--- /dev/null\n+++ b/run\n@@"), "{added}");
    }
}
