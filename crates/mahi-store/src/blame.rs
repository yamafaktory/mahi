use gix::{
    ObjectId,
    bstr::BStr,
    config::tree::Core,
    diff::{
        Rewrites,
        blob::Algorithm,
    },
    repository::blame_file,
};

use crate::{
    diff::{
        Found,
        MAX_DIFFED_BYTES,
    },
    store::{
        Store,
        StoreError,
    },
};

/// What blaming a line of a file found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blamed {
    /// The commit that last changed the line.
    Commit(ObjectId),
    /// The file has no such line.
    NoLine,
    /// No file is at the path.
    Missing,
    /// The path names a directory, a link or a submodule, or holds an empty, `.` or `..` part.
    NotAFile,
    /// The file is larger than [`MAX_DIFFED_BYTES`].
    TooLarge,
}

impl Store {
    /// Returns the commit that last changed line `line`, counted from 1, of the file at `path`,
    /// `/`-separated, in the commit `at`, following renames. A file larger than
    /// [`MAX_DIFFED_BYTES`] in `at` is not blamed, and an earlier version that large counts as
    /// empty, so its lines are blamed on the commit that made the file smaller.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `at` or its history cannot be read.
    pub fn line_commit(&self, at: ObjectId, path: &str, line: u32) -> Result<Blamed, StoreError> {
        match self.file_at(self.commit_tree(at)?, path, MAX_DIFFED_BYTES)? {
            Found::File(_, mode) if mode.is_blob() => {}
            Found::File(..) | Found::NotAFile => return Ok(Blamed::NotAFile),
            Found::Missing => return Ok(Blamed::Missing),
            Found::TooLarge => return Ok(Blamed::TooLarge),
        }
        let Ok(ranges) = gix::blame::BlameRanges::from_one_based_inclusive_range(line..=line)
        else {
            return Ok(Blamed::NoLine);
        };
        let mut repo = self.repo.clone();
        let mut config = repo.config_snapshot_mut();
        config.set_value(&Core::BIG_FILE_THRESHOLD, MAX_DIFFED_BYTES.to_string())?;
        config.commit()?;
        let outcome = repo.blame_file(
            BStr::new(path),
            at,
            blame_file::Options {
                diff_algorithm: Some(Algorithm::Histogram),
                ranges,
                since: None,
                rewrites: Some(Rewrites::default()),
            },
        )?;
        Ok(outcome
            .entries
            .first()
            .map_or(Blamed::NoLine, |entry| Blamed::Commit(entry.commit_id)))
    }
}

#[cfg(test)]
mod tests {
    use gix::{
        objs::Commit,
        refs::transaction::PreviousValue,
    };

    use super::*;
    use crate::{
        EntryKind,
        store::{
            generic_signature,
            tests::{
                store,
                tree_of,
            },
        },
    };

    fn commit(store: &Store, parent: Option<ObjectId>, text: &[u8], message: &str) -> ObjectId {
        commit_at(store, parent, ("src/lib.rs", text), message)
    }

    fn commit_at(
        store: &Store,
        parent: Option<ObjectId>,
        (path, text): (&str, &[u8]),
        message: &str,
    ) -> ObjectId {
        let commit = Commit {
            tree: tree_of(store, &[(path, EntryKind::Blob, text)]),
            parents: parent.into_iter().collect(),
            author: generic_signature(),
            committer: generic_signature(),
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        };
        let id = store.repo.write_object(&commit).unwrap().detach();
        store
            .repo
            .reference("refs/heads/main", id, PreviousValue::Any, "test")
            .unwrap();
        id
    }

    #[test]
    fn each_line_leads_to_the_commit_that_last_changed_it() {
        let (_dir, store) = store();
        let first = commit(&store, None, b"one\ntwo\nthree\n", "first");
        let second = commit(&store, Some(first), b"one\n2\nthree\nfour\n", "second");
        let path = "src/lib.rs";
        assert_eq!(
            store.line_commit(second, path, 1).unwrap(),
            Blamed::Commit(first)
        );
        assert_eq!(
            store.line_commit(second, path, 2).unwrap(),
            Blamed::Commit(second)
        );
        assert_eq!(
            store.line_commit(second, path, 3).unwrap(),
            Blamed::Commit(first)
        );
        assert_eq!(
            store.line_commit(second, path, 4).unwrap(),
            Blamed::Commit(second)
        );
        assert_eq!(
            store.line_commit(first, path, 2).unwrap(),
            Blamed::Commit(first)
        );
    }

    #[test]
    fn a_line_past_the_end_line_zero_or_a_path_that_is_no_file_is_told_apart() {
        let (_dir, store) = store();
        let only = commit(&store, None, b"one\n", "only");
        let path = "src/lib.rs";
        assert_eq!(store.line_commit(only, path, 0).unwrap(), Blamed::NoLine);
        assert_eq!(store.line_commit(only, path, 2).unwrap(), Blamed::NoLine);
        assert_eq!(
            store.line_commit(only, "src/gone.rs", 1).unwrap(),
            Blamed::Missing
        );
        for not_a_file in ["src", "src/../src/lib.rs", "/src/lib.rs", "src//lib.rs"] {
            assert_eq!(
                store.line_commit(only, not_a_file, 1).unwrap(),
                Blamed::NotAFile,
                "{not_a_file}"
            );
        }
    }

    #[test]
    fn a_file_larger_than_a_diff_reads_is_not_blamed() {
        let (_dir, store) = store();
        let large = vec![b'x'; usize::try_from(MAX_DIFFED_BYTES).unwrap() + 1];
        let big = commit(&store, None, &large, "big");
        assert_eq!(
            store.line_commit(big, "src/lib.rs", 1).unwrap(),
            Blamed::TooLarge
        );
    }

    #[test]
    fn an_earlier_version_larger_than_a_diff_reads_counts_as_empty() {
        let (_dir, store) = store();
        let mut large = b"keep\n".to_vec();
        large.resize(usize::try_from(MAX_DIFFED_BYTES).unwrap() + 1, b'x');
        let big = commit(&store, None, &large, "big");
        let trimmed = commit(&store, Some(big), b"keep\n", "trimmed");
        assert_eq!(
            store.line_commit(trimmed, "src/lib.rs", 1).unwrap(),
            Blamed::Commit(trimmed)
        );
    }

    #[test]
    fn a_renamed_file_leads_back_to_the_commit_that_wrote_its_lines() {
        let (_dir, store) = store();
        let text: &[u8] = b"one\ntwo\nthree\nfour\nfive\nsix\n";
        let wrote = commit_at(&store, None, ("src/a.rs", text), "wrote");
        let moved = commit_at(&store, Some(wrote), ("src/b.rs", text), "moved");
        assert_eq!(
            store.line_commit(moved, "src/b.rs", 3).unwrap(),
            Blamed::Commit(wrote)
        );
    }
}
