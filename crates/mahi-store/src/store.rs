use std::{
    collections::HashSet,
    path::Path,
};

use gix::{
    ObjectId,
    Repository,
    actor::Signature,
    date::Time,
    object::Kind,
    objs::{
        Commit,
        Tree,
        tree::{
            Entry,
            EntryKind,
        },
    },
    refs::{
        FullName,
        Target,
        transaction::{
            Change,
            LogChange,
            PreviousValue,
            RefEdit,
            RefLog,
        },
    },
};
use gix_validate::path::component::{
    self,
    Mode,
};
use mahi_core::{
    THREADS_PREFIX,
    ThreadRef,
};
use mahi_crypto::{
    SealError,
    ThreadKey,
};
use thiserror::Error;

/// The committer and author name on every thread commit.
pub const COMMITTER_NAME: &str = "mahi";
/// The committer and author email on every thread commit.
pub const COMMITTER_EMAIL: &str = "mahi@mahi.invalid";

const MAX_ENTRY_NAME_BYTES: usize = 255;
const MAX_COMMIT_BYTES: u64 = 64 * 1024;
const MAX_TREE_BYTES: u64 = 1024 * 1024;
const DISABLE_REFLOG: &str = "core.logAllRefUpdates=false";
const REF_LOCK_TIMEOUT: &str = "core.filesRefLockTimeout=5000";

/// The project's git repository, seen through the objects and refs mahi writes.
#[derive(Debug)]
pub struct Store {
    pub(crate) repo: Repository,
}

/// A store operation failed.
#[derive(Debug, Error)]
pub enum StoreError {
    /// git reported an error.
    #[error("git operation failed")]
    Git(#[from] gix::Error),
    /// Sealing content failed.
    #[error("cannot seal content")]
    Seal(#[from] SealError),
    /// A thread ref does not point where the caller expected, because someone else moved it.
    #[error("{name} moved since it was last read")]
    Conflict {
        /// The ref that moved.
        name: String,
        /// Where the caller expected the ref to point.
        expected: Option<ObjectId>,
        /// Where the ref points now.
        found: Option<ObjectId>,
    },
    /// A commit has several parents, which mahi's linear histories never have.
    #[error("commit {0} has several parents")]
    NotLinear(ObjectId),
    /// A thread ref is symbolic, which mahi never writes.
    #[error("{0} is a symbolic ref")]
    Symbolic(String),
    /// An object is larger than the caller's limit.
    #[error("object {id} is larger than {limit} bytes")]
    TooLarge {
        /// The object.
        id: ObjectId,
        /// The limit that was exceeded, in bytes.
        limit: u64,
    },
    /// A tree entry name is longer than 255 bytes, or is one git refuses to check out, such as
    /// `..`, `.git` or a name that some file system reads as `.git`.
    #[error("invalid tree entry name {0:?}")]
    InvalidEntryName(String),
    /// An object is missing, or is not the kind it is used as.
    #[error("object {id} is missing or is not a {expected}")]
    WrongObject {
        /// The object.
        id: ObjectId,
        /// The kind it was expected to be.
        expected: Kind,
    },
    /// A worktree name is not a safe directory name.
    #[error("invalid worktree name {0:?}")]
    InvalidWorktreeName(String),
    /// A worktree path or name is already taken.
    #[error("{} already exists", .0.display())]
    WorktreeExists(std::path::PathBuf),
    /// Reading or writing the file system failed.
    #[error("file system operation failed")]
    Io(#[from] std::io::Error),
    /// A worktree path contains a newline, which git's worktree files cannot hold.
    #[error("worktree path {} contains a newline", .0.display())]
    InvalidWorktreePath(std::path::PathBuf),
    /// The name is not a linked worktree of this repository, or its recorded directory is not
    /// where the worktree now is.
    #[error("{0:?} is not a worktree of this repository")]
    NotAWorktree(String),
    /// A directory is where a lost worktree would be rebuilt, but it is not linked to this
    /// repository; it has to be moved or removed by hand.
    #[error("{} is not linked to this repository; move or remove it", .0.display())]
    WorktreeUnlinked(std::path::PathBuf),
    /// A path changed while it was being read; snapshot again.
    #[error("{0} changed while it was read")]
    ChangedDuringSnapshot(gix::bstr::BString),
    /// The operation stopped because it was asked to.
    #[error("interrupted")]
    Interrupted,
    /// `HEAD` points to no commit yet.
    #[error("the repository has no commit yet")]
    NoCommit,
    /// The branch `HEAD` is on has a name that is not UTF-8.
    #[error("the branch name {0:?} is not UTF-8")]
    NonUtf8Branch(gix::bstr::BString),
    /// Checking files out into a worktree failed.
    #[error("cannot check out worktree")]
    Checkout(#[source] gix::Error),
    /// A file in the tree could not be written, or collides with another.
    #[error("cannot check out {0:?}")]
    CheckoutPath(String),
    /// More refs were fetched than mahi accepts at once.
    #[error("{0} refs were fetched, more than mahi accepts")]
    TooManyRefs(usize),
    /// A history is longer than mahi walks.
    #[error("the history of {0} is longer than mahi walks")]
    HistoryTooLong(ObjectId),
    /// A thread ref would move to a commit that does not descend from where it is.
    #[error("{0} would not move forward")]
    NotFastForward(String),
    /// Two tree entries have the same name.
    #[error("duplicate tree entry name {0:?}")]
    DuplicateEntryName(String),
}

impl Store {
    /// Opens the git repository at `path`.
    ///
    /// Reflogs are disabled for everything this store writes, whatever the repository's
    /// configuration says, so a purge never has reflog entries to chase. A writer waits up to
    /// five seconds for another writer's ref lock.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Git`] if `path` is not a git repository.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            repo: gix::open_opts(path, open_options())?,
        })
    }

    /// Opens the git repository that holds `path`, looking in `path` and then in each parent
    /// directory, as git does, without crossing into another file system. Git's environment
    /// variables such as `GIT_DIR` and `GIT_CEILING_DIRECTORIES` are not read. A repository
    /// owned by another user is refused, as git refuses it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Git`] if no repository holds `path` or it is owned by another user.
    pub fn discover(path: &Path) -> Result<Self, StoreError> {
        let trust = gix::sec::trust::Mapping {
            full: open_options(),
            reduced: open_options(),
        };
        let options = gix::discover::upwards::Options {
            trust: gix::discover::upwards::TrustPolicy::Required(gix::sec::Trust::Full),
            ..gix::discover::upwards::Options::default()
        };
        let repo = gix::ThreadSafeRepository::discover_opts(path, options, trust)?;
        Ok(Self {
            repo: repo.to_thread_local(),
        })
    }

    /// Returns the commit `HEAD` points to.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NoCommit`] if `HEAD` has no commit yet, as in a new repository,
    /// or [`StoreError::Git`] if it cannot be read.
    pub fn head_commit(&self) -> Result<ObjectId, StoreError> {
        let mut head = self.repo.head()?;
        if head.is_unborn() {
            return Err(StoreError::NoCommit);
        }
        Ok(head.peel_to_commit()?.id)
    }

    /// Returns the short name of the local branch `HEAD` is on, even before its first commit,
    /// or `None` if `HEAD` is detached or points to something other than a local branch.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NonUtf8Branch`] if the branch name is not UTF-8, or
    /// [`StoreError::Git`] if `HEAD` cannot be read.
    pub fn head_branch(&self) -> Result<Option<String>, StoreError> {
        let Some(name) = self.repo.head_name()? else {
            return Ok(None);
        };
        if name.category() != Some(gix::refs::Category::LocalBranch) {
            return Ok(None);
        }
        let short = name.shorten();
        let text = std::str::from_utf8(short.as_ref())
            .map_err(|_| StoreError::NonUtf8Branch(short.to_owned()))?;
        Ok(Some(text.to_owned()))
    }

    /// Returns the commit `thread_ref` points to, or `None` if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Symbolic`] if the ref is symbolic, or [`StoreError::Git`] if it
    /// cannot be read.
    pub fn head(&self, thread_ref: &ThreadRef) -> Result<Option<ObjectId>, StoreError> {
        let name = thread_ref.to_string();
        let Some(reference) = self.repo.try_find_reference(name.as_str())? else {
            return Ok(None);
        };
        reference
            .target()
            .try_id()
            .map(|id| Some(id.to_owned()))
            .ok_or(StoreError::Symbolic(name))
    }

    /// Lists the thread refs in the repository, in name order, with the object each points to.
    ///
    /// Refs under `refs/threads/` that do not follow the thread layout, or that are symbolic,
    /// are left out, since anything may have been pushed there.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Git`] if the refs cannot be read.
    pub fn thread_refs(&self) -> Result<Vec<(ThreadRef, ObjectId)>, StoreError> {
        let platform = self.repo.references().map_err(gix::Error::from_error)?;
        let mut refs = Vec::new();
        for reference in platform
            .prefixed(THREADS_PREFIX)
            .map_err(gix::Error::from_error)?
        {
            let reference = reference.map_err(gix::Error::from_error)?;
            let Ok(name) = std::str::from_utf8(reference.name().as_bstr()) else {
                continue;
            };
            let target = reference.target();
            let (Ok(thread_ref), Some(id)) = (name.parse::<ThreadRef>(), target.try_id()) else {
                continue;
            };
            refs.push((thread_ref, id.to_owned()));
        }
        refs.sort();
        Ok(refs)
    }

    /// Returns the repository's common git directory, shared by all its worktrees.
    #[must_use]
    pub fn common_dir(&self) -> &Path {
        self.repo.common_dir()
    }

    /// Reads the blob named `name` at the top of `commit`'s tree, or `None` if there is none.
    ///
    /// Every object on the way is size-checked from its header before it is loaded: the commit
    /// against 64 KiB, its tree against 1 MiB, and the blob against `max_len`. A packed object
    /// stored as a delta may still inflate its bases while it is decoded.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::WrongObject`] if `commit` is not a commit or the entry is not a
    /// blob, [`StoreError::TooLarge`] if an object is over its limit, or [`StoreError::Git`] if
    /// reading fails.
    pub fn read_entry(
        &self,
        commit: ObjectId,
        name: &str,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.require_bounded(commit, Kind::Commit, MAX_COMMIT_BYTES)?;
        let tree_id = self
            .repo
            .find_commit(commit)?
            .tree_id()
            .map_err(gix::Error::from)?
            .detach();
        self.require_bounded(tree_id, Kind::Tree, MAX_TREE_BYTES)?;
        let tree = self.repo.find_tree(tree_id)?;
        let Some(entry) = tree.find_entry(name) else {
            return Ok(None);
        };
        let id = entry.object_id();
        if !entry.mode().is_blob() {
            return Err(StoreError::WrongObject {
                id,
                expected: Kind::Blob,
            });
        }
        self.require_bounded(id, Kind::Blob, max_len)?;
        let data = self.repo.find_object(id)?.detach().data;
        if data.len() as u64 > max_len {
            return Err(StoreError::TooLarge { id, limit: max_len });
        }
        Ok(Some(data))
    }

    /// Returns the tree `commit` records.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::WrongObject`] if `commit` is not a commit, or [`StoreError::Git`]
    /// if it cannot be read.
    pub fn commit_tree(&self, commit: ObjectId) -> Result<ObjectId, StoreError> {
        self.require_kind(commit, Kind::Commit)?;
        Ok(self
            .repo
            .find_commit(commit)?
            .tree_id()
            .map_err(gix::Error::from)?
            .detach())
    }

    /// Returns the parent of `commit`, or `None` for the first commit of a history.
    ///
    /// mahi's histories are linear, so a commit with more than one parent is refused. The
    /// commit's size is checked before it is loaded.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::WrongObject`] if `commit` is not a commit,
    /// [`StoreError::TooLarge`] if it is larger than 64 KiB, [`StoreError::NotLinear`] if it has
    /// several parents, or [`StoreError::Git`] if reading fails.
    pub fn parent(&self, commit: ObjectId) -> Result<Option<ObjectId>, StoreError> {
        self.require_bounded(commit, Kind::Commit, MAX_COMMIT_BYTES)?;
        let commit_object = self.repo.find_commit(commit)?;
        let mut parents = commit_object.parent_ids();
        let first = parents.next().map(gix::Id::detach);
        if parents.next().is_some() {
            return Err(StoreError::NotLinear(commit));
        }
        Ok(first)
    }

    /// Writes `bytes` as a blob.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Git`] if the object cannot be written.
    pub fn write_blob(&self, bytes: &[u8]) -> Result<ObjectId, StoreError> {
        Ok(self.repo.write_blob(bytes)?.detach())
    }

    /// Seals `plaintext` to `key` and writes the result as a blob.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Seal`] if sealing fails, or [`StoreError::Git`] if the object
    /// cannot be written.
    pub fn write_sealed(&self, key: &ThreadKey, plaintext: &[u8]) -> Result<ObjectId, StoreError> {
        self.write_blob(&key.seal(plaintext)?)
    }

    /// Writes a tree holding `entries`, each a name, a kind and an object.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidEntryName`] or [`StoreError::DuplicateEntryName`] if the
    /// names are not a valid set of file names, [`StoreError::WrongObject`] if an entry's object
    /// is missing or does not match its kind, or [`StoreError::Git`] if the tree cannot be
    /// written. Submodule (`Commit`) entries are not looked up, since their commits live in
    /// another repository.
    pub fn write_tree(
        &self,
        entries: &[(&str, EntryKind, ObjectId)],
    ) -> Result<ObjectId, StoreError> {
        let mut seen = HashSet::with_capacity(entries.len());
        let mut tree = Tree {
            entries: Vec::with_capacity(entries.len()),
        };
        for &(name, kind, oid) in entries {
            validate_entry_name(name, kind)?;
            if !seen.insert(name) {
                return Err(StoreError::DuplicateEntryName(name.to_owned()));
            }
            match kind {
                EntryKind::Tree => self.require_kind(oid, Kind::Tree)?,
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    self.require_kind(oid, Kind::Blob)?;
                }
                EntryKind::Commit => {}
            }
            tree.entries.push(Entry {
                mode: kind.into(),
                filename: name.into(),
                oid,
            });
        }
        tree.entries.sort();
        Ok(self.repo.write_object(&tree)?.detach())
    }

    /// Commits `tree` on top of `thread_ref` and moves the ref to the new commit.
    ///
    /// `expected` is the commit the caller last saw at `thread_ref`, or `None` if the ref does
    /// not exist yet. It becomes the new commit's parent, and the ref only moves if it still
    /// points there. The commit uses the fixed [`COMMITTER_NAME`] and [`COMMITTER_EMAIL`] and a
    /// timestamp of zero, so it carries no identity or time of its own, and no reflog is written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] if the ref no longer points at `expected`, including
    /// when another writer moves it concurrently, [`StoreError::WrongObject`] if `tree` is not a
    /// tree, or [`StoreError::Git`] if writing fails.
    pub fn append(
        &self,
        thread_ref: &ThreadRef,
        expected: Option<ObjectId>,
        tree: ObjectId,
        message: &str,
    ) -> Result<ObjectId, StoreError> {
        self.require_kind(tree, Kind::Tree)?;
        self.require_head(thread_ref, expected)?;

        let commit = Commit {
            tree,
            parents: expected.into_iter().collect(),
            author: generic_signature(),
            committer: generic_signature(),
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        };
        let id = self.repo.write_object(&commit)?.detach();

        let previous = match expected {
            Some(parent) => PreviousValue::MustExistAndMatch(Target::Object(parent)),
            None => PreviousValue::MustNotExist,
        };
        let full_name =
            FullName::try_from(thread_ref.to_string()).map_err(gix::Error::from_error)?;
        let edited = self.repo.edit_references_as(
            Some(RefEdit::new(
                full_name,
                Change::Update {
                    log: LogChange {
                        mode: RefLog::AndReference,
                        force_create_reflog: false,
                        message: "".into(),
                    },
                    expected: previous,
                    new: Target::Object(id),
                },
            )),
            None,
        );
        if let Err(error) = edited {
            self.require_head(thread_ref, expected)?;
            return Err(error.into());
        }
        Ok(id)
    }

    /// Deletes `thread_ref` if it still points at `expected`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] if the ref does not point at `expected`,
    /// [`StoreError::Symbolic`] if it is a symbolic ref, or [`StoreError::Git`] if deleting
    /// fails.
    pub fn remove(&self, thread_ref: &ThreadRef, expected: ObjectId) -> Result<(), StoreError> {
        self.require_head(thread_ref, Some(expected))?;
        let full_name =
            FullName::try_from(thread_ref.to_string()).map_err(gix::Error::from_error)?;
        let edited = self.repo.edit_references_as(
            Some(RefEdit::new(
                full_name,
                Change::Delete {
                    expected: PreviousValue::MustExistAndMatch(Target::Object(expected)),
                    log: RefLog::AndReference,
                },
            )),
            None,
        );
        if let Err(error) = edited {
            self.require_head(thread_ref, Some(expected))?;
            return Err(error.into());
        }
        Ok(())
    }

    fn require_head(
        &self,
        thread_ref: &ThreadRef,
        expected: Option<ObjectId>,
    ) -> Result<(), StoreError> {
        let found = self.head(thread_ref)?;
        if found == expected {
            return Ok(());
        }
        Err(StoreError::Conflict {
            name: thread_ref.to_string(),
            expected,
            found,
        })
    }

    fn require_bounded(&self, id: ObjectId, expected: Kind, limit: u64) -> Result<(), StoreError> {
        let header = self
            .repo
            .try_find_header(id)?
            .filter(|header| header.kind() == expected)
            .ok_or(StoreError::WrongObject { id, expected })?;
        if header.size() > limit {
            return Err(StoreError::TooLarge { id, limit });
        }
        Ok(())
    }

    pub(crate) fn require_kind(&self, id: ObjectId, expected: Kind) -> Result<(), StoreError> {
        let header = self.repo.try_find_header(id)?;
        if header.is_some_and(|header| header.kind() == expected) {
            Ok(())
        } else {
            Err(StoreError::WrongObject { id, expected })
        }
    }
}

pub(crate) fn open_options() -> gix::open::Options {
    gix::open::Options::default().config_overrides([DISABLE_REFLOG, REF_LOCK_TIMEOUT])
}

fn generic_signature() -> Signature {
    Signature {
        name: COMMITTER_NAME.into(),
        email: COMMITTER_EMAIL.into(),
        time: Time {
            seconds: 0,
            offset: 0,
        },
    }
}

fn validate_entry_name(name: &str, kind: EntryKind) -> Result<(), StoreError> {
    let mode = (kind == EntryKind::Link).then_some(Mode::Symlink);
    let valid = name.len() <= MAX_ENTRY_NAME_BYTES
        && gix_validate::path::component(name.into(), mode, component::Options::default()).is_ok();
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidEntryName(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use mahi_core::{
        AgentName,
        AgentSlot,
        ParticipantName,
        RefKind,
        ThreadId,
    };
    use tempfile::TempDir;

    use super::*;

    const LIMIT: usize = 1 << 20;

    fn store() -> (TempDir, Store) {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn transcript_ref() -> ThreadRef {
        ThreadRef::new(
            ThreadId::random().unwrap(),
            RefKind::Transcript(AgentSlot::new(
                ParticipantName::new("alice").unwrap(),
                AgentName::new("codex").unwrap(),
            )),
        )
    }

    fn empty_tree(store: &Store) -> ObjectId {
        store.write_tree(&[]).unwrap()
    }

    fn commit_on_main(store: &Store) -> ObjectId {
        std::fs::write(store.common_dir().join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let commit = Commit {
            tree: empty_tree(store),
            parents: std::iter::empty().collect(),
            author: generic_signature(),
            committer: generic_signature(),
            encoding: None,
            message: "base".into(),
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
    fn discovery_finds_the_repository_from_a_subdirectory() {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path()).unwrap();
        let nested = dir.path().join("src/deep");
        std::fs::create_dir_all(&nested).unwrap();
        let store = Store::discover(&nested).unwrap();
        assert_eq!(
            store.common_dir().canonicalize().unwrap(),
            dir.path().join(".git").canonicalize().unwrap()
        );
        let outside = TempDir::new().unwrap();
        assert!(matches!(
            Store::discover(outside.path()),
            Err(StoreError::Git(_))
        ));
    }

    #[test]
    fn head_is_read_as_a_commit_and_a_branch() {
        let (_dir, store) = store();
        assert!(matches!(store.head_commit(), Err(StoreError::NoCommit)));
        let commit = commit_on_main(&store);
        assert_eq!(store.head_commit().unwrap(), commit);
        assert_eq!(store.head_branch().unwrap().as_deref(), Some("main"));

        std::fs::write(store.common_dir().join("HEAD"), format!("{commit}\n")).unwrap();
        assert_eq!(store.head_branch().unwrap(), None);
        assert_eq!(store.head_commit().unwrap(), commit);

        std::fs::write(store.common_dir().join("HEAD"), "ref: refs/tags/v1\n").unwrap();
        assert_eq!(store.head_branch().unwrap(), None);

        let missing = "0123456789012345678901234567890123456789";
        std::fs::write(store.common_dir().join("HEAD"), format!("{missing}\n")).unwrap();
        assert!(matches!(store.head_commit(), Err(StoreError::Git(_))));
    }

    #[test]
    fn thread_refs_are_listed_and_foreign_names_left_out() {
        let (_dir, store) = store();
        let tree = empty_tree(&store);
        let transcript = transcript_ref();
        let meta = ThreadRef::new(transcript.thread(), RefKind::Meta);
        let first = store.append(&meta, None, tree, "meta").unwrap();
        let second = store.append(&transcript, None, tree, "turn").unwrap();
        for foreign in [
            "refs/threads/not-an-id/meta",
            "refs/threads/0123456789abcdef0123456789abcdef/unknown",
        ] {
            store
                .repo
                .reference(foreign, first, PreviousValue::Any, "test")
                .unwrap();
        }
        let symbolic = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        std::fs::create_dir_all(
            store
                .common_dir()
                .join(symbolic.to_string())
                .parent()
                .unwrap(),
        )
        .unwrap();
        std::fs::write(
            store.common_dir().join(symbolic.to_string()),
            format!("ref: {meta}\n"),
        )
        .unwrap();
        let listed = store.thread_refs().unwrap();
        let mut expected = vec![(meta, first), (transcript, second)];
        expected.sort();
        assert_eq!(listed, expected);
    }

    #[test]
    fn a_commit_gives_its_tree_and_other_objects_are_refused() {
        let (_dir, store) = store();
        let tree = empty_tree(&store);
        let commit = store.append(&transcript_ref(), None, tree, "turn").unwrap();
        assert_eq!(store.commit_tree(commit).unwrap(), tree);
        assert!(matches!(
            store.commit_tree(tree),
            Err(StoreError::WrongObject { .. })
        ));
    }

    #[test]
    fn missing_ref_has_no_head() {
        let (_dir, store) = store();
        assert_eq!(store.head(&transcript_ref()).unwrap(), None);
    }

    #[test]
    fn append_creates_then_extends_a_ref() {
        let (_dir, store) = store();
        let r = transcript_ref();
        let tree = empty_tree(&store);
        let first = store.append(&r, None, tree, "turn 1").unwrap();
        assert_eq!(store.head(&r).unwrap(), Some(first));
        let second = store.append(&r, Some(first), tree, "turn 2").unwrap();
        assert_eq!(store.head(&r).unwrap(), Some(second));

        let commit = store.repo.find_commit(second).unwrap();
        assert_eq!(
            commit.parent_ids().map(gix::Id::detach).collect::<Vec<_>>(),
            [first]
        );
        assert_eq!(commit.message_raw_sloppy(), "turn 2");
    }

    #[test]
    fn remove_deletes_a_ref_only_at_the_expected_commit() {
        let (_dir, store) = store();
        let r = transcript_ref();
        let tree = empty_tree(&store);
        let first = store.append(&r, None, tree, "turn 1").unwrap();
        let second = store.append(&r, Some(first), tree, "turn 2").unwrap();
        assert!(matches!(
            store.remove(&r, first),
            Err(StoreError::Conflict { .. })
        ));
        assert_eq!(store.head(&r).unwrap(), Some(second));
        store.remove(&r, second).unwrap();
        assert_eq!(store.head(&r).unwrap(), None);
        assert!(matches!(
            store.remove(&r, second),
            Err(StoreError::Conflict { found: None, .. })
        ));
    }

    #[test]
    fn commits_carry_the_generic_identity_and_no_time() {
        let (_dir, store) = store();
        let r = transcript_ref();
        let id = store.append(&r, None, empty_tree(&store), "x").unwrap();
        let commit = store.repo.find_commit(id).unwrap();
        for signature in [commit.author().unwrap(), commit.committer().unwrap()] {
            assert_eq!(signature.name, COMMITTER_NAME);
            assert_eq!(signature.email, COMMITTER_EMAIL);
            assert_eq!(signature.time().unwrap(), Time::new(0, 0));
        }
    }

    #[test]
    fn identical_content_gives_identical_commits() {
        let (_dir, store) = store();
        let tree = empty_tree(&store);
        let a = store.append(&transcript_ref(), None, tree, "same").unwrap();
        let b = store.append(&transcript_ref(), None, tree, "same").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn append_refuses_a_stale_expectation() {
        let (_dir, store) = store();
        let r = transcript_ref();
        let tree = empty_tree(&store);
        let first = store.append(&r, None, tree, "1").unwrap();
        let second = store.append(&r, Some(first), tree, "2").unwrap();

        let stale = store.append(&r, Some(first), tree, "3");
        assert!(matches!(
            stale,
            Err(StoreError::Conflict { found: Some(found), .. }) if found == second
        ));
        let recreate = store.append(&r, None, tree, "3");
        assert!(matches!(recreate, Err(StoreError::Conflict { .. })));
        assert_eq!(store.head(&r).unwrap(), Some(second));
    }

    #[test]
    fn append_writes_no_reflog() {
        let (dir, store) = store();
        let r = transcript_ref();
        store.append(&r, None, empty_tree(&store), "x").unwrap();
        assert!(!dir.path().join(".git/logs/refs/threads").exists());
        assert!(!dir.path().join(".git/logs").join(r.to_string()).exists());
    }

    #[test]
    fn sealed_blobs_round_trip_and_are_not_plaintext() {
        let (_dir, store) = store();
        let key = ThreadKey::generate();
        let id = store.write_sealed(&key, b"a transcript line").unwrap();
        let blob = store.repo.find_object(id).unwrap().detach();
        assert!(
            !blob
                .data
                .windows(b"transcript".len())
                .any(|w| w == b"transcript")
        );
        assert_eq!(key.open(&blob.data, LIMIT).unwrap(), b"a transcript line");
    }

    #[test]
    fn trees_are_sorted_regardless_of_input_order() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        let a = store
            .write_tree(&[("b", EntryKind::Blob, blob), ("a", EntryKind::Blob, blob)])
            .unwrap();
        let b = store
            .write_tree(&[("a", EntryKind::Blob, blob), ("b", EntryKind::Blob, blob)])
            .unwrap();
        assert_eq!(a, b);
        let tree = store
            .repo
            .find_tree(a)
            .unwrap()
            .decode()
            .unwrap()
            .to_owned();
        let names: Vec<_> = tree
            .entries
            .iter()
            .map(|e| e.filename.to_string())
            .collect();
        assert_eq!(names, ["a", "b"]);
    }

    #[test]
    fn trees_refuse_unsafe_names() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        let long = "x".repeat(MAX_ENTRY_NAME_BYTES + 1);
        for name in ["", ".", "..", ".git", ".GIT", "a/b", "a\0b", long.as_str()] {
            assert!(
                matches!(
                    store.write_tree(&[(name, EntryKind::Blob, blob)]),
                    Err(StoreError::InvalidEntryName(_))
                ),
                "{name:?}"
            );
        }
        assert!(
            store
                .write_tree(&[(".gitignore", EntryKind::Blob, blob)])
                .is_ok()
        );
    }

    #[test]
    fn trees_refuse_duplicate_names() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        assert!(matches!(
            store.write_tree(&[("a", EntryKind::Blob, blob), ("a", EntryKind::Tree, blob)]),
            Err(StoreError::DuplicateEntryName(_))
        ));
    }

    #[test]
    fn read_entry_reads_a_named_blob_within_its_limit() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"hello").unwrap();
        let sub = empty_tree(&store);
        let tree = store
            .write_tree(&[
                ("meta", EntryKind::Blob, blob),
                ("dir", EntryKind::Tree, sub),
            ])
            .unwrap();
        let r = transcript_ref();
        let commit = store.append(&r, None, tree, "x").unwrap();

        assert_eq!(
            store.read_entry(commit, "meta", 5).unwrap().as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(store.read_entry(commit, "missing", 5).unwrap(), None);
        assert!(matches!(
            store.read_entry(commit, "meta", 4),
            Err(StoreError::TooLarge { limit: 4, .. })
        ));
        assert!(matches!(
            store.read_entry(commit, "dir", 5),
            Err(StoreError::WrongObject {
                expected: Kind::Blob,
                ..
            })
        ));
        assert!(matches!(
            store.read_entry(tree, "meta", 5),
            Err(StoreError::WrongObject {
                expected: Kind::Commit,
                ..
            })
        ));
    }

    #[test]
    fn read_entry_refuses_symlinks_and_oversized_trees_and_commits() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"target").unwrap();
        let tree = store
            .write_tree(&[("meta", EntryKind::Link, blob)])
            .unwrap();
        let commit = store.append(&transcript_ref(), None, tree, "x").unwrap();
        assert!(matches!(
            store.read_entry(commit, "meta", 100),
            Err(StoreError::WrongObject {
                expected: Kind::Blob,
                ..
            })
        ));

        let names: Vec<String> = (0..40_000).map(|i| format!("entry-{i:05}")).collect();
        let entries: Vec<_> = names
            .iter()
            .map(|name| (name.as_str(), EntryKind::Blob, blob))
            .collect();
        let big_tree = store.write_tree(&entries).unwrap();
        let commit = store
            .append(&transcript_ref(), None, big_tree, "x")
            .unwrap();
        assert!(matches!(
            store.read_entry(commit, "entry-00000", 100),
            Err(StoreError::TooLarge { id, .. }) if id == big_tree
        ));

        let huge_message = "m".repeat(usize::try_from(MAX_COMMIT_BYTES).unwrap());
        let commit = store
            .append(&transcript_ref(), None, empty_tree(&store), &huge_message)
            .unwrap();
        assert!(matches!(
            store.read_entry(commit, "meta", 100),
            Err(StoreError::TooLarge { id, .. }) if id == commit
        ));
    }

    #[test]
    fn parent_follows_a_linear_history_and_refuses_merges() {
        let (_dir, store) = store();
        let r = transcript_ref();
        let tree = empty_tree(&store);
        let first = store.append(&r, None, tree, "1").unwrap();
        let second = store.append(&r, Some(first), tree, "2").unwrap();
        assert_eq!(store.parent(second).unwrap(), Some(first));
        assert_eq!(store.parent(first).unwrap(), None);

        let merge = store
            .repo
            .write_object(&Commit {
                tree,
                parents: [first, second].into_iter().collect(),
                author: generic_signature(),
                committer: generic_signature(),
                encoding: None,
                message: "merge".into(),
                extra_headers: Vec::new(),
            })
            .unwrap()
            .detach();
        assert!(matches!(
            store.parent(merge),
            Err(StoreError::NotLinear(id)) if id == merge
        ));
        assert!(matches!(
            store.parent(tree),
            Err(StoreError::WrongObject {
                expected: Kind::Commit,
                ..
            })
        ));
    }

    #[test]
    fn common_dir_is_the_git_directory() {
        let (dir, store) = store();
        assert_eq!(
            store.common_dir().canonicalize().unwrap(),
            dir.path().join(".git").canonicalize().unwrap()
        );
    }

    #[test]
    fn open_refuses_a_directory_that_is_not_a_repository() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(Store::open(dir.path()), Err(StoreError::Git(_))));
    }

    #[test]
    fn append_writes_no_reflog_even_when_the_repository_asks_for_all() {
        let (dir, _) = store();
        let config = dir.path().join(".git/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("[core]\n\tlogAllRefUpdates = always\n");
        std::fs::write(&config, text).unwrap();
        let store = Store::open(dir.path()).unwrap();

        let r = transcript_ref();
        let tree = empty_tree(&store);
        let first = store.append(&r, None, tree, "1").unwrap();
        store.append(&r, Some(first), tree, "2").unwrap();
        assert!(!dir.path().join(".git/logs").join(r.to_string()).exists());
    }

    #[test]
    fn append_ignores_an_existing_reflog_file() {
        let (dir, store) = store();
        let r = transcript_ref();
        let log = dir.path().join(".git/logs").join(r.to_string());
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        std::fs::write(&log, "").unwrap();

        let tree = empty_tree(&store);
        let first = store.append(&r, None, tree, "1").unwrap();
        store.append(&r, Some(first), tree, "2").unwrap();
        assert_eq!(std::fs::read(&log).unwrap(), b"");
    }

    #[test]
    fn trees_refuse_names_git_would_not_check_out() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        for name in [
            ".git.",
            ".git ",
            "git~1",
            ".git::$INDEX_ALLOCATION",
            ".gi\u{200c}t",
            "CON",
            "a\\b",
        ] {
            assert!(
                matches!(
                    store.write_tree(&[(name, EntryKind::Blob, blob)]),
                    Err(StoreError::InvalidEntryName(_))
                ),
                "{name:?}"
            );
        }
        assert!(matches!(
            store.write_tree(&[(".gitmodules", EntryKind::Link, blob)]),
            Err(StoreError::InvalidEntryName(_))
        ));
        assert!(
            store
                .write_tree(&[(".gitmodules", EntryKind::Blob, blob)])
                .is_ok()
        );
        assert!(store.write_tree(&[("link", EntryKind::Link, blob)]).is_ok());
    }

    #[test]
    fn trees_check_that_objects_exist_and_match_their_kind() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        let tree = empty_tree(&store);
        let missing = ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap();
        for (kind, id, expected) in [
            (EntryKind::Tree, blob, Kind::Tree),
            (EntryKind::Blob, tree, Kind::Blob),
            (EntryKind::BlobExecutable, missing, Kind::Blob),
            (EntryKind::Link, missing, Kind::Blob),
            (EntryKind::Tree, missing, Kind::Tree),
        ] {
            assert!(
                matches!(
                    store.write_tree(&[("entry", kind, id)]),
                    Err(StoreError::WrongObject { expected: e, .. }) if e == expected
                ),
                "{kind:?}"
            );
        }
        assert!(
            store
                .write_tree(&[
                    ("dir", EntryKind::Tree, tree),
                    ("submodule", EntryKind::Commit, missing),
                ])
                .is_ok()
        );
    }

    #[test]
    fn append_refuses_a_tree_that_is_not_a_tree() {
        let (_dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        let r = transcript_ref();
        assert!(matches!(
            store.append(&r, None, blob, "x"),
            Err(StoreError::WrongObject {
                expected: Kind::Tree,
                ..
            })
        ));
        assert_eq!(store.head(&r).unwrap(), None);
    }

    #[test]
    fn concurrent_appends_stay_linear_and_lose_only_as_conflicts() {
        let (dir, store) = store();
        let r = transcript_ref();
        let tree = empty_tree(&store);
        let successes: usize = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|worker| {
                    let (path, r) = (dir.path(), &r);
                    scope.spawn(move || {
                        let store = Store::open(path).unwrap();
                        let mut won = 0;
                        for attempt in 0..40 {
                            let head = store.head(r).unwrap();
                            match store.append(r, head, tree, &format!("{worker}-{attempt}")) {
                                Ok(_) => won += 1,
                                Err(StoreError::Conflict { .. }) => {}
                                Err(other) => panic!("{other:?}"),
                            }
                        }
                        won
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).sum()
        });

        let mut length = 0;
        let mut next = store.head(&r).unwrap();
        while let Some(id) = next {
            length += 1;
            let commit = store.repo.find_commit(id).unwrap();
            let parents: Vec<_> = commit.parent_ids().map(gix::Id::detach).collect();
            assert!(parents.len() <= 1);
            next = parents.first().copied();
        }
        assert!(successes > 0);
        assert_eq!(length, successes);
    }

    #[test]
    fn a_symbolic_thread_ref_is_refused() {
        let (_dir, store) = store();
        let r = transcript_ref();
        store
            .repo
            .edit_reference(RefEdit::new(
                FullName::try_from(r.to_string()).unwrap(),
                Change::Update {
                    log: LogChange::default(),
                    expected: PreviousValue::Any,
                    new: Target::Symbolic(FullName::try_from("refs/heads/main").unwrap()),
                },
            ))
            .unwrap();
        assert!(matches!(store.head(&r), Err(StoreError::Symbolic(_))));
    }
}
