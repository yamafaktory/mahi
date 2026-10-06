use std::{
    ffi::OsStr,
    fs,
    io,
    os::unix::ffi::OsStrExt,
    path::{
        self,
        Path,
        PathBuf,
    },
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

use gix::{
    ObjectId,
    object::Kind,
    progress::Discard,
    worktree::state::checkout,
};

use crate::{
    Store,
    StoreError,
    changes::{
        MAX_CHECKED_OUT_BYTES,
        MAX_CHECKED_OUT_FILES,
    },
};

const WORKTREES: &str = "worktrees";
const MAX_NAME_BYTES: usize = 128;

impl Store {
    /// Checks `commit` out into a new linked worktree at `path`, registered as `name`.
    ///
    /// The worktree has a detached `HEAD` at `commit` and its own index, and shares the
    /// repository's objects and refs, exactly like one made by `git worktree add --detach`, but
    /// without running `git`. `.gitattributes` conversions (`text`, `eol`, `ident`,
    /// `working-tree-encoding`) are applied as git would, but no filter driver is configured,
    /// so no filter program (such as git-lfs) ever runs. Returns the worktree's canonical path.
    ///
    /// If a step fails, or `interrupt` is set during the checkout, the worktree directory and
    /// its registration are removed; missing parent directories created for `path` may remain.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidWorktreeName`] if `name` is not a safe directory name,
    /// [`StoreError::InvalidWorktreePath`] if a path contains a newline,
    /// [`StoreError::WorktreeExists`] if `path` or a worktree called `name` exists,
    /// [`StoreError::WrongObject`] if `commit` is not a commit, [`StoreError::Interrupted`] if
    /// `interrupt` was set, [`StoreError::Checkout`] or
    /// [`StoreError::CheckoutPath`] if files could not be written, or another [`StoreError`] if
    /// reading or writing fails.
    pub fn add_worktree(
        &self,
        name: &str,
        path: &Path,
        commit: ObjectId,
        interrupt: &AtomicBool,
    ) -> Result<PathBuf, StoreError> {
        self.make_worktree(name, path, (commit, None), None, interrupt)
    }

    /// Rebuilds a linked worktree like [`Store::add_worktree`], with a detached `HEAD` and an
    /// index at `commit`, but with the files of `contents`, a tree such as an agent's latest
    /// snapshot, so the work recorded there shows as changes on top of `commit`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Store::add_worktree`], [`StoreError::WrongObject`] if
    /// `contents` is not a tree or an entry's object is not of its mode's kind,
    /// [`StoreError::CheckoutTooLarge`] if `contents` or `commit`'s tree would write more than
    /// 2,000,000 files or 64 GiB, counting a subtree each time it is named, holds a file over
    /// 256 MiB, or holds more trees or levels than mahi checks out, [`StoreError::TooLarge`]
    /// if one of their trees is larger than 1 MiB, or [`StoreError::DuplicateEntryName`] if
    /// one names an entry twice.
    pub fn restore_worktree(
        &self,
        name: &str,
        path: &Path,
        commit: ObjectId,
        contents: ObjectId,
        interrupt: &AtomicBool,
    ) -> Result<PathBuf, StoreError> {
        self.restore_worktree_within(
            (name, path),
            (commit, contents),
            (MAX_CHECKED_OUT_FILES, MAX_CHECKED_OUT_BYTES),
            interrupt,
        )
    }

    pub(crate) fn restore_worktree_within(
        &self,
        (name, path): (&str, &Path),
        (commit, contents): (ObjectId, ObjectId),
        budget: (usize, u64),
        interrupt: &AtomicBool,
    ) -> Result<PathBuf, StoreError> {
        self.require_kind(contents, Kind::Tree)?;
        self.require_kind(commit, Kind::Commit)?;
        let base = self
            .repo
            .find_commit(commit)?
            .tree_id()
            .map_err(gix::Error::from)?
            .detach();
        for tree in [contents, base] {
            if !self.fits_checkout(tree, budget, interrupt)? {
                return Err(StoreError::CheckoutTooLarge(tree));
            }
        }
        self.make_worktree(name, path, (commit, None), Some(contents), interrupt)
    }

    /// Adds a linked worktree like [`Store::add_worktree`], but with `HEAD` on the local branch
    /// `branch`, checked out at its tip, so commits made there with git move the branch.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NoBranch`] if the branch does not exist, or the errors of
    /// [`Store::add_worktree`].
    pub fn add_branch_worktree(
        &self,
        name: &str,
        path: &Path,
        branch: &str,
        interrupt: &AtomicBool,
    ) -> Result<PathBuf, StoreError> {
        let tip = self
            .branch_tip(branch)?
            .ok_or_else(|| StoreError::NoBranch(branch.to_owned()))?;
        self.make_worktree(name, path, (tip, Some(branch)), None, interrupt)
    }

    fn make_worktree(
        &self,
        name: &str,
        path: &Path,
        (commit, branch): (ObjectId, Option<&str>),
        contents: Option<ObjectId>,
        interrupt: &AtomicBool,
    ) -> Result<PathBuf, StoreError> {
        validate_name(name)?;
        self.require_kind(commit, Kind::Commit)?;
        let path = path::absolute(path)?;
        refuse_newline(&path)?;
        if fs::symlink_metadata(&path).is_ok() {
            return Err(StoreError::WorktreeExists(path));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let worktrees = fs::canonicalize(self.common_dir())?.join(WORKTREES);
        refuse_newline(&worktrees)?;
        fs::create_dir_all(&worktrees)?;
        let admin = worktrees.join(name);
        if let Err(error) = fs::create_dir(&admin) {
            return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                StoreError::WorktreeExists(admin)
            } else {
                error.into()
            });
        }
        if let Err(error) = fs::create_dir(&path) {
            let _ = fs::remove_dir_all(&admin);
            return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                StoreError::WorktreeExists(path)
            } else {
                error.into()
            });
        }

        let populated = fs::canonicalize(&path)
            .map_err(StoreError::from)
            .and_then(|canonical| {
                refuse_newline(&canonical)?;
                self.populate_worktree(&admin, &canonical, (commit, branch), contents, interrupt)?;
                Ok(canonical)
            });
        if populated.is_err() {
            let _ = fs::remove_dir_all(&path);
            let _ = fs::remove_dir_all(&admin);
        }
        populated
    }

    /// Returns the canonical directory of the linked worktree `name`, found through the
    /// repository's own record of it, never through the worktree's `.git` file.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotAWorktree`] if `name` is not a linked worktree whose recorded
    /// directory is where it should be and links back to it, or another [`StoreError`] if the
    /// repository cannot be read.
    pub fn worktree_dir(&self, name: &str) -> Result<PathBuf, StoreError> {
        let (repo, workdir) = self.open_worktree(name)?;
        let admin = fs::canonicalize(repo.git_dir())?;
        let links_back = fs::read(workdir.join(".git"))
            .is_ok_and(|link| link == line(&[b"gitdir: ", admin.as_os_str().as_bytes()]));
        if !links_back || fs::canonicalize(self.common_dir())?.starts_with(&workdir) {
            return Err(StoreError::NotAWorktree(name.to_owned()));
        }
        Ok(workdir)
    }

    /// Returns the names of the linked worktrees the repository has registered, whether or not
    /// their directories are still there, in no particular order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if the registrations cannot be read.
    pub fn worktree_names(&self) -> Result<Vec<String>, StoreError> {
        let registered = match fs::read_dir(self.common_dir().join(WORKTREES)) {
            Ok(registered) => registered,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut names = Vec::new();
        for entry in registered {
            if let Ok(name) = entry?.file_name().into_string()
                && validate_name(&name).is_ok()
            {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Returns the directory where the repository keeps the state of the linked worktree
    /// `name`, which goes when the worktree is removed or pruned.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotAWorktree`] if `name` is not a linked worktree whose recorded
    /// directory is where it should be, or [`StoreError::Io`] if it cannot be resolved.
    pub fn worktree_admin(&self, name: &str) -> Result<PathBuf, StoreError> {
        self.worktree_dir(name)?;
        Ok(fs::canonicalize(self.common_dir())?
            .join(WORKTREES)
            .join(name))
    }

    /// Returns the local branch the linked worktree `name` has `HEAD` on, or `None` when its
    /// `HEAD` is detached.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotAWorktree`] if `name` is not a linked worktree whose recorded
    /// directory is where it should be, or [`StoreError::Git`] if `HEAD` cannot be read.
    pub fn worktree_branch(&self, name: &str) -> Result<Option<String>, StoreError> {
        let (repo, _) = self.open_worktree(name)?;
        Ok(local_branch(repo.head_name()?))
    }

    /// Returns whether the local branch `branch` is checked out, in the main worktree or in a
    /// linked one, whichever worktree this store was opened from, as git refuses to check one
    /// branch out twice.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if the registered worktrees cannot be listed.
    pub fn branch_checked_out(&self, branch: &str) -> Result<bool, StoreError> {
        let wanted = format!("ref: refs/heads/{branch}");
        let on_branch = |head: &Path| {
            fs::read(head)
                .is_ok_and(|head| head.strip_suffix(b"\n").unwrap_or(&head) == wanted.as_bytes())
        };
        if on_branch(&self.common_dir().join("HEAD")) {
            return Ok(true);
        }
        let worktrees = self.common_dir().join(WORKTREES);
        Ok(self
            .worktree_names()?
            .iter()
            .any(|name| on_branch(&worktrees.join(name).join("HEAD"))))
    }

    /// Removes the registration of the linked worktree `name` when the directory it records
    /// no longer exists, as `git worktree prune` does. Returns whether it removed one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidWorktreeName`] if `name` is not a safe directory name, or
    /// [`StoreError::Io`] if the registration cannot be read or removed.
    pub fn prune_worktree(&self, name: &str) -> Result<bool, StoreError> {
        validate_name(name)?;
        let admin = fs::canonicalize(self.common_dir())?
            .join(WORKTREES)
            .join(name);
        let recorded = match fs::read(admin.join("gitdir")) {
            Ok(recorded) => recorded,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let recorded = recorded.strip_suffix(b"\n").unwrap_or(&recorded);
        let recorded = Path::new(OsStr::from_bytes(recorded));
        if !recorded.is_absolute() {
            return Ok(false);
        }
        let Some(workdir) = recorded.parent() else {
            return Ok(false);
        };
        match fs::symlink_metadata(workdir) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::remove_dir_all(&admin)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Removes the linked worktree `name`: its directory and its registration.
    ///
    /// The directory is removed only if its `.git` file points back to the registration and it
    /// does not hold the repository's git directory. If removing the directory fails partway,
    /// the registration stays and names a directory that no longer matches, so a later call
    /// returns [`StoreError::NotAWorktree`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotAWorktree`] if `name` is not a linked worktree whose recorded
    /// directory is where it should be and links back to it, or [`StoreError::Io`] if a
    /// directory cannot be removed.
    pub fn remove_worktree(&self, name: &str) -> Result<(), StoreError> {
        let workdir = self.worktree_dir(name)?;
        let admin = fs::canonicalize(self.common_dir())?
            .join(WORKTREES)
            .join(name);
        fs::remove_dir_all(&workdir)?;
        fs::remove_dir_all(&admin)?;
        Ok(())
    }

    fn populate_worktree(
        &self,
        admin: &Path,
        path: &Path,
        (commit, branch): (ObjectId, Option<&str>),
        contents: Option<ObjectId>,
        interrupt: &AtomicBool,
    ) -> Result<(), StoreError> {
        let tree = self
            .repo
            .find_commit(commit)?
            .tree_id()
            .map_err(gix::Error::from)?
            .detach();
        let objects = self.repo.objects.clone();
        let index_of = |tree: &ObjectId| {
            gix::index::State::from_tree(
                tree,
                objects.clone(),
                gix_validate::path::component::Options {
                    protect_windows: false,
                    ..gix_validate::path::component::Options::default()
                },
            )
            .map_err(|error| StoreError::Checkout(error.into()))
        };
        let mut index = index_of(&contents.unwrap_or(tree))?;
        let options = checkout::Options {
            fs: gix::fs::Capabilities::probe_dir(path),
            destination_is_initially_empty: true,
            validate: gix_validate::path::component::Options {
                protect_windows: false,
                ..gix_validate::path::component::Options::default()
            },
            ..checkout::Options::default()
        };
        let outcome = checkout(
            &mut index,
            path,
            objects.clone(),
            &Discard,
            &Discard,
            interrupt,
            options,
        );
        if interrupt.load(Ordering::Relaxed) {
            return Err(StoreError::Interrupted);
        }
        let outcome = outcome.map_err(|error| StoreError::Checkout(error.into()))?;
        if let Some(error) = outcome.errors.first() {
            return Err(StoreError::CheckoutPath(error.path.to_string()));
        }
        if let Some(collision) = outcome.collisions.first() {
            return Err(StoreError::CheckoutPath(collision.path.to_string()));
        }

        if contents.is_some_and(|contents| contents != tree) {
            index = index_of(&tree)?;
        }
        let mut file = gix::index::File::from_state(index, admin.join("index"));
        file.write(gix::index::write::Options::default())
            .map_err(gix::Error::from)?;
        match branch {
            Some(branch) => fs::write(admin.join("HEAD"), format!("ref: refs/heads/{branch}\n"))?,
            None => fs::write(admin.join("HEAD"), format!("{commit}\n"))?,
        }
        fs::write(admin.join("commondir"), "../..\n")?;
        fs::write(
            admin.join("gitdir"),
            line(&[path.join(".git").as_os_str().as_bytes()]),
        )?;
        fs::write(
            path.join(".git"),
            line(&[b"gitdir: ", admin.as_os_str().as_bytes()]),
        )?;
        Ok(())
    }
}

fn line(parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = parts.concat();
    bytes.push(b'\n');
    bytes
}

fn refuse_newline(path: &Path) -> Result<(), StoreError> {
    if path.as_os_str().as_bytes().contains(&b'\n') {
        return Err(StoreError::InvalidWorktreePath(path.to_path_buf()));
    }
    Ok(())
}

fn local_branch(head: Option<gix::refs::FullName>) -> Option<String> {
    let head = head?;
    let short = head.as_bstr().strip_prefix(b"refs/heads/")?;
    std::str::from_utf8(short).ok().map(str::to_owned)
}

pub(crate) fn validate_name(name: &str) -> Result<(), StoreError> {
    let valid = name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && gix_validate::path::component(
            name.into(),
            None,
            gix_validate::path::component::Options::default(),
        )
        .is_ok();
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidWorktreeName(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::{
        ffi::OsStrExt,
        fs::PermissionsExt,
    };

    use gix::objs::{
        Tree,
        tree::{
            Entry,
            EntryKind,
        },
    };
    use mahi_core::{
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use tempfile::TempDir;

    use super::*;

    pub(super) fn store() -> (TempDir, Store) {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path().join("repo")).unwrap();
        let store = Store::open(&dir.path().join("repo")).unwrap();
        (dir, store)
    }

    fn commit(store: &Store, tree: ObjectId) -> ObjectId {
        let r = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        store.append(&r, None, tree, "base").unwrap()
    }

    pub(super) fn sample_commit(store: &Store) -> ObjectId {
        let readme = store.write_blob(b"hello\n").unwrap();
        let script = store.write_blob(b"#!/bin/sh\necho hi\n").unwrap();
        let target = store.write_blob(b"README.md").unwrap();
        let bin = store
            .write_tree(&[("run", EntryKind::BlobExecutable, script)])
            .unwrap();
        let root = store
            .write_tree(&[
                ("README.md", EntryKind::Blob, readme),
                ("bin", EntryKind::Tree, bin),
                ("link", EntryKind::Link, target),
            ])
            .unwrap();
        commit(store, root)
    }

    #[test]
    fn a_restored_worktree_has_the_snapshots_files_on_top_of_its_base() {
        let (dir, store) = store();
        let base = sample_commit(&store);
        let changed = store.write_blob(b"changed by the agent\n").unwrap();
        let added = store.write_blob(b"new\n").unwrap();
        let script = store.write_blob(b"#!/bin/sh\necho hi\n").unwrap();
        let bin = store
            .write_tree(&[("run", EntryKind::BlobExecutable, script)])
            .unwrap();
        let snapshot = store
            .write_tree(&[
                ("README.md", EntryKind::Blob, changed),
                ("bin", EntryKind::Tree, bin),
                ("notes.txt", EntryKind::Blob, added),
            ])
            .unwrap();
        let path = store
            .restore_worktree(
                "agent",
                &dir.path().join("wt"),
                base,
                snapshot,
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(
            fs::read(path.join("README.md")).unwrap(),
            b"changed by the agent\n"
        );
        assert_eq!(fs::read(path.join("notes.txt")).unwrap(), b"new\n");
        assert!(fs::symlink_metadata(path.join("link")).is_err());
        let repo = gix::open(&path).unwrap();
        assert_eq!(repo.head_id().unwrap().detach(), base);
        let index = repo.index().unwrap();
        let paths: Vec<String> = index
            .entries()
            .iter()
            .map(|entry| entry.path(&index).to_string())
            .collect();
        assert_eq!(paths, ["README.md", "bin/run", "link"]);
        let recorded = store
            .snapshot(
                "agent",
                &crate::GlobalPatterns::default(),
                &mut crate::SnapshotCache::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(recorded.tree, snapshot);
        assert!(matches!(
            store.restore_worktree(
                "other",
                &dir.path().join("wt2"),
                base,
                base,
                &AtomicBool::new(false)
            ),
            Err(StoreError::WrongObject { .. })
        ));
    }

    #[test]
    fn a_tree_naming_its_subtrees_over_and_over_is_refused_before_anything_is_written() {
        let (dir, store) = store();
        let base = sample_commit(&store);
        let blob = store.write_blob(b"x").unwrap();
        let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let mut level = store
            .write_tree(&names.map(|name| (name, EntryKind::Blob, blob)))
            .unwrap();
        let mut two = None;
        for depth in 0..7 {
            level = store
                .write_tree(&names.map(|name| (name, EntryKind::Tree, level)))
                .unwrap();
            if depth == 0 {
                two = Some(level);
            }
        }
        let stop = AtomicBool::new(false);
        let path = dir.path().join("bomb");
        assert!(matches!(
            store.restore_worktree("bomb", &path, base, level, &stop),
            Err(StoreError::CheckoutTooLarge(tree)) if tree == level
        ));
        assert!(fs::symlink_metadata(&path).is_err());
        assert!(fs::symlink_metadata(store.common_dir().join("worktrees/bomb")).is_err());

        let two = two.unwrap();
        assert!(matches!(
            store.restore_worktree_within(("small", &path), (base, two), (63, u64::MAX), &stop),
            Err(StoreError::CheckoutTooLarge(_))
        ));
        let restored = store
            .restore_worktree_within(("small", &path), (base, two), (64, u64::MAX), &stop)
            .unwrap();
        assert!(restored.join("h/h").is_file());

        let mut deep = store.write_tree(&[("f", EntryKind::Blob, blob)]).unwrap();
        for _ in 0..crate::MAX_SNAPSHOT_DEPTH {
            deep = store.write_tree(&[("d", EntryKind::Tree, deep)]).unwrap();
        }
        let deepest = store
            .restore_worktree("deepest", &dir.path().join("deepest"), base, deep, &stop)
            .unwrap();
        let mut file = deepest;
        file.extend(std::iter::repeat_n("d", crate::MAX_SNAPSHOT_DEPTH));
        assert!(file.join("f").is_file());
        let deeper = store.write_tree(&[("d", EntryKind::Tree, deep)]).unwrap();
        assert!(matches!(
            store.restore_worktree("deeper", &dir.path().join("deeper"), base, deeper, &stop),
            Err(StoreError::CheckoutTooLarge(_))
        ));

        let large = store.write_blob(&[0; 1024]).unwrap();
        let heavy = store
            .write_tree(&names.map(|name| (name, EntryKind::Blob, large)))
            .unwrap();
        let refused = dir.path().join("refused");
        assert!(matches!(
            store.restore_worktree_within(
                ("heavy", &refused),
                (base, heavy),
                (64, 8 * 1024 - 1),
                &stop
            ),
            Err(StoreError::CheckoutTooLarge(_))
        ));
        assert!(fs::symlink_metadata(&refused).is_err());
        store
            .restore_worktree_within(
                ("heavy", &dir.path().join("heavy")),
                (base, heavy),
                (64, 8 * 1024),
                &stop,
            )
            .unwrap();

        let mut chain = store.write_tree(&[("f", EntryKind::Blob, blob)]).unwrap();
        for _ in 0..100 {
            chain = store.write_tree(&[("c", EntryKind::Tree, chain)]).unwrap();
        }
        let wrapped = |levels: usize| {
            let mut tree = chain;
            for _ in 0..levels {
                tree = store.write_tree(&[("w", EntryKind::Tree, tree)]).unwrap();
            }
            store
                .write_tree(&[("a", EntryKind::Tree, chain), ("b", EntryKind::Tree, tree)])
                .unwrap()
        };
        let fits = store
            .fits_checkout(wrapped(155), (64, u64::MAX), &stop)
            .unwrap();
        let too_deep = store
            .fits_checkout(wrapped(156), (64, u64::MAX), &stop)
            .unwrap();
        assert!(fits && !too_deep);
        assert!(matches!(
            store.fits_checkout(wrapped(1), (64, u64::MAX), &AtomicBool::new(true)),
            Err(StoreError::Interrupted)
        ));
    }

    #[test]
    fn checks_out_files_modes_and_links() {
        let (dir, store) = store();
        let base = sample_commit(&store);
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                base,
                &AtomicBool::new(false),
            )
            .unwrap();

        assert_eq!(fs::read(path.join("README.md")).unwrap(), b"hello\n");
        let run = path.join("bin").join("run");
        assert_eq!(fs::read(&run).unwrap(), b"#!/bin/sh\necho hi\n");
        assert_ne!(fs::metadata(&run).unwrap().permissions().mode() & 0o111, 0);
        assert_eq!(
            fs::read_link(path.join("link")).unwrap(),
            Path::new("README.md")
        );
    }

    #[test]
    fn the_worktree_is_a_linked_worktree_of_the_repository() {
        let (dir, store) = store();
        let base = sample_commit(&store);
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                base,
                &AtomicBool::new(false),
            )
            .unwrap();

        let repo = gix::open(&path).unwrap();
        assert_eq!(repo.head_id().unwrap().detach(), base);
        assert_eq!(
            repo.common_dir().canonicalize().unwrap(),
            store.common_dir().canonicalize().unwrap()
        );
        assert_eq!(
            repo.workdir().unwrap().canonicalize().unwrap(),
            path.canonicalize().unwrap()
        );
        assert_eq!(repo.index().unwrap().entries().len(), 3);

        let main = gix::open(dir.path().join("repo")).unwrap();
        let names: Vec<_> = main
            .worktrees()
            .unwrap()
            .iter()
            .map(|proxy| proxy.id().to_string())
            .collect();
        assert_eq!(names, ["agent"]);
    }

    #[test]
    fn an_existing_path_or_name_is_refused() {
        let (dir, store) = store();
        let base = sample_commit(&store);
        let taken = dir.path().join("taken");
        fs::create_dir(&taken).unwrap();
        assert!(matches!(
            store.add_worktree("a", &taken, base, &AtomicBool::new(false)),
            Err(StoreError::WorktreeExists(_))
        ));

        store
            .add_worktree("b", &dir.path().join("wt1"), base, &AtomicBool::new(false))
            .unwrap();
        let second = dir.path().join("wt2");
        assert!(matches!(
            store.add_worktree("b", &second, base, &AtomicBool::new(false)),
            Err(StoreError::WorktreeExists(_))
        ));
        assert!(!second.exists());
    }

    #[test]
    fn unsafe_names_are_refused() {
        let (dir, store) = store();
        let base = sample_commit(&store);
        let long = "n".repeat(MAX_NAME_BYTES + 1);
        for name in ["", ".", "..", "a/b", ".hidden", "git~1", long.as_str()] {
            assert!(
                matches!(
                    store.add_worktree(name, &dir.path().join("wt"), base, &AtomicBool::new(false)),
                    Err(StoreError::InvalidWorktreeName(_))
                ),
                "{name:?}"
            );
        }
        assert!(!dir.path().join("wt").exists());
    }

    #[test]
    fn a_non_commit_is_refused() {
        let (dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        assert!(matches!(
            store.add_worktree("a", &dir.path().join("wt"), blob, &AtomicBool::new(false)),
            Err(StoreError::WrongObject {
                expected: Kind::Commit,
                ..
            })
        ));
    }

    #[test]
    fn gitattributes_conversions_apply_but_no_filter_runs() {
        let (dir, store) = store();
        let attributes = store
            .write_blob(b"*.txt text eol=crlf\n*.bin filter=lfs\n")
            .unwrap();
        let text = store.write_blob(b"one\ntwo\n").unwrap();
        let pointer = store.write_blob(b"version https://git-lfs\n").unwrap();
        let root = store
            .write_tree(&[
                (".gitattributes", EntryKind::Blob, attributes),
                ("a.txt", EntryKind::Blob, text),
                ("b.bin", EntryKind::Blob, pointer),
            ])
            .unwrap();
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                commit(&store, root),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(fs::read(path.join("a.txt")).unwrap(), b"one\r\ntwo\r\n");
        assert_eq!(
            fs::read(path.join("b.bin")).unwrap(),
            b"version https://git-lfs\n"
        );
    }

    #[test]
    fn the_index_records_file_stats() {
        let (dir, store) = store();
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                sample_commit(&store),
                &AtomicBool::new(false),
            )
            .unwrap();
        let repo = gix::open(&path).unwrap();
        let index = repo.index().unwrap();
        for entry in index.entries() {
            assert_ne!(entry.stat.mtime.secs, 0);
            assert_ne!(entry.stat.size, 0);
        }
    }

    #[test]
    fn an_interrupted_checkout_leaves_no_directory_or_registration() {
        let (dir, store) = store();
        let path = dir.path().join("wt");
        assert!(matches!(
            store.add_worktree(
                "agent",
                &path,
                sample_commit(&store),
                &AtomicBool::new(true)
            ),
            Err(StoreError::Interrupted)
        ));
        assert!(!path.exists());
        assert!(!store.common_dir().join(WORKTREES).join("agent").exists());
    }

    #[test]
    fn a_removed_worktree_leaves_no_directory_or_registration() {
        let (dir, store) = store();
        assert!(store.worktree_names().unwrap().is_empty());
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                sample_commit(&store),
                &AtomicBool::new(false),
            )
            .unwrap();
        fs::write(path.join("new"), b"work").unwrap();
        assert_eq!(store.worktree_names().unwrap(), ["agent"]);
        store.remove_worktree("agent").unwrap();
        assert!(store.worktree_names().unwrap().is_empty());
        assert!(!path.exists());
        assert!(!store.common_dir().join(WORKTREES).join("agent").exists());
        let main = gix::open(dir.path().join("repo")).unwrap();
        assert!(main.worktrees().unwrap().is_empty());
    }

    #[test]
    fn a_registered_worktree_is_found_and_an_unknown_one_is_not() {
        let (dir, store) = store();
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                sample_commit(&store),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(store.worktree_dir("agent").unwrap(), path);
        assert!(matches!(
            store.worktree_dir("other"),
            Err(StoreError::NotAWorktree(_))
        ));
        fs::write(path.join(".git"), b"gitdir: /elsewhere\n").unwrap();
        assert!(matches!(
            store.worktree_dir("agent"),
            Err(StoreError::NotAWorktree(_))
        ));
    }

    #[test]
    fn a_registration_is_pruned_only_when_its_directory_is_gone() {
        let (dir, store) = store();
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                sample_commit(&store),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(!store.prune_worktree("agent").unwrap());
        assert!(!store.prune_worktree("unknown").unwrap());
        fs::remove_dir_all(&path).unwrap();
        assert!(store.prune_worktree("agent").unwrap());
        assert!(!store.common_dir().join(WORKTREES).join("agent").exists());
        assert!(matches!(
            store.prune_worktree("../x"),
            Err(StoreError::InvalidWorktreeName(_))
        ));
        store
            .add_worktree(
                "relative",
                &dir.path().join("wt2"),
                sample_commit(&store),
                &AtomicBool::new(false),
            )
            .unwrap();
        let admin = store.common_dir().join(WORKTREES).join("relative");
        fs::write(admin.join("gitdir"), b"gone/.git\n").unwrap();
        assert!(!store.prune_worktree("relative").unwrap());
        assert!(admin.exists());
    }

    #[test]
    fn only_a_registered_worktree_can_be_removed() {
        let (dir, store) = store();
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                sample_commit(&store),
                &AtomicBool::new(false),
            )
            .unwrap();
        for name in ["other", "", "..", "agent/../agent"] {
            assert!(
                matches!(
                    store.remove_worktree(name),
                    Err(StoreError::NotAWorktree(_))
                ),
                "{name:?}"
            );
        }
        let link = fs::read(path.join(".git")).unwrap();
        fs::write(path.join(".git"), b"gitdir: /elsewhere\n").unwrap();
        assert!(matches!(
            store.remove_worktree("agent"),
            Err(StoreError::NotAWorktree(_))
        ));
        fs::write(path.join(".git"), link).unwrap();
        fs::rename(&path, dir.path().join("moved")).unwrap();
        assert!(matches!(
            store.remove_worktree("agent"),
            Err(StoreError::NotAWorktree(_))
        ));
        assert!(dir.path().join("moved").join("README.md").exists());
    }

    #[test]
    fn a_registration_pointing_at_the_main_checkout_removes_nothing() {
        let (dir, store) = store();
        store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                sample_commit(&store),
                &AtomicBool::new(false),
            )
            .unwrap();
        let main = fs::canonicalize(dir.path().join("repo")).unwrap();
        let admin = store.common_dir().join(WORKTREES).join("agent");
        fs::write(
            admin.join("gitdir"),
            line(&[main.join(".git").as_os_str().as_bytes()]),
        )
        .unwrap();
        assert!(matches!(
            store.remove_worktree("agent"),
            Err(StoreError::NotAWorktree(_))
        ));
        assert!(main.join(".git").join("HEAD").exists());
        assert!(dir.path().join("wt").join("README.md").exists());
    }

    #[test]
    fn a_symlink_escape_is_refused_and_writes_nothing_outside() {
        let (dir, store) = store();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let target = store.write_blob(outside.as_os_str().as_bytes()).unwrap();
        let payload = store.write_blob(b"pwned").unwrap();
        let hostile = store
            .repo
            .write_object(&Tree {
                entries: vec![
                    Entry {
                        mode: EntryKind::Link.into(),
                        filename: "a".into(),
                        oid: target,
                    },
                    Entry {
                        mode: EntryKind::Tree.into(),
                        filename: "a".into(),
                        oid: store
                            .write_tree(&[("x", EntryKind::Blob, payload)])
                            .unwrap(),
                    },
                ],
            })
            .unwrap()
            .detach();
        let path = dir.path().join("wt");
        assert!(
            store
                .add_worktree("a", &path, commit(&store, hostile), &AtomicBool::new(false))
                .is_err()
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        assert!(!path.exists());
        assert!(!store.common_dir().join(WORKTREES).join("a").exists());
    }

    #[test]
    fn an_uncreatable_parent_leaves_no_registration() {
        let (dir, store) = store();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
        let result = store.add_worktree(
            "a",
            &locked.join("sub").join("wt"),
            sample_commit(&store),
            &AtomicBool::new(false),
        );
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(result, Err(StoreError::Io(_))));
        assert!(!store.common_dir().join(WORKTREES).join("a").exists());
        assert!(
            store
                .add_worktree(
                    "a",
                    &dir.path().join("wt"),
                    sample_commit(&store),
                    &AtomicBool::new(false)
                )
                .is_ok()
        );
    }

    #[test]
    fn a_path_with_a_newline_is_refused() {
        let (dir, store) = store();
        assert!(matches!(
            store.add_worktree(
                "a",
                &dir.path().join("w\nt"),
                sample_commit(&store),
                &AtomicBool::new(false)
            ),
            Err(StoreError::InvalidWorktreePath(_))
        ));
    }

    #[test]
    fn a_failed_checkout_leaves_nothing_behind() {
        let (dir, store) = store();
        let blob = store.write_blob(b"x").unwrap();
        let hostile = store
            .repo
            .write_object(&Tree {
                entries: vec![Entry {
                    mode: EntryKind::Blob.into(),
                    filename: ".git".into(),
                    oid: blob,
                }],
            })
            .unwrap()
            .detach();
        let base = commit(&store, hostile);
        let path = dir.path().join("wt");
        assert!(matches!(
            store.add_worktree("a", &path, base, &AtomicBool::new(false)),
            Err(StoreError::Checkout(_) | StoreError::CheckoutPath(_))
        ));
        assert!(!path.exists());
        assert!(!store.common_dir().join(WORKTREES).join("a").exists());
    }

    #[test]
    fn a_branch_worktree_has_head_on_the_branch_at_its_tip() {
        let (dir, store) = store();
        let first = sample_commit(&store);
        assert_eq!(store.branch_tip("mahi/land").unwrap(), None);
        assert_eq!(store.ensure_branch("mahi/land", first).unwrap(), first);
        let blob = store.write_blob(b"x").unwrap();
        let other = commit(
            &store,
            store
                .write_tree(&[("other", EntryKind::Blob, blob)])
                .unwrap(),
        );
        assert_eq!(store.ensure_branch("mahi/land", other).unwrap(), first);
        assert!(matches!(
            store.add_branch_worktree(
                "missing",
                &dir.path().join("missing"),
                "nope",
                &AtomicBool::new(false)
            ),
            Err(StoreError::NoBranch(_))
        ));
        for bad in ["", "-x", "a..b", "a b", "bad~", "HEAD", "@", "refs/heads/x"] {
            assert!(
                matches!(store.branch_tip(bad), Err(StoreError::InvalidBranchName(_))),
                "{bad}"
            );
        }
        let path = store
            .add_branch_worktree(
                "land",
                &dir.path().join("land"),
                "mahi/land",
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(path.join("README.md").exists());
        let admin = fs::canonicalize(store.common_dir())
            .unwrap()
            .join("worktrees/land");
        assert_eq!(
            fs::read_to_string(admin.join("HEAD")).unwrap(),
            "ref: refs/heads/mahi/land\n"
        );
        let opened = gix::open(&path).unwrap();
        assert_eq!(
            opened.head_name().unwrap().unwrap().as_bstr(),
            "refs/heads/mahi/land"
        );
        assert_eq!(opened.head_id().unwrap().detach(), first);
        assert_eq!(
            store.worktree_branch("land").unwrap().as_deref(),
            Some("mahi/land")
        );
        assert!(store.branch_checked_out("mahi/land").unwrap());
        assert!(!store.branch_checked_out("mahi/other").unwrap());
        let from_linked = Store::discover(&path).unwrap();
        assert!(from_linked.branch_checked_out("mahi/land").unwrap());
        assert!(from_linked.branch_checked_out("main").unwrap());
        let admin_state = store.worktree_admin("land").unwrap();
        assert_eq!(admin_state, admin);
        fs::write(admin.join("HEAD"), format!("{first}\n")).unwrap();
        assert_eq!(store.worktree_branch("land").unwrap(), None);
        assert!(!store.branch_checked_out("mahi/land").unwrap());
        assert!(matches!(
            store.worktree_admin("missing"),
            Err(StoreError::NotAWorktree(_))
        ));
    }
}

#[cfg(test)]
mod git_tests {
    use std::process::Command;

    use super::{
        tests::*,
        *,
    };

    #[test]
    fn git_commits_in_a_branch_worktree_move_the_branch() {
        let (dir, store) = store();
        let commit = sample_commit(&store);
        store.ensure_branch("mahi/land", commit).unwrap();
        let path = store
            .add_branch_worktree(
                "land",
                &dir.path().join("land"),
                "mahi/land",
                &AtomicBool::new(false),
            )
            .unwrap();
        fs::write(path.join("README.md"), "changed\n").unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(["-c", "user.name=t", "-c", "user.email=t@t", "-C"])
                .arg(&path)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        assert!(git(&["status", "--porcelain"]).contains("README.md"));
        git(&["commit", "-qam", "curated"]);
        let tip = store.branch_tip("mahi/land").unwrap().unwrap();
        assert_ne!(tip, commit);
        assert_eq!(store.parent(tip).unwrap(), Some(commit));
    }
}
