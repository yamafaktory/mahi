use std::{
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
                self.populate_worktree(&admin, &canonical, commit, interrupt)?;
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
        commit: ObjectId,
        interrupt: &AtomicBool,
    ) -> Result<(), StoreError> {
        let tree = self
            .repo
            .find_commit(commit)?
            .tree_id()
            .map_err(gix::Error::from)?
            .detach();
        let objects = self.repo.objects.clone();
        let mut index = gix::index::State::from_tree(
            &tree,
            objects.clone(),
            gix_validate::path::component::Options {
                protect_windows: false,
                ..gix_validate::path::component::Options::default()
            },
        )
        .map_err(|error| StoreError::Checkout(error.into()))?;
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
            &mut index, path, objects, &Discard, &Discard, interrupt, options,
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

        let mut file = gix::index::File::from_state(index, admin.join("index"));
        file.write(gix::index::write::Options::default())
            .map_err(gix::Error::from)?;
        fs::write(admin.join("HEAD"), format!("{commit}\n"))?;
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

fn validate_name(name: &str) -> Result<(), StoreError> {
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

    fn store() -> (TempDir, Store) {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path().join("repo")).unwrap();
        let store = Store::open(&dir.path().join("repo")).unwrap();
        (dir, store)
    }

    fn commit(store: &Store, tree: ObjectId) -> ObjectId {
        let r = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        store.append(&r, None, tree, "base").unwrap()
    }

    fn sample_commit(store: &Store) -> ObjectId {
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
        let path = store
            .add_worktree(
                "agent",
                &dir.path().join("wt"),
                sample_commit(&store),
                &AtomicBool::new(false),
            )
            .unwrap();
        fs::write(path.join("new"), b"work").unwrap();
        store.remove_worktree("agent").unwrap();
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
}
