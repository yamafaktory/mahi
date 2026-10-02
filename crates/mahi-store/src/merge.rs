use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::{
        self,
        Write as _,
    },
    os::fd::OwnedFd,
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

use gix::{
    ObjectId,
    bstr::{
        BStr,
        BString,
        ByteSlice,
        ByteVec,
    },
    filter::plumbing::{
        Pipeline,
        driver::apply::Delay,
        pipeline::convert::{
            ToWorktreeOutcome,
            to_worktree,
        },
    },
    merge::plumbing::{
        blob::{
            self,
            builtin_driver::{
                binary,
                text::Labels,
            },
            pipeline::WorktreeRoots,
        },
        tree::{
            self as merge_tree,
            TreatAsUnresolved,
        },
    },
    object::Kind,
    objs::{
        Write as _,
        tree::EntryMode,
    },
    worktree::stack::state::attributes::Source,
};
use rustix::{
    fs::{
        AtFlags,
        CWD,
        FileType,
        Mode,
        OFlags,
        mkdirat,
        openat,
        renameat,
        statat,
        symlinkat,
        unlinkat,
    },
    io::Errno,
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

/// The most paths a merged side may change from the base.
pub const MAX_MERGED_PATHS: usize = 65_536;
/// The most bytes of files a merge writes into a worktree in all.
pub const MAX_MERGE_WRITE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_LINK_BYTES: u64 = 4096;
pub(crate) const TEMPORARY_PREFIX: &str = ".mahi-merge-";

/// How a path of a merge conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Conflict {
    /// The file holds conflict markers around the lines both sides changed differently.
    Markers,
    /// Both sides changed the path in ways that cannot be combined, and ours was kept.
    KeptOurs,
}

/// The result of a three-way merge of trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    /// The merged tree.
    pub tree: ObjectId,
    /// The conflicting paths, sorted, each once.
    pub conflicts: Vec<(BString, Conflict)>,
}

/// Why a path of a merged tree was not written into the worktree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Left {
    /// The name is one git refuses to check out.
    UnsafeName,
    /// The path is nested deeper than [`MAX_SNAPSHOT_DEPTH`].
    TooDeep,
    /// The file is larger than [`MAX_SNAPSHOT_FILE_BYTES`], the link target longer than
    /// 4096 bytes, or the merge already wrote [`MAX_MERGE_WRITE_BYTES`].
    TooLarge,
    /// Something else is in the way, such as a link or a file where a directory should be, a
    /// directory where a file should be, or a file the worktree's last snapshot did not record
    /// where the merge adds one.
    Blocked,
    /// The path cannot be read or written, or its object is not a blob.
    Unwritable,
}

/// What writing a merged tree into a worktree did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Applied {
    /// How many files and links were written.
    pub written: usize,
    /// How many were removed.
    pub removed: usize,
    /// The paths left as they were, and why.
    pub left: Vec<(BString, Left)>,
}

type Entries = BTreeMap<BString, (EntryMode, ObjectId)>;
type Side = Option<(EntryMode, ObjectId)>;

impl Store {
    /// Merges `theirs` into `ours`, two trees that both started from the tree `base`, and
    /// writes the result as a tree, labelling the conflict markers with `labels`, ours first.
    ///
    /// No program runs: merge drivers, filters and text conversions from git's configuration
    /// or `.gitattributes` are ignored, text is merged by the built-in driver with conflict
    /// markers, and binary files (or files over [`MAX_SNAPSHOT_FILE_BYTES`]), links and paths
    /// changed in ways that cannot be combined keep `ours`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::MergeTooLarge`] if either side changes more than
    /// [`MAX_MERGED_PATHS`] paths from the base, or descends further than 64 levels, 65,536
    /// trees or 32 MiB of trees, the errors of [`Store::changed_paths`], or
    /// [`StoreError::Git`] if the merge fails.
    pub fn merge_trees(
        &self,
        base: ObjectId,
        ours: ObjectId,
        theirs: ObjectId,
        labels: (&str, &str),
    ) -> Result<Merged, StoreError> {
        for side in [ours, theirs] {
            if self.changed_paths(base, side, MAX_MERGED_PATHS)?.truncated {
                return Err(StoreError::MergeTooLarge(side));
            }
        }
        let repo = &self.repo;
        let mut diff_cache = repo.diff_resource_cache_for_tree_diff()?;
        let mut blob_merge = self.blob_merger(ours)?;
        let mut options: merge_tree::Options = repo.tree_merge_options()?.into();
        options.fail_on_conflict = None;
        options.rewrites = options.rewrites.map(|rewrites| gix::diff::Rewrites {
            copies: None,
            percentage: None,
            ..rewrites
        });
        options.blob_merge.resolve_binary_with = Some(binary::ResolveWith::Ours);
        options.symlink_conflicts = Some(binary::ResolveWith::Ours);
        options.tree_conflicts = Some(merge_tree::ResolveWith::Ours);
        let labels = Labels {
            ancestor: Some("base".into()),
            current: Some(labels.0.into()),
            other: Some(labels.1.into()),
        };
        let mut outcome = gix::merge::plumbing::tree(
            &base,
            &ours,
            &theirs,
            labels,
            &repo.objects,
            |buf| repo.write_buf(Kind::Blob, buf),
            &mut gix::diff::tree::State::default(),
            &mut diff_cache,
            &mut blob_merge,
            options,
        )
        .map_err(|error| StoreError::Git(error.into()))?;
        let tree = outcome
            .tree
            .write(|tree| repo.write(tree))
            .map_err(|error| StoreError::Git(error.into()))?;
        let mut conflicts: Vec<(BString, Conflict)> = Vec::new();
        for conflict in &outcome.conflicts {
            if !conflict.is_unresolved(TreatAsUnresolved::forced_resolution()) {
                continue;
            }
            let kind = if conflict
                .content_merge()
                .is_some_and(|merge| merge.resolution == blob::Resolution::Conflict)
            {
                Conflict::Markers
            } else {
                Conflict::KeptOurs
            };
            for location in [conflict.ours.location(), conflict.theirs.location()] {
                conflicts.push((location.to_owned(), kind));
            }
        }
        conflicts.sort();
        conflicts.dedup_by(|later, earlier| later.0 == earlier.0);
        Ok(Merged { tree, conflicts })
    }

    /// Writes into the linked worktree `name` what differs from the tree `ours`, the
    /// worktree's files as last recorded, to the tree `merged`.
    ///
    /// Every directory is opened relative to its parent without following symbolic links, and
    /// every file and link is written under a temporary name and renamed into place, so
    /// nothing outside the worktree is written. A path that cannot be written is left as it is
    /// and listed in [`Applied::left`]. `.gitattributes` conversions of `merged` apply, with no
    /// filter driver.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotAWorktree`] if `name` is not a linked worktree whose recorded
    /// directory is where it should be, [`StoreError::Interrupted`] if `interrupt` was set,
    /// [`StoreError::TooLarge`] if a tree is larger than 1 MiB, or another [`StoreError`] if
    /// the repository cannot be read.
    pub fn apply_merge(
        &self,
        name: &str,
        ours: ObjectId,
        merged: ObjectId,
        interrupt: &AtomicBool,
    ) -> Result<Applied, StoreError> {
        self.apply_merge_within(name, (ours, merged), MAX_MERGE_WRITE_BYTES, interrupt)
    }

    fn apply_merge_within(
        &self,
        name: &str,
        (ours, merged): (ObjectId, ObjectId),
        budget: u64,
        interrupt: &AtomicBool,
    ) -> Result<Applied, StoreError> {
        let (_, workdir) = self.open_worktree(name)?;
        let root = openat(
            CWD,
            &workdir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let mut writer = Writer {
            store: self,
            pipeline: self.worktree_pipeline(merged, ours)?,
            interrupt,
            budget,
            temporary: String::with_capacity(TEMPORARY_PREFIX.len() + 32),
            applied: Applied::default(),
        };
        writer.directory(&root, Some(ours), Some(merged), BStr::new(""), 0)?;
        writer.applied.left.sort();
        Ok(writer.applied)
    }

    fn blob_merger(&self, attributes_from: ObjectId) -> Result<blob::Platform, StoreError> {
        let repo = &self.repo;
        let mut filter_options = gix::filter::Pipeline::options(repo)?;
        filter_options.drivers.clear();
        let filter = Pipeline::new(repo.command_context()?, filter_options);
        let pipeline = blob::Pipeline::new(
            WorktreeRoots::default(),
            filter,
            blob::pipeline::Options {
                large_file_threshold_bytes: MAX_SNAPSHOT_FILE_BYTES,
            },
        );
        Ok(blob::Platform::new(
            pipeline,
            blob::pipeline::Mode::ToGit,
            self.attributes_of(attributes_from)?,
            Vec::new(),
            blob::platform::Options::default(),
        ))
    }

    fn worktree_pipeline(
        &self,
        merged: ObjectId,
        ours: ObjectId,
    ) -> Result<WorktreePipeline, StoreError> {
        let repo = &self.repo;
        let mut options = gix::filter::Pipeline::options(repo)?;
        options.drivers.clear();
        Ok(WorktreePipeline {
            filter: Pipeline::new(repo.command_context()?, options),
            attributes: self
                .attributes_of(merged)
                .or_else(|_| self.attributes_of(ours))?,
        })
    }

    fn attributes_of(&self, tree: ObjectId) -> Result<gix::worktree::Stack, StoreError> {
        let index = gix::index::State::from_tree(
            &tree,
            &self.repo.objects,
            gix_validate::path::component::Options {
                protect_windows: false,
                ..gix_validate::path::component::Options::default()
            },
        )
        .map_err(|error| StoreError::Git(error.into()))?;
        let stack = self.repo.attributes_only(&index, Source::IdMapping)?;
        Ok((*stack).clone())
    }

    fn entries(&self, tree: Option<ObjectId>) -> Result<Entries, StoreError> {
        let mut entries = Entries::new();
        let Some(tree) = tree else {
            return Ok(entries);
        };
        self.bounded_size(tree, Kind::Tree, MAX_TREE_BYTES)?;
        for entry in self.repo.find_tree(tree)?.iter() {
            let entry = entry.map_err(gix::Error::from)?;
            let name = entry.filename().to_owned();
            if entries.contains_key(&name) {
                return Err(StoreError::DuplicateEntryName(name.to_string()));
            }
            entries.insert(name, (entry.mode(), entry.object_id()));
        }
        Ok(entries)
    }
}

struct WorktreePipeline {
    filter: Pipeline,
    attributes: gix::worktree::Stack,
}

struct Writer<'a> {
    store: &'a Store,
    pipeline: WorktreePipeline,
    interrupt: &'a AtomicBool,
    budget: u64,
    temporary: String,
    applied: Applied,
}

enum Opened {
    Directory(OwnedFd),
    Missing,
    Blocked,
    Unreadable,
}

impl Writer<'_> {
    fn leave(&mut self, path: BString, why: Left) {
        self.applied.left.push((path, why));
    }

    fn directory(
        &mut self,
        dir: &OwnedFd,
        old: Option<ObjectId>,
        new: Option<ObjectId>,
        prefix: &BStr,
        depth: usize,
    ) -> Result<(), StoreError> {
        let before = self.store.entries(old)?;
        let after = self.store.entries(new)?;
        let (mut olds, mut news) = (before.iter().peekable(), after.iter().peekable());
        let mut path = BString::default();
        loop {
            let (name, old, new) = match (olds.peek(), news.peek()) {
                (Some((old, _)), Some((new, _))) if old < new => {
                    let Some((name, entry)) = olds.next() else {
                        break;
                    };
                    (name, Some(*entry), None)
                }
                (Some((old, _)), Some((new, _))) if old == new => {
                    let (Some((name, old)), Some((_, new))) = (olds.next(), news.next()) else {
                        break;
                    };
                    (name, Some(*old), Some(*new))
                }
                (_, Some(_)) => {
                    let Some((name, entry)) = news.next() else {
                        break;
                    };
                    (name, None, Some(*entry))
                }
                (Some(_), None) => {
                    let Some((name, entry)) = olds.next() else {
                        break;
                    };
                    (name, Some(*entry), None)
                }
                (None, None) => break,
            };
            if self.interrupt.load(Ordering::Relaxed) {
                return Err(StoreError::Interrupted);
            }
            if old == new {
                continue;
            }
            path.clear();
            if !prefix.is_empty() {
                path.push_str(prefix);
                path.push_byte(b'/');
            }
            path.push_str(name);
            if !safe_name(name.as_bstr(), new.or(old)) {
                self.leave(path.clone(), Left::UnsafeName);
                continue;
            }
            self.entry(dir, name.as_bstr(), (old, new), path.as_bstr(), depth)?;
        }
        Ok(())
    }

    fn entry(
        &mut self,
        dir: &OwnedFd,
        name: &BStr,
        (old, new): (Side, Side),
        path: &BStr,
        depth: usize,
    ) -> Result<(), StoreError> {
        let tree = |entry: Side| entry.filter(|(mode, _)| mode.is_tree()).map(|(_, id)| id);
        let leaf = |entry: Side| entry.filter(|(mode, _)| !mode.is_tree() && !mode.is_commit());
        let (old_tree, new_tree) = (tree(old), tree(new));
        if leaf(old).is_some() && new_tree.is_some() && !self.remove_leaf(dir, name, path) {
            return Ok(());
        }
        if old_tree.is_some() || new_tree.is_some() {
            if depth + 1 >= MAX_SNAPSHOT_DEPTH {
                self.leave(path.to_owned(), Left::TooDeep);
                return Ok(());
            }
            match open_directory(dir, name, new_tree.is_some()) {
                Opened::Directory(child) => {
                    self.directory(&child, old_tree, new_tree, path, depth + 1)?;
                }
                Opened::Missing => {}
                Opened::Blocked => {
                    self.leave(path.to_owned(), Left::Blocked);
                    return Ok(());
                }
                Opened::Unreadable => {
                    self.leave(path.to_owned(), Left::Unwritable);
                    return Ok(());
                }
            }
            if new_tree.is_none() {
                match unlinkat(dir, name.as_bytes(), AtFlags::REMOVEDIR) {
                    Ok(()) | Err(Errno::NOENT) => {}
                    Err(_) if leaf(new).is_some() => {
                        self.leave(path.to_owned(), Left::Blocked);
                        return Ok(());
                    }
                    Err(_) => {}
                }
            }
        }
        match (leaf(old), leaf(new)) {
            (old_leaf, Some((mode, id))) => {
                self.write_leaf(dir, name, (mode, id, old_leaf.is_none()), path)
            }
            (Some(_), None) if new_tree.is_none() => {
                self.remove_leaf(dir, name, path);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn remove_leaf(&mut self, dir: &OwnedFd, name: &BStr, path: &BStr) -> bool {
        match statat(dir, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => return true,
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
                self.leave(path.to_owned(), Left::Blocked);
                return false;
            }
            Ok(_) => {}
            Err(_) => {
                self.leave(path.to_owned(), Left::Unwritable);
                return false;
            }
        }
        match unlinkat(dir, name.as_bytes(), AtFlags::empty()) {
            Ok(()) => {
                self.applied.removed += 1;
                true
            }
            Err(Errno::NOENT) => true,
            Err(_) => {
                self.leave(path.to_owned(), Left::Unwritable);
                false
            }
        }
    }

    fn write_leaf(
        &mut self,
        dir: &OwnedFd,
        name: &BStr,
        (mode, id, added): (EntryMode, ObjectId, bool),
        path: &BStr,
    ) -> Result<(), StoreError> {
        if added
            && !matches!(
                statat(dir, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW),
                Err(Errno::NOENT)
            )
        {
            self.leave(path.to_owned(), Left::Blocked);
            return Ok(());
        }
        let limit = if mode.is_link() {
            MAX_LINK_BYTES
        } else {
            MAX_SNAPSHOT_FILE_BYTES
        };
        let size = match self.store.bounded_size(id, Kind::Blob, limit) {
            Ok(size) if size <= self.budget => size,
            Ok(_) | Err(StoreError::TooLarge { .. }) => {
                self.leave(path.to_owned(), Left::TooLarge);
                return Ok(());
            }
            Err(StoreError::WrongObject { .. }) => {
                self.leave(path.to_owned(), Left::Unwritable);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if mode.is_link() {
            self.budget -= size;
        }
        let bytes = self.store.read_blob(id, limit)?;
        let mut temporary = std::mem::take(&mut self.temporary);
        temporary.clear();
        let random = mahi_core::ThreadId::random().map_err(io::Error::other)?;
        let _ = write!(temporary, "{TEMPORARY_PREFIX}{random}");
        self.place(dir, name, (mode, &bytes), &temporary, path);
        self.temporary = temporary;
        Ok(())
    }

    fn place(
        &mut self,
        dir: &OwnedFd,
        name: &BStr,
        (mode, bytes): (EntryMode, &[u8]),
        temporary: &str,
        path: &BStr,
    ) {
        let written = if mode.is_link() {
            symlinkat(bytes, dir, temporary).map_err(io::Error::from)
        } else {
            self.write_converted(dir, temporary, bytes, path, mode.is_executable())
        };
        if let Err(error) = written {
            let _ = unlinkat(dir, temporary, AtFlags::empty());
            let why = if error.kind() == io::ErrorKind::FileTooLarge {
                Left::TooLarge
            } else {
                Left::Unwritable
            };
            self.leave(path.to_owned(), why);
            return;
        }
        match renameat(dir, temporary, dir, name.as_bytes()) {
            Ok(()) => self.applied.written += 1,
            Err(error) => {
                let _ = unlinkat(dir, temporary, AtFlags::empty());
                let why = if matches!(error, Errno::ISDIR | Errno::NOTEMPTY | Errno::EXIST) {
                    Left::Blocked
                } else {
                    Left::Unwritable
                };
                self.leave(path.to_owned(), why);
            }
        }
    }

    fn write_converted(
        &mut self,
        dir: &OwnedFd,
        temporary: &str,
        bytes: &[u8],
        path: &BStr,
        executable: bool,
    ) -> io::Result<()> {
        let WorktreePipeline { filter, attributes } = &mut self.pipeline;
        let entry = attributes
            .at_entry(path, None, &self.store.repo.objects)
            .map_err(io::Error::other)?;
        let outcome = filter
            .convert_to_worktree(
                bytes,
                path,
                &mut |_, outcome| {
                    entry.matching_attributes(outcome);
                },
                to_worktree::Options {
                    can_delay: Delay::Forbid,
                    ..to_worktree::Options::default()
                },
            )
            .map_err(io::Error::other)?;
        match outcome {
            ToWorktreeOutcome::Unchanged(bytes) | ToWorktreeOutcome::Buffer(bytes) => {
                let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                if length > self.budget {
                    return Err(io::ErrorKind::FileTooLarge.into());
                }
                self.budget -= length;
                write_file(dir, temporary, bytes, executable)
            }
            ToWorktreeOutcome::Process(_) => {
                Err(io::Error::other("a filter process was asked for"))
            }
        }
    }
}

fn safe_name(name: &BStr, entry: Option<(EntryMode, ObjectId)>) -> bool {
    let mode = entry.and_then(|(mode, _)| {
        if mode.is_link() {
            Some(gix_validate::path::component::Mode::Symlink)
        } else {
            None
        }
    });
    gix_validate::path::component(
        name,
        mode,
        gix_validate::path::component::Options {
            protect_windows: false,
            ..gix_validate::path::component::Options::default()
        },
    )
    .is_ok()
        && !name.starts_with(TEMPORARY_PREFIX.as_bytes())
}

fn open_directory(dir: &OwnedFd, name: &BStr, create: bool) -> Opened {
    let open = || {
        openat(
            dir,
            name.as_bytes(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    };
    match open() {
        Ok(child) => return Opened::Directory(child),
        Err(Errno::NOENT) if create => {}
        Err(Errno::NOENT) => return Opened::Missing,
        Err(Errno::LOOP | Errno::NOTDIR) => return Opened::Blocked,
        Err(_) => return Opened::Unreadable,
    }
    match mkdirat(dir, name.as_bytes(), Mode::from_raw_mode(0o755)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(Errno::NOTDIR | Errno::LOOP) => return Opened::Blocked,
        Err(_) => return Opened::Unreadable,
    }
    open().map_or(Opened::Blocked, Opened::Directory)
}

fn write_file(dir: &OwnedFd, name: &str, bytes: &[u8], executable: bool) -> io::Result<()> {
    let mode = if executable { 0o755 } else { 0o644 };
    let fd = openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode),
    )?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)?;
    file.sync_data()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{
            PermissionsExt,
            symlink,
        },
        path::PathBuf,
    };

    use gix::objs::tree::EntryKind;
    use mahi_core::{
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use tempfile::TempDir;

    use super::*;

    struct Repo {
        dir: TempDir,
        store: Store,
    }

    impl Repo {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            gix::init(dir.path().join("repo")).unwrap();
            let store = Store::open(&dir.path().join("repo")).unwrap();
            Self { dir, store }
        }

        fn tree(&self, files: &[(&str, &[u8])]) -> ObjectId {
            self.tree_of(files, &[])
        }

        fn tree_of(&self, files: &[(&str, &[u8])], dirs: &[(&str, ObjectId)]) -> ObjectId {
            let mut entries: Vec<(&str, EntryKind, ObjectId)> = files
                .iter()
                .map(|(name, bytes)| {
                    (
                        *name,
                        EntryKind::Blob,
                        self.store.write_blob(bytes).unwrap(),
                    )
                })
                .collect();
            entries.extend(dirs.iter().map(|(name, id)| (*name, EntryKind::Tree, *id)));
            self.store.write_tree(&entries).unwrap()
        }

        fn worktree(&self, tree: ObjectId) -> PathBuf {
            let r = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
            let commit = self.store.append(&r, None, tree, "ours").unwrap();
            self.store
                .add_worktree(
                    "agent",
                    &self.dir.path().join("agent"),
                    commit,
                    &AtomicBool::new(false),
                )
                .unwrap()
        }

        fn merge(&self, base: ObjectId, ours: ObjectId, theirs: ObjectId) -> Merged {
            self.store
                .merge_trees(base, ours, theirs, ("alice.claude", "bob.codex"))
                .unwrap()
        }

        fn apply(&self, ours: ObjectId, merged: ObjectId) -> Applied {
            self.store
                .apply_merge("agent", ours, merged, &AtomicBool::new(false))
                .unwrap()
        }
    }

    #[test]
    fn both_sides_changes_are_merged_and_only_what_differs_is_written() {
        let repo = Repo::new();
        let base = repo.tree(&[("a.txt", b"1\n2\n3\n"), ("b.txt", b"b\n")]);
        let ours = repo.tree(&[("a.txt", b"1 ours\n2\n3\n"), ("b.txt", b"b\n")]);
        let lib = repo.tree(&[("c.rs", b"fn c() {}\n")]);
        let theirs = repo.tree_of(&[("a.txt", b"1\n2\n3 theirs\n")], &[("lib", lib)]);
        let merged = repo.merge(base, ours, theirs);
        assert!(merged.conflicts.is_empty(), "{:?}", merged.conflicts);

        let worktree = repo.worktree(ours);
        fs::write(worktree.join("untracked.txt"), "mine").unwrap();
        let applied = repo.apply(ours, merged.tree);
        assert_eq!(
            applied,
            Applied {
                written: 2,
                removed: 1,
                left: Vec::new()
            }
        );
        assert_eq!(
            fs::read_to_string(worktree.join("a.txt")).unwrap(),
            "1 ours\n2\n3 theirs\n"
        );
        assert_eq!(
            fs::read_to_string(worktree.join("lib/c.rs")).unwrap(),
            "fn c() {}\n"
        );
        assert!(!worktree.join("b.txt").exists());
        assert_eq!(
            fs::read_to_string(worktree.join("untracked.txt")).unwrap(),
            "mine"
        );
        let leftovers: Vec<_> = fs::read_dir(&worktree)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(TEMPORARY_PREFIX))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn lines_both_sides_changed_differently_get_labelled_conflict_markers() {
        let repo = Repo::new();
        let base = repo.tree(&[("a.txt", b"one\n")]);
        let ours = repo.tree(&[("a.txt", b"ours\n")]);
        let theirs = repo.tree(&[("a.txt", b"theirs\n")]);
        let merged = repo.merge(base, ours, theirs);
        assert_eq!(merged.conflicts, [("a.txt".into(), Conflict::Markers)]);
        let worktree = repo.worktree(ours);
        repo.apply(ours, merged.tree);
        let text = fs::read_to_string(worktree.join("a.txt")).unwrap();
        assert!(text.contains("<<<<<<< alice.claude\nours\n"), "{text}");
        assert!(text.contains("theirs\n>>>>>>> bob.codex\n"), "{text}");
    }

    #[test]
    fn a_change_against_a_deletion_or_two_binary_changes_keep_ours() {
        let repo = Repo::new();
        let base = repo.tree(&[("gone.txt", b"x\n"), ("image.bin", b"\0base")]);
        let ours = repo.tree(&[("image.bin", b"\0ours")]);
        let theirs = repo.tree(&[("gone.txt", b"changed\n"), ("image.bin", b"\0theirs")]);
        let merged = repo.merge(base, ours, theirs);
        assert_eq!(
            merged.conflicts,
            [
                ("gone.txt".into(), Conflict::KeptOurs),
                ("image.bin".into(), Conflict::KeptOurs)
            ]
        );
        let entries = repo.store.entries(Some(merged.tree)).unwrap();
        let image = entries.get(BStr::new("image.bin")).unwrap().1;
        assert_eq!(repo.store.read_blob(image, 64).unwrap(), b"\0ours");
    }

    #[test]
    fn a_link_or_file_in_the_way_is_left_and_nothing_is_written_through_it() {
        let repo = Repo::new();
        let base = repo.tree(&[("keep.txt", b"k\n")]);
        let ours = base;
        let src = repo.tree(&[("new.rs", b"new\n")]);
        let docs = repo.tree(&[("guide.md", b"guide\n")]);
        let theirs = repo.tree_of(&[("keep.txt", b"k\n")], &[("src", src), ("docs", docs)]);
        let merged = repo.merge(base, ours, theirs);
        let worktree = repo.worktree(ours);
        let outside = repo.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, worktree.join("src")).unwrap();
        fs::write(worktree.join("docs"), "a file").unwrap();
        let applied = repo.apply(ours, merged.tree);
        assert_eq!(
            applied.left,
            [
                ("docs".into(), Left::Blocked),
                ("src".into(), Left::Blocked)
            ]
        );
        assert_eq!(applied.written, 0);
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        assert_eq!(fs::read_to_string(worktree.join("docs")).unwrap(), "a file");
    }

    #[test]
    fn a_directory_where_a_file_should_be_is_left_and_a_file_becomes_a_directory() {
        let repo = Repo::new();
        let base = repo.tree(&[("notes", b"n\n"), ("plan", b"p\n")]);
        let ours = base;
        let notes = repo.tree(&[("today.md", b"today\n")]);
        let theirs = repo.tree_of(&[("plan", b"p2\n")], &[("notes", notes)]);
        let merged = repo.merge(base, ours, theirs);
        let worktree = repo.worktree(ours);
        fs::remove_file(worktree.join("plan")).unwrap();
        fs::create_dir(worktree.join("plan")).unwrap();
        fs::write(worktree.join("plan/inside"), "x").unwrap();
        let applied = repo.apply(ours, merged.tree);
        assert_eq!(applied.left, [("plan".into(), Left::Blocked)]);
        assert_eq!(
            fs::read_to_string(worktree.join("notes/today.md")).unwrap(),
            "today\n"
        );
        assert!(worktree.join("plan/inside").exists());
    }

    #[test]
    fn merge_drivers_and_filters_from_git_config_never_run() {
        let repo = Repo::new();
        let ran = repo.dir.path().join("ran");
        let config = repo.dir.path().join("repo/.git/config");
        let mut text = fs::read_to_string(&config).unwrap();
        for (section, key) in [("merge \"evil\"", "driver"), ("filter \"evil\"", "smudge")] {
            writeln!(text, "[{section}]\n\t{key} = touch {}", ran.display()).unwrap();
        }
        fs::write(&config, text).unwrap();
        let repo = Repo {
            store: Store::open(&repo.dir.path().join("repo")).unwrap(),
            dir: repo.dir,
        };
        let attributes: &[u8] = b"* merge=evil filter=evil\n";
        let base = repo.tree(&[(".gitattributes", attributes), ("a.txt", b"one\n")]);
        let ours = repo.tree(&[(".gitattributes", attributes), ("a.txt", b"ours\n")]);
        let theirs = repo.tree(&[
            (".gitattributes", attributes),
            ("a.txt", b"theirs\n"),
            ("b.txt", b"b\n"),
        ]);
        let merged = repo.merge(base, ours, theirs);
        assert_eq!(merged.conflicts, [("a.txt".into(), Conflict::Markers)]);
        let worktree = repo.worktree(ours);
        let applied = repo.apply(ours, merged.tree);
        assert_eq!(applied.written, 2);
        assert_eq!(fs::read_to_string(worktree.join("b.txt")).unwrap(), "b\n");
        assert!(!ran.exists());
    }

    fn raw_tree(repo: &Repo, entries: &[(&str, EntryKind, ObjectId)]) -> ObjectId {
        let mut tree = gix::objs::Tree {
            entries: entries
                .iter()
                .map(|(name, kind, oid)| gix::objs::tree::Entry {
                    mode: (*kind).into(),
                    filename: (*name).into(),
                    oid: *oid,
                })
                .collect(),
        };
        tree.entries.sort();
        repo.store.repo.write_object(&tree).unwrap().detach()
    }

    #[test]
    fn an_unsafe_name_or_a_non_blob_entry_is_listed_and_the_rest_is_written() {
        let repo = Repo::new();
        let base = repo.tree(&[("keep.txt", b"k\n")]);
        let ours = base;
        let hook = repo.store.write_blob(b"evil").unwrap();
        let inner = repo.tree(&[("x", b"x")]);
        let fine = repo.store.write_blob(b"fine\n").unwrap();
        let keep = repo.store.write_blob(b"k\n").unwrap();
        let theirs = raw_tree(
            &repo,
            &[
                (".git", EntryKind::Blob, hook),
                ("fake.txt", EntryKind::Blob, inner),
                ("fine.txt", EntryKind::Blob, fine),
                ("keep.txt", EntryKind::Blob, keep),
            ],
        );
        let worktree = repo.worktree(ours);
        let applied = repo.apply(ours, theirs);
        assert_eq!(
            applied.left,
            [
                (".git".into(), Left::UnsafeName),
                ("fake.txt".into(), Left::Unwritable)
            ]
        );
        assert_eq!(
            fs::read_to_string(worktree.join("fine.txt")).unwrap(),
            "fine\n"
        );
    }

    #[test]
    fn an_unreadable_directory_is_listed_and_the_rest_is_written() {
        let repo = Repo::new();
        let locked = repo.tree(&[("a", b"a\n")]);
        let base = repo.tree_of(&[("top.txt", b"1\n")], &[("locked", locked)]);
        let ours = base;
        let changed = repo.tree(&[("a", b"changed\n")]);
        let theirs = repo.tree_of(&[("top.txt", b"2\n")], &[("locked", changed)]);
        let worktree = repo.worktree(ours);
        fs::set_permissions(worktree.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
        let applied = repo.apply(ours, theirs);
        fs::set_permissions(worktree.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(applied.left, [("locked".into(), Left::Unwritable)]);
        assert_eq!(fs::read_to_string(worktree.join("top.txt")).unwrap(), "2\n");
        assert_eq!(
            fs::read_to_string(worktree.join("locked/a")).unwrap(),
            "a\n"
        );
    }

    #[test]
    fn a_file_the_snapshot_did_not_record_is_not_replaced_by_an_added_one() {
        let repo = Repo::new();
        let base = repo.tree(&[("keep.txt", b"k\n")]);
        let ours = base;
        let theirs = repo.tree(&[("keep.txt", b"k\n"), ("build.log", b"theirs\n")]);
        let worktree = repo.worktree(ours);
        fs::write(worktree.join("build.log"), "ignored but mine").unwrap();
        let applied = repo.apply(ours, theirs);
        assert_eq!(applied.left, [("build.log".into(), Left::Blocked)]);
        assert_eq!(
            fs::read_to_string(worktree.join("build.log")).unwrap(),
            "ignored but mine"
        );
    }

    #[test]
    fn files_past_the_write_budget_are_left_as_too_large() {
        let repo = Repo::new();
        let base = repo.tree(&[("keep.txt", b"k\n")]);
        let ours = base;
        let theirs = repo.tree(&[
            ("a.txt", b"0123456789"),
            ("b.txt", b"0123456789"),
            ("keep.txt", b"k\n"),
        ]);
        let worktree = repo.worktree(ours);
        let applied = repo
            .store
            .apply_merge_within("agent", (ours, theirs), 15, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(applied.written, 1);
        assert_eq!(applied.left, [("b.txt".into(), Left::TooLarge)]);
        assert!(worktree.join("a.txt").exists());
        assert!(!worktree.join("b.txt").exists());
    }

    #[test]
    fn the_write_budget_counts_files_as_converted_for_the_worktree() {
        let repo = Repo::new();
        let attributes: &[u8] = b"*.txt eol=crlf\n";
        let base = repo.tree(&[(".gitattributes", attributes)]);
        let ours = base;
        let theirs = repo.tree(&[(".gitattributes", attributes), ("a.txt", b"a\nb\nc\nd\n")]);
        let worktree = repo.worktree(ours);
        let applied = repo
            .store
            .apply_merge_within("agent", (ours, theirs), 10, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(applied.left, [("a.txt".into(), Left::TooLarge)]);
        assert!(!worktree.join("a.txt").exists());
    }

    #[test]
    fn only_exact_renames_are_followed() {
        let repo = Repo::new();
        let text: &[u8] = b"one\ntwo\nthree\nfour\nfive\n";
        let base = repo.tree(&[("old.txt", text)]);
        let ours = repo.tree(&[("old.txt", b"one\ntwo\nthree\nfour\nfive\nsix\n")]);
        let theirs = repo.tree(&[("new.txt", b"one\ntwo\nthree\nfour\nfive!\n")]);
        let merged = repo.merge(base, ours, theirs);
        assert_eq!(merged.conflicts, [("old.txt".into(), Conflict::KeptOurs)]);
        let moved = repo.tree(&[("moved.txt", text)]);
        let merged = repo.merge(base, ours, moved);
        assert!(merged.conflicts.is_empty(), "{:?}", merged.conflicts);
        let entries = repo.store.entries(Some(merged.tree)).unwrap();
        assert_eq!(entries.keys().collect::<Vec<_>>(), [BStr::new("moved.txt")]);
    }

    #[test]
    fn a_temporary_file_left_behind_is_not_recorded_by_snapshots() {
        let repo = Repo::new();
        let ours = repo.tree(&[("keep.txt", b"k\n")]);
        let worktree = repo.worktree(ours);
        fs::write(worktree.join(format!("{TEMPORARY_PREFIX}leftover")), "x").unwrap();
        let snapshot = repo
            .store
            .snapshot(
                "agent",
                &crate::GlobalPatterns::default(),
                &mut crate::SnapshotCache::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(snapshot.tree, ours);
    }

    #[test]
    fn modes_and_links_are_written_as_the_merged_tree_says() {
        let repo = Repo::new();
        let base = repo.tree(&[("run", b"echo\n")]);
        let ours = base;
        let script = repo.store.write_blob(b"echo\n").unwrap();
        let target = repo.store.write_blob(b"run").unwrap();
        let theirs = repo
            .store
            .write_tree(&[
                ("run", EntryKind::BlobExecutable, script),
                ("start", EntryKind::Link, target),
            ])
            .unwrap();
        let merged = repo.merge(base, ours, theirs);
        let worktree = repo.worktree(ours);
        let applied = repo.apply(ours, merged.tree);
        assert_eq!(applied.written, 2);
        let mode = fs::metadata(worktree.join("run"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
        assert_eq!(
            fs::read_link(worktree.join("start")).unwrap(),
            PathBuf::from("run")
        );
    }
}
