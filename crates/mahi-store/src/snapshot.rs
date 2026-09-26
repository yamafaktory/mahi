use std::{
    cell::Cell,
    collections::{
        HashMap,
        HashSet,
    },
    ffi::OsStr,
    fs::{
        self,
        File,
    },
    io::{
        self,
        Read,
    },
    os::{
        fd::OwnedFd,
        unix::ffi::OsStrExt,
    },
    path::{
        Path,
        PathBuf,
    },
    rc::Rc,
};

use gix::{
    ObjectId,
    Repository,
    attrs::search::{
        MetadataCollection,
        Outcome,
    },
    bstr::{
        BStr,
        BString,
        ByteSlice,
        ByteVec,
    },
    filter::plumbing::{
        Pipeline,
        pipeline::convert::ToGitOutcome,
    },
    glob::pattern::Case,
    ignore::search::Ignore,
    index::{
        self,
        AccelerateLookup,
        entry::Mode,
    },
    object::Kind,
    objs::{
        Find as _,
        Tree,
        Write as _,
        tree::{
            Entry,
            EntryKind,
        },
    },
};
use rustix::{
    fs::{
        AtFlags,
        CWD,
        Dir,
        FileType,
        Mode as FsMode,
        OFlags,
        fstat,
        openat,
        readlinkat,
        statat,
    },
    io::Errno,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    Store,
    StoreError,
    store::open_options,
};

/// Files larger than this are left out of snapshots and reported instead.
pub const MAX_SNAPSHOT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Directories nested deeper than this are left out of snapshots and reported instead.
pub const MAX_SNAPSHOT_DEPTH: usize = 256;

const MAX_PATTERN_FILE_BYTES: u64 = 1024 * 1024;
const WORKTREES: &str = "worktrees";
const STAMP_PREFIX: &str = ".mahi-stamp-";
const NO_CACHE: ((i64, i64), u64) = ((i64::MIN, 0), u64::MAX);
const IGNORE_FILE: &[u8] = b".gitignore";
const ATTRIBUTES_FILE: &[u8] = b".gitattributes";

/// User-level pattern files, outside any repository, that snapshots honour.
#[derive(Debug, Clone, Default)]
pub struct GlobalPatterns {
    /// The user's ignore file, such as `~/.config/git/ignore`; `core.excludesFile` wins.
    pub excludes: Option<PathBuf>,
    /// The user's attributes file, such as `~/.config/git/attributes`; `core.attributesFile`
    /// wins.
    pub attributes: Option<PathBuf>,
}

/// Why a path was left out of a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Skipped {
    /// The file is larger than [`MAX_SNAPSHOT_FILE_BYTES`], or a pattern file is larger than
    /// 1 MiB.
    TooLarge,
    /// The file or directory cannot be read.
    Unreadable,
    /// The file cannot be converted as its `.gitattributes` ask, such as an invalid
    /// `working-tree-encoding`.
    Unconvertible,
    /// The name is one git refuses to check out, such as `.GIT` or `git~1`.
    UnsafeName,
    /// A `.gitignore` or `.gitattributes` that is not a regular file, such as a symbolic link.
    NotAFile,
    /// The directory is nested deeper than [`MAX_SNAPSHOT_DEPTH`].
    TooDeep,
}

/// The result of snapshotting a worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The tree recording the worktree.
    pub tree: ObjectId,
    /// Paths left out, and why.
    pub skipped: Vec<(BString, Skipped)>,
    /// How many files were read, rather than taken from the [`SnapshotCache`].
    pub read: usize,
}

/// What is remembered between snapshots of one worktree, so unchanged files are not read again.
///
/// A file's blob is reused when its device, inode, size, modification and change times, mode
/// and owner, the `.gitattributes` rules and index entry that apply to it are all unchanged,
/// and both its modification and change times are earlier than the start of the snapshot that
/// recorded it, measured on the worktree's own file system. A write within the same instant,
/// or one whose modification time was set back, is never missed. Files on another file system
/// than the worktree root are always read, and so is every file when that file system is not
/// one whose change times can be trusted (ext4, xfs, btrfs, tmpfs, f2fs, zfs, bcachefs or
/// overlayfs on Linux, APFS on macOS) or when the worktree root is not writable.
#[derive(Debug, Default)]
pub struct SnapshotCache {
    key: Option<CacheKey>,
    files: HashMap<BString, Cached>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheKey {
    common_dir: (u64, u64),
    name: String,
    root: (u64, u64),
}

#[derive(Debug, Clone)]
struct Cached {
    stat: FileStat,
    attributes: [u8; 32],
    index_id: Option<ObjectId>,
    recorded_at: (i64, i64),
    id: ObjectId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStat {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    mode: u32,
    uid: u32,
}

impl SnapshotCache {
    /// Returns how many files are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Returns whether nothing is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

enum Leaf {
    File(File, FileStat),
    Link(Vec<u8>),
    Directory,
    Other,
}

struct Frame {
    attributes: [u8; 32],
    dir: OwnedFd,
    rela: BString,
    ignored: bool,
    depth: usize,
    name: Vec<u8>,
    names: std::vec::IntoIter<Vec<u8>>,
    entries: Vec<Entry>,
}

enum Step {
    Entry(Entry),
    Descend(OwnedFd, BString, bool),
    Nothing,
}

enum PatternFile {
    Found(Vec<u8>),
    Missing,
    Skip(Skipped),
}

impl Store {
    /// Records the current content of the linked worktree registered as `name`.
    ///
    /// The worktree is found through the repository's own record of it
    /// (`worktrees/<name>`), never through the worktree's `.git` file, which its agent can
    /// rewrite. mahi walks the worktree itself: every directory and file is opened relative to
    /// its parent without following symbolic links and without blocking, and `.gitignore` and
    /// `.gitattributes` are read the same way, capped at 1 MiB and ignored unless they are
    /// regular files. Nothing outside the worktree is ever read.
    ///
    /// The tree is what `git add -A` would record: untracked files matched by `.gitignore`,
    /// `.git`, nested repositories and special files are left out, tracked files are kept even
    /// when ignored, submodule entries are kept, and the same `.gitattributes` conversions
    /// apply, with no filter driver. Paths that cannot be recorded are left out and listed in
    /// [`Snapshot::skipped`] rather than failing the snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotAWorktree`] if `name` is not a linked worktree whose recorded
    /// directory is where it should be, [`StoreError::ChangedDuringSnapshot`] if a path changed
    /// while it was read (the caller should snapshot again), or another [`StoreError`] if the
    /// repository cannot be read or written.
    pub fn snapshot(
        &self,
        name: &str,
        globals: &GlobalPatterns,
        cache: &mut SnapshotCache,
    ) -> Result<Snapshot, StoreError> {
        let (repo, workdir) = self.open_worktree(name)?;
        let index = repo.index_or_empty()?;
        let case = if repo.config_snapshot().boolean("core.ignoreCase") == Some(true) {
            Case::Fold
        } else {
            Case::Sensitive
        };

        let mut filter_options = gix::filter::Pipeline::options(&repo)?;
        filter_options.drivers.clear();
        let root = openat(
            CWD,
            &workdir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            FsMode::empty(),
        )
        .map_err(io::Error::from)?;
        let key = CacheKey {
            common_dir: dev_ino(&rustix::fs::stat(repo.common_dir()).map_err(io::Error::from)?)?,
            name: name.to_owned(),
            root: dev_ino(&fstat(&root).map_err(io::Error::from)?)?,
        };
        if cache.key.as_ref() != Some(&key) {
            *cache = SnapshotCache {
                key: Some(key),
                files: HashMap::new(),
            };
        }
        let (started, stamp_dev) = if trusted_times(&root) {
            stamp(&root).unwrap_or(NO_CACHE)
        } else {
            NO_CACHE
        };

        let mut collection = MetadataCollection::default();
        let attributes = global_attributes(&repo, globals, &mut collection)?;
        let lookup = (case == Case::Fold).then(|| index.prepare_icase_backing());
        let root_attributes = root_fingerprint(&repo, globals, case)?;
        let mut walk = Walk {
            cache_out: HashMap::with_capacity(cache.files.len()),
            cache_in: std::mem::take(&mut cache.files),
            started,
            stamp_dev,
            read: 0,
            ignore: global_ignore(&repo, globals)?,
            attributes,
            collection,
            pipeline: Pipeline::new(repo.command_context()?, filter_options),
            skipped: Vec::new(),
            skipped_paths: HashSet::new(),
            case,
            index: &index,
            lookup,
            repo: &repo,
        };
        let walked = walk.walk(root, root_attributes);
        let mut files = std::mem::take(&mut walk.cache_out);
        if walked.is_err() {
            for (path, cached) in walk.cache_in.drain() {
                files.entry(path).or_insert(cached);
            }
        }
        cache.files = files;
        let tree = match walked? {
            Some(tree) => tree,
            None => repo.write_object(Tree::empty())?.detach(),
        };
        Ok(Snapshot {
            tree,
            skipped: walk.skipped,
            read: walk.read,
        })
    }

    fn open_worktree(&self, name: &str) -> Result<(Repository, PathBuf), StoreError> {
        let not_a_worktree = || StoreError::NotAWorktree(name.to_owned());
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return Err(not_a_worktree());
        }
        let admin = fs::canonicalize(self.common_dir())?
            .join(WORKTREES)
            .join(name);
        let recorded = fs::read(admin.join("gitdir")).map_err(|_| not_a_worktree())?;
        let recorded = recorded.strip_suffix(b"\n").unwrap_or(&recorded);
        let expected = Path::new(OsStr::from_bytes(recorded))
            .parent()
            .ok_or_else(not_a_worktree)?;
        let expected = fs::canonicalize(expected).map_err(|_| not_a_worktree())?;
        let repo = gix::open_opts(&admin, open_options()).map_err(|_| not_a_worktree())?;
        let workdir = repo
            .workdir()
            .map(fs::canonicalize)
            .transpose()?
            .ok_or_else(not_a_worktree)?;
        if workdir != expected
            || fs::canonicalize(repo.git_dir())? != admin
            || repo.config_snapshot().string("core.worktree").is_some()
        {
            return Err(not_a_worktree());
        }
        Ok((repo, workdir))
    }
}

fn global_ignore(
    repo: &Repository,
    globals: &GlobalPatterns,
) -> Result<gix::ignore::Search, StoreError> {
    let configured = repo.config_snapshot().trusted_path("core.excludesFile")?;
    let excludes = configured.or_else(|| globals.excludes.clone());
    let mut buf = Vec::new();
    Ok(gix::ignore::Search::from_git_dir(
        repo.common_dir(),
        excludes,
        &mut buf,
        Ignore::default(),
    )?)
}

fn global_attributes(
    repo: &Repository,
    globals: &GlobalPatterns,
    collection: &mut MetadataCollection,
) -> Result<gix::attrs::Search, StoreError> {
    let configured = repo.config_snapshot().trusted_path("core.attributesFile")?;
    let files: Vec<PathBuf> = configured
        .or_else(|| globals.attributes.clone())
        .into_iter()
        .chain([repo.common_dir().join("info").join("attributes")])
        .collect();
    let mut buf = Vec::new();
    Ok(gix::attrs::Search::new_globals(
        files, &mut buf, collection,
    )?)
}

struct Walk<'a> {
    cache_in: HashMap<BString, Cached>,
    cache_out: HashMap<BString, Cached>,
    started: (i64, i64),
    stamp_dev: u64,
    read: usize,
    ignore: gix::ignore::Search,
    attributes: gix::attrs::Search,
    collection: MetadataCollection,
    pipeline: Pipeline,
    skipped: Vec<(BString, Skipped)>,
    skipped_paths: HashSet<BString>,
    case: Case,
    index: &'a index::State,
    lookup: Option<AccelerateLookup<'a>>,
    repo: &'a Repository,
}

impl<'a> Walk<'a> {
    fn walk(
        &mut self,
        root: OwnedFd,
        root_attributes: [u8; 32],
    ) -> Result<Option<ObjectId>, StoreError> {
        let mut stack = vec![self.enter(
            root,
            BString::default(),
            false,
            0,
            Vec::new(),
            root_attributes,
        )?];
        loop {
            let Some(frame) = stack.last_mut() else {
                return Ok(None);
            };
            if let Some(name) = frame.names.next() {
                let rela = join(&frame.rela, &name);
                let (ignored, depth, attributes) = (frame.ignored, frame.depth, frame.attributes);
                match self.step(&frame.dir, &name, rela, ignored, depth, attributes)? {
                    Step::Entry(entry) => frame.entries.push(entry),
                    Step::Nothing => {}
                    Step::Descend(child, prefix, child_ignored) => {
                        let child =
                            self.enter(child, prefix, child_ignored, depth + 1, name, attributes)?;
                        stack.push(child);
                    }
                }
                continue;
            }
            let Some(frame) = stack.pop() else {
                return Ok(None);
            };
            self.ignore.patterns.pop();
            self.attributes.pop_pattern_list();
            let tree = self.write_tree(frame.entries)?;
            match (stack.last_mut(), tree) {
                (None, tree) => return Ok(tree),
                (Some(parent), Some(tree)) => parent.entries.push(Entry {
                    mode: EntryKind::Tree.into(),
                    filename: frame.name.into(),
                    oid: tree,
                }),
                (Some(_), None) => {}
            }
        }
    }

    fn write_tree(&self, mut entries: Vec<Entry>) -> Result<Option<ObjectId>, StoreError> {
        if entries.is_empty() {
            return Ok(None);
        }
        entries.sort();
        Ok(Some(self.repo.write_object(&Tree { entries })?.detach()))
    }

    fn enter(
        &mut self,
        dir: OwnedFd,
        rela: BString,
        ignored: bool,
        depth: usize,
        name: Vec<u8>,
        parent_attributes: [u8; 32],
    ) -> Result<Frame, StoreError> {
        let ignore_source = join(&rela, IGNORE_FILE);
        let ignore_file = if ignored {
            PatternFile::Missing
        } else {
            read_pattern_file(&dir, IGNORE_FILE)?
        };
        let ignore_bytes = self.found_or_record(ignore_file, &ignore_source);
        self.ignore.add_patterns_buffer(
            &ignore_bytes,
            gix::path::from_bstr(ignore_source.as_bstr()).into_owned(),
            Some(Path::new("")),
            Ignore::default(),
        );
        let attributes_source = join(&rela, ATTRIBUTES_FILE);
        let attributes_file = read_pattern_file(&dir, ATTRIBUTES_FILE)?;
        let attributes_bytes = self.found_or_record(attributes_file, &attributes_source);
        let attributes: [u8; 32] = Sha256::new()
            .chain_update(parent_attributes)
            .chain_update((attributes_bytes.len() as u64).to_le_bytes())
            .chain_update(&attributes_bytes)
            .finalize()
            .into();
        self.attributes.add_patterns_buffer(
            &attributes_bytes,
            gix::path::from_bstr(attributes_source.as_bstr()).into_owned(),
            Some(Path::new("")),
            &mut self.collection,
            rela.is_empty(),
        );

        let mut names: Vec<Vec<u8>> = Vec::new();
        for entry in Dir::read_from(&dir).map_err(io::Error::from)? {
            let entry = entry.map_err(io::Error::from)?;
            let entry_name = entry.file_name().to_bytes();
            if entry_name != b"."
                && entry_name != b".."
                && entry_name != b".git"
                && !entry_name.starts_with(STAMP_PREFIX.as_bytes())
            {
                names.push(entry_name.to_vec());
            }
        }
        Ok(Frame {
            attributes,
            dir,
            rela,
            ignored,
            depth,
            name,
            names: names.into_iter(),
            entries: Vec::new(),
        })
    }

    fn step(
        &mut self,
        dir: &OwnedFd,
        name: &[u8],
        rela: BString,
        dir_ignored: bool,
        depth: usize,
        attributes: [u8; 32],
    ) -> Result<Step, StoreError> {
        if !safe_name(name) {
            self.skipped.push((rela, Skipped::UnsafeName));
            return Ok(Step::Nothing);
        }
        let leaf = match open_entry(dir, name) {
            Ok(leaf) => leaf,
            Err(Errno::NOENT) => return Ok(Step::Nothing),
            Err(Errno::ACCESS | Errno::PERM) => {
                self.skip_once(rela, Skipped::Unreadable);
                return Ok(Step::Nothing);
            }
            Err(Errno::LOOP | Errno::NOTDIR | Errno::MLINK) => {
                return Err(StoreError::ChangedDuringSnapshot(rela));
            }
            Err(error) => return Err(StoreError::Io(error.into())),
        };
        let tracked = self.tracked(rela.as_bstr());
        let index = self.index;
        let filename: BString = tracked.map_or_else(
            || name.into(),
            |entry| {
                let path = entry.path(index);
                path.rfind_byte(b'/')
                    .map_or(path, |slash| &path[slash + 1..])
                    .into()
            },
        );
        let entry = |mode: EntryKind, oid: ObjectId| {
            Step::Entry(Entry {
                mode: mode.into(),
                filename: filename.clone(),
                oid,
            })
        };
        match leaf {
            Leaf::Directory => {
                if let Some(gitlink) = tracked.filter(|entry| entry.mode == Mode::COMMIT) {
                    return Ok(entry(EntryKind::Commit, gitlink.id));
                }
                let mut prefix = rela.clone();
                prefix.push(b'/');
                let tracks_under = self.tracks_under(prefix.as_bstr());
                let ignored = dir_ignored || self.is_ignored(rela.as_bstr(), true);
                if ignored && !tracks_under {
                    return Ok(Step::Nothing);
                }
                if depth + 1 > MAX_SNAPSHOT_DEPTH {
                    self.skipped.push((rela, Skipped::TooDeep));
                    return Ok(Step::Nothing);
                }
                let child = match openat(
                    dir,
                    OsStr::from_bytes(name),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    FsMode::empty(),
                ) {
                    Ok(child) => child,
                    Err(Errno::ACCESS | Errno::PERM) => {
                        self.skip_once(rela, Skipped::Unreadable);
                        return Ok(Step::Nothing);
                    }
                    Err(Errno::NOENT) => return Ok(Step::Nothing),
                    Err(Errno::LOOP | Errno::NOTDIR | Errno::MLINK) => {
                        return Err(StoreError::ChangedDuringSnapshot(rela));
                    }
                    Err(error) => return Err(StoreError::Io(error.into())),
                };
                if !tracks_under && statat(&child, ".git", AtFlags::SYMLINK_NOFOLLOW).is_ok() {
                    return Ok(Step::Nothing);
                }
                Ok(Step::Descend(child, prefix, ignored))
            }
            Leaf::Link(target) => {
                if tracked.is_none() && (dir_ignored || self.is_ignored(rela.as_bstr(), false)) {
                    return Ok(Step::Nothing);
                }
                let id = self.repo.write_blob(&target)?.detach();
                Ok(entry(EntryKind::Link, id))
            }
            Leaf::File(file, stat) => {
                if tracked.is_none() && (dir_ignored || self.is_ignored(rela.as_bstr(), false)) {
                    return Ok(Step::Nothing);
                }
                let kind = if stat.mode & 0o100 != 0 {
                    EntryKind::BlobExecutable
                } else {
                    EntryKind::Blob
                };
                let index_id = tracked.map(|entry| entry.id);
                Ok(self
                    .file_id(rela, file, stat, attributes, index_id)?
                    .map_or(Step::Nothing, |id| entry(kind, id)))
            }
            Leaf::Other => Ok(Step::Nothing),
        }
    }

    fn file_id(
        &mut self,
        rela: BString,
        file: File,
        stat: FileStat,
        attributes: [u8; 32],
        index_id: Option<ObjectId>,
    ) -> Result<Option<ObjectId>, StoreError> {
        if stat.size > MAX_SNAPSHOT_FILE_BYTES {
            self.skipped.push((rela, Skipped::TooLarge));
            return Ok(None);
        }
        let stamp_dev = self.stamp_dev;
        let cached = self.cache_in.remove(&rela).filter(|cached| {
            cached.stat == stat
                && cached.attributes == attributes
                && cached.index_id == index_id
                && stat.dev == stamp_dev
                && stat.mtime < cached.recorded_at
                && stat.ctime < cached.recorded_at
        });
        let id = if let Some(cached) = cached {
            cached.id
        } else {
            self.read += 1;
            let Some(id) = self.hash_file(&rela, file, stat.size)? else {
                self.skipped.push((rela, Skipped::Unconvertible));
                return Ok(None);
            };
            id
        };
        self.cache_out.insert(
            rela,
            Cached {
                stat,
                attributes,
                index_id,
                recorded_at: self.started,
                id,
            },
        );
        Ok(Some(id))
    }

    fn tracked(&self, rela: &BStr) -> Option<&'a index::Entry> {
        match &self.lookup {
            Some(lookup) => self.index.entry_by_path_icase(rela, true, lookup),
            None => self.index.entry_by_path(rela),
        }
    }

    fn skip_once(&mut self, rela: BString, reason: Skipped) {
        if self.skipped_paths.insert(rela.clone()) {
            self.skipped.push((rela, reason));
        }
    }

    fn is_ignored(&self, rela: &BStr, is_dir: bool) -> bool {
        self.ignore
            .pattern_matching_relative_path(rela, Some(is_dir), self.case)
            .is_some_and(|found| !found.pattern.is_negative())
    }

    fn tracks_under(&self, prefix: &BStr) -> bool {
        self.index
            .prefixed_entries(prefix)
            .is_some_and(|entries| !entries.is_empty())
    }

    fn found_or_record(&mut self, file: PatternFile, source: &BString) -> Vec<u8> {
        match file {
            PatternFile::Found(bytes) => bytes,
            PatternFile::Missing => Vec::new(),
            PatternFile::Skip(reason) => {
                self.skip_once(source.clone(), reason);
                Vec::new()
            }
        }
    }

    fn hash_file(
        &mut self,
        rela: &BString,
        file: File,
        size: u64,
    ) -> Result<Option<ObjectId>, StoreError> {
        let short = Rc::new(Cell::new(false));
        let exact = ExactReader {
            inner: file.take(size),
            left: size,
            short: Rc::clone(&short),
        };
        let path = gix::path::from_bstr(rela.as_bstr()).into_owned();
        let (attributes, collection, case) = (&self.attributes, &self.collection, self.case);
        let (index, repo) = (self.index, self.repo);
        let converted = self.pipeline.convert_to_git(
            exact,
            &path,
            &mut |rela_path: &BStr, out: &mut Outcome| {
                out.initialize(collection);
                attributes.pattern_matching_relative_path(rela_path, case, Some(false), out);
            },
            &mut |buf| {
                let Some(entry) = index.entry_by_path(rela.as_bstr()) else {
                    return Ok(None);
                };
                let object = repo.objects.try_find(&entry.id, buf)?;
                Ok(object.filter(|o| o.kind == Kind::Blob).map(|_| ()))
            },
        );
        let outcome = match converted {
            Ok(outcome) => outcome,
            Err(_) if short.get() => {
                return Err(StoreError::ChangedDuringSnapshot(rela.clone()));
            }
            Err(_) => return Ok(None),
        };
        let id = match outcome {
            ToGitOutcome::Unchanged(mut reader) => {
                match self
                    .repo
                    .objects
                    .write_stream(Kind::Blob, size, &mut reader)
                {
                    Ok(id) => id,
                    Err(_) if short.get() => {
                        return Err(StoreError::ChangedDuringSnapshot(rela.clone()));
                    }
                    Err(error) => return Err(StoreError::Git(error.into())),
                }
            }
            ToGitOutcome::Buffer(buffer) => self.repo.write_blob(buffer)?.detach(),
            ToGitOutcome::Process(_) => return Ok(None),
        };
        Ok(Some(id))
    }
}

struct ExactReader<R> {
    inner: R,
    left: u64,
    short: Rc<Cell<bool>>,
}

impl<R: Read> Read for ExactReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        if read == 0 && self.left > 0 && !buf.is_empty() {
            self.short.set(true);
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= read as u64;
        Ok(read)
    }
}

fn join(dir: &BString, name: &[u8]) -> BString {
    let mut path = dir.clone();
    path.push_str(name);
    path
}

fn safe_name(name: &[u8]) -> bool {
    gix_validate::path::component(
        name.as_bstr(),
        None,
        gix_validate::path::component::Options {
            protect_windows: false,
            ..gix_validate::path::component::Options::default()
        },
    )
    .is_ok()
}

fn open_entry(dir: &OwnedFd, name: &[u8]) -> Result<Leaf, Errno> {
    let name = OsStr::from_bytes(name);
    let stat = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => Ok(Leaf::Directory),
        FileType::Symlink => Ok(Leaf::Link(readlinkat(dir, name, Vec::new())?.into_bytes())),
        FileType::RegularFile => {
            let fd = openat(
                dir,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                FsMode::empty(),
            )?;
            let stat = fstat(&fd)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(Errno::MLINK);
            }
            Ok(Leaf::File(File::from(fd), file_stat(&stat)?))
        }
        _ => Ok(Leaf::Other),
    }
}

fn convert<T: TryInto<U>, U>(value: T) -> Result<U, Errno> {
    value.try_into().map_err(|_| Errno::INVAL)
}

fn file_stat(stat: &rustix::fs::Stat) -> Result<FileStat, Errno> {
    Ok(FileStat {
        dev: convert(stat.st_dev)?,
        ino: convert(stat.st_ino)?,
        size: convert(stat.st_size)?,
        mtime: (convert(stat.st_mtime)?, convert(stat.st_mtime_nsec)?),
        ctime: (convert(stat.st_ctime)?, convert(stat.st_ctime_nsec)?),
        mode: convert(stat.st_mode)?,
        uid: convert(stat.st_uid)?,
    })
}

fn stamp(root: &OwnedFd) -> Result<((i64, i64), u64), StoreError> {
    let random = mahi_core::ThreadId::random().map_err(io::Error::other)?;
    let name = format!("{STAMP_PREFIX}{random}");
    let fd = openat(
        root,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        FsMode::from_raw_mode(0o600),
    )
    .map_err(io::Error::from)?;
    let stat = fstat(&fd).map_err(io::Error::from);
    let removed = rustix::fs::unlinkat(root, name.as_str(), AtFlags::empty());
    let stat = file_stat(&stat?).map_err(io::Error::from)?;
    removed.map_err(io::Error::from)?;
    Ok((stat.mtime, stat.dev))
}

#[cfg(target_os = "linux")]
fn trusted_times(root: &OwnedFd) -> bool {
    const TRUSTED: [i64; 8] = [
        0xEF53,
        0x5846_5342,
        0x9123_683E,
        0x0102_1994,
        0xF2F5_2010,
        0x2FC1_2FC1,
        0xCA45_1A4E,
        0x794C_7630,
    ];
    rustix::fs::fstatfs(root)
        .ok()
        .and_then(|stat| convert::<_, i64>(stat.f_type).ok())
        .is_some_and(|kind| TRUSTED.contains(&kind))
}

#[cfg(target_os = "macos")]
fn trusted_times(root: &OwnedFd) -> bool {
    rustix::fs::fstatfs(root).is_ok_and(|stat| {
        let name: Vec<u8> = stat
            .f_fstypename
            .iter()
            .take_while(|byte| **byte != 0)
            .filter_map(|byte| u8::try_from(*byte).ok())
            .collect();
        name == b"apfs"
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn trusted_times(_root: &OwnedFd) -> bool {
    false
}

fn dev_ino(stat: &rustix::fs::Stat) -> Result<(u64, u64), StoreError> {
    Ok((
        convert(stat.st_dev).map_err(io::Error::from)?,
        convert(stat.st_ino).map_err(io::Error::from)?,
    ))
}

fn root_fingerprint(
    repo: &Repository,
    globals: &GlobalPatterns,
    case: Case,
) -> Result<[u8; 32], StoreError> {
    let config = repo.config_snapshot();
    let mut hasher = Sha256::new();
    hasher.update([u8::from(case == Case::Fold)]);
    for key in [
        "core.autocrlf",
        "core.eol",
        "core.safecrlf",
        "core.checkRoundtripEncoding",
        "core.attributesFile",
    ] {
        let value = config.string(key);
        hasher.update(value.as_ref().map_or(&b""[..], |value| value.as_slice()));
        hasher.update([0]);
    }
    let files = [
        config
            .trusted_path("core.attributesFile")?
            .or_else(|| globals.attributes.clone()),
        Some(repo.common_dir().join("info").join("attributes")),
    ];
    for file in files.into_iter().flatten() {
        let mut bytes = Vec::new();
        let read = open_regular(&file).and_then(|opened| {
            opened
                .take(MAX_PATTERN_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
        });
        match read {
            Ok(_) => {
                hasher.update((bytes.len() as u64).to_le_bytes());
                hasher.update(&bytes);
            }
            Err(error) => hasher.update(format!("unreadable {:?}", error.kind())),
        }
    }
    Ok(hasher.finalize().into())
}

fn open_regular(path: &Path) -> io::Result<File> {
    let fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        FsMode::empty(),
    )?;
    if FileType::from_raw_mode(fstat(&fd)?.st_mode) != FileType::RegularFile {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(File::from(fd))
}

fn read_pattern_file(dir: &OwnedFd, name: &[u8]) -> Result<PatternFile, StoreError> {
    match open_entry(dir, name) {
        Ok(Leaf::File(_, stat)) if stat.size > MAX_PATTERN_FILE_BYTES => {
            Ok(PatternFile::Skip(Skipped::TooLarge))
        }
        Ok(Leaf::File(file, stat)) => {
            let mut bytes = Vec::with_capacity(usize::try_from(stat.size).unwrap_or(0));
            file.take(MAX_PATTERN_FILE_BYTES).read_to_end(&mut bytes)?;
            Ok(PatternFile::Found(bytes))
        }
        Ok(Leaf::Link(_) | Leaf::Directory | Leaf::Other) | Err(Errno::MLINK | Errno::LOOP) => {
            Ok(PatternFile::Skip(Skipped::NotAFile))
        }
        Err(Errno::NOENT) => Ok(PatternFile::Missing),
        Err(Errno::ACCESS | Errno::PERM) => Ok(PatternFile::Skip(Skipped::Unreadable)),
        Err(error) => Err(StoreError::Io(error.into())),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{
        PermissionsExt,
        symlink,
    };

    use mahi_core::{
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use tempfile::TempDir;

    use super::*;

    struct Setup {
        dir: TempDir,
        store: Store,
    }

    fn setup() -> Setup {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path().join("repo")).unwrap();
        let store = Store::open(&dir.path().join("repo")).unwrap();
        Setup { dir, store }
    }

    fn base(store: &Store, entries: &[(&str, EntryKind, &[u8])]) -> ObjectId {
        let mut editor = store
            .repo
            .edit_tree(ObjectId::empty_tree(store.repo.object_hash()))
            .unwrap();
        for (path, kind, content) in entries {
            let id = if *kind == EntryKind::Commit {
                ObjectId::from_hex(content).unwrap()
            } else {
                store.write_blob(content).unwrap()
            };
            editor.upsert(*path, *kind, id).unwrap();
        }
        let tree = editor.write().unwrap().detach();
        let r = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        store.append(&r, None, tree, "base").unwrap()
    }

    fn tree_of(store: &Store, commit: ObjectId) -> ObjectId {
        store
            .repo
            .find_commit(commit)
            .unwrap()
            .tree_id()
            .unwrap()
            .detach()
    }

    fn default_base(store: &Store) -> ObjectId {
        base(
            store,
            &[
                ("README.md", EntryKind::Blob, b"hello\n"),
                (
                    ".gitignore",
                    EntryKind::Blob,
                    b"target/\n*.log\n!keep.log\n",
                ),
                ("sub/.gitignore", EntryKind::Blob, b"local.txt\n"),
                ("tracked.log", EntryKind::Blob, b"kept though ignored\n"),
            ],
        )
    }

    fn checkout(setup: &Setup, commit: ObjectId) -> PathBuf {
        setup
            .store
            .add_worktree("agent", &setup.dir.path().join("wt"), commit)
            .unwrap()
    }

    fn snapshot(setup: &Setup) -> Snapshot {
        setup
            .store
            .snapshot(
                "agent",
                &GlobalPatterns::default(),
                &mut SnapshotCache::default(),
            )
            .unwrap()
    }

    fn names(store: &Store, tree: ObjectId) -> Vec<(String, EntryKind)> {
        let tree = store.repo.find_tree(tree).unwrap();
        let mut recorder = gix::traverse::tree::Recorder::default();
        tree.traverse().breadthfirst(&mut recorder).unwrap();
        let mut out: Vec<_> = recorder
            .records
            .into_iter()
            .filter(|entry| entry.mode.kind() != EntryKind::Tree)
            .map(|entry| (entry.filepath.to_string(), entry.mode.kind()))
            .collect();
        out.sort();
        out
    }

    fn only_names(store: &Store, tree: ObjectId) -> Vec<String> {
        names(store, tree)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    fn blob(store: &Store, tree: ObjectId, path: &str) -> Vec<u8> {
        let tree = store.repo.find_tree(tree).unwrap();
        let entry = tree.lookup_entry_by_path(path).unwrap().unwrap();
        store
            .repo
            .find_object(entry.object_id())
            .unwrap()
            .detach()
            .data
    }

    #[cfg(target_os = "linux")]
    fn special_file(path: &Path) {
        rustix::fs::mkfifoat(CWD, path, FsMode::from_raw_mode(0o600)).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    fn special_file(path: &Path) {
        let short = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let socket = short.path().join("s");
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        fs::rename(&socket, path).unwrap();
    }

    fn sorted(mut skipped: Vec<(BString, Skipped)>) -> Vec<(BString, Skipped)> {
        skipped.sort();
        skipped
    }

    #[test]
    fn an_untouched_worktree_snapshots_to_the_base_tree() {
        let setup = setup();
        let commit = default_base(&setup.store);
        checkout(&setup, commit);
        let snapshot = snapshot(&setup);
        assert_eq!(snapshot.tree, tree_of(&setup.store, commit));
        assert!(snapshot.skipped.is_empty());
    }

    #[test]
    fn edits_new_files_modes_links_and_deletions_are_recorded() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        fs::write(path.join("README.md"), b"changed\n").unwrap();
        fs::create_dir_all(path.join("src/deep")).unwrap();
        fs::write(path.join("src/deep/main.rs"), b"fn main() {}\n").unwrap();
        fs::write(path.join("run.sh"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(path.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("README.md", path.join("link")).unwrap();
        fs::remove_file(path.join("tracked.log")).unwrap();

        let tree = snapshot(&setup).tree;
        assert_eq!(
            names(&setup.store, tree),
            [
                (".gitignore".to_owned(), EntryKind::Blob),
                ("README.md".to_owned(), EntryKind::Blob),
                ("link".to_owned(), EntryKind::Link),
                ("run.sh".to_owned(), EntryKind::BlobExecutable),
                ("src/deep/main.rs".to_owned(), EntryKind::Blob),
                ("sub/.gitignore".to_owned(), EntryKind::Blob),
            ]
        );
        assert_eq!(blob(&setup.store, tree, "README.md"), b"changed\n");
        assert_eq!(blob(&setup.store, tree, "link"), b"README.md");
    }

    #[test]
    fn ignore_rules_apply_as_in_git() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        fs::create_dir_all(path.join("target/debug")).unwrap();
        fs::write(path.join("target/debug/big"), b"artifact").unwrap();
        fs::write(path.join("build.log"), b"log").unwrap();
        fs::write(path.join("keep.log"), b"negated").unwrap();
        fs::write(path.join("sub/local.txt"), b"ignored below").unwrap();
        fs::write(path.join("local.txt"), b"not ignored at the top").unwrap();
        gix::init(path.join("vendor")).unwrap();
        fs::write(path.join("vendor/file"), b"nested").unwrap();

        assert_eq!(
            only_names(&setup.store, snapshot(&setup).tree),
            [
                ".gitignore",
                "README.md",
                "keep.log",
                "local.txt",
                "sub/.gitignore",
                "tracked.log",
            ]
        );
    }

    #[test]
    fn tracked_files_in_ignored_directories_are_kept() {
        let setup = setup();
        let commit = base(
            &setup.store,
            &[
                (".gitignore", EntryKind::Blob, b"build/\n"),
                ("build/keep.txt", EntryKind::Blob, b"tracked"),
            ],
        );
        let path = checkout(&setup, commit);
        fs::write(path.join("build/new.txt"), b"untracked").unwrap();
        fs::write(path.join("build/keep.txt"), b"edited").unwrap();
        let tree = snapshot(&setup).tree;
        assert_eq!(
            only_names(&setup.store, tree),
            [".gitignore", "build/keep.txt"]
        );
        assert_eq!(blob(&setup.store, tree, "build/keep.txt"), b"edited");
    }

    #[test]
    fn a_file_replaced_by_a_directory_and_back_is_followed() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        fs::remove_file(path.join("README.md")).unwrap();
        fs::create_dir(path.join("README.md")).unwrap();
        fs::write(path.join("README.md/inner"), b"x").unwrap();
        fs::remove_dir_all(path.join("sub")).unwrap();
        fs::write(path.join("sub"), b"now a file").unwrap();
        assert_eq!(
            only_names(&setup.store, snapshot(&setup).tree),
            [".gitignore", "README.md/inner", "sub", "tracked.log"]
        );
    }

    #[test]
    fn eol_conversions_match_git_so_nothing_looks_changed() {
        let setup = setup();
        let commit = base(
            &setup.store,
            &[
                (".gitattributes", EntryKind::Blob, b"*.txt text eol=crlf\n"),
                ("a.txt", EntryKind::Blob, b"one\ntwo\n"),
            ],
        );
        let path = checkout(&setup, commit);
        assert_eq!(fs::read(path.join("a.txt")).unwrap(), b"one\r\ntwo\r\n");
        assert_eq!(snapshot(&setup).tree, tree_of(&setup.store, commit));
    }

    #[test]
    fn an_unconvertible_file_is_skipped_not_retried() {
        let setup = setup();
        let commit = base(
            &setup.store,
            &[(
                ".gitattributes",
                EntryKind::Blob,
                b"*.u16 working-tree-encoding=UTF-16\n",
            )],
        );
        let path = checkout(&setup, commit);
        fs::write(path.join("bad.u16"), b"abc").unwrap();
        assert_eq!(
            snapshot(&setup).skipped,
            [(BString::from("bad.u16"), Skipped::Unconvertible)]
        );
    }

    #[test]
    fn submodule_entries_are_kept() {
        let setup = setup();
        let commit = base(
            &setup.store,
            &[
                ("README.md", EntryKind::Blob, b"x"),
                (
                    "a/subm",
                    EntryKind::Commit,
                    b"0123456789abcdef0123456789abcdef01234567",
                ),
            ],
        );
        checkout(&setup, commit);
        assert_eq!(snapshot(&setup).tree, tree_of(&setup.store, commit));
    }

    #[test]
    fn a_submodule_under_a_symlinked_parent_becomes_a_link() {
        let setup = setup();
        let commit = base(
            &setup.store,
            &[(
                "a/subm",
                EntryKind::Commit,
                b"0123456789abcdef0123456789abcdef01234567",
            )],
        );
        let path = checkout(&setup, commit);
        let outside = setup.dir.path().join("outside");
        fs::create_dir_all(outside.join("subm")).unwrap();
        fs::remove_dir_all(path.join("a")).unwrap();
        symlink(&outside, path.join("a")).unwrap();
        assert_eq!(
            names(&setup.store, snapshot(&setup).tree),
            [("a".to_owned(), EntryKind::Link)]
        );
    }

    #[test]
    fn a_redirected_git_file_is_not_followed() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let outside = setup.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"do not take").unwrap();
        let evil = setup.dir.path().join("evil");
        gix::init_bare(&evil).unwrap();
        fs::write(
            evil.join("config"),
            format!("[core]\n\tworktree = {}\n", outside.display()),
        )
        .unwrap();
        fs::write(path.join(".git"), format!("gitdir: {}\n", evil.display())).unwrap();

        let names = only_names(&setup.store, snapshot(&setup).tree);
        assert!(!names.iter().any(|name| name.contains("secret")));
        assert!(names.contains(&"README.md".to_owned()));
    }

    #[test]
    fn an_unknown_or_moved_worktree_is_refused() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        for name in ["nope", "", "../agent", ".agent"] {
            assert!(
                matches!(
                    setup.store.snapshot(
                        name,
                        &GlobalPatterns::default(),
                        &mut SnapshotCache::default()
                    ),
                    Err(StoreError::NotAWorktree(_))
                ),
                "{name:?}"
            );
        }
        fs::rename(&path, setup.dir.path().join("moved")).unwrap();
        assert!(matches!(
            setup.store.snapshot(
                "agent",
                &GlobalPatterns::default(),
                &mut SnapshotCache::default()
            ),
            Err(StoreError::NotAWorktree(_))
        ));
    }

    #[test]
    fn symlinked_directories_are_recorded_as_links_not_followed() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let outside = setup.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"do not take").unwrap();
        symlink(&outside, path.join("escape")).unwrap();
        let tree = snapshot(&setup).tree;
        assert!(names(&setup.store, tree).contains(&("escape".to_owned(), EntryKind::Link)));
        assert_eq!(
            blob(&setup.store, tree, "escape"),
            outside.as_os_str().as_bytes()
        );
    }

    #[test]
    fn hostile_pattern_files_are_skipped_never_followed_or_blocked_on() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let outside = setup.dir.path().join("outside-ignore");
        fs::write(&outside, b"*\n").unwrap();
        fs::create_dir(path.join("linked")).unwrap();
        symlink(&outside, path.join("linked/.gitignore")).unwrap();
        fs::write(path.join("linked/kept.txt"), b"x").unwrap();
        fs::create_dir(path.join("piped")).unwrap();
        special_file(&path.join("piped/.gitignore"));
        special_file(&path.join("piped/.gitattributes"));
        fs::write(path.join("piped/kept.txt"), b"y").unwrap();
        fs::create_dir(path.join("zero")).unwrap();
        symlink("/dev/zero", path.join("zero/.gitattributes")).unwrap();
        let big = File::create(path.join("sub/.gitattributes")).unwrap();
        big.set_len(MAX_PATTERN_FILE_BYTES + 1).unwrap();

        let snapshot = snapshot(&setup);
        let names = only_names(&setup.store, snapshot.tree);
        assert!(names.contains(&"linked/kept.txt".to_owned()));
        assert!(names.contains(&"piped/kept.txt".to_owned()));
        assert_eq!(
            sorted(snapshot.skipped),
            [
                (BString::from("linked/.gitignore"), Skipped::NotAFile),
                (BString::from("piped/.gitattributes"), Skipped::NotAFile),
                (BString::from("piped/.gitignore"), Skipped::NotAFile),
                (BString::from("sub/.gitattributes"), Skipped::TooLarge),
                (BString::from("zero/.gitattributes"), Skipped::NotAFile),
            ]
        );
    }

    #[test]
    fn unreadable_entries_are_skipped_and_listed() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        fs::write(path.join("secret.txt"), b"x").unwrap();
        fs::set_permissions(path.join("secret.txt"), fs::Permissions::from_mode(0o000)).unwrap();
        fs::create_dir(path.join("closed")).unwrap();
        fs::write(path.join("closed/inner"), b"y").unwrap();
        fs::set_permissions(path.join("closed"), fs::Permissions::from_mode(0o000)).unwrap();
        let result = setup.store.snapshot(
            "agent",
            &GlobalPatterns::default(),
            &mut SnapshotCache::default(),
        );
        fs::set_permissions(path.join("closed"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            sorted(result.unwrap().skipped),
            [
                (BString::from("closed"), Skipped::Unreadable),
                (BString::from("secret.txt"), Skipped::Unreadable),
            ]
        );
    }

    #[test]
    fn unsafe_names_and_fifos_are_left_out() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        fs::write(path.join("git~1"), b"x").unwrap();
        special_file(&path.join("pipe"));
        let snapshot = snapshot(&setup);
        assert_eq!(
            snapshot.skipped,
            [(BString::from("git~1"), Skipped::UnsafeName)]
        );
        assert!(
            !only_names(&setup.store, snapshot.tree)
                .iter()
                .any(|name| name == "pipe")
        );
    }

    #[test]
    fn files_over_the_limit_are_left_out_and_listed() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let big = File::create(path.join("huge.bin")).unwrap();
        big.set_len(MAX_SNAPSHOT_FILE_BYTES + 1).unwrap();
        assert_eq!(
            snapshot(&setup).skipped,
            [(BString::from("huge.bin"), Skipped::TooLarge)]
        );
    }

    #[test]
    fn a_stray_git_entry_does_not_hide_tracked_files() {
        let setup = setup();
        let commit = base(
            &setup.store,
            &[("vendor/v.c", EntryKind::Blob, b"int v;\n")],
        );
        let path = checkout(&setup, commit);
        fs::write(path.join("vendor/.git"), b"").unwrap();
        assert_eq!(snapshot(&setup).tree, tree_of(&setup.store, commit));
    }

    #[test]
    fn names_only_windows_refuses_are_kept() {
        let setup = setup();
        let commit = base(
            &setup.store,
            &[
                ("aux.c", EntryKind::Blob, b"x"),
                ("con", EntryKind::Blob, b"y"),
            ],
        );
        let path = checkout(&setup, commit);
        fs::write(path.join("weird\\name"), b"z").unwrap();
        let snapshot = snapshot(&setup);
        assert!(snapshot.skipped.is_empty(), "{:?}", snapshot.skipped);
        assert_eq!(
            only_names(&setup.store, snapshot.tree),
            ["aux.c", "con", "weird\\name"]
        );
    }

    #[test]
    fn directories_beyond_the_depth_limit_are_listed() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let mut deep = path.join("d");
        let mut rela = String::from("d");
        for _ in 0..MAX_SNAPSHOT_DEPTH {
            deep.push("d");
            rela.push_str("/d");
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("f"), b"x").unwrap();
        let skipped = snapshot(&setup).skipped;
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].1, Skipped::TooDeep);
        assert!(rela.as_bytes().starts_with(skipped[0].0.as_slice()));
    }

    #[test]
    fn a_large_directory_snapshots_like_its_base() {
        let setup = setup();
        let names: Vec<String> = (0..3000).map(|i| format!("file-{i:05}.txt")).collect();
        let entries: Vec<(&str, EntryKind, &[u8])> = names
            .iter()
            .map(|name| (name.as_str(), EntryKind::Blob, name.as_bytes()))
            .collect();
        let commit = base(&setup.store, &entries);
        checkout(&setup, commit);
        assert_eq!(snapshot(&setup).tree, tree_of(&setup.store, commit));
    }

    #[test]
    fn an_empty_worktree_snapshots_to_the_empty_tree() {
        let setup = setup();
        let commit = base(&setup.store, &[("only", EntryKind::Blob, b"x")]);
        let path = checkout(&setup, commit);
        fs::remove_file(path.join("only")).unwrap();
        assert_eq!(
            snapshot(&setup).tree,
            ObjectId::empty_tree(setup.store.repo.object_hash())
        );
    }

    #[test]
    fn a_case_only_rename_keeps_the_index_spelling_when_case_is_ignored() {
        let setup = setup();
        let config = setup.dir.path().join("repo/.git/config");
        let mut text = fs::read_to_string(&config).unwrap();
        text.push_str("[core]\n\tignoreCase = true\n");
        fs::write(&config, text).unwrap();
        let store = Store::open(&setup.dir.path().join("repo")).unwrap();
        let setup = Setup {
            dir: setup.dir,
            store,
        };
        let commit = base(&setup.store, &[("README.md", EntryKind::Blob, b"hello\n")]);
        let path = checkout(&setup, commit);
        fs::rename(path.join("README.md"), path.join("Readme.md")).unwrap();
        assert_eq!(snapshot(&setup).tree, tree_of(&setup.store, commit));
    }

    #[test]
    fn many_unreadable_files_are_each_listed_once() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        fs::create_dir(path.join("locked")).unwrap();
        for i in 0..2000 {
            let file = path.join("locked").join(format!("f{i}"));
            fs::write(&file, b"x").unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        }
        let skipped = snapshot(&setup).skipped;
        assert_eq!(skipped.len(), 2000);
    }

    fn cached_snapshot(setup: &Setup, cache: &mut SnapshotCache) -> Snapshot {
        setup
            .store
            .snapshot("agent", &GlobalPatterns::default(), cache)
            .unwrap()
    }

    #[test]
    fn an_unchanged_worktree_is_not_read_again() {
        let setup = setup();
        let commit = default_base(&setup.store);
        checkout(&setup, commit);
        let mut cache = SnapshotCache::default();
        let first = cached_snapshot(&setup, &mut cache);
        assert_eq!(first.read, 4);
        assert_eq!(cache.len(), 4);
        let second = cached_snapshot(&setup, &mut cache);
        assert_eq!(second.read, 0);
        assert_eq!(second.tree, first.tree);
    }

    #[test]
    fn only_edited_files_are_read_again() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        fs::write(path.join("README.md"), b"edited\n").unwrap();
        let snapshot = cached_snapshot(&setup, &mut cache);
        assert_eq!(snapshot.read, 1);
        assert_eq!(blob(&setup.store, snapshot.tree, "README.md"), b"edited\n");
    }

    #[test]
    fn a_same_size_rewrite_is_seen() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        fs::write(path.join("README.md"), b"HELLO\n").unwrap();
        let snapshot = cached_snapshot(&setup, &mut cache);
        assert_eq!(blob(&setup.store, snapshot.tree, "README.md"), b"HELLO\n");
    }

    #[test]
    fn entries_recorded_too_recently_are_read_again() {
        let setup = setup();
        checkout(&setup, default_base(&setup.store));
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        for cached in cache.files.values_mut() {
            cached.recorded_at = cached.stat.mtime;
        }
        assert_eq!(cached_snapshot(&setup, &mut cache).read, 4);
    }

    #[test]
    fn changed_attributes_invalidate_the_files_below_them() {
        let setup = setup();
        let commit = base(
            &setup.store,
            &[
                ("top.txt", EntryKind::Blob, b"a\n"),
                ("sub/low.txt", EntryKind::Blob, b"b\n"),
            ],
        );
        let path = checkout(&setup, commit);
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        fs::write(path.join("sub/.gitattributes"), b"*.txt ident\n").unwrap();
        assert_eq!(cached_snapshot(&setup, &mut cache).read, 2);
        assert_eq!(cached_snapshot(&setup, &mut cache).read, 0);
    }

    #[test]
    fn a_backdated_same_size_edit_is_seen() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        let file = path.join("README.md");
        let before = rustix::fs::stat(&file).unwrap();
        fs::write(&file, b"HELLO\n").unwrap();
        let old = rustix::fs::Timespec {
            tv_sec: before.st_mtime,
            tv_nsec: convert(before.st_mtime_nsec).unwrap(),
        };
        rustix::fs::utimensat(
            CWD,
            &file,
            &rustix::fs::Timestamps {
                last_access: old,
                last_modification: old,
            },
            AtFlags::empty(),
        )
        .unwrap();
        let snapshot = cached_snapshot(&setup, &mut cache);
        assert_eq!(blob(&setup.store, snapshot.tree, "README.md"), b"HELLO\n");
    }

    #[test]
    fn a_change_time_in_the_same_instant_as_the_stamp_forces_a_read() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let long_ago = rustix::fs::Timespec {
            tv_sec: 1_000_000_000,
            tv_nsec: 0,
        };
        for name in ["README.md", ".gitignore", "sub/.gitignore", "tracked.log"] {
            rustix::fs::utimensat(
                CWD,
                path.join(name),
                &rustix::fs::Timestamps {
                    last_access: long_ago,
                    last_modification: long_ago,
                },
                AtFlags::empty(),
            )
            .unwrap();
        }
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        for cached in cache.files.values_mut() {
            assert!(cached.stat.mtime < cached.stat.ctime);
            cached.recorded_at = cached.stat.ctime;
        }
        assert_eq!(cached_snapshot(&setup, &mut cache).read, 4);
    }

    #[test]
    fn an_unwritable_root_snapshots_without_the_cache() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
        let result = setup
            .store
            .snapshot("agent", &GlobalPatterns::default(), &mut cache);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(result.unwrap().read, 4);
    }

    #[test]
    fn a_leftover_stamp_is_never_recorded() {
        let setup = setup();
        let commit = default_base(&setup.store);
        let path = checkout(&setup, commit);
        fs::write(path.join(".mahi-stamp-0123456789abcdef"), b"").unwrap();
        assert_eq!(snapshot(&setup).tree, tree_of(&setup.store, commit));
    }

    #[test]
    fn the_test_file_system_allows_the_cache() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let root = openat(
            CWD,
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            FsMode::empty(),
        )
        .unwrap();
        assert!(
            trusted_times(&root),
            "tests must run on a file system the cache trusts"
        );
    }

    #[test]
    fn a_changed_index_entry_forces_a_read() {
        let setup = setup();
        checkout(&setup, default_base(&setup.store));
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        for cached in cache.files.values_mut() {
            cached.index_id = None;
        }
        assert_eq!(cached_snapshot(&setup, &mut cache).read, 4);
    }

    #[test]
    fn the_stamp_leaves_nothing_behind() {
        let setup = setup();
        let path = checkout(&setup, default_base(&setup.store));
        let snapshot = cached_snapshot(&setup, &mut SnapshotCache::default());
        assert!(
            !only_names(&setup.store, snapshot.tree)
                .iter()
                .any(|name| name.contains("mahi-stamp"))
        );
        assert!(!fs::read_dir(&path).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("mahi-stamp")
        }));
    }

    #[test]
    fn toggling_ignore_case_invalidates_the_cache() {
        let setup = setup();
        checkout(&setup, default_base(&setup.store));
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        let current = setup
            .store
            .repo
            .config_snapshot()
            .boolean("core.ignoreCase")
            == Some(true);
        let config = setup.dir.path().join("repo/.git/config");
        let text = fs::read_to_string(&config).unwrap();
        fs::write(
            &config,
            format!("{text}[core]\n\tignoreCase = {}\n", !current),
        )
        .unwrap();
        let store = Store::open(&setup.dir.path().join("repo")).unwrap();
        let again = store
            .snapshot("agent", &GlobalPatterns::default(), &mut cache)
            .unwrap();
        assert_eq!(again.read, 4);
    }

    #[test]
    fn a_cache_from_another_worktree_is_not_used() {
        let setup = setup();
        let commit = default_base(&setup.store);
        checkout(&setup, commit);
        setup
            .store
            .add_worktree("other", &setup.dir.path().join("other"), commit)
            .unwrap();
        let mut cache = SnapshotCache::default();
        cached_snapshot(&setup, &mut cache);
        let other = setup
            .store
            .snapshot("other", &GlobalPatterns::default(), &mut cache)
            .unwrap();
        assert_eq!(other.read, 4);
    }

    #[test]
    fn a_file_that_shrinks_while_read_is_flagged() {
        let short = Rc::new(Cell::new(false));
        let mut exact = ExactReader {
            inner: &b"abc"[..],
            left: 5,
            short: Rc::clone(&short),
        };
        let mut out = Vec::new();
        assert!(exact.read_to_end(&mut out).is_err());
        assert!(short.get());
    }
}
