use std::{
    fmt::Write as _,
    fs::File,
    io::{
        self,
        BufWriter,
        Write,
    },
    os::{
        fd::OwnedFd,
        unix::ffi::OsStrExt,
    },
    path::{
        Path,
        PathBuf,
    },
};

use mahi_core::{
    AgentSlot,
    ThreadId,
};
use mahi_crypto::ThreadKey;
use mahi_store::{
    ObjectId,
    Store,
    StoreError,
};
use mahi_thread::{
    MAX_SESSION_BYTES,
    MAX_SESSION_FILES,
    ParticipantKey,
    SessionError,
    SessionPath,
    SessionReader,
    SessionWriter,
    session_ref,
    signed_by,
};
use rustix::{
    fs::{
        AtFlags,
        Dir,
        FileType,
        Mode,
        OFlags,
    },
    io::Errno,
};
use thiserror::Error;

use crate::session::CommitKey;

const MAX_DEPTH: usize = 15;
const MAX_ENTRIES: usize = 2 * MAX_SESSION_FILES;
const STAGING_PREFIX: &str = ".mahi-restoring-";

/// Where an agent keeps its session files: `dir`, `/`-separated, inside its state directory
/// `state`.
#[derive(Debug, Clone)]
pub(crate) struct SessionSource {
    pub(crate) state: PathBuf,
    pub(crate) dir: String,
}

/// Which thread and agent a session belongs to, the key its files are sealed to, and the user's
/// own key, which alone may have signed it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionOf<'a> {
    pub(crate) thread: ThreadId,
    pub(crate) slot: &'a AgentSlot,
    pub(crate) key: &'a ThreadKey,
    pub(crate) own: &'a ParticipantKey,
}

#[derive(Debug, Error)]
pub(crate) enum SyncError {
    #[error("cannot read the agent's session files")]
    Read(#[source] io::Error),
    #[error("cannot write the agent's session files")]
    Write(#[source] io::Error),
    #[error("the agent's session directory is not a directory of its own")]
    NotADirectory,
    #[error("the agent's session directory holds more than {MAX_ENTRIES} entries")]
    TooManyEntries,
    #[error("the agent's session files hold more than {MAX_SESSION_BYTES} bytes")]
    TooLarge,
    #[error("the recorded session {0} is not signed by your key")]
    NotOwn(ObjectId),
    #[error("the session recorder stopped unexpectedly")]
    Stopped,
    #[error("cannot draw a name for the restored session")]
    Random(#[source] getrandom::Error),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Records the files under `source` on the agent's session ref, and returns the new commit, or
/// `None` when there is no session directory yet or nothing changed. Only regular files and
/// directories are read, never through a symbolic link, and the directory is walked once to
/// count its entries and add up its files' sizes before anything is sealed.
pub(crate) fn record(
    store: &Store,
    of: SessionOf<'_>,
    source: &SessionSource,
    commits: &CommitKey,
) -> Result<Option<ObjectId>, SyncError> {
    let Some(root) = open_session_dir(source)? else {
        return Ok(None);
    };
    let mut files = 0;
    let mut bytes: u64 = 0;
    walk(&root, "", 0, &mut 0, &mut |_, _, size| {
        files += 1;
        bytes = bytes.saturating_add(size);
        if files > MAX_SESSION_FILES {
            return Err(SyncError::TooManyEntries);
        }
        if bytes > MAX_SESSION_BYTES {
            return Err(SyncError::TooLarge);
        }
        Ok(())
    })?;
    let session = session_ref(of.thread, of.slot);
    let previous = store.head(&session)?;
    let mut writer = SessionWriter::new(store, of.key, commits.key(), previous)?;
    walk(&root, "", 0, &mut 0, &mut |path, fd, _| {
        writer.add(path, &mut File::from(fd))?;
        Ok(())
    })?;
    let commit = writer.commit(of.thread, of.slot, commits.signer())?;
    Ok((Some(commit) != previous).then_some(commit))
}

fn open_session_dir(source: &SessionSource) -> Result<Option<OwnedFd>, SyncError> {
    let mut current = match open_dir_at(None, &source.state) {
        Ok(fd) => fd,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SyncError::Read(error)),
    };
    for component in source.dir.split('/') {
        current = match open_dir_at(Some(&current), Path::new(component)) {
            Ok(fd) => fd,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if not_a_directory(&error) => return Err(SyncError::NotADirectory),
            Err(error) => return Err(SyncError::Read(error)),
        };
    }
    Ok(Some(current))
}

fn open_dir_at(parent: Option<&OwnedFd>, path: &Path) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let opened = match parent {
        Some(parent) => rustix::fs::openat(parent, path, flags, Mode::empty()),
        None => rustix::fs::open(path, flags, Mode::empty()),
    };
    opened.map_err(io::Error::from)
}

type Visit<'v> = dyn FnMut(SessionPath, OwnedFd, u64) -> Result<(), SyncError> + 'v;

fn walk(
    dir: &OwnedFd,
    prefix: &str,
    depth: usize,
    entries: &mut usize,
    visit: &mut Visit<'_>,
) -> Result<(), SyncError> {
    let mut names = Vec::new();
    for entry in Dir::read_from(dir).map_err(|error| SyncError::Read(error.into()))? {
        let entry = entry.map_err(|error| SyncError::Read(error.into()))?;
        *entries += 1;
        if *entries > MAX_ENTRIES {
            return Err(SyncError::TooManyEntries);
        }
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
    names.sort();
    for name in names {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let Ok(session_path) = SessionPath::new(&path) else {
            continue;
        };
        let opened = rustix::fs::openat(
            dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let fd = match opened {
            Ok(fd) => fd,
            Err(Errno::LOOP | Errno::NOENT | Errno::NXIO | Errno::ACCESS | Errno::NAMETOOLONG) => {
                continue;
            }
            Err(error) => return Err(SyncError::Read(error.into())),
        };
        let stat = rustix::fs::fstat(&fd).map_err(|error| SyncError::Read(error.into()))?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory if depth < MAX_DEPTH => {
                walk(&fd, &path, depth + 1, entries, visit)?;
            }
            FileType::RegularFile => {
                let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
                visit(session_path, fd, size)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Writes the files of the agent's latest recorded session under `source`, and returns how
/// many, unless the session directory is already there, or nothing was recorded. The files are
/// written into a new directory beside it, which then takes its name, so an interrupted restore
/// leaves no half session behind.
pub(crate) fn restore(
    store: &Store,
    of: SessionOf<'_>,
    source: &SessionSource,
) -> Result<usize, SyncError> {
    let Some(commit) = store.head(&session_ref(of.thread, of.slot))? else {
        return Ok(0);
    };
    if !signed_by(store, commit, of.own)? {
        return Err(SyncError::NotOwn(commit));
    }
    let reader = SessionReader::open(store, of.key, commit)?;
    let Some((parents, name)) = split_last(&source.dir) else {
        return Err(SyncError::NotADirectory);
    };
    let mut parent = private_dir_at(None, &source.state)?;
    for component in &parents {
        parent = private_dir_at(Some(&parent), Path::new(component))?;
    }
    match rustix::fs::statat(&parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => return Ok(0),
        Err(Errno::NOENT) => {}
        Err(error) => return Err(SyncError::Write(error.into())),
    }
    let staging_name = staging_name()?;
    rustix::fs::mkdirat(&parent, staging_name.as_str(), Mode::from_raw_mode(0o700))
        .map_err(|error| SyncError::Write(error.into()))?;
    let staging = open_dir_at(Some(&parent), Path::new(&staging_name)).map_err(SyncError::Write)?;
    let written = write_files(&reader, &staging).and_then(|count| {
        rustix::fs::renameat(&parent, staging_name.as_str(), &parent, name)
            .map_err(|error| SyncError::Write(error.into()))?;
        Ok(count)
    });
    if written.is_err() {
        let _ = remove_tree(&staging);
        let _ = rustix::fs::unlinkat(&parent, staging_name.as_str(), AtFlags::REMOVEDIR);
    }
    written
}

fn staging_name() -> Result<String, SyncError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(SyncError::Random)?;
    let mut name = STAGING_PREFIX.to_owned();
    for byte in random {
        let _ = write!(name, "{byte:02x}");
    }
    Ok(name)
}

fn remove_tree(dir: &OwnedFd) -> io::Result<()> {
    let mut names = Vec::new();
    for entry in Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(entry.file_name().to_owned());
        }
    }
    for name in names {
        match open_dir_at(
            Some(dir),
            Path::new(std::ffi::OsStr::from_bytes(name.as_bytes())),
        ) {
            Ok(child) => {
                remove_tree(&child)?;
                rustix::fs::unlinkat(dir, name.as_c_str(), AtFlags::REMOVEDIR)?;
            }
            Err(_) => rustix::fs::unlinkat(dir, name.as_c_str(), AtFlags::empty())?,
        }
    }
    Ok(())
}

fn split_last(dir: &str) -> Option<(Vec<&str>, &str)> {
    let mut components: Vec<&str> = dir.split('/').collect();
    let last = components.pop()?;
    Some((components, last))
}

fn private_dir_at(parent: Option<&OwnedFd>, path: &Path) -> Result<OwnedFd, SyncError> {
    let made = match parent {
        Some(parent) => rustix::fs::mkdirat(parent, path, Mode::from_raw_mode(0o700)),
        None => rustix::fs::mkdir(path, Mode::from_raw_mode(0o700)),
    };
    match made {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(SyncError::Write(error.into())),
    }
    open_dir_at(parent, path).map_err(|error| {
        if not_a_directory(&error) {
            SyncError::NotADirectory
        } else {
            SyncError::Write(error)
        }
    })
}

fn not_a_directory(error: &io::Error) -> bool {
    [Errno::LOOP, Errno::NOTDIR]
        .iter()
        .any(|errno| error.raw_os_error() == Some(errno.raw_os_error()))
}

fn write_files(reader: &SessionReader<'_>, root: &OwnedFd) -> Result<usize, SyncError> {
    for (index, file) in reader.files().iter().enumerate() {
        let components: Vec<&str> = file.path.components().collect();
        let Some((name, parents)) = components.split_last() else {
            return Err(SyncError::NotADirectory);
        };
        let mut dir = None;
        for component in parents {
            let next = private_dir_at(Some(dir.as_ref().unwrap_or(root)), Path::new(component))?;
            dir = Some(next);
        }
        let fd = rustix::fs::openat(
            dir.as_ref().unwrap_or(root),
            *name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| SyncError::Write(error.into()))?;
        let mut out = BufWriter::new(File::from(fd));
        reader.copy(index, &mut out)?;
        out.flush().map_err(SyncError::Write)?;
    }
    Ok(reader.files().len())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{
            PermissionsExt,
            symlink,
        },
    };

    use mahi_core::{
        AgentName,
        ParticipantName,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;

    struct Setup {
        _repo: TempDir,
        store: Store,
        key: ThreadKey,
        thread: ThreadId,
        slot: AgentSlot,
        signer: CommitKey,
    }

    fn setup() -> Setup {
        let repo = TempDir::new().unwrap();
        gix::init(repo.path()).unwrap();
        Setup {
            store: Store::open(repo.path()).unwrap(),
            _repo: repo,
            key: ThreadKey::generate(),
            thread: ThreadId::random().unwrap(),
            slot: AgentSlot::new(
                ParticipantName::new("alice").unwrap(),
                AgentName::new("claude").unwrap(),
            ),
            signer: CommitKey::new(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap())
                .unwrap(),
        }
    }

    fn of(setup: &Setup) -> SessionOf<'_> {
        SessionOf {
            thread: setup.thread,
            slot: &setup.slot,
            key: &setup.key,
            own: setup.signer.key(),
        }
    }

    fn source(state: &Path, dir: &str) -> SessionSource {
        SessionSource {
            state: state.to_path_buf(),
            dir: dir.to_owned(),
        }
    }

    #[test]
    fn session_files_move_to_the_directory_another_worktree_path_names() {
        let setup = setup();
        let here = TempDir::new().unwrap();
        let project = here.path().join("projects").join("-old-path");
        fs::create_dir_all(project.join("uuid").join("subagents")).unwrap();
        fs::write(project.join("uuid.jsonl"), b"{\"turn\":1}\n").unwrap();
        fs::write(
            project.join("uuid").join("subagents").join("a.jsonl"),
            b"sub\n",
        )
        .unwrap();
        fs::write(here.path().join(".credentials.json"), b"secret").unwrap();
        symlink(here.path().join(".credentials.json"), project.join("leak")).unwrap();
        let from = source(here.path(), "projects/-old-path");
        let first = record(&setup.store, of(&setup), &from, &setup.signer)
            .unwrap()
            .unwrap();
        assert_eq!(
            record(&setup.store, of(&setup), &from, &setup.signer).unwrap(),
            None
        );

        let there = TempDir::new().unwrap();
        let to = source(there.path(), "projects/-new-path");
        assert_eq!(restore(&setup.store, of(&setup), &to).unwrap(), 2);
        let restored = there.path().join("projects").join("-new-path");
        assert_eq!(
            fs::read(restored.join("uuid.jsonl")).unwrap(),
            b"{\"turn\":1}\n"
        );
        assert_eq!(
            fs::read(restored.join("uuid/subagents/a.jsonl")).unwrap(),
            b"sub\n"
        );
        assert!(!restored.join("leak").exists());
        assert_eq!(
            fs::read_dir(there.path().join("projects")).unwrap().count(),
            1
        );
        let mode = fs::metadata(restored.join("uuid.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        fs::write(restored.join("uuid.jsonl"), b"newer here\n").unwrap();
        assert_eq!(restore(&setup.store, of(&setup), &to).unwrap(), 0);
        assert_eq!(
            fs::read(restored.join("uuid.jsonl")).unwrap(),
            b"newer here\n"
        );
        let second = record(&setup.store, of(&setup), &to, &setup.signer)
            .unwrap()
            .unwrap();
        assert_eq!(setup.store.parent(second).unwrap(), Some(first));
    }

    fn objects(setup: &Setup) -> usize {
        walkdir(&setup.store.common_dir().join("objects"))
    }

    fn walkdir(path: &Path) -> usize {
        fs::read_dir(path).map_or(0, |entries| {
            entries
                .map(|entry| {
                    let entry = entry.unwrap();
                    if entry.file_type().unwrap().is_dir() {
                        walkdir(&entry.path())
                    } else {
                        1
                    }
                })
                .sum()
        })
    }

    #[test]
    fn an_oversized_session_is_refused_before_anything_is_sealed_and_special_files_are_skipped() {
        let setup = setup();
        let state = TempDir::new().unwrap();
        let project = state.path().join("p");
        fs::create_dir(&project).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(project.join("socket")).unwrap();
        #[cfg(target_os = "linux")]
        rustix::fs::mknodat(
            rustix::fs::CWD,
            project.join("pipe"),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        fs::write(project.join("small"), b"small").unwrap();
        let from = source(state.path(), "p");
        let commit = record(&setup.store, of(&setup), &from, &setup.signer)
            .unwrap()
            .unwrap();
        let reader = SessionReader::open(&setup.store, &setup.key, commit).unwrap();
        assert_eq!(reader.files().len(), 1);

        let huge = File::create(project.join("huge")).unwrap();
        huge.set_len(MAX_SESSION_BYTES).unwrap();
        let before = objects(&setup);
        assert!(matches!(
            record(&setup.store, of(&setup), &from, &setup.signer),
            Err(SyncError::TooLarge)
        ));
        assert_eq!(objects(&setup), before);
    }

    #[test]
    fn a_session_signed_by_someone_else_is_not_restored() {
        let setup = setup();
        let here = TempDir::new().unwrap();
        fs::create_dir(here.path().join("p")).unwrap();
        fs::write(here.path().join("p").join("f"), b"f").unwrap();
        record(
            &setup.store,
            of(&setup),
            &source(here.path(), "p"),
            &setup.signer,
        )
        .unwrap();
        let stranger =
            CommitKey::new(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()).unwrap();
        let there = TempDir::new().unwrap();
        let foreign = SessionOf {
            own: stranger.key(),
            ..of(&setup)
        };
        assert!(matches!(
            restore(&setup.store, foreign, &source(there.path(), "q")),
            Err(SyncError::NotOwn(_))
        ));
        assert!(!there.path().join("q").exists());
    }

    #[test]
    fn nothing_is_recorded_or_restored_without_a_session() {
        let setup = setup();
        let empty = TempDir::new().unwrap();
        let from = source(empty.path(), "projects/-none");
        assert_eq!(
            record(&setup.store, of(&setup), &from, &setup.signer).unwrap(),
            None
        );
        assert_eq!(restore(&setup.store, of(&setup), &from).unwrap(), 0);
        assert!(!empty.path().join("projects").join("-none").exists());
    }

    #[test]
    fn a_session_directory_planted_as_a_link_is_neither_read_nor_written_through() {
        let setup = setup();
        let state = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("private"), b"x").unwrap();
        fs::create_dir(state.path().join("projects")).unwrap();
        symlink(outside.path(), state.path().join("projects").join("-p")).unwrap();
        let planted = source(state.path(), "projects/-p");
        assert!(matches!(
            record(&setup.store, of(&setup), &planted, &setup.signer),
            Err(SyncError::NotADirectory)
        ));
        symlink(outside.path(), state.path().join("linked")).unwrap();
        let recorded = TempDir::new().unwrap();
        fs::create_dir_all(recorded.path().join("d")).unwrap();
        fs::write(recorded.path().join("d").join("f"), b"f").unwrap();
        record(
            &setup.store,
            of(&setup),
            &source(recorded.path(), "d"),
            &setup.signer,
        )
        .unwrap();
        assert!(matches!(
            restore(
                &setup.store,
                of(&setup),
                &source(state.path(), "linked/sub")
            ),
            Err(SyncError::NotADirectory)
        ));
        assert!(!outside.path().join("sub").exists());
    }
}
