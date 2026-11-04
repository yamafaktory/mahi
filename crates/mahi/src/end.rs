use std::{
    env,
    ffi::OsStr,
    fmt::Write as _,
    fs,
    io,
    os::unix::ffi::OsStrExt,
    path::{
        Path,
        PathBuf,
    },
    sync::atomic::AtomicBool,
};

use mahi_core::{
    AgentSlot,
    NameError,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_identity::{
    AgentError,
    AgentSigner,
    ConfigDir,
    ConfigError,
    IdentityError,
    SigningKey,
    SshAgent,
};
use mahi_sandbox::{
    SignalError,
    Termination,
    TerminationSignals,
};
use mahi_store::{
    GlobalPatterns,
    Snapshot,
    SnapshotCache,
    Store,
    StoreError,
};
use mahi_thread::{
    KeyError,
    OwnerError,
    ParticipantKey,
    ThreadError,
    load_meta,
};
use thiserror::Error;

use crate::{
    cli::EndCommand,
    environment::Environment,
    run::until_stopped,
    session::{
        self,
        CommitKey,
        ResumeError,
        SNAPSHOT_MESSAGE,
    },
    thread_lock::{
        LockError,
        ThreadLock,
    },
};

const SNAPSHOT_ATTEMPTS: usize = 3;
const LISTED: usize = 10;

#[derive(Debug, Error)]
pub(crate) enum EndError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot find mahi's configuration directory")]
    Config(#[from] ConfigError),
    #[error("mahi is not set up; run mahi init first")]
    NotInitialised(#[source] IdentityError),
    #[error("the signing key cannot identify thread owners")]
    OwnerKey(#[source] KeyError),
    #[error("SSH_AUTH_SOCK is not set; start ssh-agent and add your signing key (ssh-add)")]
    NoSshAgent,
    #[error("cannot sign with the SSH key")]
    Signer(#[from] AgentError),
    #[error("cannot make a participant name from USER")]
    ParticipantName(#[source] NameError),
    #[error("cannot open the git repository")]
    Store(#[from] StoreError),
    #[error("an agent of thread {0} is still running; stop it before ending the thread")]
    Running(ThreadId),
    #[error("cannot lock the thread")]
    Lock(#[source] io::Error),
    #[error(transparent)]
    Agent(#[from] ResumeError),
    #[error("cannot open thread {0}; only a thread you started or joined can be ended")]
    NotOwner(ThreadId, #[source] Box<ThreadError>),
    #[error("cannot tell who owns thread {0}")]
    ThreadOwner(ThreadId, #[source] OwnerError),
    #[error("cannot take the last snapshot of the worktree")]
    Snapshot(#[source] StoreError),
    #[error(
        "the last snapshot leaves out {0}; nothing was removed, and --force removes them anyway"
    )]
    Unrecorded(String),
    #[error("the worktree {} no longer links back to the repository; it was left in place", .0.display())]
    Broken(PathBuf),
    #[error("cannot catch the signals that stop mahi")]
    Signals(#[source] SignalError),
    #[error("cannot remove what the thread left on disk")]
    Remove(#[source] io::Error),
}

/// What `mahi end` did.
#[derive(Debug)]
pub(crate) enum Ended {
    Done(String),
    Stopped(Termination),
}

/// Ends a thread the user owns and none of whose agents runs: records each of the user's
/// agents' worktrees in a last snapshot, then removes the worktrees, the agents' state and the
/// thread's locks. The thread's refs stay.
pub(crate) fn end(command: &EndCommand, environment: &Environment) -> Result<Ended, EndError> {
    let thread = command.thread;
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(EndError::CurrentDirectory)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let signing = SigningKey::load(&config.signing_key_file()).map_err(EndError::NotInitialised)?;
    let own = ParticipantKey::from_public_key(signing.public_key()).map_err(EndError::OwnerKey)?;
    let participant = session::participant_from(environment.user.as_deref())
        .map_err(EndError::ParticipantName)?;
    let store = Store::discover(&cwd)?;
    let owner = session::thread_owner(&store, thread, own)
        .map_err(|error| EndError::ThreadOwner(thread, error))?;
    let lock = match ThreadLock::acquire(&config, thread) {
        Ok(lock) => lock,
        Err(LockError::Busy(_) | LockError::AgentBusy(..)) => {
            return Err(EndError::Running(thread));
        }
        Err(LockError::Io(error)) => return Err(EndError::Lock(error)),
    };
    let slots = session::own_slots(&store, thread, &participant)?;
    if slots.is_empty() {
        return Err(ResumeError::NoAgent(thread).into());
    }
    load_meta(&store, thread, &owner, 0)
        .map_err(|error| EndError::NotOwner(thread, Box::new(error)))?;
    let socket = environment
        .ssh_auth_sock
        .as_deref()
        .ok_or(EndError::NoSshAgent)?;
    let signer = AgentSigner::new(SshAgent::new(socket), signing.public_key().clone())?;
    signer.require_loaded()?;
    let commits = CommitKey::new(signer).map_err(EndError::OwnerKey)?;
    let termination = TerminationSignals::listen().map_err(EndError::Signals)?;
    let globals = environment.git_patterns();
    let (recorded, caught) = until_stopped(&termination, |interrupt| {
        slots
            .into_iter()
            .map(|slot| {
                record_last(
                    &store,
                    thread,
                    slot,
                    (&globals, &commits),
                    command.force,
                    interrupt,
                )
            })
            .collect::<Result<Vec<Recorded>, EndError>>()
    });
    if let Some(signal) = caught {
        return Ok(Ended::Stopped(signal));
    }
    let mut report = String::new();
    for Recorded {
        report: part,
        worktree,
    } in recorded?
    {
        report.push_str(&part);
        if let Some((name, worktree)) = worktree {
            store.remove_worktree(&name)?;
            if let Some(repository) = worktree.parent() {
                let _ = fs::remove_dir(repository);
            }
            let _ = writeln!(report, "removed the worktree {}", worktree.display());
        }
    }
    match fs::remove_dir_all(session::state_root(&store, thread)) {
        Ok(()) => report.push_str("removed the agents' state\n"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(EndError::Remove(error)),
    }
    lock.remove().map_err(EndError::Remove)?;
    let _ = writeln!(
        report,
        "ended thread {thread}; its history stays in refs/threads/{thread}"
    );
    Ok(Ended::Done(report))
}

/// What an agent's last snapshot left to do: the report so far, and the worktree to remove,
/// by name and directory.
struct Recorded {
    report: String,
    worktree: Option<(String, PathBuf)>,
}

fn record_last(
    store: &Store,
    thread: ThreadId,
    slot: AgentSlot,
    (globals, commits): (&GlobalPatterns, &CommitKey),
    force: bool,
    interrupt: &AtomicBool,
) -> Result<Recorded, EndError> {
    let name = session::worktree_name(thread, slot.agent());
    let mut report = String::new();
    let worktree = match store.worktree_dir(&name) {
        Ok(worktree) => worktree,
        Err(StoreError::NotAWorktree(_)) => {
            if store.prune_worktree(&name)? {
                report.push_str("the worktree was already gone; removed its registration\n");
            } else {
                let registration = store.common_dir().join("worktrees").join(&name);
                if fs::symlink_metadata(&registration).is_ok() {
                    return Err(EndError::Broken(
                        registered_dir(&registration).unwrap_or(registration),
                    ));
                }
            }
            return Ok(Recorded {
                report,
                worktree: None,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let taken = snapshot(store, &name, globals, interrupt)?;
    if !taken.skipped.is_empty() {
        let listed = listing(&taken);
        if !force {
            return Err(EndError::Unrecorded(listed));
        }
        let _ = writeln!(report, "discarded what the snapshot left out: {listed}");
    }
    let snapshots = ThreadRef::new(thread, RefKind::Snapshots(slot));
    let head = store.head(&snapshots)?;
    let unchanged = head
        .map(|commit| store.commit_tree(commit))
        .transpose()?
        .is_some_and(|tree| tree == taken.tree);
    if !unchanged {
        store
            .append_signed(
                &snapshots,
                head,
                taken.tree,
                SNAPSHOT_MESSAGE,
                commits.signer(),
            )
            .map_err(EndError::Snapshot)?;
        report.push_str("recorded the worktree's last changes\n");
    }
    Ok(Recorded {
        report,
        worktree: Some((name, worktree)),
    })
}

fn listing(taken: &Snapshot) -> String {
    let mut listed: Vec<String> = taken
        .skipped
        .iter()
        .take(LISTED)
        .map(|(path, _)| path.to_string())
        .collect();
    if taken.skipped.len() > LISTED {
        listed.push(format!("{} more", taken.skipped.len() - LISTED));
    }
    listed.join(", ")
}

fn snapshot(
    store: &Store,
    name: &str,
    globals: &GlobalPatterns,
    interrupt: &AtomicBool,
) -> Result<Snapshot, EndError> {
    let mut left = SNAPSHOT_ATTEMPTS;
    loop {
        left -= 1;
        match store.snapshot(name, globals, &mut SnapshotCache::default(), interrupt) {
            Err(StoreError::ChangedDuringSnapshot(_)) if left > 0 => {}
            outcome => return outcome.map_err(EndError::Snapshot),
        }
    }
}

fn registered_dir(registration: &Path) -> Option<PathBuf> {
    let recorded = fs::read(registration.join("gitdir")).ok()?;
    let recorded = recorded.strip_suffix(b"\n").unwrap_or(&recorded);
    Path::new(OsStr::from_bytes(recorded))
        .parent()
        .map(Path::to_path_buf)
}
