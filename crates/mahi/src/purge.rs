use std::{
    env,
    fmt::Write as _,
    fs,
    io,
    sync::{
        Arc,
        atomic::AtomicBool,
    },
};

use mahi_core::{
    NameError,
    ParticipantName,
    RefKind,
    THREADS_PREFIX,
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
    Pushed,
    Store,
    StoreError,
};
use mahi_thread::{
    KeyError,
    MAX_META_BYTES,
    META_ENTRY,
    MetaDocument,
    OwnerError,
    ParticipantKey,
    ThreadError,
    tombstone_thread,
};
use thiserror::Error;

use crate::{
    cli::PurgeCommand,
    environment::Environment,
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    run::until_stopped,
    session,
    sync::{
        self,
        FetchError,
        PushError,
        SetupError,
        SyncSetup,
    },
    thread_lock::{
        LockError,
        ThreadLock,
    },
};

const LAND: &str = "land";

#[derive(Debug, Error)]
pub(crate) enum PurgeError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot find mahi's configuration directory")]
    Config(#[from] ConfigError),
    #[error("mahi is not set up; run mahi init first")]
    NotInitialised(#[source] IdentityError),
    #[error("the signing key cannot identify thread owners")]
    OwnerKey(#[source] KeyError),
    #[error("cannot make a participant name from USER")]
    ParticipantName(#[source] NameError),
    #[error("cannot open the git repository")]
    Store(#[from] StoreError),
    #[error("cannot tell who owns thread {0}")]
    ThreadOwner(ThreadId, #[source] OwnerError),
    #[error("thread {0} has no meta here")]
    Unknown(ThreadId),
    #[error("an agent of thread {0} is still running; stop it before purging the thread")]
    Running(ThreadId),
    #[error("cannot lock the thread")]
    Lock(#[source] io::Error),
    #[error("cannot use the chosen remote")]
    Remote(#[source] SetupError),
    #[error("SSH_AUTH_SOCK is not set; start ssh-agent and add your signing key (ssh-add)")]
    NoSshAgent,
    #[error("cannot sign with the SSH key")]
    Signer(#[from] AgentError),
    #[error("cannot fetch the thread before ending it, so nothing was purged")]
    Fetch(#[source] FetchError),
    #[error("cannot end the thread")]
    Thread(#[source] ThreadError),
    #[error("cannot reach the remote")]
    Push(#[source] PushError),
    #[error("the remote did not take the thread's end ({0}); nothing was deleted there or here")]
    TombstoneNotPushed(String),
    #[error("the remote kept {0} of your refs; the local copy is kept so mahi purge can try again")]
    RemoteKept(usize),
    #[error("cannot ask for confirmation")]
    Prompt(#[source] io::Error),
    #[error("cannot catch the signals that stop mahi")]
    Signals(#[source] SignalError),
    #[error("cannot remove what the thread left on disk")]
    Remove(#[source] io::Error),
}

/// What `mahi purge` did.
#[derive(Debug)]
pub(crate) enum Purged {
    Done(String),
    Kept,
    Stopped(Termination, String),
    Failed(String, PurgeError),
}

/// Purges a thread: on the chosen remote first, where its owner ends it with a tombstone and
/// deletes its other refs and a participant deletes their own agents' refs, then here, where
/// its refs, worktrees, agents' state and locks go.
pub(crate) fn purge(
    command: &PurgeCommand,
    environment: &Environment,
) -> Result<Purged, PurgeError> {
    let thread = command.thread;
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(PurgeError::CurrentDirectory)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let signing =
        SigningKey::load(&config.signing_key_file()).map_err(PurgeError::NotInitialised)?;
    let own =
        ParticipantKey::from_public_key(signing.public_key()).map_err(PurgeError::OwnerKey)?;
    let participant = session::participant_from(environment.user.as_deref())
        .map_err(PurgeError::ParticipantName)?;
    let store = Store::discover(&cwd)?;
    if read_meta(&store, thread).is_none() {
        return Err(PurgeError::Unknown(thread));
    }
    let owner = session::thread_owner(&store, thread, own.clone())
        .map_err(|error| PurgeError::ThreadOwner(thread, error))?;
    let is_owner = owner == own && signed_by(&store, thread, &own);
    let lock = match ThreadLock::acquire(&config, thread) {
        Ok(lock) => lock,
        Err(LockError::Busy(_) | LockError::AgentBusy(..) | LockError::LandBusy(_)) => {
            return Err(PurgeError::Running(thread));
        }
        Err(LockError::Io(error)) => return Err(PurgeError::Lock(error)),
    };
    let setup = SyncSetup::chosen(&store, environment, false).map_err(PurgeError::Remote)?;
    if !command.yes && !confirmed(thread, setup.as_ref())? {
        return Ok(Purged::Kept);
    }
    let signer = if is_owner {
        let socket = environment
            .ssh_auth_sock
            .as_deref()
            .ok_or(PurgeError::NoSshAgent)?;
        let signer = AgentSigner::new(SshAgent::new(socket), signing.public_key().clone())?;
        signer.require_loaded()?;
        Some(signer)
    } else {
        None
    };
    let mut report = String::new();
    let termination = TerminationSignals::listen().map_err(PurgeError::Signals)?;
    let (done, caught) = until_stopped(&termination, |interrupt| {
        purge_here_and_there(
            (&store, environment, setup.as_ref()),
            (thread, &participant, &owner),
            signer.as_ref(),
            interrupt,
            &mut report,
        )
    });
    if let Some(signal) = caught {
        return Ok(Purged::Stopped(signal, report));
    }
    if let Err(error) = done {
        return Ok(Purged::Failed(report, error));
    }
    let keep_meta = signer.is_some() || ended_here(&store, thread, &owner);
    if let Err(error) = forget_here(&store, (thread, &participant), keep_meta, &mut report) {
        return Ok(Purged::Failed(report, error));
    }
    lock.remove().map_err(PurgeError::Remove)?;
    let _ = writeln!(report, "purged thread {thread}");
    Ok(Purged::Done(report))
}

/// Ends the thread on the chosen remote, if any: the owner fetches the thread first, so the
/// tombstone follows the newest `meta` the remote holds, and a remote without the thread gets
/// nothing. The owner's tombstone is committed here too.
fn purge_here_and_there(
    (store, environment, setup): (&Store, &Environment, Option<&SyncSetup>),
    (thread, participant, owner): (ThreadId, &ParticipantName, &ParticipantKey),
    signer: Option<&AgentSigner>,
    interrupt: &Arc<AtomicBool>,
    report: &mut String,
) -> Result<(), PurgeError> {
    let mut remote = setup;
    if let (Some(setup), Some(_)) = (setup, signer) {
        let limit = sync::transfer_limits(environment).fetch_limit;
        let fetched = sync::fetch_from((store, setup), (thread, owner, None), limit, interrupt)
            .map_err(PurgeError::Fetch)?;
        if fetched.is_none() {
            let _ = writeln!(report, "{} has no copy of the thread", setup.name);
            remote = None;
        }
    }
    if let Some(signer) = signer {
        tombstone_thread(store, thread, signer).map_err(PurgeError::Thread)?;
        let _ = writeln!(report, "ended thread {thread} here");
    }
    match remote {
        Some(setup) => purge_remote(
            (store, setup),
            (thread, participant),
            signer.is_some(),
            interrupt,
            report,
        )?,
        None if setup.is_none() => {
            report.push_str("no remote is chosen; only the local copy is purged\n");
        }
        None => {}
    }
    Ok(())
}

fn forget_here(
    store: &Store,
    (thread, participant): (ThreadId, &ParticipantName),
    keep_meta: bool,
    report: &mut String,
) -> Result<(), PurgeError> {
    remove_local(store, thread, participant, report)?;
    let deleted = store.forget_thread(thread, keep_meta)?;
    let _ = writeln!(report, "deleted {deleted} of the thread's refs here");
    Ok(())
}

/// Pushes the owner's tombstone, already committed here, and deletes the thread's other refs
/// on the remote, or, for a participant who is not the `owner`, deletes their own agents'
/// refs there, refusing to go on when the remote kept any of them.
fn purge_remote(
    (store, setup): (&Store, &SyncSetup),
    (thread, participant): (ThreadId, &ParticipantName),
    owner: bool,
    interrupt: &Arc<AtomicBool>,
    report: &mut String,
) -> Result<(), PurgeError> {
    let meta = ThreadRef::new(thread, RefKind::Meta);
    if owner {
        let transport = setup.connect(interrupt).map_err(PurgeError::Push)?;
        let pushed = store
            .push_refs(transport, std::slice::from_ref(&meta), interrupt)
            .map_err(|error| PurgeError::Push(PushError::Push(error)))?;
        match pushed.first() {
            Some((_, Pushed::Updated | Pushed::UpToDate)) => {
                let _ = writeln!(report, "ended thread {thread} on {}", setup.name);
            }
            Some((_, outcome)) => return Err(PurgeError::TombstoneNotPushed(describe(outcome))),
            None => return Err(PurgeError::TombstoneNotPushed("no meta".to_owned())),
        }
    }
    let meta_name = meta.to_string();
    let own_prefix = format!("{THREADS_PREFIX}{thread}/agents/{participant}.");
    let transport = setup.connect(interrupt).map_err(PurgeError::Push)?;
    let deleted = store
        .delete_remote_refs(
            transport,
            thread,
            &|name| selected(name, owner, (&meta_name, &own_prefix)),
            interrupt,
        )
        .map_err(|error| PurgeError::Push(PushError::Push(error)))?;
    let mut kept = 0;
    for (name, outcome) in deleted {
        if outcome == Pushed::Updated {
            let _ = writeln!(report, "deleted {name} on {}", setup.name);
        } else {
            kept += 1;
            let _ = writeln!(
                report,
                "kept {name} on {}: {}",
                setup.name,
                describe(&outcome)
            );
        }
    }
    if kept > 0 && !owner {
        return Err(PurgeError::RemoteKept(kept));
    }
    Ok(())
}

fn selected(name: &str, owner: bool, (meta, own_prefix): (&str, &str)) -> bool {
    if owner {
        name != meta
    } else {
        name.starts_with(own_prefix)
    }
}

fn describe(outcome: &Pushed) -> String {
    match outcome {
        Pushed::Updated => "done".to_owned(),
        Pushed::UpToDate => "already there".to_owned(),
        Pushed::Behind => {
            "another clone of yours changed the thread's meta on the remote after this one \
             fetched it; this clone has ended the thread already, so run mahi purge from that \
             clone"
                .to_owned()
        }
        Pushed::Unchecked(reason) | Pushed::Refused(reason) => reason.clone(),
        Pushed::Deferred | Pushed::TooLarge(_) => "it did not fit within push-limit".to_owned(),
    }
}

fn confirmed(thread: ThreadId, setup: Option<&SyncSetup>) -> Result<bool, PurgeError> {
    let mut prompt = TerminalPrompt::open().map_err(PurgeError::Prompt)?;
    let where_ = match setup {
        Some(setup) => format!("here and on {}", setup.name),
        None => "here only, since no remote is chosen".to_owned(),
    };
    let answer = prompt
        .answer(&format!(
            "Purge thread {thread} {where_}? Its history, worktrees and agents' state are \
             deleted for good. [y/N] "
        ))
        .map_err(PurgeError::Prompt)?;
    Ok(matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn read_meta(store: &Store, thread: ThreadId) -> Option<Vec<u8>> {
    let commit = store.head(&ThreadRef::new(thread, RefKind::Meta)).ok()??;
    store
        .read_entry(commit, META_ENTRY, MAX_META_BYTES as u64)
        .ok()?
}

fn signed_by(store: &Store, thread: ThreadId, key: &ParticipantKey) -> bool {
    read_meta(store, thread)
        .is_some_and(|encoded| MetaDocument::decode(&encoded, thread, key).is_ok())
}

fn ended_here(store: &Store, thread: ThreadId, owner: &ParticipantKey) -> bool {
    read_meta(store, thread).is_some_and(|encoded| {
        matches!(
            MetaDocument::decode(&encoded, thread, owner),
            Ok(MetaDocument::Purged(_))
        )
    })
}

fn remove_local(
    store: &Store,
    thread: ThreadId,
    participant: &ParticipantName,
    report: &mut String,
) -> Result<(), PurgeError> {
    let mut names: Vec<String> = session::own_slots(store, thread, participant)?
        .iter()
        .map(|slot| session::worktree_name(thread, slot.agent()))
        .collect();
    names.push(format!("{thread}@{LAND}"));
    for name in names {
        match store.worktree_dir(&name) {
            Ok(worktree) => {
                if let Ok(Some(branch)) = store.worktree_branch(&name) {
                    let _ = writeln!(
                        report,
                        "kept the branch {branch}; git branch -D {branch} deletes it"
                    );
                }
                store.remove_worktree(&name)?;
                if let Some(repository) = worktree.parent() {
                    let _ = fs::remove_dir(repository);
                }
                let _ = writeln!(report, "removed the worktree {}", worktree.display());
            }
            Err(StoreError::NotAWorktree(_)) => {
                store.prune_worktree(&name)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    match fs::remove_dir_all(session::state_root(store, thread)) {
        Ok(()) => report.push_str("removed the agents' state\n"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(PurgeError::Remove(error)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_owner_deletes_all_but_meta_and_a_participant_only_their_own_agents_refs() {
        let thread = ThreadId::random().unwrap();
        let meta = format!("refs/threads/{thread}/meta");
        let own = format!("refs/threads/{thread}/agents/alice.");
        let names = [
            meta.clone(),
            format!("refs/threads/{thread}/state"),
            format!("refs/threads/{thread}/agents/alice.claude/snapshots"),
            format!("refs/threads/{thread}/agents/alice-b.claude/snapshots"),
            format!("refs/threads/{thread}/agents/bob.codex/transcript"),
        ];
        let pick = |owner| -> Vec<&str> {
            names
                .iter()
                .map(String::as_str)
                .filter(|name| selected(name, owner, (&meta, &own)))
                .collect()
        };
        let all_but_meta: Vec<&str> = names[1..].iter().map(String::as_str).collect();
        assert_eq!(pick(true), all_but_meta);
        assert_eq!(pick(false), [names[2].as_str()]);
    }
}
