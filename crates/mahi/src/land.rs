use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    fs,
    io::{
        self,
        Read,
    },
    path::Path,
    sync::atomic::AtomicBool,
};

use mahi_core::{
    AgentSlot,
    NameError,
    ParticipantName,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_identity::{
    ConfigDir,
    ConfigError,
    IdentityError,
    SigningKey,
};
use mahi_sandbox::{
    SignalError,
    Termination,
    TerminationSignals,
};
use mahi_store::{
    SnapshotCache,
    Store,
    StoreError,
};
use mahi_thread::{
    KeyError,
    MetaError,
    OwnerError,
    ParticipantKey,
    ThreadError,
    VerifiedMeta,
    load_meta,
    signed_by,
};
use thiserror::Error;

use crate::{
    cli::LandCommand,
    environment::Environment,
    merge::{
        self,
        MergeRequest,
    },
    merged::MergedFrom,
    run::{
        self,
        Host,
        RunError,
        until_stopped,
    },
    session,
    thread_lock::{
        LandLock,
        LockError,
    },
};

const LAND: &str = "land";
const LANDED_FILE: &str = "mahi-landed";
const MAX_STATE_BYTES: u64 = 64 * 1024;
const LANDING: &str = "the landing worktree";

#[derive(Debug, Error)]
pub(crate) enum LandError {
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
    Repository(#[source] StoreError),
    #[error("cannot read the thread's snapshots")]
    Snapshots(#[source] StoreError),
    #[error("cannot make the landing worktree")]
    Worktree(#[source] StoreError),
    #[error("cannot merge {0} into the landing worktree")]
    Merge(Box<AgentSlot>, #[source] StoreError),
    #[error("cannot land on {0}: it is the thread's landing branch")]
    OntoLandingBranch(String),
    #[error("cannot land on {0}: it is checked out in another worktree")]
    BranchCheckedOut(String),
    #[error("cannot land on {0}: it does not contain the tip of the landing branch {1}")]
    BranchBehind(String, String),
    #[error("the landing worktree is not on a branch; check one out there with git")]
    Detached,
    #[error("the landing worktree is on {0}, not on {1}")]
    OtherBranch(String, String),
    #[error("the landing worktree records more agents than mahi keeps; cannot record {0}")]
    TooManySources(AgentSlot),
    #[error("cannot tell who owns thread {0}")]
    ThreadOwner(ThreadId, #[source] OwnerError),
    #[error(transparent)]
    Run(#[from] Box<RunError>),
    #[error("cannot open thread {0}")]
    Meta(ThreadId, #[source] Box<ThreadError>),
    #[error("cannot read the thread's landing branch")]
    Private(#[source] MetaError),
    #[error("the landing branch {0} does not exist here")]
    NoLandingBranch(String),
    #[error("cannot lock the thread")]
    Lock(#[from] LockError),
    #[error("thread {0} lists no participant called {1}")]
    SourceNotListed(ThreadId, ParticipantName),
    #[error("{0} has no snapshot here")]
    NoSnapshot(AgentSlot),
    #[error("the latest snapshot of {0} is not signed by the key the thread lists for it")]
    NotSigned(AgentSlot),
    #[error("cannot record what was landed")]
    State(#[source] io::Error),
    #[error("cannot catch the signals that stop mahi")]
    Signals(#[source] SignalError),
}

/// What `mahi land` did.
#[derive(Debug)]
pub(crate) enum Outcome {
    Done(String),
    Stopped(Termination, String),
}

/// Makes or reuses the landing worktree of `command.thread`, on its landing branch, and merges
/// into it the latest snapshot of each agent named, or of every agent in the thread.
pub(crate) fn land(command: &LandCommand, environment: &Environment) -> Result<Outcome, LandError> {
    let thread = command.thread;
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(LandError::CurrentDirectory)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let signing =
        SigningKey::load(&config.signing_key_file()).map_err(LandError::NotInitialised)?;
    let own = ParticipantKey::from_public_key(signing.public_key()).map_err(LandError::OwnerKey)?;
    let participant = session::participant_from(environment.user.as_deref())
        .map_err(LandError::ParticipantName)?;
    let store = Store::discover(&cwd).map_err(LandError::Repository)?;
    let owner = session::thread_owner(&store, thread, own.clone())
        .map_err(|error| LandError::ThreadOwner(thread, error))?;
    let _lock = LandLock::acquire(&config, thread)?;
    let fetched = run::listed_and_fetched(
        &store,
        environment,
        (thread, true),
        &owner,
        (&own, &participant),
        &signing,
        None,
    )
    .map_err(Box::new)?;
    if let Err(signal) = fetched {
        return Ok(Outcome::Stopped(signal, String::new()));
    }
    let meta = load_meta(&store, thread, &owner, 0)
        .map_err(|error| LandError::Meta(thread, Box::new(error)))?;
    let sources = sources(&store, &meta, &command.from)?;
    let name = format!("{thread}@{LAND}");
    let (landing, branch) = landing_and_branch(
        &store,
        (&name, command.branch.as_deref()),
        &meta,
        (&participant, &config),
    )?;
    let termination = TerminationSignals::listen().map_err(LandError::Signals)?;
    let mut report = String::new();
    let (done, caught) = until_stopped(&termination, |interrupt| {
        if let Some(landing) = &landing {
            new_landing_worktree(
                (&store, environment),
                &name,
                (landing, &branch),
                interrupt,
                &mut report,
            )?;
        } else {
            let path = store.worktree_dir(&name).map_err(LandError::Worktree)?;
            let _ = writeln!(report, "landing worktree: {}", path.display());
        }
        merge_sources(
            &store,
            (&name, &meta),
            &sources,
            (environment, interrupt),
            &mut report,
        )
    });
    if let Some(signal) = caught {
        return Ok(Outcome::Stopped(signal, report));
    }
    done?;
    let _ = writeln!(
        report,
        "commit there with git on branch {branch}, then run mahi land {thread} --push"
    );
    Ok(Outcome::Done(report))
}

/// Returns the agents to land: those `from` names, each of a participant `meta` lists, or
/// else every agent of the thread that has snapshots here.
fn sources(
    store: &Store,
    meta: &VerifiedMeta,
    from: &[AgentSlot],
) -> Result<Vec<AgentSlot>, LandError> {
    let thread = meta.thread();
    let listed = |slot: &AgentSlot| {
        meta.participants()
            .any(|listed| listed.name() == slot.participant())
    };
    if !from.is_empty() {
        for slot in from {
            if !listed(slot) {
                return Err(LandError::SourceNotListed(
                    thread,
                    slot.participant().clone(),
                ));
            }
        }
        return Ok(from.to_vec());
    }
    let mut all = BTreeSet::new();
    for (thread_ref, _) in store.thread_refs().map_err(LandError::Snapshots)? {
        if thread_ref.thread() != thread {
            continue;
        }
        if let RefKind::Snapshots(slot) = thread_ref.kind()
            && listed(slot)
        {
            all.insert(slot.clone());
        }
    }
    Ok(all.into_iter().collect())
}

/// Returns the thread's landing branch when the landing worktree `name` has to be made, read
/// with the thread key, and the branch to land on: the one the worktree is on, else `wanted`,
/// else `mahi/<thread>`.
fn landing_and_branch(
    store: &Store,
    (name, wanted): (&str, Option<&str>),
    meta: &VerifiedMeta,
    (participant, config): (&ParticipantName, &ConfigDir),
) -> Result<(Option<String>, String), LandError> {
    store.prune_worktree(name).map_err(LandError::Worktree)?;
    let existing = existing_branch(store, name, wanted)?;
    let landing = if existing.is_some() {
        None
    } else {
        let key = run::unlock_thread_key(meta, participant, config).map_err(Box::new)?;
        Some(
            meta.private(&key)
                .map_err(LandError::Private)?
                .landing_branch()
                .to_owned(),
        )
    };
    let branch = match (existing, wanted) {
        (Some(branch), _) => branch,
        (None, Some(branch)) => branch.to_owned(),
        (None, None) => format!("mahi/{}", meta.thread()),
    };
    Ok((landing, branch))
}

/// Returns `None` when the landing worktree `name` is not there yet, or else the branch it is
/// on, refusing a detached one or a `wanted` branch other than that one.
fn existing_branch(
    store: &Store,
    name: &str,
    wanted: Option<&str>,
) -> Result<Option<String>, LandError> {
    let on = match store.worktree_branch(name) {
        Ok(Some(on)) => on,
        Ok(None) => return Err(LandError::Detached),
        Err(StoreError::NotAWorktree(_)) => return Ok(None),
        Err(error) => return Err(LandError::Worktree(error)),
    };
    if let Some(wanted) = wanted
        && on != wanted
    {
        return Err(LandError::OtherBranch(on, wanted.to_owned()));
    }
    Ok(Some(on))
}

/// Makes the landing worktree `name` on `branch`, which starts at the tip of `landing` or, if
/// it exists, must contain it and be checked out nowhere else.
fn new_landing_worktree(
    (store, environment): (&Store, &Environment),
    name: &str,
    (landing, branch): (&str, &str),
    interrupt: &AtomicBool,
    report: &mut String,
) -> Result<(), LandError> {
    if branch == landing {
        return Err(LandError::OntoLandingBranch(branch.to_owned()));
    }
    let tip = store
        .branch_tip(landing)
        .map_err(LandError::Worktree)?
        .ok_or_else(|| LandError::NoLandingBranch(landing.to_owned()))?;
    if let Some(existing) = store.branch_tip(branch).map_err(LandError::Worktree)? {
        if store
            .branch_checked_out(branch)
            .map_err(LandError::Worktree)?
        {
            return Err(LandError::BranchCheckedOut(branch.to_owned()));
        }
        if !store
            .descends_from(existing, tip)
            .map_err(LandError::Worktree)?
        {
            return Err(LandError::BranchBehind(
                branch.to_owned(),
                landing.to_owned(),
            ));
        }
    }
    store
        .ensure_branch(branch, tip)
        .map_err(LandError::Worktree)?;
    let host = Host::from_environment(environment).map_err(Box::new)?;
    let git_dir =
        fs::canonicalize(store.common_dir()).map_err(|error| LandError::Worktree(error.into()))?;
    let worktrees = run::worktree_dir(environment, &host, &git_dir).map_err(Box::new)?;
    let path = store
        .add_branch_worktree(name, &worktrees.join(name), branch, interrupt)
        .map_err(LandError::Worktree)?;
    let _ = writeln!(
        report,
        "landing worktree: {} (branch {branch} from {landing})",
        path.display()
    );
    Ok(())
}

/// Merges into the landing worktree `name` the latest snapshot of each of `sources`, from the
/// one it landed last, recording each.
fn merge_sources(
    store: &Store,
    (name, meta): (&str, &VerifiedMeta),
    sources: &[AgentSlot],
    (environment, interrupt): (&Environment, &AtomicBool),
    report: &mut String,
) -> Result<(), LandError> {
    let thread = meta.thread();
    let state = store
        .worktree_admin(name)
        .map_err(LandError::Worktree)?
        .join(LANDED_FILE);
    let mut landed = read_landed(&state)?;
    let globals = environment.git_patterns();
    let mut cache = SnapshotCache::default();
    for slot in sources {
        let commit = store
            .head(&ThreadRef::new(thread, RefKind::Snapshots(slot.clone())))
            .map_err(LandError::Snapshots)?
            .ok_or_else(|| LandError::NoSnapshot(slot.clone()))?;
        let key = meta
            .participants()
            .find(|listed| listed.name() == slot.participant())
            .map(|listed| listed.key().clone())
            .ok_or_else(|| LandError::SourceNotListed(thread, slot.participant().clone()))?;
        if !signed_by(store, commit, &key).unwrap_or(false) {
            return Err(LandError::NotSigned(slot.clone()));
        }
        let request = MergeRequest {
            from: slot.clone(),
            commit,
            thread_base: meta.base(),
        };
        let failed = |error| LandError::Merge(Box::new(slot.clone()), error);
        let base = merge::merge_base(store, &landed, &request).map_err(failed)?;
        if base == commit {
            let _ = writeln!(
                report,
                "{LANDING} already has the latest snapshot of {slot}"
            );
            continue;
        }
        let ours = store
            .snapshot(name, &globals, &mut cache, interrupt)
            .map_err(failed)?
            .tree;
        let theirs = slot.to_string();
        let merged = store
            .merge_trees(
                store.commit_tree(base).map_err(failed)?,
                ours,
                store.commit_tree(commit).map_err(failed)?,
                (LANDING, &theirs),
            )
            .map_err(failed)?;
        if !landed.record(slot.clone(), commit) {
            return Err(LandError::TooManySources(slot.clone()));
        }
        let applied = store
            .apply_merge(name, ours, merged.tree, interrupt)
            .map_err(failed)?;
        write_landed(&state, &landed)?;
        report.push_str(&merge::report(slot, &LANDING, &merged, &applied));
    }
    Ok(())
}

fn read_landed(state: &Path) -> Result<MergedFrom, LandError> {
    let file = match fs::File::open(state) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(MergedFrom::default()),
        Err(error) => return Err(LandError::State(error)),
    };
    let mut text = Vec::new();
    file.take(MAX_STATE_BYTES)
        .read_to_end(&mut text)
        .map_err(LandError::State)?;
    Ok(MergedFrom::parse(&text))
}

fn write_landed(state: &Path, landed: &MergedFrom) -> Result<(), LandError> {
    let directory = state.parent().ok_or_else(|| {
        LandError::State(io::Error::new(
            io::ErrorKind::NotFound,
            "no state directory",
        ))
    })?;
    let staged = directory.join(format!(".{LANDED_FILE}.mahi"));
    fs::write(&staged, landed.message()).map_err(LandError::State)?;
    fs::rename(&staged, state).map_err(LandError::State)
}
