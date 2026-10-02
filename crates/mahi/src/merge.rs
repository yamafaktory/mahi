use std::{
    env,
    fmt::Write as _,
    fs,
    io,
    sync::atomic::AtomicBool,
};

use mahi_core::{
    AgentName,
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
    Applied,
    Conflict,
    GlobalPatterns,
    Left,
    Merged,
    ObjectId,
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
    signed_by,
};
use thiserror::Error;

use crate::{
    cli::MergeCommand,
    environment::Environment,
    merged::MergedFrom,
    run::{
        self,
        RunError,
        until_stopped,
    },
    session::{
        self,
        CommitKey,
        ResumeError,
    },
    thread_lock::{
        AgentLock,
        LockError,
    },
};

const SNAPSHOT_ATTEMPTS: usize = 3;
const LISTED: usize = 20;

#[derive(Debug, Error)]
pub(crate) enum MergeError {
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
    #[error(transparent)]
    Agent(#[from] ResumeError),
    #[error(transparent)]
    Run(#[from] Box<RunError>),
    #[error("cannot open thread {0}")]
    Meta(ThreadId, #[source] Box<ThreadError>),
    #[error("{0} cannot be merged into itself")]
    SameAgent(AgentSlot),
    #[error("{1} is running; merging into a running agent is not supported yet")]
    Running(ThreadId, AgentName),
    #[error("cannot lock the agent")]
    Lock(#[source] io::Error),
    #[error("thread {0} does not list {1}")]
    SourceNotListed(ThreadId, ParticipantName),
    #[error("the latest snapshot of {0} is not signed by the key the thread lists for it")]
    NotSigned(AgentSlot),
    #[error("the worktree of {0} is gone; resume it first")]
    NoWorktree(AgentSlot),
    #[error("{0} merged from more agents than mahi records")]
    TooManySources(AgentSlot),
    #[error("cannot catch the signals that stop mahi")]
    Signals(#[source] SignalError),
}

/// What `mahi merge` did: its report, or the signal that stopped it, with the report of a
/// merge that was recorded before it stopped.
#[derive(Debug)]
pub(crate) enum Outcome {
    Done(String),
    Stopped(Termination, Option<String>),
}

/// The agent whose work is merged: its slot and its latest snapshot's tree.
struct Source<'a> {
    slot: &'a AgentSlot,
    tree: ObjectId,
}

/// The agent merged into: its slot, worktree name and snapshots, and what it merged so far.
struct Target<'a> {
    slot: &'a AgentSlot,
    worktree: &'a str,
    snapshots: &'a ThreadRef,
    merged: MergedFrom,
}

/// Merges the latest snapshot of `command.from` into the worktree of one of the user's agents
/// in `command.thread`, which must not be running, and records the merge in a snapshot.
pub(crate) fn merge(
    command: &MergeCommand,
    environment: &Environment,
) -> Result<Outcome, MergeError> {
    let thread = command.thread;
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(MergeError::CurrentDirectory)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let signing =
        SigningKey::load(&config.signing_key_file()).map_err(MergeError::NotInitialised)?;
    let own =
        ParticipantKey::from_public_key(signing.public_key()).map_err(MergeError::OwnerKey)?;
    let participant = session::participant_from(environment.user.as_deref())
        .map_err(MergeError::ParticipantName)?;
    let store = Store::discover(&cwd)?;
    let owner = session::thread_owner(&store, thread, own.clone())
        .map_err(|error| MergeError::ThreadOwner(thread, error))?;
    let into = session::pick_slot(&store, thread, &participant, command.into.as_ref())?;
    if into == command.from {
        return Err(MergeError::SameAgent(into));
    }
    let _lock = match AgentLock::acquire(&config, thread, into.agent()) {
        Ok(lock) => lock,
        Err(LockError::Busy(_) | LockError::AgentBusy(..)) => {
            return Err(MergeError::Running(thread, into.agent().clone()));
        }
        Err(LockError::Io(error)) => return Err(MergeError::Lock(error)),
    };
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
    let commits = match fetched {
        Ok(commits) => commits,
        Err(signal) => return Ok(Outcome::Stopped(signal, None)),
    };
    let meta = load_meta(&store, thread, &owner, 0)
        .map_err(|error| MergeError::Meta(thread, Box::new(error)))?;
    let source_key = meta
        .participants()
        .find(|listed| listed.name() == command.from.participant())
        .map(|listed| listed.key().clone())
        .ok_or_else(|| MergeError::SourceNotListed(thread, command.from.participant().clone()))?;
    let (commit, tree) = run::source_snapshot(&store, &meta, &command.from).map_err(Box::new)?;
    if !signed_by(&store, commit, &source_key).unwrap_or(false) {
        return Err(MergeError::NotSigned(command.from.clone()));
    }
    let worktree = session::worktree_name(thread, into.agent());
    match store.worktree_dir(&worktree) {
        Ok(_) => {}
        Err(StoreError::NotAWorktree(_)) => return Err(MergeError::NoWorktree(into)),
        Err(error) => return Err(error.into()),
    }
    let snapshots = ThreadRef::new(thread, RefKind::Snapshots(into.clone()));
    let mut merged = MergedFrom::read(&store, &snapshots)?;
    let base = match merged.of(&command.from) {
        Some(last) if store.descends_from(commit, last)? => last,
        _ => meta.base(),
    };
    if base == commit {
        return Ok(Outcome::Done(format!(
            "{into} already has the latest snapshot of {}\n",
            command.from
        )));
    }
    if !merged.record(command.from.clone(), commit) {
        return Err(MergeError::TooManySources(into));
    }
    let base_tree = store.commit_tree(base)?;
    let termination = TerminationSignals::listen().map_err(MergeError::Signals)?;
    let globals = environment.git_patterns();
    let source = Source {
        slot: &command.from,
        tree,
    };
    let target = Target {
        slot: &into,
        worktree: &worktree,
        snapshots: &snapshots,
        merged,
    };
    let (report, caught) = until_stopped(&termination, |interrupt| {
        merge_into(
            &store,
            (source, target),
            base_tree,
            (&globals, &commits),
            interrupt,
        )
    });
    if let Some(signal) = caught {
        return Ok(Outcome::Stopped(signal, report.ok()));
    }
    Ok(Outcome::Done(report?))
}

/// Merges `source` into `target`'s worktree from `base`, then records the result in a
/// snapshot carrying `target`'s trailers, which already name `source`'s snapshot, and returns
/// the report. Once the worktree is written, the snapshot is taken even if `interrupt` is set,
/// so a merge is never left unrecorded.
fn merge_into(
    store: &Store,
    (source, target): (Source<'_>, Target<'_>),
    base: ObjectId,
    (globals, commits): (&GlobalPatterns, &CommitKey),
    interrupt: &AtomicBool,
) -> Result<String, MergeError> {
    let mut cache = SnapshotCache::default();
    let ours = snapshot(store, target.worktree, (globals, &mut cache), interrupt)?;
    let labels = (target.slot.to_string(), source.slot.to_string());
    let merged = store.merge_trees(base, ours, source.tree, (&labels.0, &labels.1))?;
    let applied = store.apply_merge(target.worktree, ours, merged.tree, interrupt)?;
    let after = snapshot(
        store,
        target.worktree,
        (globals, &mut cache),
        &AtomicBool::new(false),
    )?;
    let head = store.head(target.snapshots)?;
    store.append_signed(
        target.snapshots,
        head,
        after,
        &target.merged.message(),
        commits.signer(),
    )?;
    Ok(report(source.slot, target.slot, &merged, &applied))
}

fn snapshot(
    store: &Store,
    worktree: &str,
    (globals, cache): (&GlobalPatterns, &mut SnapshotCache),
    interrupt: &AtomicBool,
) -> Result<ObjectId, StoreError> {
    let mut left = SNAPSHOT_ATTEMPTS;
    loop {
        left -= 1;
        match store.snapshot(worktree, globals, cache, interrupt) {
            Err(StoreError::ChangedDuringSnapshot(_)) if left > 0 => {}
            outcome => return outcome.map(|snapshot| snapshot.tree),
        }
    }
}

/// Says what a merge did: the files written and removed, the conflicts and the paths left.
pub(crate) fn report(
    from: &AgentSlot,
    into: &AgentSlot,
    merged: &Merged,
    applied: &Applied,
) -> String {
    let mut report = format!(
        "merged {from} into {into}: {} written, {} removed\n",
        applied.written, applied.removed
    );
    let markers = merged
        .conflicts
        .iter()
        .filter(|(_, conflict)| *conflict == Conflict::Markers)
        .map(|(path, _)| path);
    list(
        &mut report,
        format_args!("conflict markers to resolve in"),
        markers,
    );
    let kept = merged
        .conflicts
        .iter()
        .filter(|(_, conflict)| *conflict == Conflict::KeptOurs)
        .map(|(path, _)| path);
    list(&mut report, format_args!("kept {into}'s side of"), kept);
    for (why, label) in [
        (Left::UnsafeName, "names git refuses to check out"),
        (Left::TooDeep, "nested too deep"),
        (Left::TooLarge, "too large"),
        (Left::Blocked, "something else is in the way"),
        (Left::Unwritable, "cannot be written"),
    ] {
        let paths = applied
            .left
            .iter()
            .filter(|(_, left)| *left == why)
            .map(|(path, _)| path);
        list(
            &mut report,
            format_args!("left as they were ({label})"),
            paths,
        );
    }
    report
}

fn list<'a, T: std::fmt::Debug + 'a>(
    report: &mut String,
    heading: std::fmt::Arguments<'_>,
    paths: impl Iterator<Item = &'a T>,
) {
    let mut count = 0;
    for path in paths {
        if count == 0 {
            let _ = write!(report, "{heading}:");
        }
        if count < LISTED {
            let _ = write!(report, " {path:?}");
        }
        count += 1;
    }
    if count > LISTED {
        let _ = write!(report, " and {} more", count - LISTED);
    }
    if count > 0 {
        report.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use gix::bstr::BString;

    use super::*;

    #[test]
    fn the_report_lists_conflicts_and_left_paths_escaped_and_cut_short() {
        let from: AgentSlot = "bob.codex".parse().unwrap();
        let into: AgentSlot = "alice.claude".parse().unwrap();
        let merged = Merged {
            tree: ObjectId::empty_tree(gix::hash::Kind::Sha1),
            conflicts: vec![
                (BString::from("a.txt"), Conflict::Markers),
                (BString::from("bad\x1b]0;x\x07"), Conflict::Markers),
                (BString::from("image.bin"), Conflict::KeptOurs),
            ],
        };
        let applied = Applied {
            written: 3,
            removed: 1,
            left: (0..25)
                .map(|index| (BString::from(format!("p{index:02}")), Left::Blocked))
                .collect(),
        };
        let report = report(&from, &into, &merged, &applied);
        assert!(report.starts_with("merged bob.codex into alice.claude: 3 written, 1 removed\n"));
        assert!(
            report.contains("conflict markers to resolve in: \"a.txt\" \"bad\\x1b]0;x\\x07\"\n"),
            "{report}"
        );
        assert!(
            report.contains("kept alice.claude's side of: \"image.bin\"\n"),
            "{report}"
        );
        assert!(
            report.contains("something else is in the way): \"p00\""),
            "{report}"
        );
        assert!(report.contains("\"p19\" and 5 more\n"), "{report}");
        assert!(!report.contains('\x1b'));
    }
}
