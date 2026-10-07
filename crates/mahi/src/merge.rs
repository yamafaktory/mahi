use std::{
    env,
    fmt::Write as _,
    fs,
    io,
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
    merge_door::{
        self,
        DoorError,
    },
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
const LISTED_IN_PROMPT: usize = 10;
const LONGEST_LISTED: usize = 200;

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
    #[error("thread {0} is locked by another mahi command; try again once it is done")]
    ThreadBusy(ThreadId),
    #[error("cannot find the socket of the mahi running the agent")]
    Door(#[source] io::Error),
    #[error(transparent)]
    Ask(#[from] DoorError),
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
    #[error("the agent's mahi stopped recording before it could merge")]
    RecorderGone,
}

/// What `mahi merge` did: its report, or the signal that stopped it, with the report of a
/// merge that was recorded before it stopped.
#[derive(Debug)]
pub(crate) enum Outcome {
    Done(String),
    Stopped(Termination, Option<String>),
}

/// What a merge brings into an agent's worktree: the latest snapshot of the agent `from`,
/// already checked to be signed by the key the thread lists for it, and the thread's base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MergeRequest {
    pub(crate) from: AgentSlot,
    pub(crate) commit: ObjectId,
    pub(crate) thread_base: ObjectId,
}

/// Where a merge writes: the agent's slot, worktree and snapshots, and how its snapshots are
/// taken and signed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Recording<'a> {
    pub(crate) slot: &'a AgentSlot,
    pub(crate) worktree: &'a str,
    pub(crate) snapshots: &'a ThreadRef,
    pub(crate) globals: &'a GlobalPatterns,
    pub(crate) commits: &'a CommitKey,
}

/// What a merge did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MergeDone {
    /// The agent already has the requested snapshot; nothing changed.
    Already(String),
    /// The merge was written and recorded in the snapshot `commit` of the tree `tree`.
    Merged {
        report: String,
        commit: ObjectId,
        tree: ObjectId,
        /// What to ask the agent when the merge left conflicts.
        prompt: Option<String>,
    },
}

impl MergeDone {
    /// Returns what to tell the user.
    pub(crate) fn report(&self) -> &str {
        match self {
            Self::Already(report) | Self::Merged { report, .. } => report,
        }
    }
}

/// Merges the latest snapshot of `command.from` into the worktree of one of the user's agents
/// in `command.thread` and records the merge in a snapshot; when the agent runs, its mahi
/// merges, once the agent is idle.
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
    let lock = match AgentLock::acquire(&config, thread, into.agent()) {
        Ok(lock) => Some(lock),
        Err(LockError::AgentBusy(..)) => None,
        Err(LockError::Busy(_) | LockError::LandBusy(_)) => {
            return Err(MergeError::ThreadBusy(thread));
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
    let (commit, _) = run::source_snapshot(&store, &meta, &command.from).map_err(Box::new)?;
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
    let request = MergeRequest {
        from: command.from.clone(),
        commit,
        thread_base: meta.base(),
    };
    if lock.is_none() {
        return ask_running(&store, environment, (&into, &snapshots), &request);
    }
    let termination = TerminationSignals::listen().map_err(MergeError::Signals)?;
    let globals = environment.git_patterns();
    let recording = Recording {
        slot: &into,
        worktree: &worktree,
        snapshots: &snapshots,
        globals: &globals,
        commits: &commits,
    };
    let (done, caught) = until_stopped(&termination, |interrupt| {
        let head = store.head(&snapshots)?;
        merge_now(
            &store,
            recording,
            &request,
            (&mut SnapshotCache::default(), head),
            interrupt,
        )
    });
    let report = done.map(|done| done.report().to_owned());
    if let Some(signal) = caught {
        return Ok(Outcome::Stopped(signal, report.ok()));
    }
    Ok(Outcome::Done(report?))
}

/// Asks the mahi running `into`, whose snapshots are `snapshots`, to merge `request` once the
/// agent is idle, unless it already has that snapshot.
fn ask_running(
    store: &Store,
    environment: &Environment,
    (into, snapshots): (&AgentSlot, &ThreadRef),
    request: &MergeRequest,
) -> Result<Outcome, MergeError> {
    let merged = MergedFrom::read(store, snapshots)?;
    let own = store.head(snapshots)?.map(|head| (into, head));
    let theirs = merged_by(store, request.commit);
    if merge_base(store, (&merged, own), (request, &theirs))? == request.commit {
        return Ok(Outcome::Done(already(into, request).report().to_owned()));
    }
    let door = merge_door::door_path(&environment.runtime_dir(), snapshots.thread(), into.agent())
        .map_err(MergeError::Door)?;
    eprintln!(
        "mahi: {} is in use by another mahi; asking it to merge once the agent is idle",
        into.agent()
    );
    Ok(Outcome::Done(merge_door::ask(&door, request)?))
}

/// Merges `request` into `into`'s worktree, whose snapshots are at `head` and remembered in
/// `cache`, from the base [`merge_base`] gives; then records the result in a snapshot whose
/// trailers name `request.commit` and what that snapshot had itself merged. Once the worktree is
/// written, the snapshot is taken even if `interrupt` is set, so a merge is never left
/// unrecorded.
pub(crate) fn merge_now(
    store: &Store,
    into: Recording<'_>,
    request: &MergeRequest,
    (cache, head): (&mut SnapshotCache, Option<ObjectId>),
    interrupt: &AtomicBool,
) -> Result<MergeDone, MergeError> {
    let mut merged_from = MergedFrom::read(store, into.snapshots)?;
    let theirs = merged_by(store, request.commit);
    let own = head.map(|head| (into.slot, head));
    let base = merge_base(store, (&merged_from, own), (request, &theirs))?;
    if base == request.commit {
        return Ok(already(into.slot, request));
    }
    if !merged_from.record(request.from.clone(), request.commit) {
        return Err(MergeError::TooManySources(into.slot.clone()));
    }
    merged_from.absorb(store, (&theirs, into.snapshots.thread()), Some(into.slot));
    let (base, theirs) = (store.commit_tree(base)?, store.commit_tree(request.commit)?);
    let ours = snapshot(store, into.worktree, (into.globals, cache), interrupt)?;
    let labels = (into.slot.to_string(), request.from.to_string());
    let merged = store.merge_trees(base, ours, theirs, (&labels.0, &labels.1))?;
    let applied = store.apply_merge(into.worktree, ours, merged.tree, interrupt)?;
    let tree = snapshot(
        store,
        into.worktree,
        (into.globals, cache),
        &AtomicBool::new(false),
    )?;
    let commit = store.append_signed(
        into.snapshots,
        head,
        tree,
        &merged_from.message(),
        into.commits.signer(),
    )?;
    Ok(MergeDone::Merged {
        report: report(&request.from, into.slot, &merged, &applied),
        commit,
        tree,
        prompt: conflict_prompt(&request.from, &merged),
    })
}

/// Returns the snapshot a merge of `request` starts from: the snapshot of `request.from` that
/// `merged` says was merged last, when the requested one descends from it; else a snapshot of
/// another agent that both the requested history, by its own trailers, and the target hold,
/// through `merged` or through its own snapshots at `own` when the target is that agent, as
/// after a handoff; or else the thread's base.
pub(crate) fn merge_base(
    store: &Store,
    (merged, own): (&MergedFrom, Option<(&AgentSlot, ObjectId)>),
    (request, theirs): (&MergeRequest, &MergedFrom),
) -> Result<ObjectId, StoreError> {
    if let Some(last) = merged.of(&request.from)
        && store.descends_from(request.commit, last)?
    {
        return Ok(last);
    }
    Ok(merged
        .shared_with(store, theirs, own)
        .unwrap_or(request.thread_base))
}

/// Reads what the snapshot history ending at `commit` merged, or nothing when it cannot be
/// read, since a merge only uses it to find a closer base.
pub(crate) fn merged_by(store: &Store, commit: ObjectId) -> MergedFrom {
    MergedFrom::read_from(store, Some(commit)).unwrap_or_default()
}

fn already(into: &AgentSlot, request: &MergeRequest) -> MergeDone {
    MergeDone::Already(format!(
        "{into} already has the latest snapshot of {}\n",
        request.from
    ))
}

/// Returns what to ask the agent after a merge that left conflicts: to resolve the markers,
/// and to look at the files where its side was kept.
fn conflict_prompt(from: &AgentSlot, merged: &Merged) -> Option<String> {
    if merged.conflicts.is_empty() {
        return None;
    }
    let mut prompt = format!(
        "mahi merged the latest work of {from} into this worktree, and some changes conflict.\n"
    );
    let markers = merged
        .conflicts
        .iter()
        .filter(|(_, conflict)| *conflict == Conflict::Markers)
        .map(|(path, _)| path);
    list(
        &mut prompt,
        (
            format_args!("Resolve the conflict markers in"),
            LISTED_IN_PROMPT,
        ),
        markers,
    );
    let kept = merged
        .conflicts
        .iter()
        .filter(|(_, conflict)| *conflict == Conflict::KeptOurs)
        .map(|(path, _)| path);
    list(
        &mut prompt,
        (
            format_args!("Your version was kept, but {from} changed these too; check them"),
            LISTED_IN_PROMPT,
        ),
        kept,
    );
    Some(prompt)
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
    into: &dyn std::fmt::Display,
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
        (format_args!("conflict markers to resolve in"), LISTED),
        markers,
    );
    let kept = merged
        .conflicts
        .iter()
        .filter(|(_, conflict)| *conflict == Conflict::KeptOurs)
        .map(|(path, _)| path);
    list(
        &mut report,
        (format_args!("kept {into}'s side of"), LISTED),
        kept,
    );
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
            (format_args!("left as they were ({label})"), LISTED),
            paths,
        );
    }
    report
}

fn list<'a, T: std::fmt::Debug + 'a>(
    report: &mut String,
    (heading, most): (std::fmt::Arguments<'_>, usize),
    paths: impl Iterator<Item = &'a T>,
) {
    let mut count = 0;
    for path in paths {
        if count == 0 {
            let _ = write!(report, "{heading}:");
        }
        if count < most {
            let start = report.len();
            let _ = write!(report, " {path:?}");
            if report.len() - start > LONGEST_LISTED {
                let mut end = start + LONGEST_LISTED;
                while !report.is_char_boundary(end) {
                    end -= 1;
                }
                report.truncate(end);
                report.push_str("...");
            }
        }
        count += 1;
    }
    if count > most {
        let _ = write!(report, " and {} more", count - most);
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

    #[test]
    fn the_prompt_after_a_merge_names_the_files_to_resolve_and_to_check_or_is_not_asked() {
        let from: AgentSlot = "bob.codex".parse().unwrap();
        let mut merged = Merged {
            tree: ObjectId::empty_tree(gix::hash::Kind::Sha1),
            conflicts: Vec::new(),
        };
        assert_eq!(conflict_prompt(&from, &merged), None);
        merged.conflicts = vec![
            (BString::from("a.txt"), Conflict::Markers),
            (BString::from("image.bin"), Conflict::KeptOurs),
        ];
        let prompt = conflict_prompt(&from, &merged).unwrap();
        assert!(
            prompt.starts_with("mahi merged the latest work of bob.codex"),
            "{prompt}"
        );
        assert!(
            prompt.contains("Resolve the conflict markers in: \"a.txt\"\n"),
            "{prompt}"
        );
        assert!(
            prompt.contains("bob.codex changed these too; check them: \"image.bin\"\n"),
            "{prompt}"
        );
    }

    #[test]
    fn a_long_path_is_cut_short_in_the_report() {
        let from: AgentSlot = "bob.codex".parse().unwrap();
        let into: AgentSlot = "alice.claude".parse().unwrap();
        let long = "\u{e9}".repeat(400);
        let merged = Merged {
            tree: ObjectId::empty_tree(gix::hash::Kind::Sha1),
            conflicts: vec![(BString::from(long.as_str()), Conflict::Markers)],
        };
        let report = report(&from, &into, &merged, &Applied::default());
        let line = report.lines().nth(1).unwrap();
        assert!(line.ends_with("..."), "{line}");
        assert!(line.len() < "conflict markers to resolve in:".len() + LONGEST_LISTED + 4);
    }
}
