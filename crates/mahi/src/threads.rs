use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    env,
    fmt::Write as _,
    fs,
    io,
};

use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
};
use mahi_identity::{
    ConfigDir,
    SigningKey,
};
use mahi_store::{
    Store,
    StoreError,
};
use mahi_term::HomeRow;
use mahi_thread::{
    ParticipantKey,
    remembered_owner,
};
use thiserror::Error;

use crate::{
    environment::Environment,
    landed_branch::BranchRecord,
    purge,
    session,
};

#[derive(Debug, Error)]
pub(crate) enum ThreadsError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot read the repository's threads")]
    Store(#[from] StoreError),
}

/// One thread of the repository, as its refs show it.
#[derive(Debug, Default, PartialEq, Eq)]
struct ThreadSummary {
    agents: BTreeSet<AgentSlot>,
    worktree: bool,
    purged: bool,
    leftover: bool,
}

/// Returns the user's own key, which signs the threads they own, when mahi is set up.
pub(crate) fn own_key(environment: &Environment) -> Option<ParticipantKey> {
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )
    .ok()?;
    let signing = SigningKey::load(&config.signing_key_file()).ok()?;
    ParticipantKey::from_public_key(signing.public_key()).ok()
}

/// Returns the repository's threads as the home screen lists them, leaving out a thread purged
/// here; a thread whose remembered owner cannot be read counts as a teammate's.
pub(crate) fn home_rows(
    store: &Store,
    own: Option<&ParticipantKey>,
) -> Result<Vec<HomeRow>, StoreError> {
    Ok(summarise(store, own)?
        .into_iter()
        .map(|(thread, summary)| HomeRow {
            thread: thread.to_string(),
            agents: agents_of(&summary, None),
            worktree: summary.worktree,
            owned: matches!(remembered_owner(store, thread), Ok(None)),
        })
        .collect())
}

/// Lists a thread's agents, or says it was purged by its owner and how to purge what is left
/// here: with `mahi purge` when the `thread` is given, for the command line.
fn agents_of(summary: &ThreadSummary, thread: Option<ThreadId>) -> String {
    if summary.purged {
        return match thread {
            Some(thread) => {
                format!("purged by its owner; mahi purge {thread} removes what is left here")
            }
            None => "purged by its owner; purging removes what is left here".to_owned(),
        };
    }
    if summary.agents.is_empty() {
        return "no agent".to_owned();
    }
    let mut listed = String::new();
    for (index, agent) in summary.agents.iter().enumerate() {
        if index > 0 {
            listed.push_str(", ");
        }
        let _ = write!(listed, "{agent}");
    }
    listed
}

/// Lists the threads of the repository around the current directory, with their agents and
/// whether their worktree is still there, leaving out a thread purged here. Reads no encrypted
/// content.
pub(crate) fn threads(environment: &Environment) -> Result<String, ThreadsError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(ThreadsError::CurrentDirectory)?;
    let store = Store::discover(&cwd)?;
    let summaries = summarise(&store, own_key(environment).as_ref())?;
    if summaries.is_empty() {
        return Ok("no threads in this repository\n".to_owned());
    }
    let mut listing = String::new();
    for (thread, summary) in summaries {
        let agents = agents_of(&summary, Some(thread));
        let worktree = if summary.worktree {
            "worktree"
        } else {
            "no worktree"
        };
        let _ = write!(listing, "{thread}  {agents}  {worktree}");
        if let Some(record) = BranchRecord::read(&store, thread).filter(|record| record.gone) {
            let _ = write!(
                listing,
                "  branch {} gone from the remote, merged or closed; mahi purge {thread} removes \
                 the thread",
                BranchRecord::shown(&record.branch)
            );
        }
        listing.push('\n');
    }
    Ok(listing)
}

/// Groups the repository's thread refs by thread, keeping only threads that have a `meta` ref
/// and leaving out those whose `meta` is the owner's tombstone with nothing else left here: no
/// other ref, fetched ref, worktree or agents' state.
/// The owner of a thread with no remembered owner is `own`, the user.
fn summarise(
    store: &Store,
    own: Option<&ParticipantKey>,
) -> Result<BTreeMap<ThreadId, ThreadSummary>, StoreError> {
    let mut with_meta = BTreeMap::new();
    let mut agents: BTreeMap<ThreadId, BTreeSet<AgentSlot>> = BTreeMap::new();
    let mut with_state = BTreeSet::new();
    for (thread_ref, _) in store.thread_refs()? {
        let thread = thread_ref.thread();
        match thread_ref.kind() {
            RefKind::Meta => {
                with_meta.insert(thread, ThreadSummary::default());
            }
            RefKind::Snapshots(slot) | RefKind::Transcript(slot) | RefKind::Session(slot) => {
                agents.entry(thread).or_default().insert(slot.clone());
            }
            RefKind::State => {
                with_state.insert(thread);
            }
        }
    }
    for (thread, summary) in &mut with_meta {
        summary.agents = agents.remove(thread).unwrap_or_default();
        summary.worktree = session::has_thread_worktree(store, *thread)?;
        summary.purged = purged(store, *thread, own);
        summary.leftover = summary.purged
            && (!summary.agents.is_empty()
                || summary.worktree
                || with_state.contains(thread)
                || !store
                    .fetched_refs(*thread)
                    .is_ok_and(|refs| refs.is_empty())
                || session::state_root(store, *thread).exists());
    }
    with_meta.retain(|_, summary| !summary.purged || summary.leftover);
    Ok(with_meta)
}

fn purged(store: &Store, thread: ThreadId, own: Option<&ParticipantKey>) -> bool {
    let Ok(remembered) = remembered_owner(store, thread) else {
        return false;
    };
    remembered
        .as_ref()
        .or(own)
        .is_some_and(|owner| purge::ended_here(store, thread, owner))
}

#[cfg(test)]
mod tests {
    use mahi_core::{
        AgentName,
        ParticipantName,
        ThreadRef,
    };

    use super::*;

    fn slot(participant: &str, agent: &str) -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new(participant).unwrap(),
            AgentName::new(agent).unwrap(),
        )
    }

    #[test]
    fn agents_are_grouped_per_thread_and_threads_without_meta_are_hidden() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let tree = store.write_tree(&[]).unwrap();
        let listed = ThreadId::random().unwrap();
        let hidden = ThreadId::random().unwrap();
        let alice = slot("alice", "claude");
        let bob = slot("bob", "codex");
        for thread_ref in [
            ThreadRef::new(listed, RefKind::Meta),
            ThreadRef::new(listed, RefKind::Snapshots(alice.clone())),
            ThreadRef::new(listed, RefKind::Transcript(alice.clone())),
            ThreadRef::new(listed, RefKind::Snapshots(bob.clone())),
            ThreadRef::new(hidden, RefKind::Snapshots(alice.clone())),
        ] {
            store.append(&thread_ref, None, tree, "test").unwrap();
        }
        let summaries = summarise(&store, None).unwrap();
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[&listed];
        assert_eq!(summary.agents.iter().collect::<Vec<_>>(), [&alice, &bob]);
        assert!(!summary.worktree);
    }
}
