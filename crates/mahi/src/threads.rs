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
use mahi_store::{
    Store,
    StoreError,
};
use thiserror::Error;

use crate::{
    landed_branch::BranchRecord,
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
}

/// Lists the threads of the repository around the current directory, with their agents and
/// whether their worktree is still there. Reads no encrypted content.
pub(crate) fn threads() -> Result<String, ThreadsError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(ThreadsError::CurrentDirectory)?;
    let store = Store::discover(&cwd)?;
    let summaries = summarise(&store)?;
    if summaries.is_empty() {
        return Ok("no threads in this repository\n".to_owned());
    }
    let mut listing = String::new();
    for (thread, summary) in summaries {
        let agents: Vec<String> = summary.agents.iter().map(ToString::to_string).collect();
        let agents = if agents.is_empty() {
            "no agent".to_owned()
        } else {
            agents.join(", ")
        };
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

/// Groups the repository's thread refs by thread, keeping only threads that have a `meta` ref.
fn summarise(store: &Store) -> Result<BTreeMap<ThreadId, ThreadSummary>, StoreError> {
    let mut with_meta = BTreeMap::new();
    let mut agents: BTreeMap<ThreadId, BTreeSet<AgentSlot>> = BTreeMap::new();
    for (thread_ref, _) in store.thread_refs()? {
        let thread = thread_ref.thread();
        match thread_ref.kind() {
            RefKind::Meta => {
                with_meta.insert(thread, ThreadSummary::default());
            }
            RefKind::Snapshots(slot) | RefKind::Transcript(slot) | RefKind::Session(slot) => {
                agents.entry(thread).or_default().insert(slot.clone());
            }
            RefKind::State => {}
        }
    }
    for (thread, summary) in &mut with_meta {
        summary.agents = agents.remove(thread).unwrap_or_default();
        summary.worktree = session::has_thread_worktree(store, *thread)?;
    }
    Ok(with_meta)
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
        let summaries = summarise(&store).unwrap();
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[&listed];
        assert_eq!(summary.agents.iter().collect::<Vec<_>>(), [&alice, &bob]);
        assert!(!summary.worktree);
    }
}
