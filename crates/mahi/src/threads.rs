use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    env,
    fmt::{
        Display,
        Write as _,
    },
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
use serde::{
    Serialize,
    Serializer,
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
    #[error("cannot write the threads as JSON")]
    Json(#[source] serde_json::Error),
}

/// How `mahi threads` prints the threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// One line per thread, for a person.
    Text,
    /// One JSON array, for a script.
    Json,
}

/// One thread as `mahi threads --json` prints it.
#[derive(Debug, Serialize)]
struct ListedThread<'summary> {
    #[serde(serialize_with = "as_text")]
    id: ThreadId,
    agents: Slots<'summary>,
    worktree: bool,
    purged: bool,
    gone_branch: Option<String>,
}

fn as_text<S: Serializer>(value: &impl Display, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

#[derive(Debug)]
struct Slots<'summary>(&'summary BTreeSet<AgentSlot>);

impl Serialize for Slots<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(AsText))
    }
}

#[derive(Debug)]
struct AsText<'value, T>(&'value T);

impl<T: Display> Serialize for AsText<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self.0)
    }
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

/// Lists the threads of the repository around the current directory in `format`, with their
/// agents and whether their worktree is still there, leaving out a thread purged here. Reads no
/// encrypted content.
pub(crate) fn threads(environment: &Environment, format: Format) -> Result<String, ThreadsError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(ThreadsError::CurrentDirectory)?;
    let store = Store::discover(&cwd)?;
    let summaries = summarise(&store, own_key(environment).as_ref())?;
    match format {
        Format::Text => Ok(listing_text(&store, &summaries)),
        Format::Json => listing_json(&store, &summaries),
    }
}

fn gone_branch(store: &Store, thread: ThreadId) -> Option<String> {
    BranchRecord::read(store, thread)
        .filter(|record| record.gone)
        .map(|record| record.branch)
}

fn listing_text(store: &Store, summaries: &BTreeMap<ThreadId, ThreadSummary>) -> String {
    if summaries.is_empty() {
        return "no threads in this repository\n".to_owned();
    }
    let mut listing = String::new();
    for (&thread, summary) in summaries {
        let agents = agents_of(summary, Some(thread));
        let worktree = if summary.worktree {
            "worktree"
        } else {
            "no worktree"
        };
        let _ = write!(listing, "{thread}  {agents}  {worktree}");
        if let Some(branch) = gone_branch(store, thread) {
            let branch = BranchRecord::shown(&branch);
            let _ = write!(
                listing,
                "  branch {branch} gone from the remote, merged or closed; mahi purge {thread} \
                 removes the thread"
            );
        }
        listing.push('\n');
    }
    listing
}

fn listing_json(
    store: &Store,
    summaries: &BTreeMap<ThreadId, ThreadSummary>,
) -> Result<String, ThreadsError> {
    let listed: Vec<ListedThread<'_>> = summaries
        .iter()
        .map(|(&thread, summary)| ListedThread {
            id: thread,
            agents: Slots(&summary.agents),
            worktree: summary.worktree,
            purged: summary.purged,
            gone_branch: gone_branch(store, thread),
        })
        .collect();
    let mut listing = serde_json::to_string(&listed).map_err(ThreadsError::Json)?;
    listing.push('\n');
    Ok(listing)
}

/// Returns the agents `thread` has refs of here, in order.
///
/// # Errors
///
/// Returns the [`StoreError`] of reading the refs.
pub(crate) fn thread_agents(store: &Store, thread: ThreadId) -> Result<Vec<AgentSlot>, StoreError> {
    let agents: BTreeSet<AgentSlot> = store
        .thread_refs()?
        .into_iter()
        .filter(|(thread_ref, _)| thread_ref.thread() == thread)
        .filter_map(|(thread_ref, _)| match thread_ref.kind() {
            RefKind::Snapshots(slot) | RefKind::Transcript(slot) | RefKind::Session(slot) => {
                Some(slot.clone())
            }
            RefKind::Meta | RefKind::State => None,
        })
        .collect();
    Ok(agents.into_iter().collect())
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
    use mahi_store::ObjectId;

    use super::*;

    fn slot(participant: &str, agent: &str) -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new(participant).unwrap(),
            AgentName::new(agent).unwrap(),
        )
    }

    #[test]
    fn a_threads_agents_come_from_its_own_agent_refs_once_each_in_order() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let tree = store.write_tree(&[]).unwrap();
        let thread = ThreadId::random().unwrap();
        let other = ThreadId::random().unwrap();
        let (alice, bob) = (slot("alice", "claude"), slot("bob", "codex"));
        for thread_ref in [
            ThreadRef::new(thread, RefKind::Meta),
            ThreadRef::new(thread, RefKind::State),
            ThreadRef::new(thread, RefKind::Transcript(bob.clone())),
            ThreadRef::new(thread, RefKind::Snapshots(bob.clone())),
            ThreadRef::new(thread, RefKind::Session(alice.clone())),
            ThreadRef::new(other, RefKind::Snapshots(slot("carol", "claude"))),
        ] {
            store.append(&thread_ref, None, tree, "test").unwrap();
        }
        assert_eq!(thread_agents(&store, thread).unwrap(), [alice, bob]);
        assert!(
            thread_agents(&store, ThreadId::random().unwrap())
                .unwrap()
                .is_empty()
        );
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

    #[test]
    fn json_names_a_branch_the_forge_deleted_as_it_is_and_text_shows_it_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let tree = store.write_tree(&[]).unwrap();
        let thread = ThreadId::random().unwrap();
        let alice = slot("alice", "claude");
        for thread_ref in [
            ThreadRef::new(thread, RefKind::Meta),
            ThreadRef::new(thread, RefKind::Snapshots(alice)),
        ] {
            store.append(&thread_ref, None, tree, "test").unwrap();
        }
        BranchRecord {
            remote: "up".to_owned(),
            branch: "mahi/\"x\"\u{200b}".to_owned(),
            tip: ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap(),
            landing: "main".to_owned(),
            gone: true,
        }
        .write(&store, thread)
        .unwrap();
        let summaries = summarise(&store, None).unwrap();
        assert_eq!(
            listing_json(&store, &summaries).unwrap(),
            format!(
                "[{{\"id\":\"{thread}\",\"agents\":[\"alice.claude\"],\"worktree\":false,\
                 \"purged\":false,\"gone_branch\":\"mahi/\\\"x\\\"\u{200b}\"}}]\n"
            )
        );
        assert!(
            listing_text(&store, &summaries).contains("branch mahi/\"x\" gone from the remote"),
        );
    }
}
