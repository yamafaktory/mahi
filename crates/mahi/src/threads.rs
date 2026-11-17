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
    ops::ControlFlow,
};

use jiff::Timestamp;
use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
};
use mahi_crypto::ThreadKey;
use mahi_identity::{
    ConfigDir,
    ConfigError,
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
    walk_turns_while,
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
    thread_keys::{
        MahiKey,
        ThreadKeys,
        UnlockError,
    },
    when::{
        self,
        Clock,
        TimeText,
    },
};

const ACTIVITY_TURNS: usize = 64;

#[derive(Debug, Error)]
pub(crate) enum ThreadsError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot read the repository's threads")]
    Store(#[from] StoreError),
    #[error("cannot write the threads as JSON")]
    Json(#[source] serde_json::Error),
    #[error("mahi is not set up; run mahi init")]
    NotSetUp,
    #[error("cannot find mahi's configuration")]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Unlock(#[from] UnlockError),
}

/// Whether `mahi threads` reads when each thread was last active, which asks for the
/// passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Activity {
    /// Reads no encrypted content.
    Left,
    /// Reads each agent's newest turns that carry a time.
    Read,
}

/// What `mahi threads` prints: the threads, and one line for each thread it could not read.
#[derive(Debug)]
pub(crate) struct Listed {
    pub(crate) listing: String,
    pub(crate) unread: String,
}

/// When a thread was last active, in `mahi threads --json --activity`: the newest time its
/// turns carry, or unknown when none carries one or the thread cannot be read.
#[derive(Debug, Clone, Copy)]
enum LastActive {
    At(TimeText),
    Unknown,
}

impl Serialize for LastActive {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::At(time) => time.serialize(serializer),
            Self::Unknown => serializer.serialize_none(),
        }
    }
}

/// How `mahi threads` prints the threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// One line per thread, for a person.
    Text,
    /// One JSON array, for a script.
    Json,
}

impl Format {
    /// Returns JSON when `--json` was given, and text otherwise.
    pub(crate) fn chosen(json: bool) -> Self {
        if json { Self::Json } else { Self::Text }
    }
}

/// One thread as `mahi threads --json` prints it.
#[derive(Debug, Serialize)]
struct ListedThread<'summary> {
    id: AsText<'summary, ThreadId>,
    agents: Slots<'summary>,
    worktree: bool,
    purged: bool,
    gone_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_active: Option<LastActive>,
}

#[derive(Debug)]
struct Slots<'summary>(&'summary BTreeSet<AgentSlot>);

impl Serialize for Slots<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(AsText))
    }
}

/// A value serialized as the text its `Display` writes.
#[derive(Debug)]
pub(crate) struct AsText<'value, T>(pub(crate) &'value T);

impl<T: Display> Serialize for AsText<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self.0)
    }
}

/// The repository's threads, each as its refs show it.
pub(crate) type Summaries = BTreeMap<ThreadId, ThreadSummary>;

/// One thread of the repository, as its refs show it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ThreadSummary {
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
/// here, each with when it was last active, as `activity` holds it and its clock shows it; a
/// thread whose remembered owner cannot be read counts as a teammate's.
pub(crate) fn home_rows(
    store: &Store,
    summaries: &Summaries,
    activity: Option<(&BTreeMap<ThreadId, Timestamp>, &Clock)>,
) -> Vec<HomeRow> {
    summaries
        .iter()
        .map(|(&thread, summary)| HomeRow {
            thread: thread.to_string(),
            agents: agents_of(summary, None),
            worktree: summary.worktree,
            owned: matches!(remembered_owner(store, thread), Ok(None)),
            last_active: activity.and_then(|(last, clock)| {
                let mut shown = String::new();
                clock.push(&mut shown, *last.get(&thread)?);
                Some(shown)
            }),
        })
        .collect()
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
/// agents and whether their worktree is still there, leaving out a thread purged here. With
/// [`Activity::Read`], it also says when each thread was last active, asking once for the
/// passphrase of the user's mahi key; otherwise it reads no encrypted content.
pub(crate) fn threads(
    environment: &Environment,
    format: Format,
    activity: Activity,
) -> Result<Listed, ThreadsError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(ThreadsError::CurrentDirectory)?;
    let store = Store::discover(&cwd)?;
    let own = own_key(environment);
    let summaries = summarise(&store, own.as_ref())?;
    let mut unread = String::new();
    let last = match activity {
        Activity::Left => None,
        Activity::Read if readable(&summaries).next().is_none() => Some(BTreeMap::new()),
        Activity::Read => {
            let own = own.ok_or(ThreadsError::NotSetUp)?;
            let config = ConfigDir::resolve(
                environment.home.as_deref(),
                environment.xdg_config_home.as_deref(),
            )?;
            let mut keys = ThreadKeys::new(&store, &own, MahiKey::Locked(&config));
            Some(last_activity(&store, &mut keys, &summaries, &mut unread)?)
        }
    };
    let clock = Clock::new(when::now(), environment.time_zone.clone());
    let listing = match format {
        Format::Text => listing_text(&store, &summaries, last.as_ref().map(|last| (last, &clock))),
        Format::Json => listing_json(&store, &summaries, last.as_ref())?,
    };
    Ok(Listed { listing, unread })
}

/// Returns when each of the `summaries`' threads that `keys` opens was last active, reporting
/// into `unread` what cannot be read.
fn last_activity(
    store: &Store,
    keys: &mut ThreadKeys<'_>,
    summaries: &Summaries,
    unread: &mut String,
) -> Result<BTreeMap<ThreadId, Timestamp>, UnlockError> {
    let mut last = BTreeMap::new();
    let threads = readable(summaries);
    for (thread, agents) in threads {
        if let Some(newest) = thread_last_active(store, keys, (thread, agents), unread)? {
            last.insert(thread, newest);
        }
    }
    Ok(last)
}

/// Returns when `thread`, whose agents are `agents`, was last active: the newest time its
/// agents' turns carry, once `keys` opens it; reports into `unread` what cannot be read.
pub(crate) fn thread_last_active(
    store: &Store,
    keys: &mut ThreadKeys<'_>,
    (thread, agents): (ThreadId, &BTreeSet<AgentSlot>),
    unread: &mut String,
) -> Result<Option<Timestamp>, UnlockError> {
    let key = match keys.open(thread)? {
        Ok(key) => key,
        Err(error) => {
            let _ = writeln!(unread, "mahi: cannot read thread {thread}: {error}");
            return Ok(None);
        }
    };
    let times = agents.iter().filter_map(|agent| {
        newest_time(store, &key, (thread, agent)).unwrap_or_else(|error| {
            let _ = writeln!(
                unread,
                "mahi: cannot read every turn of {agent} in thread {thread}: {error}"
            );
            None
        })
    });
    Ok(times.max())
}

/// Returns the newest time `agent`'s turns in `thread` carry, looking back at most
/// [`ACTIVITY_TURNS`] turns; or why its turns cannot be read.
fn newest_time(
    store: &Store,
    key: &ThreadKey,
    (thread, agent): (ThreadId, &AgentSlot),
) -> Result<Option<Timestamp>, String> {
    let mut newest = None;
    walk_turns_while(store, key, thread, agent, ACTIVITY_TURNS, |turn| {
        newest = turn.newest_time();
        if newest.is_some() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .map_err(|error| crate::describe(&error))?;
    Ok(newest)
}

/// Returns the repository's threads a search reads, each with its agents, leaving out a thread
/// its owner purged.
pub(crate) fn searchable(
    store: &Store,
    own: Option<&ParticipantKey>,
) -> Result<Vec<(ThreadId, BTreeSet<AgentSlot>)>, StoreError> {
    let summaries = summarise(store, own)?;
    Ok(readable(&summaries)
        .map(|(thread, agents)| (thread, agents.clone()))
        .collect())
}

/// Returns the `summaries`' threads whose records a reader opens, each with its agents: every
/// thread but those their owner purged.
pub(crate) fn readable(
    summaries: &Summaries,
) -> impl Iterator<Item = (ThreadId, &BTreeSet<AgentSlot>)> {
    summaries
        .iter()
        .filter(|(_, summary)| !summary.purged)
        .map(|(&thread, summary)| (thread, &summary.agents))
}

fn gone_branch(store: &Store, thread: ThreadId) -> Option<String> {
    BranchRecord::read(store, thread)
        .filter(|record| record.gone)
        .map(|record| record.branch)
}

fn listing_text(
    store: &Store,
    summaries: &BTreeMap<ThreadId, ThreadSummary>,
    activity: Option<(&BTreeMap<ThreadId, Timestamp>, &Clock)>,
) -> String {
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
        if let Some((last, clock)) = activity
            && let Some(time) = last.get(&thread)
        {
            listing.push_str("  last active ");
            clock.push(&mut listing, *time);
        }
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
    activity: Option<&BTreeMap<ThreadId, Timestamp>>,
) -> Result<String, ThreadsError> {
    let listed: Vec<ListedThread<'_>> = summaries
        .iter()
        .map(|(thread, summary)| ListedThread {
            id: AsText(thread),
            agents: Slots(&summary.agents),
            worktree: summary.worktree,
            purged: summary.purged,
            gone_branch: gone_branch(store, *thread),
            last_active: activity.map(|last| {
                last.get(thread)
                    .map_or(LastActive::Unknown, |time| LastActive::At(TimeText(*time)))
            }),
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
/// Returns the repository's threads as their refs show them, leaving out a thread purged here;
/// `own` is the user's key, which tells a thread they own.
pub(crate) fn summarise(
    store: &Store,
    own: Option<&ParticipantKey>,
) -> Result<Summaries, StoreError> {
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
    use mahi_thread::Event;

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
    fn the_last_activity_read_unlocked_is_the_newest_time_a_threads_turns_carry() {
        use mahi_thread::TurnRecord;

        use crate::workspace_live::tests::{
            append_alices_turn,
            setup,
        };

        let setup = setup();
        let owner = setup.owner();
        let (asked, ended): (Timestamp, Timestamp) = (
            "2026-11-16T13:00:00Z".parse().unwrap(),
            "2026-11-16T13:02:00Z".parse().unwrap(),
        );
        let events = vec![
            Event::new(0, Some(asked), b"prompt\n".to_vec()).unwrap(),
            Event::new(1, Some(ended), b"turn-end\n".to_vec()).unwrap(),
        ];
        let tip = append_alices_turn(&setup, None, &TurnRecord::new(0, events).unwrap());
        append_alices_turn(&setup, Some(&tip), &TurnRecord::new(1, Vec::new()).unwrap());
        let summaries = summarise(&setup.store, Some(&owner)).unwrap();
        let mut keys = ThreadKeys::new(
            &setup.store,
            &owner,
            MahiKey::Unlocked(setup.identity.clone()),
        );
        let mut unread = String::new();
        let last = last_activity(&setup.store, &mut keys, &summaries, &mut unread).unwrap();
        assert_eq!(last, BTreeMap::from([(setup.thread, ended)]), "{unread}");
    }

    #[test]
    fn last_activity_shows_after_the_worktree_and_in_json_only_when_read() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let tree = store.write_tree(&[]).unwrap();
        let (active, quiet) = (ThreadId::random().unwrap(), ThreadId::random().unwrap());
        for thread in [active, quiet] {
            for thread_ref in [
                ThreadRef::new(thread, RefKind::Meta),
                ThreadRef::new(thread, RefKind::Snapshots(slot("alice", "claude"))),
            ] {
                store.append(&thread_ref, None, tree, "test").unwrap();
            }
        }
        let summaries = summarise(&store, None).unwrap();
        let now: Timestamp = "2026-11-16T13:05:00Z".parse().unwrap();
        let then: Timestamp = "2026-11-16T13:02:00Z".parse().unwrap();
        let last = BTreeMap::from([(active, then)]);
        let text = listing_text(
            &store,
            &summaries,
            Some((&last, &Clock::new(Some(now), None))),
        );
        assert!(
            text.contains(&format!(
                "{active}  alice.claude  no worktree  last active 3m ago\n"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("{quiet}  alice.claude  no worktree\n")),
            "{text}"
        );
        let json = listing_json(&store, &summaries, Some(&last)).unwrap();
        assert!(
            json.contains(&format!(
                "\"id\":\"{active}\",\"agents\":[\"alice.claude\"],\"worktree\":false,\
                 \"purged\":false,\"gone_branch\":null,\"last_active\":\"2026-11-16T13:02:00Z\"}}"
            )),
            "{json}"
        );
        assert!(
            json.contains(&format!("\"id\":\"{quiet}\",")) && json.contains("\"last_active\":null"),
            "{json}"
        );
        assert!(
            !listing_json(&store, &summaries, None)
                .unwrap()
                .contains("last_active")
        );
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
            worktree: None,
            from: None,
            gone: true,
            answer: None,
        }
        .write(&store, thread)
        .unwrap();
        let summaries = summarise(&store, None).unwrap();
        assert_eq!(
            listing_json(&store, &summaries, None).unwrap(),
            format!(
                "[{{\"id\":\"{thread}\",\"agents\":[\"alice.claude\"],\"worktree\":false,\
                 \"purged\":false,\"gone_branch\":\"mahi/\\\"x\\\"\u{200b}\"}}]\n"
            )
        );
        assert!(
            listing_text(&store, &summaries, None)
                .contains("branch mahi/\"x\" gone from the remote"),
        );
    }
}
