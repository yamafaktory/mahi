use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    AgentSlot,
    ParticipantName,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_live::{
    COMMIT_BYTES,
    LiveError,
    LiveNode,
    SnapshotsRequest,
    TurnEnd,
};
use mahi_store::{
    ObjectId,
    Store,
    StoreError,
    TakeLimits,
};
use mahi_thread::{
    NodeId,
    ParticipantKey,
    Role,
    SnapshotsAccepted,
    SnapshotsRefusal,
    ThreadError,
    VerifiedMeta,
    accept_snapshots,
    load_meta,
};
use thiserror::Error;

use crate::turn_end;

const MAX_HEARD: usize = 256;
const MAX_HEARD_PER_PARTICIPANT: usize = 16;
const MAX_COMMITS: usize = 4096;
const MAX_ANSWER_BYTES: u64 = 256 << 20;
const ROUND_EVERY: Duration = Duration::from_secs(1);
const RETRY_SOON: Duration = Duration::from_secs(5);
const RETRY_LATER: Duration = Duration::from_secs(30);
const PAUSE: Duration = Duration::from_millis(100);
const MAX_SOON_TRIES: u8 = 3;

/// The latest turn-end snapshot heard of each teammate's agent, with the node that announced
/// it: at most 256 agents, and 16 of one participant.
#[derive(Debug, Default)]
pub(crate) struct Heard {
    latest: Mutex<HashMap<AgentSlot, (NodeId, ObjectId)>>,
}

impl Heard {
    /// Notes that `node`, which the live layer checked owns the agent, announced `ended`.
    pub(crate) fn hear(&self, node: NodeId, ended: &TurnEnd) {
        let Ok(commit) = ObjectId::try_from(ended.commit.as_slice()) else {
            return;
        };
        let Ok(mut latest) = self.latest.lock() else {
            return;
        };
        if !latest.contains_key(&ended.slot) {
            let theirs = latest
                .keys()
                .filter(|slot| slot.participant() == ended.slot.participant())
                .count();
            if latest.len() >= MAX_HEARD || theirs >= MAX_HEARD_PER_PARTICIPANT {
                return;
            }
        }
        latest.insert(ended.slot.clone(), (node, commit));
    }

    fn waiting(&self) -> Vec<(AgentSlot, NodeId, ObjectId)> {
        self.latest
            .lock()
            .map(|latest| {
                latest
                    .iter()
                    .map(|(slot, (node, commit))| (slot.clone(), *node, *commit))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn forget(&self, slot: &AgentSlot, commit: ObjectId) {
        if let Ok(mut latest) = self.latest.lock()
            && latest.get(slot).is_some_and(|(_, heard)| *heard == commit)
        {
            latest.remove(slot);
        }
    }
}

#[derive(Debug, Error)]
enum CatchUpError {
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error("cannot read the thread's meta")]
    Meta(#[from] ThreadError),
    #[error("{0} does not collaborate in the thread")]
    NotCollaborator(ParticipantName),
    #[error("the agent's host is not reached")]
    NotReached,
    #[error("the agent's host did not send its snapshots")]
    Live(#[from] LiveError),
    #[error("the host's tip is not a turn end of the agent")]
    NotATurnEnd,
    #[error("the snapshots were refused")]
    Refused(#[from] SnapshotsRefusal),
    #[error("the agent's history went apart from the one held here")]
    Diverged,
    #[error("the host served less than it announced")]
    Short,
    #[error("the host stopped")]
    Stopped,
}

/// When a heard turn end is tried again, and how many times in a row it was tried again soon.
#[derive(Debug, Clone, Copy)]
struct Pending {
    until: Instant,
    soon_tries: u8,
}

/// What to do with a heard turn end after trying to catch up with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    Forget,
    RetrySoon,
    RetryLater,
}

impl CatchUpError {
    fn next(&self) -> Next {
        match self {
            Self::NotCollaborator(_) | Self::Refused(_) | Self::Diverged | Self::NotATurnEnd => {
                Next::Forget
            }
            Self::NotReached
            | Self::Stopped
            | Self::Live(LiveError::Unavailable | LiveError::TimedOut | LiveError::Connect(_)) => {
                Next::RetrySoon
            }
            Self::Store(_)
            | Self::Meta(_)
            | Self::Short
            | Self::Live(
                LiveError::Runtime(_)
                | LiveError::InsideRuntime
                | LiveError::Bind(_)
                | LiveError::SocketAddress(_)
                | LiveError::Node(_)
                | LiveError::Address(_)
                | LiveError::Stream(_)
                | LiveError::Closed
                | LiveError::HostKey
                | LiveError::Refused
                | LiveError::TooLarge
                | LiveError::Malformed
                | LiveError::Gossip(_)
                | LiveError::TopicClosed
                | LiveError::FrameTooLarge
                | LiveError::NotLive,
            ) => Next::RetryLater,
        }
    }
}

/// What catching up needs: the node that fetches, the repository, the thread and its owner's
/// key, the participant the user is, what was heard, and the most bytes one answer may hold.
#[derive(Debug)]
pub(crate) struct CatchUp {
    pub(crate) node: Arc<LiveNode>,
    pub(crate) git_dir: PathBuf,
    pub(crate) thread: ThreadId,
    pub(crate) owner: ParticipantKey,
    pub(crate) local: ParticipantName,
    pub(crate) heard: Arc<Heard>,
    pub(crate) fetch_limit: u64,
}

impl CatchUp {
    /// Fetches, about once a second until `stop` is set, the turn-end snapshots heard that the
    /// repository lacks, from the node that announced each, and accepts each as
    /// [`accept_snapshots`] does once it is checked. A busy or unreached host is asked again
    /// after 5 s, three times at most in a row, another failure after 30 s, and a turn end
    /// that can never be taken (of a participant who is not a collaborator, not a turn end,
    /// refused or gone apart), or whose host stays unreached, is forgotten until it is heard
    /// again.
    pub(crate) fn start(self, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
        thread::spawn(move || self.run(&stop))
    }

    fn run(&self, stop: &AtomicBool) {
        let mut waiting: HashMap<AgentSlot, Pending> = HashMap::new();
        while !stop.load(Ordering::SeqCst) {
            let round = Instant::now();
            waiting.retain(|_, pending| pending.until > round || pending.soon_tries > 0);
            let heard = self.heard.waiting();
            if !heard.is_empty()
                && let Ok(store) = Store::open(&self.git_dir)
            {
                self.round(&store, &heard, (&mut waiting, stop));
            }
            while !stop.load(Ordering::SeqCst) && round.elapsed() < ROUND_EVERY {
                thread::sleep(PAUSE);
            }
        }
    }

    fn round(
        &self,
        store: &Store,
        heard: &[(AgentSlot, NodeId, ObjectId)],
        (waiting, stop): (&mut HashMap<AgentSlot, Pending>, &AtomicBool),
    ) {
        let now = Instant::now();
        for (slot, node, commit) in heard {
            if stop.load(Ordering::SeqCst)
                || waiting.get(slot).is_some_and(|pending| pending.until > now)
            {
                continue;
            }
            let next = match self.catch_up(store, (slot, *node, *commit), stop) {
                Ok(()) => Next::Forget,
                Err(error) => error.next(),
            };
            let soon_tries = waiting.get(slot).map_or(0, |pending| pending.soon_tries);
            let pending = match next {
                Next::RetrySoon if soon_tries + 1 < MAX_SOON_TRIES => Pending {
                    until: Instant::now() + RETRY_SOON,
                    soon_tries: soon_tries + 1,
                },
                Next::RetryLater => Pending {
                    until: Instant::now() + RETRY_LATER,
                    soon_tries: 0,
                },
                Next::Forget | Next::RetrySoon => {
                    waiting.remove(slot);
                    self.heard.forget(slot, *commit);
                    continue;
                }
            };
            waiting.insert(slot.clone(), pending);
        }
    }

    fn catch_up(
        &self,
        store: &Store,
        (slot, from, heard): (&AgentSlot, NodeId, ObjectId),
        stop: &AtomicBool,
    ) -> Result<(), CatchUpError> {
        let snapshots = ThreadRef::new(self.thread, RefKind::Snapshots(slot.clone()));
        let since = store.head(&snapshots)?;
        if holds(store, since, heard) {
            return Ok(());
        }
        let meta = load_meta(store, self.thread, &self.owner, 0)?;
        require_collaborator(&meta, &self.local)?;
        require_collaborator(&meta, slot.participant())?;
        let host = self.node.reached(&from).ok_or(CatchUpError::NotReached)?;
        let limit = self.fetch_limit.min(MAX_ANSWER_BYTES);
        let request = SnapshotsRequest {
            thread: self.thread,
            slot: slot.clone(),
            since: since.and_then(|since| <[u8; COMMIT_BYTES]>::try_from(since.as_bytes()).ok()),
        };
        let max_bytes = usize::try_from(limit)
            .unwrap_or(usize::MAX)
            .saturating_add(COMMIT_BYTES);
        let answer = self.node.fetch_snapshots(&host, &request, max_bytes)?;
        let tip =
            ObjectId::try_from(answer.tip.as_slice()).map_err(|_| CatchUpError::NotATurnEnd)?;
        let limits = TakeLimits {
            commits: MAX_COMMITS,
            object_bytes: limit,
        };
        store.take_history_pack(&answer.pack, since, tip, limits, stop)?;
        if !turn_end::ends_turn_of(&store.commit_message(tip)?, &slot.to_string()) {
            return Err(CatchUpError::NotATurnEnd);
        }
        if stop.load(Ordering::SeqCst) {
            return Err(CatchUpError::Stopped);
        }
        let meta = load_meta(store, self.thread, &self.owner, 0)?;
        match accept_snapshots(store, &meta, slot, tip, &self.local)? {
            SnapshotsAccepted::Diverged => Err(CatchUpError::Diverged),
            SnapshotsAccepted::Moved | SnapshotsAccepted::Kept
                if holds(store, store.head(&snapshots)?, heard) =>
            {
                Ok(())
            }
            SnapshotsAccepted::Moved | SnapshotsAccepted::Kept => Err(CatchUpError::Short),
        }
    }
}

fn holds(store: &Store, held: Option<ObjectId>, announced: ObjectId) -> bool {
    let mut budget = MAX_COMMITS;
    held.is_some_and(|held| {
        held == announced
            || store
                .descends_within(held, announced, &mut budget)
                .unwrap_or(false)
    })
}

fn require_collaborator(meta: &VerifiedMeta, name: &ParticipantName) -> Result<(), CatchUpError> {
    if meta
        .participants()
        .any(|listed| listed.name() == name && listed.role() == Role::Collaborator)
    {
        Ok(())
    } else {
        Err(CatchUpError::NotCollaborator(name.clone()))
    }
}

#[cfg(test)]
mod tests {
    use mahi_live::Relays;
    use mahi_thread::{
        Participant,
        add_participant,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;
    use crate::session::tests::{
        repository_on_main,
        start_with,
    };

    fn slot(name: &str) -> AgentSlot {
        name.parse().unwrap()
    }

    fn node() -> NodeId {
        NodeId::from_bytes(mahi_identity::NodeKey::generate().unwrap().public()).unwrap()
    }

    fn ended(name: &str, byte: u8) -> TurnEnd {
        TurnEnd {
            slot: slot(name),
            commit: [byte; COMMIT_BYTES],
        }
    }

    #[test]
    fn heard_turn_ends_are_bounded_per_participant_and_forgotten_only_when_they_match() {
        let heard = Heard::default();
        let from = node();
        for agent in 0..=MAX_HEARD_PER_PARTICIPANT {
            heard.hear(from, &ended(&format!("mallory.a{agent}"), 1));
        }
        heard.hear(from, &ended("bob.claude", 1));
        heard.hear(from, &ended("bob.claude", 2));
        let waiting = heard.waiting();
        assert_eq!(waiting.len(), MAX_HEARD_PER_PARTICIPANT + 1);
        let bobs = |heard: &Heard| {
            heard
                .waiting()
                .into_iter()
                .find(|(slot, _, _)| slot.participant().as_str() == "bob")
                .map(|(_, _, commit)| commit)
        };
        let second = ObjectId::try_from([2; COMMIT_BYTES].as_slice()).unwrap();
        assert_eq!(bobs(&heard), Some(second));
        heard.forget(
            &slot("bob.claude"),
            ObjectId::try_from([1; COMMIT_BYTES].as_slice()).unwrap(),
        );
        assert_eq!(bobs(&heard), Some(second));
        heard.forget(&slot("bob.claude"), second);
        assert_eq!(bobs(&heard), None);
    }

    #[test]
    fn a_busy_or_unreached_host_is_asked_again_soon_and_a_refusal_is_forgotten() {
        assert_eq!(
            CatchUpError::Live(LiveError::Unavailable).next(),
            Next::RetrySoon
        );
        assert_eq!(CatchUpError::NotReached.next(), Next::RetrySoon);
        assert_eq!(CatchUpError::Stopped.next(), Next::RetrySoon);
        assert_eq!(
            CatchUpError::Live(LiveError::Refused).next(),
            Next::RetryLater
        );
        assert_eq!(CatchUpError::Short.next(), Next::RetryLater);
        assert_eq!(
            CatchUpError::Refused(SnapshotsRefusal::Own).next(),
            Next::Forget
        );
        assert_eq!(
            CatchUpError::NotCollaborator(ParticipantName::new("carol").unwrap()).next(),
            Next::Forget
        );
        assert_eq!(CatchUpError::Diverged.next(), Next::Forget);
        assert_eq!(CatchUpError::NotATurnEnd.next(), Next::Forget);
    }

    #[test]
    fn nothing_is_fetched_for_an_agent_held_or_when_either_side_only_watches() {
        let (_dir, store) = repository_on_main();
        let alice_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &alice_key).unwrap();
        let thread_key = started.key.take().unwrap();
        let owner = ParticipantKey::from_public_key(alice_key.public_key()).unwrap();
        let list = |name: &str, role: Role| {
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            let participant = Participant::new(
                ParticipantName::new(name).unwrap(),
                ParticipantKey::from_public_key(key.public_key()).unwrap(),
                age::x25519::Identity::generate().to_public(),
                node(),
            )
            .unwrap()
            .with_role(role);
            add_participant(&store, started.thread, &thread_key, &alice_key, participant).unwrap();
        };
        list("carol", Role::Watcher);
        list("bob", Role::Collaborator);
        let catch_up = |local: &str| CatchUp {
            node: Arc::new(
                LiveNode::bind(
                    mahi_identity::NodeKey::generate().unwrap().secret(),
                    Relays::Disabled,
                )
                .unwrap(),
            ),
            git_dir: store.common_dir().to_path_buf(),
            thread: started.thread,
            owner: owner.clone(),
            local: ParticipantName::new(local).unwrap(),
            heard: Arc::default(),
            fetch_limit: 1 << 20,
        };
        let never = AtomicBool::new(false);
        let held = store.head(&started.snapshots).unwrap().unwrap();
        let unknown = ObjectId::try_from([9; COMMIT_BYTES].as_slice()).unwrap();

        let bob = catch_up("bob");
        assert!(
            bob.catch_up(&store, (&started.slot, node(), held), &never)
                .is_ok()
        );
        let carols =
            catch_up("carol").catch_up(&store, (&slot("bob.claude"), node(), unknown), &never);
        assert!(
            matches!(&carols, Err(CatchUpError::NotCollaborator(name)) if name.as_str() == "carol"),
            "{carols:?}"
        );
        let watched = bob.catch_up(&store, (&slot("carol.claude"), node(), unknown), &never);
        assert!(
            matches!(&watched, Err(CatchUpError::NotCollaborator(name)) if name.as_str() == "carol"),
            "{watched:?}"
        );
        let unreached = bob.catch_up(&store, (&started.slot, node(), unknown), &never);
        assert!(
            matches!(unreached, Err(CatchUpError::NotReached)),
            "{unreached:?}"
        );

        bob.heard.hear(
            node(),
            &TurnEnd {
                slot: started.slot.clone(),
                commit: [9; COMMIT_BYTES],
            },
        );
        let mut waiting = HashMap::new();
        for _ in 0..MAX_SOON_TRIES {
            assert_eq!(bob.heard.waiting().len(), 1);
            bob.round(&store, &bob.heard.waiting(), (&mut waiting, &never));
            for pending in waiting.values_mut() {
                pending.until = Instant::now();
            }
        }
        assert!(bob.heard.waiting().is_empty());
        assert!(waiting.is_empty());
    }
}
