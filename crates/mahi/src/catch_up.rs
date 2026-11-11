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
    LiveError,
    LiveNode,
    SnapshotsAnswer,
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
    LiveAccepted,
    LiveHistory,
    LiveRefusal,
    NodeId,
    ParticipantKey,
    ThreadError,
    VerifiedMeta,
    accept_live,
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

/// The latest turn-end snapshot heard of each teammate's agent, with its transcript's newest
/// commit and the node that announced them: at most 256 agents, and 16 of one participant.
#[derive(Debug, Default)]
pub(crate) struct Heard {
    latest: Mutex<HashMap<AgentSlot, HeardEntry>>,
}

/// What a host announced of one of its agents: its latest turn-end snapshot and its
/// transcript's newest commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Announced {
    commit: ObjectId,
    transcript: Option<ObjectId>,
}

/// An agent's snapshots and transcript refs here, with the newest commit each held when the
/// host was asked.
#[derive(Debug, Clone, Copy)]
struct Held<'refs> {
    snapshots: &'refs ThreadRef,
    since: Option<ObjectId>,
    transcript: &'refs ThreadRef,
    transcript_since: Option<ObjectId>,
}

/// An announcement heard, the node that sent it, and whether fetching it was given up.
#[derive(Debug, Clone, Copy)]
struct HeardEntry {
    node: NodeId,
    announced: Announced,
    given_up: bool,
}

impl Heard {
    /// Notes that `node`, which the live layer checked owns the agent, announced `ended`,
    /// unless fetching that same announcement was given up.
    pub(crate) fn hear(&self, node: NodeId, ended: &TurnEnd) {
        let announced = Announced {
            commit: ObjectId::from(ended.commit),
            transcript: ended.transcript.map(ObjectId::from),
        };
        let Ok(mut latest) = self.latest.lock() else {
            return;
        };
        match latest.get(&ended.slot) {
            Some(entry) if entry.given_up && entry.announced == announced => return,
            Some(_) => {}
            None => {
                let theirs = latest
                    .keys()
                    .filter(|slot| slot.participant() == ended.slot.participant())
                    .count();
                if latest.len() >= MAX_HEARD || theirs >= MAX_HEARD_PER_PARTICIPANT {
                    return;
                }
            }
        }
        latest.insert(
            ended.slot.clone(),
            HeardEntry {
                node,
                announced,
                given_up: false,
            },
        );
    }

    fn waiting(&self) -> Vec<(AgentSlot, NodeId, Announced)> {
        self.latest
            .lock()
            .map(|latest| {
                latest
                    .iter()
                    .filter(|(_, entry)| !entry.given_up)
                    .map(|(slot, entry)| (slot.clone(), entry.node, entry.announced))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn give_up(&self, slot: &AgentSlot, announced: Announced) {
        if let Ok(mut latest) = self.latest.lock()
            && let Some(entry) = latest.get_mut(slot)
            && entry.announced == announced
        {
            entry.given_up = true;
        }
    }

    fn forget(&self, slot: &AgentSlot, announced: Announced) {
        if let Ok(mut latest) = self.latest.lock()
            && latest
                .get(slot)
                .is_some_and(|entry| entry.announced == announced)
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
    Refused(#[from] LiveRefusal),
    #[error("the agent's history went apart from the one held here")]
    Diverged,
    #[error("the host served less than it announced")]
    Short,
    #[error("the host stopped")]
    Stopped,
    #[error("the agent's transcript turns were not taken")]
    Transcript {
        #[source]
        error: Box<CatchUpError>,
        alone: bool,
    },
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
    GiveUp,
    RetrySoon,
    RetryLater,
}

impl CatchUpError {
    fn next(&self) -> Next {
        match self {
            Self::Transcript { alone: true, .. } => Next::GiveUp,
            Self::NotCollaborator(_)
            | Self::Refused(_)
            | Self::Diverged
            | Self::NotATurnEnd
            | Self::Transcript { .. } => Next::Forget,
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
    /// Fetches, about once a second until `stop` is set, the turn-end snapshots and transcript
    /// commits heard that the repository lacks, from the node that announced each, and accepts
    /// each as [`accept_live`] does once it is checked. A busy or unreached host is asked again
    /// after 5 s, three times at most in a row, another failure after 30 s, and a turn end
    /// that can never be taken (of a participant who is not a collaborator, not a turn end,
    /// refused or gone apart), or whose host stays unreached, is forgotten until it is heard
    /// again. Transcript turns an answer with no snapshots still could not bring are given up
    /// until the host announces another snapshot or transcript commit for the agent.
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
        heard: &[(AgentSlot, NodeId, Announced)],
        (waiting, stop): (&mut HashMap<AgentSlot, Pending>, &AtomicBool),
    ) {
        let now = Instant::now();
        for (slot, node, announced) in heard {
            if stop.load(Ordering::SeqCst)
                || waiting.get(slot).is_some_and(|pending| pending.until > now)
            {
                continue;
            }
            let next = match self.catch_up(store, (slot, *node, *announced), stop) {
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
                Next::GiveUp => {
                    waiting.remove(slot);
                    self.heard.give_up(slot, *announced);
                    continue;
                }
                Next::Forget | Next::RetrySoon => {
                    waiting.remove(slot);
                    self.heard.forget(slot, *announced);
                    continue;
                }
            };
            waiting.insert(slot.clone(), pending);
        }
    }

    fn catch_up(
        &self,
        store: &Store,
        (slot, from, announced): (&AgentSlot, NodeId, Announced),
        stop: &AtomicBool,
    ) -> Result<(), CatchUpError> {
        let snapshots = ThreadRef::new(self.thread, RefKind::Snapshots(slot.clone()));
        let transcript = ThreadRef::new(self.thread, RefKind::Transcript(slot.clone()));
        let held = (store.head(&snapshots)?, store.head(&transcript)?);
        let transcript_held = announced
            .transcript
            .is_none_or(|announced| holds(store, held.1, announced));
        if holds(store, held.0, announced.commit) && transcript_held {
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
            since: held.0.and_then(turn_end::wire),
            transcript_since: held.1.and_then(turn_end::wire),
            limit,
        };
        let answer = self.node.fetch_snapshots(&host, &request)?;
        let held = Held {
            snapshots: &snapshots,
            since: held.0,
            transcript: &transcript,
            transcript_since: held.1,
        };
        self.take(store, (slot, announced), held, &answer, (limit, stop))
    }

    fn take(
        &self,
        store: &Store,
        (slot, announced): (&AgentSlot, Announced),
        held: Held<'_>,
        answer: &SnapshotsAnswer,
        (limit, stop): (u64, &AtomicBool),
    ) -> Result<(), CatchUpError> {
        let Held {
            snapshots,
            since,
            transcript,
            transcript_since,
        } = held;
        let limits = TakeLimits {
            commits: MAX_COMMITS,
            object_bytes: limit,
        };
        let sent = !answer.snapshots.pack.is_empty();
        let meta = if sent {
            self.take_snapshots(store, slot, since, answer, (limits, stop))?
        } else {
            load_meta(store, self.thread, &self.owner, 0)?
        };
        let taken = || {
            if let Some(turns) = &answer.transcript {
                let tip = ObjectId::from(turns.tip);
                store.take_history_pack(&turns.pack, transcript_since, tip, limits, stop)?;
                if stop.load(Ordering::SeqCst) {
                    return Err(CatchUpError::Stopped);
                }
                let accepted = accept_live(
                    store,
                    &meta,
                    (slot, LiveHistory::Transcript),
                    tip,
                    &self.local,
                )?;
                if accepted == LiveAccepted::Diverged {
                    return Err(CatchUpError::Diverged);
                }
            }
            let held = store.head(transcript)?;
            match announced.transcript {
                Some(wanted) if !holds(store, held, wanted) => Err(CatchUpError::Short),
                Some(_) | None => Ok(()),
            }
        };
        let turns = taken();
        if !holds(store, store.head(snapshots)?, announced.commit) {
            return Err(CatchUpError::Short);
        }
        turns.map_err(|error| CatchUpError::Transcript {
            error: Box::new(error),
            alone: !sent,
        })
    }

    fn take_snapshots(
        &self,
        store: &Store,
        slot: &AgentSlot,
        since: Option<ObjectId>,
        answer: &SnapshotsAnswer,
        (limits, stop): (TakeLimits, &AtomicBool),
    ) -> Result<VerifiedMeta, CatchUpError> {
        let tip = ObjectId::from(answer.snapshots.tip);
        store.take_history_pack(&answer.snapshots.pack, since, tip, limits, stop)?;
        if !turn_end::ends_turn_of(&store.commit_message(tip)?, &slot.to_string()) {
            return Err(CatchUpError::NotATurnEnd);
        }
        if stop.load(Ordering::SeqCst) {
            return Err(CatchUpError::Stopped);
        }
        let meta = load_meta(store, self.thread, &self.owner, 0)?;
        match accept_live(
            store,
            &meta,
            (slot, LiveHistory::Snapshots),
            tip,
            &self.local,
        )? {
            LiveAccepted::Diverged => Err(CatchUpError::Diverged),
            LiveAccepted::Moved | LiveAccepted::Kept => Ok(meta),
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
    if meta.collaborator(name).is_some() {
        Ok(())
    } else {
        Err(CatchUpError::NotCollaborator(name.clone()))
    }
}

#[cfg(test)]
mod tests {
    use mahi_live::{
        COMMIT_BYTES,
        HistoryPack,
        Relays,
    };
    use mahi_store::{
        EntryKind,
        HistoryLimits,
    };
    use mahi_thread::{
        Participant,
        Role,
        add_participant,
        snapshot_message,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;
    use crate::session::{
        CommitKey,
        tests::{
            repository_on_main,
            start_with,
        },
    };

    fn slot(name: &str) -> AgentSlot {
        name.parse().unwrap()
    }

    fn node() -> NodeId {
        NodeId::from_bytes(mahi_identity::NodeKey::generate().unwrap().public()).unwrap()
    }

    fn only(commit: ObjectId) -> Announced {
        Announced {
            commit,
            transcript: None,
        }
    }

    fn ended(name: &str, byte: u8) -> TurnEnd {
        TurnEnd {
            slot: slot(name),
            commit: [byte; COMMIT_BYTES],
            transcript: None,
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
        let second = only(ObjectId::from([2; COMMIT_BYTES]));
        assert_eq!(bobs(&heard), Some(second));
        heard.forget(&slot("bob.claude"), only(ObjectId::from([1; COMMIT_BYTES])));
        assert_eq!(bobs(&heard), Some(second));
        heard.forget(
            &slot("bob.claude"),
            Announced {
                transcript: Some(ObjectId::from([3; COMMIT_BYTES])),
                ..second
            },
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
        assert_eq!(CatchUpError::Refused(LiveRefusal::Own).next(), Next::Forget);
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
        let (held, unknown) = (only(held), only(ObjectId::from([9; COMMIT_BYTES])));

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
                transcript: None,
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

    struct Bob {
        store: Store,
        catch_up: CatchUp,
        slot: AgentSlot,
        signer: CommitKey,
        _dir: tempfile::TempDir,
    }

    fn bob_in_alices_thread() -> Bob {
        let (dir, store) = repository_on_main();
        let alice_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &alice_key).unwrap();
        let thread_key = started.key.take().unwrap();
        let bob_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let bob = Participant::new(
            ParticipantName::new("bob").unwrap(),
            ParticipantKey::from_public_key(bob_key.public_key()).unwrap(),
            age::x25519::Identity::generate().to_public(),
            node(),
        )
        .unwrap()
        .with_role(Role::Collaborator);
        add_participant(&store, started.thread, &thread_key, &alice_key, bob).unwrap();
        let catch_up = CatchUp {
            node: Arc::new(
                LiveNode::bind(
                    mahi_identity::NodeKey::generate().unwrap().secret(),
                    Relays::Disabled,
                )
                .unwrap(),
            ),
            git_dir: store.common_dir().to_path_buf(),
            thread: started.thread,
            owner: ParticipantKey::from_public_key(alice_key.public_key()).unwrap(),
            local: ParticipantName::new("alice").unwrap(),
            heard: Arc::default(),
            fetch_limit: 1 << 20,
        };
        Bob {
            store,
            catch_up,
            slot: slot("bob.claude"),
            signer: CommitKey::new(bob_key).unwrap(),
            _dir: dir,
        }
    }

    impl Bob {
        fn commits(&self, messages: &[&str]) -> ObjectId {
            self.commits_after(None, messages)
        }

        fn commits_after(&self, parent: Option<ObjectId>, messages: &[&str]) -> ObjectId {
            let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
            if let Some(parent) = parent {
                let repo = gix::open(self.store.common_dir()).unwrap();
                repo.reference(
                    scratch.to_string(),
                    parent,
                    gix::refs::transaction::PreviousValue::Any,
                    "test",
                )
                .unwrap();
            }
            let mut head = parent;
            for message in messages {
                let blob = self.store.write_blob(message.as_bytes()).unwrap();
                let tree = self
                    .store
                    .write_tree(&[("f", EntryKind::Blob, blob)])
                    .unwrap();
                head = Some(
                    self.store
                        .append_signed(&scratch, head, tree, message, self.signer.signer())
                        .unwrap(),
                );
            }
            head.unwrap()
        }

        fn pack(&self, tip: ObjectId) -> Vec<u8> {
            let mut pack = Vec::new();
            let limits = HistoryLimits {
                commits: 16,
                bytes: 1 << 20,
            };
            self.store
                .write_history_pack(None, tip, limits, &mut pack, &AtomicBool::new(false))
                .unwrap();
            pack
        }

        fn take(
            &self,
            announced: (ObjectId, Option<ObjectId>),
            held: (Option<ObjectId>, Option<ObjectId>),
            answer: &SnapshotsAnswer,
        ) -> Result<(), CatchUpError> {
            let announced = Announced {
                commit: announced.0,
                transcript: announced.1,
            };
            let thread = self.catch_up.thread;
            let snapshots = ThreadRef::new(thread, RefKind::Snapshots(self.slot.clone()));
            let transcript = ThreadRef::new(thread, RefKind::Transcript(self.slot.clone()));
            let held = Held {
                snapshots: &snapshots,
                since: held.0,
                transcript: &transcript,
                transcript_since: held.1,
            };
            self.catch_up.take(
                &self.store,
                (&self.slot, announced),
                held,
                answer,
                (1 << 20, &AtomicBool::new(false)),
            )
        }

        fn head(&self, kind: RefKind) -> Option<ObjectId> {
            self.store
                .head(&ThreadRef::new(self.catch_up.thread, kind))
                .unwrap()
        }
    }

    #[test]
    fn a_teammates_transcript_turns_come_in_with_their_turn_end_snapshot() {
        let bob = bob_in_alices_thread();
        let ended = snapshot_message(&turn_end::message(&bob.slot), bob.catch_up.thread);
        let snapshot = bob.commits(&[&ended]);
        let turns = bob.commits(&["turn 0", "turn 1"]);
        let answer = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(snapshot).unwrap(),
                pack: bob.pack(snapshot),
            },
            transcript: Some(HistoryPack {
                tip: turn_end::wire(turns).unwrap(),
                pack: bob.pack(turns),
            }),
        };

        bob.take((snapshot, Some(turns)), (None, None), &answer)
            .unwrap();
        assert_eq!(
            bob.head(RefKind::Snapshots(bob.slot.clone())),
            Some(snapshot)
        );
        assert_eq!(bob.head(RefKind::Transcript(bob.slot.clone())), Some(turns));
    }

    #[test]
    fn an_answer_without_transcript_turns_still_takes_the_snapshot() {
        let bob = bob_in_alices_thread();
        let ended = snapshot_message(&turn_end::message(&bob.slot), bob.catch_up.thread);
        let snapshot = bob.commits(&[&ended]);
        let answer = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(snapshot).unwrap(),
                pack: bob.pack(snapshot),
            },
            transcript: None,
        };

        bob.take((snapshot, None), (None, None), &answer).unwrap();
        assert_eq!(
            bob.head(RefKind::Snapshots(bob.slot.clone())),
            Some(snapshot)
        );
        assert_eq!(bob.head(RefKind::Transcript(bob.slot.clone())), None);
    }

    #[test]
    fn transcript_turns_another_participant_signed_are_refused() {
        let bob = bob_in_alices_thread();
        let ended = snapshot_message(&turn_end::message(&bob.slot), bob.catch_up.thread);
        let snapshot = bob.commits(&[&ended]);
        let stranger =
            CommitKey::new(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()).unwrap();
        let forged = {
            let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
            let content = bob.store.write_blob(b"forged").unwrap();
            let tree = bob
                .store
                .write_tree(&[("f", EntryKind::Blob, content)])
                .unwrap();
            bob.store
                .append_signed(&scratch, None, tree, "turn 0", stranger.signer())
                .unwrap()
        };
        let answer = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(snapshot).unwrap(),
                pack: bob.pack(snapshot),
            },
            transcript: Some(HistoryPack {
                tip: turn_end::wire(forged).unwrap(),
                pack: bob.pack(forged),
            }),
        };

        let taken = bob.take((snapshot, Some(forged)), (None, None), &answer);
        assert!(
            matches!(&taken, Err(CatchUpError::Transcript { error, alone: false }) if matches!(**error, CatchUpError::Refused(_))),
            "{taken:?}"
        );
        assert_eq!(taken.unwrap_err().next(), Next::Forget);
        assert_eq!(
            bob.head(RefKind::Snapshots(bob.slot.clone())),
            Some(snapshot)
        );
        assert_eq!(bob.head(RefKind::Transcript(bob.slot.clone())), None);
    }

    #[test]
    fn an_announced_transcript_commit_not_held_is_asked_for_even_with_the_snapshot_held() {
        let bob = bob_in_alices_thread();
        let ended = snapshot_message(&turn_end::message(&bob.slot), bob.catch_up.thread);
        let snapshot = bob.commits(&[&ended]);
        let turns = bob.commits(&["turn 0"]);
        let never = AtomicBool::new(false);
        let snapshots_only = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(snapshot).unwrap(),
                pack: bob.pack(snapshot),
            },
            transcript: None,
        };
        bob.take((snapshot, None), (None, None), &snapshots_only)
            .unwrap();
        let announced = Announced {
            commit: snapshot,
            transcript: Some(turns),
        };

        let asked = bob
            .catch_up
            .catch_up(&bob.store, (&bob.slot, node(), announced), &never);
        assert!(matches!(asked, Err(CatchUpError::NotReached)), "{asked:?}");
        let with_turns = SnapshotsAnswer {
            transcript: Some(HistoryPack {
                tip: turn_end::wire(turns).unwrap(),
                pack: bob.pack(turns),
            }),
            ..snapshots_only
        };
        bob.take((snapshot, Some(turns)), (Some(snapshot), None), &with_turns)
            .unwrap();
        assert!(
            bob.catch_up
                .catch_up(&bob.store, (&bob.slot, node(), announced), &never)
                .is_ok()
        );
    }

    #[test]
    fn an_asker_ahead_of_the_announced_snapshot_still_takes_the_transcript_turns() {
        let bob = bob_in_alices_thread();
        let ended = snapshot_message(&turn_end::message(&bob.slot), bob.catch_up.thread);
        let earlier = bob.commits(&[&ended]);
        let later = bob.commits_after(Some(earlier), &[&ended]);
        let turns = bob.commits(&["turn 0"]);
        let latest = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(later).unwrap(),
                pack: bob.pack(later),
            },
            transcript: None,
        };
        bob.take((later, None), (None, None), &latest).unwrap();
        let behind = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(earlier).unwrap(),
                pack: Vec::new(),
            },
            transcript: Some(HistoryPack {
                tip: turn_end::wire(turns).unwrap(),
                pack: bob.pack(turns),
            }),
        };

        bob.take((earlier, Some(turns)), (Some(later), None), &behind)
            .unwrap();
        assert_eq!(bob.head(RefKind::Snapshots(bob.slot.clone())), Some(later));
        assert_eq!(bob.head(RefKind::Transcript(bob.slot.clone())), Some(turns));
    }

    #[test]
    fn a_transcript_left_out_with_the_whole_room_is_given_up_until_it_changes() {
        let bob = bob_in_alices_thread();
        let ended = snapshot_message(&turn_end::message(&bob.slot), bob.catch_up.thread);
        let snapshot = bob.commits(&[&ended]);
        let turns = bob.commits(&["turn 0"]);
        let left_out = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(snapshot).unwrap(),
                pack: bob.pack(snapshot),
            },
            transcript: None,
        };
        let beside_snapshots = bob.take((snapshot, Some(turns)), (None, None), &left_out);
        assert!(
            matches!(&beside_snapshots, Err(CatchUpError::Transcript { error, alone: false }) if matches!(**error, CatchUpError::Short)),
            "{beside_snapshots:?}"
        );
        assert_eq!(beside_snapshots.unwrap_err().next(), Next::Forget);
        assert_eq!(
            bob.head(RefKind::Snapshots(bob.slot.clone())),
            Some(snapshot)
        );
        let alone = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(snapshot).unwrap(),
                pack: Vec::new(),
            },
            transcript: None,
        };
        let with_the_whole_room = bob.take((snapshot, Some(turns)), (Some(snapshot), None), &alone);
        assert_eq!(with_the_whole_room.unwrap_err().next(), Next::GiveUp);

        let heard = Heard::default();
        let announced = |transcript: [u8; COMMIT_BYTES]| TurnEnd {
            slot: bob.slot.clone(),
            commit: turn_end::wire(snapshot).unwrap(),
            transcript: Some(transcript),
        };
        heard.hear(node(), &announced(turn_end::wire(turns).unwrap()));
        heard.give_up(
            &bob.slot,
            Announced {
                commit: snapshot,
                transcript: Some(turns),
            },
        );
        assert!(heard.waiting().is_empty());
        heard.hear(node(), &announced(turn_end::wire(turns).unwrap()));
        assert!(heard.waiting().is_empty());
        heard.hear(node(), &announced([7; COMMIT_BYTES]));
        assert_eq!(heard.waiting().len(), 1);
    }

    #[test]
    fn snapshots_past_the_announced_one_are_taken_with_the_transcript_turns() {
        let bob = bob_in_alices_thread();
        let ended = snapshot_message(&turn_end::message(&bob.slot), bob.catch_up.thread);
        let announced = bob.commits(&[&ended]);
        let first = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(announced).unwrap(),
                pack: bob.pack(announced),
            },
            transcript: None,
        };
        bob.take((announced, None), (None, None), &first).unwrap();
        let newer = bob.commits_after(Some(announced), &[&ended]);
        let turns = bob.commits(&["turn 0"]);
        let mut pack = Vec::new();
        bob.store
            .write_history_pack(
                Some(announced),
                newer,
                HistoryLimits {
                    commits: 16,
                    bytes: 1 << 20,
                },
                &mut pack,
                &AtomicBool::new(false),
            )
            .unwrap();
        let both = SnapshotsAnswer {
            snapshots: HistoryPack {
                tip: turn_end::wire(newer).unwrap(),
                pack,
            },
            transcript: Some(HistoryPack {
                tip: turn_end::wire(turns).unwrap(),
                pack: bob.pack(turns),
            }),
        };

        bob.take((announced, Some(turns)), (Some(announced), None), &both)
            .unwrap();
        assert_eq!(bob.head(RefKind::Snapshots(bob.slot.clone())), Some(newer));
        assert_eq!(bob.head(RefKind::Transcript(bob.slot.clone())), Some(turns));
    }
}
