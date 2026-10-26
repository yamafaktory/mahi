use std::{
    collections::HashSet,
    io::Write,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    thread,
    time::Duration,
};

use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_store::{
    ObjectId,
    Store,
    StoreError,
};
use mahi_thread::{
    ParticipantKey,
    Role,
    ThreadError,
    load_meta,
    signed_by,
};
use thiserror::Error;

use crate::{
    held,
    inject::{
        self,
        Activity,
        AgentInput,
        Pace,
        Readiness,
    },
    merge::{
        AgentSettings,
        MergeError,
        MergeRequest,
    },
    merged::MergedFrom,
    recorder::Merger,
    turn_end,
};

const LOOK_EVERY: Duration = Duration::from_secs(1);

/// Where the user's agent takes its teammates' work from: the repository, the thread and its
/// owner's key, and the agent's own slot.
#[derive(Debug, Clone)]
pub(crate) struct AutoMerge {
    pub(crate) git_dir: PathBuf,
    pub(crate) thread: ThreadId,
    pub(crate) owner: ParticipantKey,
    pub(crate) own: AgentSlot,
}

#[derive(Debug, Error)]
pub(crate) enum UnmergedError {
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error("cannot read the thread's meta")]
    Meta(#[from] ThreadError),
}

impl AutoMerge {
    /// Returns the merges the user's agent is behind on, none while `meta` does not list the
    /// user as a collaborator: for each agent of another
    /// collaborator `meta` lists, its latest turn-end snapshot, when it is not in `tried`, is
    /// signed by that collaborator, and neither it nor a later one of theirs was merged into
    /// the agent yet, unless a snapshot of theirs that changes agent settings waits for the
    /// user, with their later turns behind it.
    pub(crate) fn unmerged(
        &self,
        store: &Store,
        tried: &HashSet<ObjectId>,
    ) -> Result<Vec<MergeRequest>, UnmergedError> {
        self.unmerged_among(store, &store.thread_refs()?, tried)
    }

    fn unmerged_among(
        &self,
        store: &Store,
        heads: &[(ThreadRef, ObjectId)],
        tried: &HashSet<ObjectId>,
    ) -> Result<Vec<MergeRequest>, UnmergedError> {
        let meta = load_meta(store, self.thread, &self.owner, 0)?;
        let collaborates = meta.participants().any(|listed| {
            listed.name() == self.own.participant() && listed.role() == Role::Collaborator
        });
        if !collaborates {
            return Ok(Vec::new());
        }
        let own = ThreadRef::new(self.thread, RefKind::Snapshots(self.own.clone()));
        let merged = MergedFrom::read(store, &own)?;
        let mut requests = Vec::new();
        for (thread_ref, head) in heads {
            let RefKind::Snapshots(slot) = thread_ref.kind() else {
                continue;
            };
            if thread_ref.thread() != self.thread || slot.participant() == self.own.participant() {
                continue;
            }
            let Some(writer) = meta.participants().find(|listed| {
                listed.name() == slot.participant() && listed.role() == Role::Collaborator
            }) else {
                continue;
            };
            if held::waits(&held::file(store, self.thread, (&self.own, slot))) {
                continue;
            }
            let Some(tip) = turn_end::latest(store, slot, *head).filter(|tip| !tried.contains(tip))
            else {
                continue;
            };
            let taken = merged.of(slot).is_some_and(|merged| {
                merged == tip || store.descends_from(merged, tip).unwrap_or(false)
            });
            if taken || !signed_by(store, tip, writer.key()).unwrap_or(false) {
                continue;
            }
            requests.push(MergeRequest {
                from: slot.clone(),
                commit: tip,
                thread_base: meta.base(),
            });
        }
        Ok(requests)
    }

    /// Says whether `request` is still one of the merges the agent is behind on.
    fn is_due(&self, request: &MergeRequest) -> bool {
        let Ok(store) = Store::open(&self.git_dir) else {
            return false;
        };
        self.unmerged(&store, &HashSet::new())
            .is_ok_and(|due| due.contains(request))
    }

    /// Merges, while `running` is set, each turn-end snapshot of a teammate the agent is
    /// behind on, one after the other, each once the agent is idle after a turn its hook
    /// reported, or since it started, with its input held, holding agent settings, and only when
    /// it is still due then;
    /// each snapshot is tried once in this run, whatever the merge gives, but for a merge
    /// refused while the agent's conflicts are unresolved, and the thread refs are looked
    /// through again only once one of them moved.
    pub(crate) fn run(
        &self,
        merger: &Merger,
        (activity, agent, writer): (&Activity, &impl AgentInput, &Mutex<impl Write>),
        (running, pace): (&AtomicBool, Pace),
    ) {
        let mut tried = HashSet::new();
        let mut seen = Vec::new();
        while running.load(Ordering::SeqCst) {
            thread::sleep(LOOK_EVERY);
            let Ok(store) = Store::open(&self.git_dir) else {
                continue;
            };
            let Ok(heads) = store.thread_refs() else {
                continue;
            };
            if heads == seen {
                continue;
            }
            let Ok(requests) = self.unmerged_among(&store, &heads, &tried) else {
                continue;
            };
            seen = heads;
            for request in requests {
                let commit = request.commit;
                tried.insert(commit);
                let done = inject::when_ready(
                    activity,
                    agent,
                    writer,
                    (running, pace, Readiness::AfterTurnEnd),
                    || {
                        self.is_due(&request)
                            .then(|| merger.merge(request, AgentSettings::Hold))
                    },
                );
                let Some(outcome) = done else {
                    return;
                };
                if let Some(Err(MergeError::MarkersUnresolved(_))) = outcome {
                    tried.remove(&commit);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::Instant,
    };

    use mahi_agent::hook::HookKind;
    use mahi_core::ParticipantName;
    use mahi_store::{
        EntryKind,
        GlobalPatterns,
    };
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
    use crate::{
        recorder::{
            Recorder,
            Target,
        },
        session::{
            CommitKey,
            Started,
            tests::{
                repository_on_main,
                start_with,
            },
        },
    };

    struct Closed;

    impl AgentInput for Closed {
        fn palette_open(&self) -> bool {
            false
        }

        fn bracketed_paste(&self) -> bool {
            false
        }
    }

    struct Team {
        _dir: tempfile::TempDir,
        store: Store,
        alice: PrivateKey,
        started: Started,
        thread_key: mahi_crypto::ThreadKey,
        bob: (CommitKey, Participant),
        carol: (CommitKey, Participant),
    }

    fn team() -> Team {
        let (dir, store) = repository_on_main();
        let alice = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &alice).unwrap();
        let thread_key = started.key.take().unwrap();
        let list = |name: &str, role: Role| {
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            let participant = Participant::new(
                ParticipantName::new(name).unwrap(),
                ParticipantKey::from_public_key(key.public_key()).unwrap(),
                age::x25519::Identity::generate().to_public(),
                mahi_thread::NodeId::from_bytes(
                    mahi_identity::NodeKey::generate().unwrap().public(),
                )
                .unwrap(),
            )
            .unwrap()
            .with_role(role);
            add_participant(
                &store,
                started.thread,
                &thread_key,
                &alice,
                participant.clone(),
            )
            .unwrap();
            (CommitKey::new(key).unwrap(), participant)
        };
        let bob = list("bob", Role::Collaborator);
        let carol = list("carol", Role::Watcher);
        Team {
            _dir: dir,
            store,
            alice,
            started,
            thread_key,
            bob,
            carol,
        }
    }

    impl Team {
        fn auto_merge(&self) -> AutoMerge {
            AutoMerge {
                git_dir: self.store.common_dir().to_path_buf(),
                thread: self.started.thread,
                owner: ParticipantKey::from_public_key(self.alice.public_key()).unwrap(),
                own: self.started.slot.clone(),
            }
        }

        fn give_role(&self, participant: &Participant, role: Role) {
            add_participant(
                &self.store,
                self.started.thread,
                &self.thread_key,
                &self.alice,
                participant.clone().with_role(role),
            )
            .unwrap();
        }

        fn record_merged(&self, from: &str, commit: ObjectId) {
            let mut merged = MergedFrom::read(&self.store, &self.started.snapshots).unwrap();
            merged.record(from.parse().unwrap(), commit);
            let head = self.store.head(&self.started.snapshots).unwrap();
            let tree = self.store.commit_tree(head.unwrap()).unwrap();
            self.store
                .append(&self.started.snapshots, head, tree, &merged.message())
                .unwrap();
        }

        fn ended_with_readme(&self, slot: &str, signer: &CommitKey, readme: &str) -> ObjectId {
            let readme = self.store.write_blob(readme.as_bytes()).unwrap();
            let tree = self
                .store
                .write_tree(&[("README", EntryKind::Blob, readme)])
                .unwrap();
            self.commit_turn_end(slot, signer, tree)
        }

        fn commit_turn_end(&self, slot: &str, signer: &CommitKey, tree: ObjectId) -> ObjectId {
            let slot: AgentSlot = slot.parse().unwrap();
            let snapshots = ThreadRef::new(self.started.thread, RefKind::Snapshots(slot.clone()));
            let head = self.store.head(&snapshots).unwrap();
            self.store
                .append_signed(
                    &snapshots,
                    head,
                    tree,
                    &turn_end::message(&slot),
                    signer.signer(),
                )
                .unwrap()
        }

        fn ended(&self, slot: &str, signer: Option<&CommitKey>) -> ObjectId {
            let slot: AgentSlot = slot.parse().unwrap();
            let snapshots = ThreadRef::new(self.started.thread, RefKind::Snapshots(slot.clone()));
            let head = self.store.head(&snapshots).unwrap();
            let readme = self.store.write_blob(b"hello\n").unwrap();
            let notes = self
                .store
                .write_blob(format!("from {slot}\n").as_bytes())
                .unwrap();
            let tree = self
                .store
                .write_tree(&[
                    ("README", EntryKind::Blob, readme),
                    ("notes.txt", EntryKind::Blob, notes),
                ])
                .unwrap();
            let message = turn_end::message(&slot);
            match signer {
                Some(signer) => self
                    .store
                    .append_signed(&snapshots, head, tree, &message, signer.signer())
                    .unwrap(),
                None => self.store.append(&snapshots, head, tree, &message).unwrap(),
            }
        }
    }

    #[test]
    fn only_a_collaborators_signed_turn_end_not_merged_yet_is_due() {
        let team = team();
        let bobs = team.ended("bob.claude", Some(&team.bob.0));
        team.ended("carol.claude", Some(&team.carol.0));
        team.ended("bob.codex", None);
        let auto = team.auto_merge();

        let due = auto.unmerged(&team.store, &HashSet::new()).unwrap();
        assert_eq!(due.len(), 1, "{due:?}");
        assert_eq!(due[0].from.to_string(), "bob.claude");
        assert_eq!(due[0].commit, bobs);

        team.record_merged("bob.claude", bobs);
        assert!(
            auto.unmerged(&team.store, &HashSet::new())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_teammates_later_turns_wait_behind_their_snapshot_held_for_the_user() {
        let team = team();
        let first = team.ended("bob.claude", Some(&team.bob.0));
        let auto = team.auto_merge();
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        let waiting = held::file(&team.store, team.started.thread, (&auto.own, &bob));
        held::HeldSettings::new(first, &["CLAUDE.md".to_owned()])
            .keep(&waiting)
            .unwrap();
        let later = team.ended("bob.claude", Some(&team.bob.0));
        assert!(
            auto.unmerged(&team.store, &HashSet::new())
                .unwrap()
                .is_empty()
        );
        held::HeldSettings::release(&waiting).unwrap();
        let due = auto.unmerged(&team.store, &HashSet::new()).unwrap();
        assert_eq!(due.len(), 1, "{due:?}");
        assert_eq!(due[0].commit, later);
    }

    #[test]
    fn a_user_who_is_only_a_watcher_takes_in_no_ones_work() {
        let team = team();
        team.ended("bob.claude", Some(&team.bob.0));
        let carols = AutoMerge {
            own: "carol.claude".parse().unwrap(),
            ..team.auto_merge()
        };
        assert!(
            carols
                .unmerged(&team.store, &HashSet::new())
                .unwrap()
                .is_empty()
        );
        team.give_role(&team.carol.1, Role::Collaborator);
        assert_eq!(
            carols.unmerged(&team.store, &HashSet::new()).unwrap().len(),
            1
        );
    }

    #[test]
    fn a_snapshot_older_than_the_one_merged_is_not_due_and_a_newer_one_is() {
        let team = team();
        let older = team.ended("bob.claude", Some(&team.bob.0));
        let newer = team.ended("bob.claude", Some(&team.bob.0));
        let auto = team.auto_merge();
        team.record_merged("bob.claude", older);
        let due = auto.unmerged(&team.store, &HashSet::new()).unwrap();
        assert_eq!(due.len(), 1, "{due:?}");
        assert_eq!(due[0].commit, newer);
        team.record_merged("bob.claude", newer);
        assert!(
            auto.unmerged(&team.store, &HashSet::new())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_users_own_agents_another_signers_and_tried_snapshots_are_not_due() {
        let team = team();
        let own = format!("{}.codex", team.started.slot.participant());
        team.ended(&own, Some(&CommitKey::new(team.alice.clone()).unwrap()));
        team.ended("bob.codex", Some(&team.carol.0));
        let bobs = team.ended("bob.claude", Some(&team.bob.0));
        let auto = team.auto_merge();
        let due = auto.unmerged(&team.store, &HashSet::new()).unwrap();
        assert_eq!(due.len(), 1, "{due:?}");
        assert_eq!(due[0].commit, bobs);
        assert!(
            auto.unmerged(&team.store, &HashSet::from([bobs]))
                .unwrap()
                .is_empty()
        );
    }

    struct Merging {
        recorder: Recorder,
        merger: Merger,
        activity: Activity,
        writer: Mutex<Vec<u8>>,
        running: AtomicBool,
    }

    fn pace() -> Pace {
        Pace {
            quiet: Duration::from_millis(50),
            look_every: Duration::from_millis(10),
            enter_after: Duration::from_millis(1),
            stale_turn: Duration::from_secs(60),
        }
    }

    impl Team {
        fn merging(&mut self) -> Merging {
            let recorder = Recorder::start(
                Target {
                    git_dir: self.store.common_dir().to_path_buf(),
                    slot: self.started.slot.clone(),
                    worktree: crate::session::worktree_name(
                        self.started.thread,
                        self.started.slot.agent(),
                    ),
                    snapshots: self.started.snapshots.clone(),
                    globals: GlobalPatterns::default(),
                    commits: CommitKey::new(self.alice.clone()).unwrap(),
                },
                self.started.first_snapshot.take().unwrap(),
                mahi_schedule::Schedule::new(
                    Duration::from_millis(20),
                    Duration::from_millis(40),
                    Duration::from_millis(5),
                )
                .unwrap(),
            );
            let merger = recorder.merger();
            let activity = Activity::default();
            activity.saw(HookKind::Prompt, b"");
            activity.keys(b"\x1b");
            Merging {
                recorder,
                merger,
                activity,
                writer: Mutex::new(Vec::new()),
                running: AtomicBool::new(true),
            }
        }

        fn settled(&self) -> ObjectId {
            let mut head = self.store.head(&self.started.snapshots).unwrap().unwrap();
            loop {
                thread::sleep(Duration::from_millis(300));
                let now = self.store.head(&self.started.snapshots).unwrap().unwrap();
                if now == head {
                    return head;
                }
                head = now;
            }
        }

        fn own_snapshots_since(&self, since: ObjectId) -> usize {
            let mut count = 0;
            let mut at = self.store.head(&self.started.snapshots).unwrap();
            while let Some(commit) = at.filter(|commit| *commit != since) {
                count += 1;
                at = self.store.parent(commit).unwrap();
            }
            count
        }
    }

    #[test]
    fn a_teammates_turn_end_is_merged_once_the_agent_is_idle() {
        let mut team = team();
        team.ended("bob.claude", Some(&team.bob.0));
        let merging = team.merging();
        let auto = team.auto_merge();
        let notes = team.started.worktree.join("notes.txt");
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                auto.run(
                    &merging.merger,
                    (&merging.activity, &Closed, &merging.writer),
                    (&merging.running, pace()),
                );
            });
            thread::sleep(Duration::from_millis(2500));
            assert!(!notes.exists(), "merged after an interrupt, not a turn end");
            merging.activity.saw(HookKind::TurnEnd, b"");
            let deadline = Instant::now() + Duration::from_secs(20);
            while !notes.exists() {
                assert!(Instant::now() < deadline, "bob's work was never merged");
                thread::sleep(Duration::from_millis(20));
            }
            merging.running.store(false, Ordering::SeqCst);
            running.join().unwrap();
        });
        assert_eq!(fs::read_to_string(&notes).unwrap(), "from bob.claude\n");
        assert!(
            auto.unmerged(&team.store, &HashSet::new())
                .unwrap()
                .is_empty()
        );
        merging.recorder.finish().unwrap();
        let taken_in = MergedFrom::read(&team.store, &team.started.snapshots).unwrap();
        assert!(taken_in.of(&"bob.claude".parse().unwrap()).is_some());
    }

    #[test]
    fn a_merge_that_leaves_a_path_is_not_tried_again() {
        let mut team = team();
        team.ended("bob.claude", Some(&team.bob.0));
        let worktree = team.started.worktree.clone();
        fs::write(worktree.join(".gitignore"), "notes.txt\n").unwrap();
        fs::write(worktree.join("notes.txt"), "mine\n").unwrap();
        let merging = team.merging();
        let auto = team.auto_merge();
        let settled = team.settled();
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                auto.run(
                    &merging.merger,
                    (&merging.activity, &Closed, &merging.writer),
                    (&merging.running, pace()),
                );
            });
            merging.activity.saw(HookKind::TurnEnd, b"");
            thread::sleep(Duration::from_secs(5));
            merging.running.store(false, Ordering::SeqCst);
            running.join().unwrap();
        });
        merging.recorder.finish().unwrap();
        assert_eq!(
            fs::read_to_string(worktree.join("notes.txt")).unwrap(),
            "mine\n"
        );
        assert_eq!(team.own_snapshots_since(settled), 1);
    }

    #[test]
    fn a_teammate_made_a_watcher_while_the_agent_works_is_not_merged() {
        let mut team = team();
        team.ended("bob.claude", Some(&team.bob.0));
        let merging = team.merging();
        let auto = team.auto_merge();
        let notes = team.started.worktree.join("notes.txt");
        merging.activity.saw(HookKind::Prompt, b"");
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                auto.run(
                    &merging.merger,
                    (&merging.activity, &Closed, &merging.writer),
                    (&merging.running, pace()),
                );
            });
            thread::sleep(Duration::from_millis(1500));
            team.give_role(&team.bob.1, Role::Watcher);
            merging.activity.saw(HookKind::TurnEnd, b"");
            thread::sleep(Duration::from_millis(1500));
            merging.running.store(false, Ordering::SeqCst);
            running.join().unwrap();
        });
        merging.recorder.finish().unwrap();
        assert!(!notes.exists(), "a watcher's work was merged");
    }

    #[test]
    fn a_merge_that_leaves_conflicts_holds_the_next_ones_until_the_agent_resolves_them() {
        let mut team = team();
        fs::write(team.started.worktree.join("README"), "alice\n").unwrap();
        team.ended_with_readme("bob.claude", &team.bob.0, "bob\n");
        let merging = team.merging();
        let auto = team.auto_merge();
        let readme = team.started.worktree.join("README");
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                auto.run(
                    &merging.merger,
                    (&merging.activity, &Closed, &merging.writer),
                    (&merging.running, pace()),
                );
            });
            merging.activity.saw(HookKind::TurnEnd, b"");
            let deadline = Instant::now() + Duration::from_secs(20);
            while !fs::read_to_string(&readme).unwrap().contains("<<<<<<<") {
                assert!(Instant::now() < deadline, "bob's work was never merged");
                thread::sleep(Duration::from_millis(20));
            }
            thread::sleep(Duration::from_millis(500));
            let later = team.ended("bob.claude", Some(&team.bob.0));
            thread::sleep(Duration::from_millis(2500));
            let merged = MergedFrom::read(&team.store, &team.started.snapshots).unwrap();
            assert_ne!(merged.of(&"bob.claude".parse().unwrap()), Some(later));
            assert!(!team.started.worktree.join("notes.txt").exists());
            fs::write(&readme, "alice and bob\n").unwrap();
            merging.recorder.events().turn_ended();
            merging.activity.saw(HookKind::TurnEnd, b"");
            let bob = "bob.claude".parse().unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while MergedFrom::read(&team.store, &team.started.snapshots)
                .unwrap()
                .of(&bob)
                != Some(later)
            {
                if Instant::now() >= deadline {
                    merging.running.store(false, Ordering::SeqCst);
                    panic!("bob's later work was never merged");
                }
                thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(
                fs::read_to_string(team.started.worktree.join("notes.txt")).unwrap(),
                "from bob.claude\n"
            );
            merging.running.store(false, Ordering::SeqCst);
            running.join().unwrap();
        });
        merging.recorder.finish().unwrap();
    }
}
