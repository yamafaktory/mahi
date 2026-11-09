use std::{
    collections::HashSet,
    io::Write,
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
    time::Duration,
};

use mahi_core::{
    AgentSlot,
    ParticipantName,
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
    ThreadError,
    load_meta,
    signed_by,
};
use thiserror::Error;

use crate::{
    held::{
        self,
        HeldError,
        HeldSettings,
        SyncRecord,
        Waits,
    },
    held_queue::{
        Choice,
        HeldQueue,
    },
    inject::{
        self,
        Activity,
        AgentInput,
        Pace,
        Readiness,
    },
    landed_branch::BranchRecord,
    merge::{
        AgentSettings,
        MergeDone,
        MergeError,
        MergeRequest,
        PathsLeft,
    },
    merged::MergedFrom,
    recorder::{
        Merger,
        Wanted,
    },
    source::{
        LandingBranch,
        Source,
    },
    sync_state,
    turn_end,
};

const LOOK_EVERY: Duration = Duration::from_secs(1);

/// Where the user's agent takes its teammates' work from: the repository, the thread and its
/// owner's key, and the agent's own slot; and the snapshots that wait for the user, as the
/// palette shows them.
#[derive(Debug, Clone)]
pub(crate) struct AutoMerge {
    pub(crate) git_dir: PathBuf,
    pub(crate) thread: ThreadId,
    pub(crate) owner: ParticipantKey,
    pub(crate) own: AgentSlot,
    pub(crate) waiting: Arc<HeldQueue>,
}

#[derive(Debug, Error)]
pub(crate) enum UnmergedError {
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error("cannot read the thread's meta")]
    Meta(#[from] ThreadError),
}

#[derive(Debug, Error)]
enum NotTaken {
    #[error("cannot read the thread's members")]
    Meta,
    #[error("you are no longer a collaborator")]
    NotCollaborator,
    #[error("{0} is no longer a collaborator")]
    TeammateNotCollaborator(ParticipantName),
    #[error("{0} did not sign this turn")]
    Unsigned(ParticipantName),
}

impl AutoMerge {
    pub(crate) fn behind(
        &self,
        store: &Store,
    ) -> Result<Vec<(AgentSlot, ObjectId)>, UnmergedError> {
        let meta = load_meta(store, self.thread, &self.owner, 0)?;
        let collaborates = |slot: &AgentSlot| meta.collaborator(slot.participant()).is_some();
        let mut behind: Vec<(AgentSlot, ObjectId)> = self
            .unmerged(store, &HashSet::new())?
            .into_iter()
            .map(|request| (request.from, request.commit))
            .collect();
        let held = held::list(store, self.thread, &self.own)
            .into_iter()
            .filter(|(slot, _)| collaborates(slot))
            .map(|(slot, record)| (slot, record.commit));
        behind.extend(held);
        behind.sort();
        Ok(behind)
    }

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
        if meta.collaborator(self.own.participant()).is_none() {
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
            let Some(writer) = meta.collaborator(slot.participant()) else {
                continue;
            };
            let Ok(SyncRecord {
                skipped,
                waits: Waits::Free,
            }) = SyncRecord::load(&held::file(store, self.thread, (&self.own, slot)))
            else {
                continue;
            };
            let Some(tip) = turn_end::latest(store, slot, *head).filter(|tip| !tried.contains(tip))
            else {
                continue;
            };
            let taken = [merged.of(slot), skipped]
                .into_iter()
                .flatten()
                .any(|merged| merged == tip || store.descends_from(merged, tip).unwrap_or(false));
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

    /// Does what the user chose for the snapshot `record` of `from` that waited: skips it, or
    /// takes it, agent settings and all, once the agent is ready, when its teammate is still a
    /// collaborator who signed it. Returns `false` when the run ended meanwhile.
    fn choose(
        &self,
        store: &Store,
        (merger, from, record, choice): (&Merger, &Source, &HeldSettings, Choice),
        (activity, agent, writer): (&Activity, &impl AgentInput, &Mutex<impl Write>),
        (running, pace): (&AtomicBool, Pace),
    ) -> bool {
        let slot = match from {
            Source::Agent(slot) => slot,
            Source::Landing(_) => {
                return choice != Choice::Take
                    || self.take_landing(
                        store,
                        (merger, from, record),
                        (activity, agent, writer),
                        (running, pace),
                    );
            }
        };
        let waiting = held::file(store, self.thread, (&self.own, slot));
        match choice {
            Choice::Skip => {
                let _ = record.skip(&waiting);
                true
            }
            Choice::Take => {
                let request = match self.signed_by_collaborator(store, slot, record.commit) {
                    Ok(request) => request,
                    Err(reason) => {
                        self.waiting
                            .failed((from, record.commit), reason.to_string());
                        return true;
                    }
                };
                let done = inject::when_ready(
                    activity,
                    agent,
                    writer,
                    (running, pace, Readiness::TurnClosed),
                    || merger.merge(request, AgentSettings::Take),
                );
                let Some(outcome) = done else {
                    return false;
                };
                if let Err(error) = outcome {
                    self.waiting
                        .failed((from, record.commit), error.to_string());
                }
                true
            }
        }
    }

    /// Takes the landing branch's merge that waited for the user, agent settings and all, once
    /// the agent is idle with its turn closed, when the last landing still brings it. Returns
    /// `false` when the run ended meanwhile.
    fn take_landing(
        &self,
        store: &Store,
        (merger, from, record): (&Merger, &Source, &HeldSettings),
        (activity, agent, writer): (&Activity, &impl AgentInput, &Mutex<impl Write>),
        (running, pace): (&AtomicBool, Pace),
    ) -> bool {
        let waiting = held::file_for(store, self.thread, (&self.own, from));
        let Some(wanted) = pending_landing(store, self.thread).filter(
            |wanted| matches!(wanted, Wanted::Landing { tip, .. } if *tip == record.commit),
        ) else {
            let _ = sync_state::remove(&waiting);
            return true;
        };
        let done = inject::when_ready(
            activity,
            agent,
            writer,
            (running, pace, Readiness::TurnClosed),
            || {
                let still = Store::open(&self.git_dir)
                    .ok()
                    .and_then(|store| pending_landing(&store, self.thread))
                    .as_ref()
                    == Some(&wanted);
                still.then(|| merger.merge_wanted(wanted.clone(), AgentSettings::Take))
            },
        );
        let Some(outcome) = done else {
            return false;
        };
        match outcome {
            Some(Ok(done)) => {
                let _ = sync_state::remove(&waiting);
                self.landing_taken(store, &wanted, &done);
            }
            Some(Err(error)) => self
                .waiting
                .failed((from, record.commit), error.to_string()),
            None => {
                let _ = sync_state::remove(&waiting);
            }
        }
        true
    }

    /// Returns the merges that wait for the user: each teammate's snapshot that changes agent
    /// settings, and the landing branch's merge that does, while the last landing still brings
    /// it.
    fn held_now(&self, store: &Store) -> Vec<(Source, HeldSettings)> {
        let mut held: Vec<(Source, HeldSettings)> = held::list(store, self.thread, &self.own)
            .into_iter()
            .map(|(slot, record)| (Source::Agent(slot), record))
            .collect();
        held.extend(held_landing(store, self.thread, &self.own));
        held
    }

    /// Returns the merge of `from`'s snapshot `commit`, when `meta` lists both the user and
    /// `from`'s participant as collaborators and that participant signed it.
    fn signed_by_collaborator(
        &self,
        store: &Store,
        from: &AgentSlot,
        commit: ObjectId,
    ) -> Result<MergeRequest, NotTaken> {
        let meta = load_meta(store, self.thread, &self.owner, 0).map_err(|_| NotTaken::Meta)?;
        meta.collaborator(self.own.participant())
            .ok_or(NotTaken::NotCollaborator)?;
        let teammate = from.participant();
        let writer = meta
            .collaborator(teammate)
            .ok_or_else(|| NotTaken::TeammateNotCollaborator(teammate.clone()))?;
        if !signed_by(store, commit, writer.key()).unwrap_or(false) {
            return Err(NotTaken::Unsigned(teammate.clone()));
        }
        Ok(MergeRequest {
            from: from.clone(),
            commit,
            thread_base: meta.base(),
        })
    }

    /// Returns what the last landing brought from the landing branch and the agent's worktree
    /// has not taken yet: the record of a landing whose pushed tip's tree differs from the
    /// worktree tree it measured, while no merge of it waits for the user; a held merge of an
    /// earlier landing's tip is dropped, since this one brings what it did.
    fn landing_due(&self, store: &Store) -> Option<Wanted> {
        let wanted = pending_landing(store, self.thread)?;
        let Wanted::Landing { landing, tip, .. } = &wanted else {
            return None;
        };
        let from = Source::Landing(landing.clone());
        let waiting = held::file_for(store, self.thread, (&self.own, &from));
        if held::waits(&waiting) {
            match HeldSettings::load(&waiting) {
                Ok(None) => {}
                Ok(Some(held)) if held.commit != *tip => sync_state::remove(&waiting).ok()?,
                Err(HeldError::Malformed(_)) => sync_state::remove(&waiting).ok()?,
                Ok(Some(_)) | Err(HeldError::Io(..)) => return None,
            }
        }
        Some(wanted)
    }

    /// Forgets the worktree tree the last landing measured once the agent's worktree took all
    /// that `wanted` brought, as `done` says, so the next landing measures from the pushed
    /// tip's tree; a merge that left a path as it was keeps it, to be merged again.
    fn landing_taken(&self, store: &Store, wanted: &Wanted, done: &MergeDone) {
        let (
            Wanted::Landing { measured, tip, .. },
            MergeDone::Merged {
                left: PathsLeft::None,
                ..
            },
        ) = (wanted, done)
        else {
            return;
        };
        let forgotten = BranchRecord::update(store, self.thread, |record| {
            let still = record.tip == *tip && record.worktree == Some(*measured);
            if still {
                record.worktree = None;
            }
            still
        });
        if forgotten.unwrap_or(false) {
            let _ = store.release_landed_tree(self.thread, *measured);
        }
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
        let mut tried_landing = None;
        let mut seen = Vec::new();
        while running.load(Ordering::SeqCst) {
            thread::sleep(LOOK_EVERY);
            let Ok(store) = Store::open(&self.git_dir) else {
                continue;
            };
            self.waiting.show(self.held_now(&store));
            for (from, record, choice) in self.waiting.take_choices() {
                seen.clear();
                if !self.choose(
                    &store,
                    (merger, &from, &record, choice),
                    (activity, agent, writer),
                    (running, pace),
                ) {
                    return;
                }
            }
            if let Some(wanted) = self.landing_due(&store)
                && tried_landing.as_ref() != Some(&wanted)
                && !self.merge_landing(
                    merger,
                    &wanted,
                    &mut tried_landing,
                    (activity, agent, writer),
                    (running, pace),
                )
            {
                return;
            }
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

    /// Merges what the last landing brought from the landing branch, `wanted`, once the agent
    /// is idle after a turn its hook reported, and only while it is still due then; tried once
    /// in this run, but for a merge refused while the agent's conflicts are unresolved.
    /// Returns `false` when the run ended meanwhile.
    fn merge_landing(
        &self,
        merger: &Merger,
        wanted: &Wanted,
        tried: &mut Option<Wanted>,
        (activity, agent, writer): (&Activity, &impl AgentInput, &Mutex<impl Write>),
        (running, pace): (&AtomicBool, Pace),
    ) -> bool {
        *tried = Some(wanted.clone());
        let done = inject::when_ready(
            activity,
            agent,
            writer,
            (running, pace, Readiness::AfterTurnEnd),
            || {
                let store = Store::open(&self.git_dir).ok()?;
                (self.landing_due(&store).as_ref() == Some(wanted)).then(|| {
                    (
                        merger.merge_wanted(wanted.clone(), AgentSettings::Hold),
                        store,
                    )
                })
            },
        );
        let Some(outcome) = done else {
            return false;
        };
        match outcome {
            Some((Ok(done), store)) => self.landing_taken(&store, wanted, &done),
            Some((Err(MergeError::MarkersUnresolved(_)), _)) => *tried = None,
            Some((Err(_), _)) | None => {}
        }
        true
    }
}

fn pending_landing(store: &Store, thread: ThreadId) -> Option<Wanted> {
    let record = BranchRecord::read(store, thread)?;
    let measured = record.worktree?;
    let landing = LandingBranch::new(&record.remote, &record.landing)?;
    Some(Wanted::Landing {
        landing,
        measured,
        tip: record.tip,
    })
}

pub(crate) fn held_landing(
    store: &Store,
    thread: ThreadId,
    own: &AgentSlot,
) -> Option<(Source, HeldSettings)> {
    let Wanted::Landing { landing, tip, .. } = pending_landing(store, thread)? else {
        return None;
    };
    let from = Source::Landing(landing);
    let file = held::file_for(store, thread, (own, &from));
    let record = HeldSettings::load(&file).ok()??;
    (record.commit == tip).then_some((from, record))
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
        Role,
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
                waiting: Arc::default(),
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
    fn a_landing_is_behind_on_a_collaborators_due_and_held_turn_ends_only() {
        let team = team();
        let auto = team.auto_merge();
        assert!(auto.behind(&team.store).unwrap().is_empty());
        let bobs = team.ended("bob.claude", Some(&team.bob.0));
        team.ended("carol.claude", Some(&team.carol.0));
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        assert_eq!(auto.behind(&team.store).unwrap(), vec![(bob.clone(), bobs)]);

        let waiting = held::file(&team.store, team.started.thread, (&auto.own, &bob));
        held::HeldSettings::new(bobs, &["CLAUDE.md".to_owned()])
            .keep(&waiting)
            .unwrap();
        assert_eq!(auto.behind(&team.store).unwrap(), vec![(bob.clone(), bobs)]);
        team.give_role(&team.bob.1, Role::Watcher);
        assert!(auto.behind(&team.store).unwrap().is_empty());
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
        held::SyncRecord::default().save(&waiting).unwrap();
        let due = auto.unmerged(&team.store, &HashSet::new()).unwrap();
        assert_eq!(due.len(), 1, "{due:?}");
        assert_eq!(due[0].commit, later);
    }

    fn tree_of(team: &Team, files: &[(&str, &str)]) -> ObjectId {
        let entries: Vec<_> = files
            .iter()
            .map(|(name, text)| {
                (
                    *name,
                    EntryKind::Blob,
                    team.store.write_blob(text.as_bytes()).unwrap(),
                )
            })
            .collect();
        team.store.write_tree(&entries).unwrap()
    }

    fn wait_for(what: &str, running: &AtomicBool, until: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !until() {
            if Instant::now() >= deadline {
                running.store(false, Ordering::SeqCst);
                panic!("{what}");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_skipped_settings_change_stays_out_and_the_teammates_next_turn_comes_in() {
        let mut team = team();
        let worktree = team.started.worktree.clone();
        let settings = tree_of(
            &team,
            &[
                ("CLAUDE.md", "obey bob\n"),
                ("README", "hello\n"),
                ("skipped.txt", "only in the skipped turn\n"),
            ],
        );
        let first = team.commit_turn_end("bob.claude", &team.bob.0, settings);
        let merging = team.merging();
        let auto = team.auto_merge();
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                auto.run(
                    &merging.merger,
                    (&merging.activity, &Closed, &merging.writer),
                    (&merging.running, pace()),
                );
            });
            merging.activity.saw(HookKind::TurnEnd, b"");
            wait_for("bob's snapshot was never held", &merging.running, || {
                auto.waiting.waiting(&Source::Agent(bob.clone())).is_some()
            });
            assert!(auto.waiting.wants_open());
            assert!(
                auto.waiting
                    .choose((&Source::Agent(bob.clone()), first), Choice::Skip)
            );
            let next = tree_of(
                &team,
                &[
                    ("CLAUDE.md", "obey bob\n"),
                    ("README", "hello\n"),
                    ("notes.txt", "next\n"),
                ],
            );
            team.commit_turn_end("bob.claude", &team.bob.0, next);
            wait_for("bob's next turn was never merged", &merging.running, || {
                worktree.join("notes.txt").exists()
            });
            merging.running.store(false, Ordering::SeqCst);
            running.join().unwrap();
        });
        merging.recorder.finish().unwrap();
        assert!(!worktree.join("CLAUDE.md").exists());
        assert!(!worktree.join("skipped.txt").exists());
    }

    #[test]
    fn a_taken_settings_change_is_merged_whole() {
        let mut team = team();
        let worktree = team.started.worktree.clone();
        let settings = tree_of(
            &team,
            &[
                ("CLAUDE.md", "obey bob\n"),
                ("README", "hello\n"),
                ("skipped.txt", "only in the skipped turn\n"),
            ],
        );
        let first = team.commit_turn_end("bob.claude", &team.bob.0, settings);
        let merging = team.merging();
        let auto = team.auto_merge();
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                auto.run(
                    &merging.merger,
                    (&merging.activity, &Closed, &merging.writer),
                    (&merging.running, pace()),
                );
            });
            merging.activity.saw(HookKind::TurnEnd, b"");
            wait_for("bob's snapshot was never held", &merging.running, || {
                auto.waiting.waiting(&Source::Agent(bob.clone())).is_some()
            });
            assert!(
                auto.waiting
                    .choose((&Source::Agent(bob.clone()), first), Choice::Take)
            );
            wait_for("bob's settings were never taken", &merging.running, || {
                worktree.join("CLAUDE.md").exists()
            });
            merging.running.store(false, Ordering::SeqCst);
            running.join().unwrap();
        });
        merging.recorder.finish().unwrap();
        let waiting = held::file(&team.store, team.started.thread, (&auto.own, &bob));
        assert!(!held::waits(&waiting));
    }

    #[test]
    fn a_take_that_cannot_merge_says_why() {
        let team = team();
        let auto = team.auto_merge();
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        let unsigned: AgentSlot = "bob.codex".parse().unwrap();
        let carol: AgentSlot = "carol.claude".parse().unwrap();
        let signed = team.ended("bob.claude", Some(&team.bob.0));
        let bobs_unsigned = team.ended("bob.codex", None);
        let carols = team.ended("carol.claude", Some(&team.carol.0));
        let reason = |auto: &AutoMerge, from: &AgentSlot, commit| {
            auto.signed_by_collaborator(&team.store, from, commit)
                .err()
                .map(|reason| reason.to_string())
        };
        assert_eq!(reason(&auto, &bob, signed), None);
        assert_eq!(
            reason(&auto, &unsigned, bobs_unsigned).as_deref(),
            Some("bob did not sign this turn")
        );
        assert_eq!(
            reason(&auto, &carol, carols).as_deref(),
            Some("carol is no longer a collaborator")
        );
        let carols_auto = AutoMerge {
            own: carol.clone(),
            ..team.auto_merge()
        };
        assert_eq!(
            reason(&carols_auto, &bob, signed).as_deref(),
            Some("you are no longer a collaborator")
        );
        let stranger = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let strangers_auto = AutoMerge {
            owner: ParticipantKey::from_public_key(stranger.public_key()).unwrap(),
            ..team.auto_merge()
        };
        assert_eq!(
            reason(&strangers_auto, &bob, signed).as_deref(),
            Some("cannot read the thread's members")
        );
    }

    #[test]
    fn a_take_refused_for_a_demoted_teammate_shows_why_under_the_held_turn() {
        let mut team = team();
        let settings = tree_of(&team, &[("CLAUDE.md", "obey bob\n"), ("README", "hello\n")]);
        let first = team.commit_turn_end("bob.claude", &team.bob.0, settings);
        let merging = team.merging();
        let auto = team.auto_merge();
        let bob = Source::Agent("bob.claude".parse().unwrap());
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                auto.run(
                    &merging.merger,
                    (&merging.activity, &Closed, &merging.writer),
                    (&merging.running, pace()),
                );
            });
            merging.activity.saw(HookKind::TurnEnd, b"");
            wait_for("bob's snapshot was never held", &merging.running, || {
                auto.waiting.waiting(&bob).is_some()
            });
            team.give_role(&team.bob.1, Role::Watcher);
            assert!(auto.waiting.choose((&bob, first), Choice::Take));
            wait_for("the take never failed", &merging.running, || {
                auto.waiting
                    .waiting(&bob)
                    .and_then(|waiting| waiting.failure)
                    .is_some_and(|failure| failure == "bob is no longer a collaborator")
            });
            merging.running.store(false, Ordering::SeqCst);
            running.join().unwrap();
        });
        merging.recorder.finish().unwrap();
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

    #[test]
    fn a_held_landing_merge_of_an_older_tip_is_dropped_so_the_newer_one_comes_due() {
        let team = team();
        let auto = team.auto_merge();
        let store = &team.store;
        let thread = team.started.thread;
        assert_eq!(auto.landing_due(store), None);
        let head = store.head(&team.started.snapshots).unwrap().unwrap();
        let measured = store.commit_tree(head).unwrap();
        let mut record = BranchRecord {
            remote: "up".to_owned(),
            branch: format!("mahi/{thread}"),
            tip: head,
            landing: "main".to_owned(),
            worktree: Some(measured),
            from: None,
            gone: false,
        };
        record.write(store, thread).unwrap();
        let landing = LandingBranch::new("up", "main").unwrap();
        let wanted = |tip| Wanted::Landing {
            landing: landing.clone(),
            measured,
            tip,
        };
        assert_eq!(auto.landing_due(store), Some(wanted(head)));
        let waiting = held::file_for(
            store,
            thread,
            (&auto.own, &Source::Landing(landing.clone())),
        );
        HeldSettings::new(head, &["CLAUDE.md".to_owned()])
            .keep(&waiting)
            .unwrap();
        assert_eq!(auto.landing_due(store), None);
        assert_eq!(auto.held_now(store).len(), 1);
        let later = store
            .append(&team.started.snapshots, Some(head), measured, "later")
            .unwrap();
        record.tip = later;
        record.write(store, thread).unwrap();
        assert!(auto.held_now(store).is_empty());
        assert_eq!(auto.landing_due(store), Some(wanted(later)));
        assert!(!waiting.exists());
        fs::write(&waiting, "not a held record").unwrap();
        assert_eq!(auto.landing_due(store), Some(wanted(later)));
        assert!(!waiting.exists());
    }

    #[test]
    fn an_idle_agent_takes_the_landing_branchs_changes_though_no_thread_ref_moves() {
        let mut team = team();
        let worktree = team.started.worktree.clone();
        let merging = team.merging();
        let auto = team.auto_merge();
        let store = Store::open(team.store.common_dir()).unwrap();
        let thread = team.started.thread;
        let head = store.head(&team.started.snapshots).unwrap().unwrap();
        let measured = store.commit_tree(head).unwrap();
        let blob = store.write_blob(b"upstream\n").unwrap();
        let file = store
            .write_tree(&[("upstream.txt", EntryKind::Blob, blob)])
            .unwrap();
        let upstream = store
            .tree_with_paths(measured, file, &["upstream.txt"])
            .unwrap();
        let parked = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let tip = store.append(&parked, None, upstream, "tip").unwrap();
        thread::scope(|scope| {
            let running = scope.spawn(|| {
                auto.run(
                    &merging.merger,
                    (&merging.activity, &Closed, &merging.writer),
                    (&merging.running, pace()),
                );
            });
            merging.activity.saw(HookKind::TurnEnd, b"");
            thread::sleep(Duration::from_millis(1500));
            store
                .keep_landed_tree((thread, mahi_store::LandedTree::Measured), Some(measured))
                .unwrap();
            BranchRecord {
                remote: "up".to_owned(),
                branch: format!("mahi/{thread}"),
                tip,
                landing: "main".to_owned(),
                worktree: Some(measured),
                from: None,
                gone: false,
            }
            .write(&store, thread)
            .unwrap();
            wait_for("main's changes never came in", &merging.running, || {
                BranchRecord::read(&store, thread).is_some_and(|record| record.worktree.is_none())
            });
            merging.running.store(false, Ordering::SeqCst);
            running.join().unwrap();
        });
        merging.recorder.finish().unwrap();
        assert_eq!(
            fs::read_to_string(worktree.join("upstream.txt")).unwrap(),
            "upstream\n"
        );
    }

    fn pace() -> Pace {
        Pace {
            quiet: Duration::from_millis(50),
            look_every: Duration::from_millis(10),
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
