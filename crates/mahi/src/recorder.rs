use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
        mpsc::{
            self,
            Receiver,
            Sender,
        },
    },
    thread::{
        self,
        JoinHandle,
    },
};

use mahi_core::{
    AgentSlot,
    ThreadRef,
};
use mahi_schedule::{
    Poker,
    Schedule,
    Scheduler,
    Trigger,
};
use mahi_store::{
    GlobalPatterns,
    ObjectId,
    Store,
    StoreError,
};
use thiserror::Error;

use crate::{
    merge::{
        self,
        AgentSettings,
        MergeDone,
        MergeError,
        MergeRequest,
        Recording,
    },
    session::{
        CommitKey,
        Recorded,
        SNAPSHOT_MESSAGE,
    },
    turn_end,
};

const FINAL_ATTEMPTS: usize = 3;

/// Snapshots an agent's worktree on its own thread while the agent runs.
#[derive(Debug)]
pub(crate) struct Recorder {
    poker: Poker,
    worker: JoinHandle<Result<usize, RecordError>>,
    abandon: Arc<AtomicBool>,
    turn_ended: Arc<AtomicBool>,
    merges: Sender<MergeJob>,
}

/// A merge the recorder makes between its snapshots, and where it says what came of it.
#[derive(Debug)]
struct MergeJob {
    request: MergeRequest,
    settings: AgentSettings,
    done: mpsc::SyncSender<Result<MergeDone, MergeError>>,
}

/// Asks the recorder to merge another agent's snapshot into the worktree it records, so the
/// merge and its snapshot come between the recorder's own snapshots.
#[derive(Debug, Clone)]
pub(crate) struct Merger {
    poker: Poker,
    merges: Sender<MergeJob>,
}

/// Tells the recorder what the agent did: a change that asks for a snapshot soon, or the end
/// of a turn, which a turn-end snapshot records.
#[derive(Debug, Clone)]
pub(crate) struct AgentEvents {
    poker: Poker,
    turn_ended: Arc<AtomicBool>,
}

impl AgentEvents {
    /// Asks for a snapshot soon, as when the agent used a tool.
    pub(crate) fn changed(&self) {
        self.poker.poke();
    }

    /// Asks for a turn-end snapshot at once, taken before any merge and even when the
    /// worktree did not change.
    pub(crate) fn turn_ended(&self) {
        self.turn_ended.store(true, Ordering::SeqCst);
        self.poker.poke_now();
    }
}

impl Merger {
    /// Merges `request`, writing agent settings as `settings` says, and waits for what came of
    /// it.
    pub(crate) fn merge(
        &self,
        request: MergeRequest,
        settings: AgentSettings,
    ) -> Result<MergeDone, MergeError> {
        let (done, outcome) = mpsc::sync_channel(1);
        self.merges
            .send(MergeJob {
                request,
                settings,
                done,
            })
            .map_err(|_| MergeError::RecorderGone)?;
        self.poker.poke();
        outcome.recv().map_err(|_| MergeError::RecorderGone)?
    }
}

/// Where a [`Recorder`] reads and writes.
#[derive(Debug)]
pub(crate) struct Target {
    pub(crate) git_dir: PathBuf,
    pub(crate) slot: AgentSlot,
    pub(crate) worktree: String,
    pub(crate) snapshots: ThreadRef,
    pub(crate) globals: GlobalPatterns,
    pub(crate) commits: CommitKey,
}

#[derive(Debug, Error)]
pub(crate) enum RecordError {
    #[error("cannot snapshot the worktree")]
    Store(#[from] StoreError),
    #[error("the snapshot thread stopped unexpectedly")]
    Stopped,
}

/// Which snapshot to take: a plain one, committed only when the worktree changed, or the one
/// that ends a turn, committed unless the last commit already ends a turn with the same tree.
#[derive(Debug, Clone, Copy)]
enum SnapshotKind<'msg> {
    Plain,
    TurnEnd {
        message: &'msg str,
        last_ended: Option<ObjectId>,
    },
}

/// The signals the recorder's thread reads: when to snapshot, the merges asked for, whether
/// a turn ended, and whether to give up.
struct Signals<'sig> {
    scheduler: Scheduler,
    merges: &'sig Receiver<MergeJob>,
    turn_ended: &'sig AtomicBool,
    abandon: &'sig AtomicBool,
}

impl Recorder {
    /// Starts snapshotting `target` on `schedule`, after `first`, the snapshot already taken.
    pub(crate) fn start(target: Target, first: Recorded, schedule: Schedule) -> Self {
        let (scheduler, poker) = Scheduler::new(schedule);
        let abandon = Arc::new(AtomicBool::new(false));
        let turn_ended = Arc::new(AtomicBool::new(false));
        let (stop, ended) = (Arc::clone(&abandon), Arc::clone(&turn_ended));
        let (merges, jobs) = mpsc::channel();
        let worker = thread::spawn(move || {
            record(
                &target,
                first,
                Signals {
                    scheduler,
                    merges: &jobs,
                    turn_ended: &ended,
                    abandon: &stop,
                },
            )
        });
        Self {
            poker,
            worker,
            abandon,
            turn_ended,
            merges,
        }
    }

    /// Returns a handle that tells the recorder what the agent did.
    pub(crate) fn events(&self) -> AgentEvents {
        AgentEvents {
            poker: self.poker.clone(),
            turn_ended: Arc::clone(&self.turn_ended),
        }
    }

    /// Returns a handle that has the recorder merge another agent's work into the worktree.
    pub(crate) fn merger(&self) -> Merger {
        Merger {
            poker: self.poker.clone(),
            merges: self.merges.clone(),
        }
    }

    /// Returns a flag that, once set, stops the snapshot in progress, including the last one.
    pub(crate) fn abandon_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.abandon)
    }

    /// Takes a last snapshot and stops. Returns how many paths the last snapshot left out, or
    /// the first error the recorder met, including a last snapshot that could not be taken.
    pub(crate) fn finish(self) -> Result<usize, RecordError> {
        self.poker.close();
        self.worker.join().map_err(|_| RecordError::Stopped)?
    }
}

fn record(
    target: &Target,
    mut last: Recorded,
    mut signals: Signals<'_>,
) -> Result<usize, RecordError> {
    let store = Store::open(&target.git_dir)?;
    let abandon = signals.abandon;
    let mut first_error = None;
    let mut skipped = 0;
    let turn_end = turn_end::message(&target.slot);
    let mut last_ended = None;
    let mut conflicted = false;
    loop {
        let trigger = signals.scheduler.wait();
        let closing = trigger == Trigger::Closed;
        let mut changed = false;
        if signals.turn_ended.swap(false, Ordering::SeqCst) && !conflicted {
            let kind = SnapshotKind::TurnEnd {
                message: &turn_end,
                last_ended,
            };
            let outcome = snapshot(&store, target, &mut last, kind, FINAL_ATTEMPTS, abandon);
            if let Ok((_, left_out)) = &outcome {
                skipped = *left_out;
                last_ended = Some(last.commit);
            }
            let (ended_changed, error) = settle(outcome.map(|(changed, _)| changed), closing);
            changed |= ended_changed;
            if let Some(error) = error {
                first_error.get_or_insert(error);
            }
        }
        while let Ok(job) = signals.merges.try_recv() {
            let done = if conflicted {
                Err(MergeError::MarkersUnresolved(target.slot.clone()))
            } else {
                merge_between(
                    &store,
                    target,
                    &mut last,
                    (&job.request, job.settings),
                    abandon,
                )
            };
            conflicted |= matches!(
                &done,
                Ok(MergeDone::Merged { markers: true, .. }) | Err(MergeError::MarkersWritten(_))
            );
            let _ = job.done.send(done);
        }
        let attempts = if closing { FINAL_ATTEMPTS } else { 1 };
        let outcome = snapshot(
            &store,
            target,
            &mut last,
            SnapshotKind::Plain,
            attempts,
            abandon,
        );
        if let Ok((_, left_out)) = &outcome {
            skipped = *left_out;
        }
        let (plain_changed, error) = settle(outcome.map(|(changed, _)| changed), closing);
        signals.scheduler.record(changed || plain_changed);
        if let Some(error) = error {
            first_error.get_or_insert(error);
        }
        if closing {
            return first_error.map_or(Ok(skipped), |error| Err(error.into()));
        }
    }
}

fn merge_between(
    store: &Store,
    target: &Target,
    last: &mut Recorded,
    request: (&MergeRequest, AgentSettings),
    abandon: &AtomicBool,
) -> Result<MergeDone, MergeError> {
    let recording = Recording {
        slot: &target.slot,
        worktree: &target.worktree,
        snapshots: &target.snapshots,
        globals: &target.globals,
        commits: &target.commits,
    };
    let done = merge::merge_now(
        store,
        recording,
        request,
        (&mut last.cache, Some(last.commit)),
        abandon,
    )?;
    if let MergeDone::Merged { commit, tree, .. } = &done {
        last.commit = *commit;
        last.tree = *tree;
    }
    Ok(done)
}

fn settle(outcome: Result<bool, StoreError>, closing: bool) -> (bool, Option<StoreError>) {
    match outcome {
        Ok(changed) => (changed, None),
        Err(StoreError::ChangedDuringSnapshot(_)) if !closing => (true, None),
        Err(error) => (false, Some(error)),
    }
}

fn snapshot(
    store: &Store,
    target: &Target,
    last: &mut Recorded,
    kind: SnapshotKind<'_>,
    attempts: usize,
    abandon: &AtomicBool,
) -> Result<(bool, usize), StoreError> {
    let mut left = attempts;
    let taken = loop {
        left = left.saturating_sub(1);
        match store.snapshot(&target.worktree, &target.globals, &mut last.cache, abandon) {
            Err(StoreError::ChangedDuringSnapshot(_)) if left > 0 => {}
            outcome => break outcome?,
        }
    };
    let skipped = taken.skipped.len();
    let changed = taken.tree != last.tree;
    let message = match kind {
        SnapshotKind::Plain if !changed => return Ok((false, skipped)),
        SnapshotKind::TurnEnd { last_ended, .. } if !changed && last_ended == Some(last.commit) => {
            return Ok((false, skipped));
        }
        SnapshotKind::Plain => SNAPSHOT_MESSAGE,
        SnapshotKind::TurnEnd { message, .. } => message,
    };
    last.commit = store.append_signed(
        &target.snapshots,
        Some(last.commit),
        taken.tree,
        message,
        target.commits.signer(),
    )?;
    last.tree = taken.tree;
    Ok((changed, skipped))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{
            Duration,
            Instant,
        },
    };

    use mahi_thread::{
        ParticipantKey,
        signed_by,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;
    use crate::{
        merged::MergedFrom,
        session::tests::{
            repository_on_main,
            start_with,
        },
    };

    fn fast() -> Schedule {
        Schedule::new(
            Duration::from_millis(20),
            Duration::from_millis(40),
            Duration::from_millis(5),
        )
        .unwrap()
    }

    fn snapshot_trees(store: &Store, snapshots: &ThreadRef) -> Vec<gix::ObjectId> {
        let repo = gix::open(store.common_dir()).unwrap();
        let mut trees = Vec::new();
        let mut next = store.head(snapshots).unwrap();
        while let Some(commit) = next {
            trees.push(
                repo.find_commit(commit)
                    .unwrap()
                    .tree_id()
                    .unwrap()
                    .detach(),
            );
            next = store.parent(commit).unwrap();
        }
        trees
    }

    fn file_in_tree(store: &Store, tree: gix::ObjectId, name: &str) -> Option<Vec<u8>> {
        let repo = gix::open(store.common_dir()).unwrap();
        let tree = repo.find_tree(tree).unwrap();
        let entry = tree.find_entry(name)?;
        Some(entry.object().unwrap().data.clone())
    }

    #[test]
    fn changes_are_recorded_once_each_and_the_last_one_on_finish() {
        let (dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let put = |name: &str, content: &str| {
            let staged = dir.path().join(name);
            fs::write(&staged, content).unwrap();
            fs::rename(&staged, started.worktree.join(name)).unwrap();
        };
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: crate::session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer.clone()).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            fast(),
        );
        let zero = store.head(&started.snapshots).unwrap();
        put("first", "one");
        let deadline = Instant::now() + Duration::from_secs(20);
        while store.head(&started.snapshots).unwrap() == zero {
            assert!(Instant::now() < deadline, "the change was never recorded");
            std::thread::sleep(Duration::from_millis(10));
        }
        put("last", "two");
        assert_eq!(recorder.finish().unwrap(), 0);

        let trees = snapshot_trees(&store, &started.snapshots);
        assert_eq!(trees.len(), 3, "{trees:?}");
        let newest = trees[0];
        assert_eq!(
            file_in_tree(&store, newest, "last").as_deref(),
            Some(b"two".as_slice())
        );
        assert_eq!(
            file_in_tree(&store, trees[1], "first").as_deref(),
            Some(b"one".as_slice())
        );
        assert_eq!(file_in_tree(&store, trees[1], "last"), None);
        assert_eq!(file_in_tree(&store, trees[2], "first"), None);
        let key = ParticipantKey::from_public_key(signer.public_key()).unwrap();
        let mut next = store.head(&started.snapshots).unwrap();
        while let Some(commit) = next {
            assert!(signed_by(&store, commit, &key).unwrap(), "{commit}");
            next = store.parent(commit).unwrap();
        }
    }

    #[test]
    fn a_turn_end_is_a_signed_snapshot_with_its_trailer_even_when_nothing_changed() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let zero = store.head(&started.snapshots).unwrap().unwrap();
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: crate::session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer.clone()).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            fast(),
        );
        recorder.events().turn_ended();
        let deadline = Instant::now() + Duration::from_secs(20);
        while store.head(&started.snapshots).unwrap() == Some(zero) {
            assert!(Instant::now() < deadline, "the turn end was never recorded");
            std::thread::sleep(Duration::from_millis(10));
        }
        recorder.finish().unwrap();

        let ended = store.head(&started.snapshots).unwrap().unwrap();
        assert_eq!(store.parent(ended).unwrap(), Some(zero));
        assert_eq!(
            store.commit_message(ended).unwrap(),
            format!("snapshot\n\nMahi-Turn-End: {}\n", started.slot)
        );
        let trees = snapshot_trees(&store, &started.snapshots);
        assert_eq!(trees[0], trees[1]);
        let key = ParticipantKey::from_public_key(signer.public_key()).unwrap();
        assert!(signed_by(&store, ended, &key).unwrap());
    }

    fn wait_for_new_head(store: &Store, snapshots: &ThreadRef, old: Option<ObjectId>) -> ObjectId {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let head = store.head(snapshots).unwrap();
            if head != old {
                return head.unwrap();
            }
            assert!(Instant::now() < deadline, "no new snapshot");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_turn_end_marks_only_its_own_snapshot_and_is_not_repeated_without_a_change() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let zero = store.head(&started.snapshots).unwrap();
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: crate::session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer.clone()).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            fast(),
        );
        let events = recorder.events();
        events.turn_ended();
        let ended = wait_for_new_head(&store, &started.snapshots, zero);
        fs::write(started.worktree.join("next"), "next turn").unwrap();
        events.changed();
        let plain = wait_for_new_head(&store, &started.snapshots, Some(ended));
        assert_eq!(store.commit_message(plain).unwrap(), SNAPSHOT_MESSAGE);
        events.turn_ended();
        let ended_again = wait_for_new_head(&store, &started.snapshots, Some(plain));
        events.turn_ended();
        recorder.finish().unwrap();

        assert_eq!(store.head(&started.snapshots).unwrap(), Some(ended_again));
        assert_eq!(store.parent(ended_again).unwrap(), Some(plain));
        assert_eq!(
            store.commit_message(ended_again).unwrap(),
            format!("snapshot\n\nMahi-Turn-End: {}\n", started.slot)
        );
    }

    #[test]
    fn a_turn_end_is_recorded_before_a_merge_asked_for_with_it() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let readme = store.write_blob(b"hello\n").unwrap();
        let notes = store.write_blob(b"from bob\n").unwrap();
        let theirs = store
            .write_tree(&[
                ("README", mahi_store::EntryKind::Blob, readme),
                ("notes.txt", mahi_store::EntryKind::Blob, notes),
            ])
            .unwrap();
        let bob: mahi_core::AgentSlot = "bob.codex".parse().unwrap();
        let commit = store
            .append(
                &ThreadRef::new(started.thread, mahi_core::RefKind::Snapshots(bob.clone())),
                None,
                theirs,
                SNAPSHOT_MESSAGE,
            )
            .unwrap();
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: crate::session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer.clone()).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            Schedule::new(
                Duration::from_secs(2),
                Duration::from_secs(60),
                Duration::from_millis(5),
            )
            .unwrap(),
        );
        fs::write(started.worktree.join("mine"), "my turn").unwrap();
        recorder.events().turn_ended();
        let MergeDone::Merged {
            commit: merge_commit,
            ..
        } = recorder
            .merger()
            .merge(
                MergeRequest {
                    from: bob,
                    commit,
                    thread_base: store.head_commit().unwrap(),
                },
                AgentSettings::Take,
            )
            .unwrap()
        else {
            panic!("nothing was merged");
        };
        recorder.finish().unwrap();

        let ended = store.parent(merge_commit).unwrap().unwrap();
        assert_eq!(
            store.commit_message(ended).unwrap(),
            format!("snapshot\n\nMahi-Turn-End: {}\n", started.slot)
        );
        let repo = gix::open(store.common_dir()).unwrap();
        let tree = repo.find_commit(ended).unwrap().tree().unwrap();
        assert!(tree.find_entry("mine").is_some());
        assert!(tree.find_entry("notes.txt").is_none());
    }

    #[test]
    fn a_change_during_a_snapshot_is_retried_but_not_at_the_end() {
        let changed = || Err(StoreError::ChangedDuringSnapshot("file".into()));
        assert!(matches!(settle(changed(), false), (true, None)));
        assert!(matches!(
            settle(changed(), true),
            (false, Some(StoreError::ChangedDuringSnapshot(_)))
        ));
        assert!(matches!(settle(Ok(true), true), (true, None)));
        assert!(matches!(
            settle(Err(StoreError::NoCommit), false),
            (false, Some(StoreError::NoCommit))
        ));
    }

    #[test]
    fn paths_left_out_of_the_last_snapshot_are_counted() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: crate::session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer.clone()).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            fast(),
        );
        fs::create_dir(started.worktree.join("GIT~1")).unwrap();
        fs::write(started.worktree.join("GIT~1").join("x"), "x").unwrap();
        assert_eq!(recorder.finish().unwrap(), 1);
    }

    #[test]
    fn an_abandoned_recorder_takes_no_last_snapshot() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let zero = store.head(&started.snapshots).unwrap();
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: crate::session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer.clone()).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            Schedule::new(
                Duration::from_secs(60),
                Duration::from_secs(60),
                Duration::from_millis(5),
            )
            .unwrap(),
        );
        fs::write(started.worktree.join("late"), "late").unwrap();
        recorder
            .abandon_flag()
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            recorder.finish(),
            Err(RecordError::Store(StoreError::Interrupted))
        ));
        assert_eq!(store.head(&started.snapshots).unwrap(), zero);
    }

    #[test]
    fn a_failing_snapshot_is_reported_on_finish() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: "not-a-worktree".to_owned(),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer.clone()).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            fast(),
        );
        assert!(matches!(
            recorder.finish(),
            Err(RecordError::Store(StoreError::NotAWorktree(_)))
        ));
    }

    #[test]
    fn a_merge_comes_between_snapshots_and_the_next_one_follows_it() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let readme = store.write_blob(b"hello\n").unwrap();
        let notes = store.write_blob(b"from bob\n").unwrap();
        let theirs = store
            .write_tree(&[
                ("README", mahi_store::EntryKind::Blob, readme),
                ("notes.txt", mahi_store::EntryKind::Blob, notes),
            ])
            .unwrap();
        let bob: mahi_core::AgentSlot = "bob.codex".parse().unwrap();
        let commit = store
            .append(
                &ThreadRef::new(started.thread, mahi_core::RefKind::Snapshots(bob.clone())),
                None,
                theirs,
                SNAPSHOT_MESSAGE,
            )
            .unwrap();
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: crate::session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer.clone()).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            fast(),
        );
        let merger = recorder.merger();
        let request = MergeRequest {
            from: bob,
            commit,
            thread_base: store.head_commit().unwrap(),
        };
        let MergeDone::Merged {
            commit: merge_commit,
            prompt,
            ..
        } = merger.merge(request.clone(), AgentSettings::Take).unwrap()
        else {
            panic!("nothing was merged");
        };
        assert_eq!(prompt, None);
        assert_eq!(store.head(&started.snapshots).unwrap(), Some(merge_commit));
        assert_eq!(
            fs::read_to_string(started.worktree.join("notes.txt")).unwrap(),
            "from bob\n"
        );
        assert!(matches!(
            merger.merge(request.clone(), AgentSettings::Take).unwrap(),
            MergeDone::Already(_)
        ));
        fs::write(started.worktree.join("later"), "after the merge").unwrap();
        recorder.finish().unwrap();
        let last = store.head(&started.snapshots).unwrap().unwrap();
        assert_ne!(last, merge_commit);
        assert_eq!(store.parent(last).unwrap(), Some(merge_commit));
        assert!(matches!(
            merger.merge(request, AgentSettings::Take),
            Err(MergeError::RecorderGone)
        ));
    }

    struct Merging {
        _dir: tempfile::TempDir,
        store: Store,
        started: crate::session::Started,
        recorder: Recorder,
        bob: mahi_core::AgentSlot,
    }

    fn merging() -> Merging {
        let (dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let recorder = Recorder::start(
            Target {
                git_dir: store.common_dir().to_path_buf(),
                slot: started.slot.clone(),
                worktree: crate::session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals: GlobalPatterns::default(),
                commits: CommitKey::new(signer).unwrap(),
            },
            started.first_snapshot.take().unwrap(),
            fast(),
        );
        Merging {
            _dir: dir,
            store,
            started,
            recorder,
            bob: "bob.codex".parse().unwrap(),
        }
    }

    impl Merging {
        fn bobs(&self, files: &[(&str, &str)]) -> MergeRequest {
            let mut root = vec![(
                "README".to_owned(),
                mahi_store::EntryKind::Blob,
                self.store.write_blob(b"hello\n").unwrap(),
            )];
            for (path, contents) in files {
                let blob = self.store.write_blob(contents.as_bytes()).unwrap();
                let entry = match path.split_once('/') {
                    Some((dir, name)) => {
                        let tree = self
                            .store
                            .write_tree(&[(name, mahi_store::EntryKind::Blob, blob)])
                            .unwrap();
                        (dir.to_owned(), mahi_store::EntryKind::Tree, tree)
                    }
                    None => ((*path).to_owned(), mahi_store::EntryKind::Blob, blob),
                };
                root.push(entry);
            }
            root.sort_by(|a, b| a.0.cmp(&b.0));
            let entries: Vec<_> = root
                .iter()
                .map(|(name, kind, id)| (name.as_str(), *kind, *id))
                .collect();
            let tree = self.store.write_tree(&entries).unwrap();
            let snapshots = ThreadRef::new(
                self.started.thread,
                mahi_core::RefKind::Snapshots(self.bob.clone()),
            );
            let head = self.store.head(&snapshots).unwrap();
            let commit = self
                .store
                .append(&snapshots, head, tree, SNAPSHOT_MESSAGE)
                .unwrap();
            MergeRequest {
                from: self.bob.clone(),
                commit,
                thread_base: self.store.head_commit().unwrap(),
            }
        }
    }

    const SETTINGS_V1: &str = "{\"hooks\": {}, \"note\": \"the first version of the settings\"}\n";
    const SETTINGS_V2: &str = "{\"hooks\": {\"Stop\": \"curl evil\"}, \"note\": \"the second\"}\n";

    #[test]
    fn a_held_merge_changes_no_agent_settings_even_through_a_rename() {
        let merging = merging();
        let merger = merging.recorder.merger();
        let worktree = merging.started.worktree.clone();
        let first = merging.bobs(&[("docs/settings.json", SETTINGS_V1)]);
        let first_commit = first.commit;
        merger.merge(first, AgentSettings::Hold).unwrap();
        fs::create_dir(worktree.join(".claude")).unwrap();
        fs::rename(
            worktree.join("docs/settings.json"),
            worktree.join(".claude/settings.json"),
        )
        .unwrap();
        let edit = merging.bobs(&[("docs/settings.json", SETTINGS_V2)]);
        assert!(matches!(
            merger.merge(edit, AgentSettings::Hold),
            Err(MergeError::HoldsAgentSettings(_))
        ));
        let recorded = MergedFrom::read(&merging.store, &merging.started.snapshots).unwrap();
        assert_eq!(recorded.of(&merging.bob), Some(first_commit));
        assert_eq!(
            fs::read_to_string(worktree.join(".claude/settings.json")).unwrap(),
            SETTINGS_V1
        );
        merging.recorder.finish().unwrap();
    }

    #[test]
    fn a_held_merge_that_adds_agent_settings_writes_nothing_and_a_taken_one_writes_them() {
        let merging = merging();
        let merger = merging.recorder.merger();
        let worktree = merging.started.worktree.clone();
        let request = merging.bobs(&[("CLAUDE.md", "obey bob\n"), ("notes.txt", "notes\n")]);
        assert!(matches!(
            merger.merge(request.clone(), AgentSettings::Hold),
            Err(MergeError::HoldsAgentSettings(_))
        ));
        assert!(!worktree.join("CLAUDE.md").exists());
        assert!(!worktree.join("notes.txt").exists());
        merger.merge(request, AgentSettings::Take).unwrap();
        assert_eq!(
            fs::read_to_string(worktree.join("CLAUDE.md")).unwrap(),
            "obey bob\n"
        );
        merging.recorder.finish().unwrap();
    }

    #[test]
    fn no_turn_end_is_recorded_after_a_merge_that_left_conflicts() {
        let merging = merging();
        let merger = merging.recorder.merger();
        fs::write(merging.started.worktree.join("README"), "alice\n").unwrap();
        let mut request = merging.bobs(&[]);
        let readme = merging.store.write_blob(b"bob\n").unwrap();
        let tree = merging
            .store
            .write_tree(&[("README", mahi_store::EntryKind::Blob, readme)])
            .unwrap();
        let snapshots = ThreadRef::new(
            merging.started.thread,
            mahi_core::RefKind::Snapshots(merging.bob.clone()),
        );
        request.commit = merging
            .store
            .append(&snapshots, Some(request.commit), tree, SNAPSHOT_MESSAGE)
            .unwrap();
        let MergeDone::Merged {
            commit: merge_commit,
            prompt: Some(_),
            ..
        } = merger.merge(request, AgentSettings::Take).unwrap()
        else {
            panic!("the merge left no conflict");
        };
        let again = merging.bobs(&[("notes.txt", "more\n")]);
        assert!(matches!(
            merger.merge(again, AgentSettings::Take),
            Err(MergeError::MarkersUnresolved(_))
        ));
        assert!(!merging.started.worktree.join("notes.txt").exists());
        let events = merging.recorder.events();
        events.turn_ended();
        fs::write(merging.started.worktree.join("later"), "after").unwrap();
        events.turn_ended();
        merging.recorder.finish().unwrap();
        let mut at = merging.store.head(&merging.started.snapshots).unwrap();
        while let Some(commit) = at.filter(|commit| *commit != merge_commit) {
            let message = merging.store.commit_message(commit).unwrap().to_string();
            assert!(!message.contains("Mahi-Turn-End"), "{message}");
            at = merging.store.parent(commit).unwrap();
        }
    }

    #[test]
    fn a_conflict_that_keeps_ours_without_markers_lets_turn_ends_and_merges_go_on() {
        let merging = merging();
        let merger = merging.recorder.merger();
        fs::write(merging.started.worktree.join("logo.bin"), b"\0ours\0").unwrap();
        let MergeDone::Merged {
            commit: merge_commit,
            prompt: Some(_),
            markers: false,
            ..
        } = merger
            .merge(
                merging.bobs(&[("logo.bin", "\0theirs\0")]),
                AgentSettings::Take,
            )
            .unwrap()
        else {
            panic!("the merge did not keep ours without markers");
        };
        let later = merging.bobs(&[("logo.bin", "\0theirs\0"), ("notes.txt", "more\n")]);
        merger.merge(later, AgentSettings::Take).unwrap();
        merging.recorder.events().turn_ended();
        merging.recorder.finish().unwrap();
        let mut at = merging.store.head(&merging.started.snapshots).unwrap();
        let mut ended = false;
        while let Some(commit) = at.filter(|commit| *commit != merge_commit) {
            let message = merging.store.commit_message(commit).unwrap().to_string();
            ended |= message.contains("Mahi-Turn-End");
            at = merging.store.parent(commit).unwrap();
        }
        assert!(ended, "no turn end was recorded after the merge");
    }

    #[test]
    fn a_merge_that_wrote_markers_and_then_failed_still_stops_turn_ends_and_merges() {
        let merging = merging();
        let merger = merging.recorder.merger();
        fs::write(merging.started.worktree.join("README"), "alice\n").unwrap();
        let mut request = merging.bobs(&[]);
        let readme = merging.store.write_blob(b"bob\n").unwrap();
        let tree = merging
            .store
            .write_tree(&[("README", mahi_store::EntryKind::Blob, readme)])
            .unwrap();
        let bobs = ThreadRef::new(
            merging.started.thread,
            mahi_core::RefKind::Snapshots(merging.bob.clone()),
        );
        request.commit = merging
            .store
            .append(&bobs, Some(request.commit), tree, SNAPSHOT_MESSAGE)
            .unwrap();
        thread::sleep(Duration::from_millis(300));
        let head = merging.store.head(&merging.started.snapshots).unwrap();
        let moved_tree = merging.store.commit_tree(head.unwrap()).unwrap();
        merging
            .store
            .append(
                &merging.started.snapshots,
                head,
                moved_tree,
                SNAPSHOT_MESSAGE,
            )
            .unwrap();
        assert!(matches!(
            merger.merge(request, AgentSettings::Take),
            Err(MergeError::MarkersWritten(_))
        ));
        let again = merging.bobs(&[("notes.txt", "more\n")]);
        assert!(matches!(
            merger.merge(again, AgentSettings::Take),
            Err(MergeError::MarkersUnresolved(_))
        ));
        merging.recorder.events().turn_ended();
        let _ = merging.recorder.finish();
        let message = |commit| merging.store.commit_message(commit).unwrap().to_string();
        let head = merging
            .store
            .head(&merging.started.snapshots)
            .unwrap()
            .unwrap();
        assert!(
            !message(head).contains("Mahi-Turn-End"),
            "{}",
            message(head)
        );
    }
}
