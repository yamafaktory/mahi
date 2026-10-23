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
};

const FINAL_ATTEMPTS: usize = 3;
const TURN_END_TRAILER: &str = "Mahi-Turn-End: ";

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
    /// Merges `request` and waits for what came of it.
    pub(crate) fn merge(&self, request: MergeRequest) -> Result<MergeDone, MergeError> {
        let (done, outcome) = mpsc::sync_channel(1);
        self.merges
            .send(MergeJob { request, done })
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
    let turn_end = format!("{SNAPSHOT_MESSAGE}\n\n{TURN_END_TRAILER}{}\n", target.slot);
    let mut last_ended = None;
    loop {
        let trigger = signals.scheduler.wait();
        let closing = trigger == Trigger::Closed;
        let mut changed = false;
        if signals.turn_ended.swap(false, Ordering::SeqCst) {
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
            let _ = job.done.send(merge_between(
                &store,
                target,
                &mut last,
                &job.request,
                abandon,
            ));
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
    request: &MergeRequest,
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
    use crate::session::tests::{
        repository_on_main,
        start_with,
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
            .merge(MergeRequest {
                from: bob,
                commit,
                thread_base: store.head_commit().unwrap(),
            })
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
        } = merger.merge(request.clone()).unwrap()
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
            merger.merge(request.clone()).unwrap(),
            MergeDone::Already(_)
        ));
        fs::write(started.worktree.join("later"), "after the merge").unwrap();
        recorder.finish().unwrap();
        let last = store.head(&started.snapshots).unwrap().unwrap();
        assert_ne!(last, merge_commit);
        assert_eq!(store.parent(last).unwrap(), Some(merge_commit));
        assert!(matches!(
            merger.merge(request),
            Err(MergeError::RecorderGone)
        ));
    }
}
