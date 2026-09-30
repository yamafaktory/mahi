use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::AtomicBool,
    },
    thread::{
        self,
        JoinHandle,
    },
};

use mahi_core::ThreadRef;
use mahi_schedule::{
    Poker,
    Schedule,
    Scheduler,
    Trigger,
};
use mahi_store::{
    GlobalPatterns,
    Store,
    StoreError,
};
use thiserror::Error;

use crate::session::{
    CommitKey,
    Recorded,
    SNAPSHOT_MESSAGE,
};

const FINAL_ATTEMPTS: usize = 3;

/// Snapshots an agent's worktree on its own thread while the agent runs.
#[derive(Debug)]
pub(crate) struct Recorder {
    poker: Poker,
    worker: JoinHandle<Result<usize, RecordError>>,
    abandon: Arc<AtomicBool>,
}

/// Where a [`Recorder`] reads and writes.
#[derive(Debug)]
pub(crate) struct Target {
    pub(crate) git_dir: PathBuf,
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

impl Recorder {
    /// Starts snapshotting `target` on `schedule`, after `first`, the snapshot already taken.
    pub(crate) fn start(target: Target, first: Recorded, schedule: Schedule) -> Self {
        let (scheduler, poker) = Scheduler::new(schedule);
        let abandon = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&abandon);
        let worker = thread::spawn(move || record(&target, first, scheduler, &stop));
        Self {
            poker,
            worker,
            abandon,
        }
    }

    /// Returns a handle that asks for a snapshot soon, as when the agent used a tool.
    pub(crate) fn poker(&self) -> Poker {
        self.poker.clone()
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
    mut scheduler: Scheduler,
    abandon: &AtomicBool,
) -> Result<usize, RecordError> {
    let store = Store::open(&target.git_dir)?;
    let mut first_error = None;
    let mut skipped = 0;
    loop {
        let trigger = scheduler.wait();
        let closing = trigger == Trigger::Closed;
        let attempts = if closing { FINAL_ATTEMPTS } else { 1 };
        let outcome = snapshot(&store, target, &mut last, attempts, abandon);
        if let Ok((_, left_out)) = &outcome {
            skipped = *left_out;
        }
        let (changed, error) = settle(outcome.map(|(changed, _)| changed), closing);
        scheduler.record(changed);
        if let Some(error) = error {
            first_error.get_or_insert(error);
        }
        if closing {
            return first_error.map_or(Ok(skipped), |error| Err(error.into()));
        }
    }
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
    if taken.tree == last.tree {
        return Ok((false, skipped));
    }
    last.commit = store.append_signed(
        &target.snapshots,
        Some(last.commit),
        taken.tree,
        SNAPSHOT_MESSAGE,
        target.commits.signer(),
    )?;
    last.tree = taken.tree;
    Ok((true, skipped))
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
}
