use std::{
    path::{
        Path,
        PathBuf,
    },
    sync::mpsc::{
        self,
        Receiver,
        TryRecvError,
    },
    thread,
};

use mahi_core::{
    AgentSlot,
    LineCounts,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_store::{
    ObjectId,
    Store,
};

use crate::{
    land_desk,
    remote,
};

const MOST_LISTED: usize = 32;
const MOST_COUNTED_BYTES: u64 = 256 * 1024;

/// The tree a landing measures from, and the tree of the latest snapshot of the user's agent.
type Trees = (ObjectId, ObjectId);

/// The files of the user's worktree that changed since the tree a landing measures them from,
/// as the latest snapshot of the user's agent holds them, each with the lines it adds and
/// removes, and whether more changed than are listed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ChangesView {
    files: Vec<(String, LineCounts)>,
    more: bool,
}

impl ChangesView {
    /// Reads the files that differ from the tree `landed` to the tree `snapshot`, at most
    /// [`MOST_LISTED`] of them, counting the lines of files up to [`MOST_COUNTED_BYTES`];
    /// `None` when the trees cannot be compared.
    fn read(store: &Store, (landed, snapshot): Trees) -> Option<Self> {
        let changes = store.changed_paths(landed, snapshot, MOST_LISTED).ok()?;
        let files = changes
            .paths
            .into_iter()
            .enumerate()
            .map(|(index, (path, _))| {
                let not_utf8 = changes.not_utf8.iter().any(|(at, _)| *at == index);
                let counts = if not_utf8 {
                    LineCounts::NotAFile
                } else {
                    store
                        .line_counts((landed, snapshot), &path, MOST_COUNTED_BYTES)
                        .unwrap_or(LineCounts::NotAFile)
                };
                (path, counts)
            })
            .collect();
        Some(Self {
            files,
            more: changes.truncated,
        })
    }

    /// Returns the changed files, each with the lines it adds and removes.
    pub(crate) fn files(&self) -> &[(String, LineCounts)] {
        &self.files
    }

    /// Says whether more files changed than are listed.
    pub(crate) fn more(&self) -> bool {
        self.more
    }
}

/// The changes last read for the user's agent and the trees they were read from, and the
/// read under way on a thread of its own, so a new snapshot is read again without holding up
/// keys and drawing.
#[derive(Debug, Default)]
pub(crate) struct ChangesCache {
    read_from: Option<Trees>,
    view: Option<ChangesView>,
    reading: Option<(Trees, Receiver<Option<ChangesView>>)>,
}

impl ChangesCache {
    /// Returns the changes of `own`'s agent in `thread`, whose base is `base`, in the
    /// repository at `git_dir`, as last read; starts reading them again when the trees they
    /// come from moved and no read is under way. `None` until they were read, while the agent
    /// has no snapshot, or when its trees cannot be read or compared.
    pub(crate) fn read(
        &mut self,
        (store, git_dir): (&Store, &Path),
        thread: ThreadId,
        own: &AgentSlot,
        base: ObjectId,
    ) -> Option<&ChangesView> {
        self.take_read();
        let from = trees(store, thread, own, base);
        if from.is_none() {
            self.read_from = None;
            self.view = None;
        } else if self.reading.is_none()
            && from != self.read_from
            && let Some(from) = from
        {
            self.reading = start_reading(git_dir.to_path_buf(), from).map(|read| (from, read));
        }
        self.view.as_ref()
    }

    fn take_read(&mut self) {
        let Some((from, reading)) = &self.reading else {
            return;
        };
        match reading.try_recv() {
            Ok(view) => {
                self.read_from = Some(*from);
                self.view = view;
                self.reading = None;
            }
            Err(TryRecvError::Disconnected) => self.reading = None,
            Err(TryRecvError::Empty) => {}
        }
    }
}

/// Reads the changes of `own`'s agent in `thread`, whose base is `base`, at once; `None` while
/// the agent has no snapshot, or when its trees cannot be read or compared.
pub(crate) fn read_now(
    store: &Store,
    thread: ThreadId,
    own: &AgentSlot,
    base: ObjectId,
) -> Option<ChangesView> {
    trees(store, thread, own, base).and_then(|from| ChangesView::read(store, from))
}

/// Reads the changes between `from`'s trees in the repository at `git_dir` on a thread of its
/// own; `None` when the thread cannot start.
fn start_reading(git_dir: PathBuf, from: Trees) -> Option<Receiver<Option<ChangesView>>> {
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("changes".to_owned())
        .spawn(move || {
            let view = Store::open(&git_dir)
                .ok()
                .and_then(|store| ChangesView::read(&store, from));
            let _ = sender.send(view);
        })
        .ok()?;
    Some(receiver)
}

/// Returns the tree a landing measures from and the tree of `own`'s latest snapshot.
fn trees(store: &Store, thread: ThreadId, own: &AgentSlot, base: ObjectId) -> Option<Trees> {
    let snapshot = store
        .head(&ThreadRef::new(thread, RefKind::Snapshots(own.clone())))
        .ok()??;
    let remote = remote::sync_remote(store).ok().flatten();
    let landed = land_desk::landed_tree(
        store,
        thread,
        remote.as_ref().map(|remote| remote.name.as_str()),
        base,
    )
    .ok()?;
    Some((landed, store.commit_tree(snapshot).ok()?))
}

#[cfg(test)]
mod tests {
    use std::time::{
        Duration,
        Instant,
    };

    use gix::objs::tree::EntryKind;

    use super::*;

    fn read_until(
        cache: &mut ChangesCache,
        (store, git_dir): (&Store, &Path),
        (thread, own, base): (ThreadId, &AgentSlot, ObjectId),
        done: impl Fn(Option<&ChangesView>) -> bool,
    ) -> Option<ChangesView> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let read = cache.read((store, git_dir), thread, own, base).cloned();
            if done(read.as_ref()) || Instant::now() > deadline {
                return read;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn the_changes_are_read_from_the_latest_snapshot_and_again_once_it_moves() {
        let (repo, store) = crate::session::tests::repository_on_main();
        let git_dir = repo.path().join(".git");
        let thread = ThreadId::random().unwrap();
        let base = store.head_commit().unwrap();
        let own: AgentSlot = "davy.claude".parse().unwrap();
        let mut cache = ChangesCache::default();
        let at = (thread, &own, base);
        assert_eq!(cache.read((&store, &git_dir), thread, &own, base), None);
        let snapshots = ThreadRef::new(thread, RefKind::Snapshots(own.clone()));
        let kept = store.write_blob(b"hello\n").unwrap();
        let with_readme = |text: &[u8]| {
            let readme = store.write_blob(text).unwrap();
            store
                .write_tree(&[
                    ("README", EntryKind::Blob, kept),
                    ("README.md", EntryKind::Blob, readme),
                ])
                .unwrap()
        };
        let first = store
            .append(
                &snapshots,
                None,
                with_readme(b"hello moto\n"),
                crate::session::SNAPSHOT_MESSAGE,
            )
            .unwrap();
        let read = read_until(&mut cache, (&store, &git_dir), at, |read| read.is_some()).unwrap();
        assert_eq!(
            read.files(),
            [(
                "README.md".to_owned(),
                LineCounts::Counted {
                    added: 1,
                    removed: 0
                }
            )]
        );
        assert!(!read.more());
        let read_from = cache.read_from;
        assert_eq!(
            cache.read((&store, &git_dir), thread, &own, base),
            Some(&read)
        );
        assert!(cache.reading.is_none());
        assert_eq!(cache.read_from, read_from);
        store
            .append(
                &snapshots,
                Some(first),
                with_readme(b"hello\nmoto\n"),
                crate::session::SNAPSHOT_MESSAGE,
            )
            .unwrap();
        let moved = read_until(&mut cache, (&store, &git_dir), at, |moved| {
            moved.is_some_and(|moved| moved != &read)
        })
        .unwrap();
        assert_eq!(
            moved.files(),
            [(
                "README.md".to_owned(),
                LineCounts::Counted {
                    added: 2,
                    removed: 0
                }
            )]
        );
        assert_ne!(cache.read_from, read_from);
    }
}
