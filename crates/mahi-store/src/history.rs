use std::{
    collections::{
        BinaryHeap,
        HashMap,
        HashSet,
        hash_map::Entry,
    },
    ops::Range,
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

use gix::ObjectId;

use crate::store::{
    Store,
    StoreError,
};

const MAX_WALKED_COMMITS: usize = 1_000_000;
const CLOCK_SKEW_SECONDS: i64 = 86_400;
const VISIBLE: u8 = 1;
const HIDDEN: u8 = 2;
const QUEUED: u8 = 4;

pub(crate) struct NewCommits {
    pub(crate) commits: Vec<ObjectId>,
    pub(crate) boundary: HashSet<ObjectId>,
}

struct Queued {
    time: i64,
    id: ObjectId,
    parents: Range<usize>,
}

impl PartialEq for Queued {
    fn eq(&self, other: &Self) -> bool {
        (self.time, self.id) == (other.time, other.id)
    }
}

impl Eq for Queued {}

impl PartialOrd for Queued {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Queued {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.time, self.id).cmp(&(other.time, other.id))
    }
}

#[derive(Default)]
struct CommitQueue {
    heap: BinaryHeap<Queued>,
    parents: Vec<ObjectId>,
    walked: usize,
}

impl CommitQueue {
    fn push(&mut self, store: &Store, id: ObjectId) -> Result<(), StoreError> {
        let commit = store.repo.find_commit(id)?;
        let time = commit.time().map_err(gix::Error::from_error)?.seconds;
        let start = self.parents.len();
        self.parents
            .extend(commit.parent_ids().map(gix::Id::detach));
        self.heap.push(Queued {
            time,
            id,
            parents: start..self.parents.len(),
        });
        Ok(())
    }

    fn pop(&mut self, interrupt: &AtomicBool) -> Result<Option<Queued>, StoreError> {
        if interrupt.load(Ordering::SeqCst) {
            return Err(StoreError::Interrupted);
        }
        let Some(next) = self.heap.pop() else {
            return Ok(None);
        };
        self.walked += 1;
        if self.walked > MAX_WALKED_COMMITS {
            return Err(StoreError::TooManyCommits(MAX_WALKED_COMMITS));
        }
        Ok(Some(next))
    }

    fn parent(&self, at: usize) -> Option<ObjectId> {
        self.parents.get(at).copied()
    }
}

struct Painter {
    queue: CommitQueue,
    flags: HashMap<ObjectId, u8>,
    pending: usize,
}

impl Painter {
    fn mark(&mut self, store: &Store, id: ObjectId, colour: u8) -> Result<(), StoreError> {
        match self.flags.entry(id) {
            Entry::Occupied(mut entry) => {
                let old = *entry.get();
                if old & HIDDEN != 0 || colour & HIDDEN == 0 {
                    entry.insert(old | colour);
                } else if old & QUEUED != 0 {
                    entry.insert(old | colour);
                    self.pending -= 1;
                } else {
                    entry.insert(old | colour | QUEUED);
                    self.queue.push(store, id)?;
                }
            }
            Entry::Vacant(entry) => {
                if colour & HIDDEN != 0 && !store.has_commit(id) {
                    return Ok(());
                }
                entry.insert(colour | QUEUED);
                self.queue.push(store, id)?;
                if colour == VISIBLE {
                    self.pending += 1;
                }
            }
        }
        Ok(())
    }
}

impl Store {
    pub(crate) fn new_commits(
        &self,
        tip: ObjectId,
        hidden: &HashSet<ObjectId>,
        interrupt: &AtomicBool,
    ) -> Result<NewCommits, StoreError> {
        let mut painter = Painter {
            queue: CommitQueue::default(),
            flags: HashMap::with_capacity(hidden.len() + 1),
            pending: 0,
        };
        for id in hidden {
            painter.mark(self, *id, HIDDEN)?;
        }
        painter.mark(self, tip, VISIBLE)?;
        let mut popped = Vec::new();
        let mut floor = i64::MAX;
        while painter.pending > 0
            || painter
                .queue
                .heap
                .peek()
                .is_some_and(|next| next.time >= floor)
        {
            let Some(next) = painter.queue.pop(interrupt)? else {
                break;
            };
            let Some(flags) = painter.flags.get_mut(&next.id) else {
                continue;
            };
            *flags &= !QUEUED;
            let colour = *flags & (VISIBLE | HIDDEN);
            if colour == VISIBLE {
                painter.pending -= 1;
                floor = floor.min(next.time.saturating_sub(CLOCK_SKEW_SECONDS));
                popped.push((next.id, next.parents.clone()));
            }
            for at in next.parents {
                if let Some(parent) = painter.queue.parent(at) {
                    painter.mark(self, parent, colour)?;
                }
            }
        }
        popped.retain(|(id, _)| {
            painter
                .flags
                .get(id)
                .is_some_and(|flags| flags & HIDDEN == 0)
        });
        let new: HashSet<ObjectId> = popped.iter().map(|(id, _)| *id).collect();
        let boundary = popped
            .iter()
            .flat_map(|(_, parents)| parents.clone())
            .filter_map(|at| painter.queue.parent(at))
            .filter(|parent| !new.contains(parent))
            .collect();
        let commits = popped.into_iter().map(|(id, _)| id).collect();
        Ok(NewCommits { commits, boundary })
    }

    pub(crate) fn reaches(
        &self,
        commit: ObjectId,
        ancestor: ObjectId,
        interrupt: &AtomicBool,
    ) -> Result<bool, StoreError> {
        let floor = self
            .repo
            .find_commit(ancestor)?
            .time()
            .map_err(gix::Error::from_error)?
            .seconds
            .saturating_sub(CLOCK_SKEW_SECONDS);
        let mut queue = CommitQueue::default();
        queue.push(self, commit)?;
        let mut seen = HashSet::from([commit]);
        while let Some(next) = queue.pop(interrupt)? {
            if next.id == ancestor {
                return Ok(true);
            }
            if next.time < floor {
                continue;
            }
            for at in next.parents {
                if let Some(parent) = queue.parent(at)
                    && seen.insert(parent)
                {
                    queue.push(self, parent)?;
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        gix::init_bare(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn commit(store: &Store, parents: &[ObjectId], time: i64) -> ObjectId {
        salted(store, parents, time, 0)
    }

    fn salted(store: &Store, parents: &[ObjectId], time: i64, salt: u32) -> ObjectId {
        let tree = store.write_tree(&[]).unwrap();
        let signature = gix::actor::Signature {
            name: "t".into(),
            email: "t@example.com".into(),
            time: gix::date::Time::new(time, 0),
        };
        store
            .repo
            .write_object(&gix::objs::Commit {
                tree,
                parents: parents.into(),
                author: signature.clone(),
                committer: signature,
                encoding: None,
                message: format!("{time} {parents:?} {salt}").into(),
                extra_headers: Vec::new(),
            })
            .unwrap()
            .detach()
    }

    #[test]
    fn a_merge_reaches_the_ancestors_of_each_parent() {
        let (_dir, store) = store();
        let none = AtomicBool::new(false);
        let base = commit(&store, &[], DAY);
        let left = commit(&store, &[base], 2 * DAY);
        let right = commit(&store, &[base], 3 * DAY);
        let merge = commit(&store, &[left, right], 4 * DAY);
        assert!(store.reaches(merge, left, &none).unwrap());
        assert!(store.reaches(merge, right, &none).unwrap());
        assert!(store.reaches(merge, base, &none).unwrap());
        assert!(store.reaches(right, right, &none).unwrap());
        assert!(!store.reaches(left, right, &none).unwrap());
        assert!(!store.reaches(base, merge, &none).unwrap());
    }

    #[test]
    fn the_walk_stops_a_day_below_the_ancestor_and_on_interrupt() {
        let (_dir, store) = store();
        let ancestor = commit(&store, &[], 100 * DAY);
        let skewed = commit(&store, &[ancestor], 98 * DAY);
        let tip = commit(&store, &[skewed], 101 * DAY);
        assert!(
            !store
                .reaches(tip, ancestor, &AtomicBool::new(false))
                .unwrap()
        );
        let close = commit(&store, &[ancestor], 100 * DAY - 3600);
        let tip = commit(&store, &[close], 101 * DAY);
        assert!(
            store
                .reaches(tip, ancestor, &AtomicBool::new(false))
                .unwrap()
        );
        assert!(matches!(
            store.reaches(tip, ancestor, &AtomicBool::new(true)),
            Err(StoreError::Interrupted)
        ));
    }

    #[test]
    fn new_commits_stop_where_the_hidden_history_joins_and_list_their_boundary() {
        let (_dir, store) = store();
        let none = AtomicBool::new(false);
        let mut root = commit(&store, &[], DAY);
        for day in 2..50 {
            root = commit(&store, &[root], day * DAY);
        }
        let base = commit(&store, &[root], 50 * DAY);
        let main_one = commit(&store, &[base], 51 * DAY);
        let main_two = commit(&store, &[main_one], 53 * DAY);
        let land_one = commit(&store, &[base], 52 * DAY);
        let merge = commit(&store, &[land_one, main_one], 54 * DAY);
        let missing = ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let found = store
            .new_commits(merge, &HashSet::from([main_two, missing]), &none)
            .unwrap();
        assert_eq!(found.commits, [merge, land_one]);
        assert_eq!(found.boundary, HashSet::from([base, main_one]));
        let all = store.new_commits(merge, &HashSet::new(), &none).unwrap();
        assert_eq!(all.commits.len(), 53);
        assert!(all.boundary.is_empty());
        let up_to_date = store
            .new_commits(main_one, &HashSet::from([main_two]), &none)
            .unwrap();
        assert!(up_to_date.commits.is_empty());
        assert!(matches!(
            store.new_commits(merge, &HashSet::new(), &AtomicBool::new(true)),
            Err(StoreError::Interrupted)
        ));
    }

    #[test]
    fn a_shared_commit_made_in_the_same_second_as_a_remote_one_is_not_sent() {
        let (_dir, store) = store();
        let none = AtomicBool::new(false);
        let mut root = commit(&store, &[], DAY);
        for day in 2..20 {
            root = commit(&store, &[root], day * DAY);
        }
        let mut orders = HashSet::new();
        for salt in 0..64 {
            let shared = salted(&store, &[root], 30 * DAY, salt);
            let remote = salted(&store, &[shared], 30 * DAY, salt);
            let tip = salted(&store, &[shared], 31 * DAY, salt);
            orders.insert(shared > remote);
            let found = store
                .new_commits(tip, &HashSet::from([remote]), &none)
                .unwrap();
            assert_eq!(found.commits, [tip], "salt {salt}");
            assert_eq!(found.boundary, HashSet::from([shared]), "salt {salt}");
        }
        assert_eq!(orders.len(), 2);
    }

    #[test]
    fn a_hidden_commit_dated_before_its_child_still_hides_what_it_reaches() {
        let (_dir, store) = store();
        let none = AtomicBool::new(false);
        let shared = commit(&store, &[], 100 * DAY);
        let remote = commit(&store, &[shared], 100 * DAY - 3600);
        let tip = commit(&store, &[shared], 150 * DAY);
        let found = store
            .new_commits(tip, &HashSet::from([remote]), &none)
            .unwrap();
        assert_eq!(found.commits, [tip]);
        assert_eq!(found.boundary, HashSet::from([shared]));
    }
}
