use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{
        Path,
        PathBuf,
    },
    sync::atomic::AtomicBool,
};

use gix::{
    ObjectId,
    object::Kind,
    odb::pack::{
        Bundle,
        bundle::write::Options,
        data::input::Mode,
    },
};

use crate::{
    push::{
        PACK_FRAMING_BYTES,
        check,
    },
    store::{
        Store,
        StoreError,
    },
};

/// The bounds of a history to pack: how many commits it may hold, and how many bytes its
/// objects may take in all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryLimits {
    /// The most commits.
    pub commits: usize,
    /// The most bytes in all.
    pub bytes: u64,
}

/// The bounds of a history to take in: how many commits it may hold, and how many bytes any
/// one of its objects, decoded, or the bookkeeping of the pack's count of objects may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TakeLimits {
    /// The most commits.
    pub commits: usize,
    /// The most bytes for one object or for the bookkeeping.
    pub object_bytes: u64,
}

impl Store {
    /// Writes into `out` a pack of the linear history from `tip` back to `since`, which it
    /// leaves out: each commit, oldest first, with the objects of its tree that neither the
    /// tree of `since` nor an earlier commit of the pack holds. Returns how many commits it
    /// packed; with none, it writes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotInHistory`] if `since` is not in the history of `tip`,
    /// [`StoreError::TooManyCommits`] if more than `limits.commits` would be packed (also when
    /// `since` is not found within them), [`StoreError::TooLarge`] if the objects would take
    /// more than `limits.bytes`, [`StoreError::Interrupted`] if `interrupt` is set, or another
    /// [`StoreError`] if the repository cannot be read or `out` written.
    pub fn write_history_pack(
        &self,
        since: Option<ObjectId>,
        tip: ObjectId,
        limits: HistoryLimits,
        out: &mut dyn Write,
        interrupt: &AtomicBool,
    ) -> Result<usize, StoreError> {
        let commits = self.history_since(since, tip, limits.commits, interrupt)?;
        if commits.is_empty() {
            return Ok(0);
        }
        let mut known = HashSet::new();
        if let Some(since) = since {
            self.mark_known(self.commit_tree(since)?, &mut known, interrupt)?;
        }
        let mut objects = Vec::with_capacity(commits.len());
        for commit in commits.iter().rev() {
            known.insert(*commit);
            objects.push(*commit);
            self.collect_new(
                self.commit_tree(*commit)?,
                &mut known,
                &mut objects,
                interrupt,
            )?;
        }
        let size = self
            .objects_size(&objects)?
            .saturating_add(PACK_FRAMING_BYTES);
        if size > limits.bytes {
            return Err(StoreError::TooLarge {
                id: tip,
                limit: limits.bytes,
            });
        }
        self.write_pack(&objects, out, interrupt)?;
        Ok(commits.len())
    }

    /// Adds the objects of `pack`, a pack another mahi wrote of the history from `tip` back to
    /// `since`, to the repository, then checks that the repository holds that whole history:
    /// every commit, each with every tree and blob of its tree. Each object of the pack is
    /// checked as it is read, and none is decoded into more than `limits.object_bytes`, which
    /// also bounds the bookkeeping for the pack's count of objects; the caller bounds the
    /// pack's own size. An empty `pack` adds nothing. The pack's objects stay in the
    /// repository even when the history is refused, unreferenced until git's garbage
    /// collection, and so may others the pack holds: holding a commit does not mean holding
    /// its history, which only this check, or a ref that moved after it, tells. Whoever reads
    /// the history still checks what it claims, such as who signed it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Git`] if `pack` is not a valid pack or holds an object over the
    /// limit, [`StoreError::WrongObject`] if an object of the history is missing,
    /// [`StoreError::NotInHistory`] or [`StoreError::TooManyCommits`] if the history from `tip`
    /// does not reach `since` within `limits.commits`, [`StoreError::Interrupted`] if
    /// `interrupt` is set, or [`StoreError::Io`] if the pack cannot be written.
    pub fn take_history_pack(
        &self,
        pack: &[u8],
        since: Option<ObjectId>,
        tip: ObjectId,
        limits: TakeLimits,
        interrupt: &AtomicBool,
    ) -> Result<(), StoreError> {
        if !pack.is_empty() {
            let directory = self.repo.objects.store_ref().path().join("pack");
            let keep = index_pack(pack, Some(&directory), limits.object_bytes, interrupt)?;
            if let Some(keep) = keep {
                fs::remove_file(keep)?;
            }
        }
        self.require_history(since, tip, limits.commits, interrupt)
    }

    fn history_since(
        &self,
        since: Option<ObjectId>,
        tip: ObjectId,
        max_commits: usize,
        interrupt: &AtomicBool,
    ) -> Result<Vec<ObjectId>, StoreError> {
        let mut commits = Vec::new();
        let mut current = Some(tip);
        while let Some(commit) = current.filter(|commit| Some(*commit) != since) {
            if commits.len() == max_commits {
                return Err(StoreError::TooManyCommits(max_commits));
            }
            check(interrupt)?;
            commits.push(commit);
            current = self.parent(commit)?;
        }
        if let Some(since) = since
            && current != Some(since)
        {
            return Err(StoreError::NotInHistory { commit: since, tip });
        }
        Ok(commits)
    }

    fn require_history(
        &self,
        since: Option<ObjectId>,
        tip: ObjectId,
        max_commits: usize,
        interrupt: &AtomicBool,
    ) -> Result<(), StoreError> {
        let commits = self.history_since(since, tip, max_commits, interrupt)?;
        let mut known = HashSet::new();
        if let Some(since) = since {
            self.mark_known(self.commit_tree(since)?, &mut known, interrupt)?;
        }
        for commit in commits {
            let mut pending = vec![self.commit_tree(commit)?];
            while let Some(tree) = pending.pop() {
                if !known.insert(tree) {
                    continue;
                }
                check(interrupt)?;
                self.require_kind(tree, Kind::Tree)?;
                for entry in self.repo.find_tree(tree)?.iter() {
                    let entry = entry.map_err(gix::Error::from)?;
                    let mode = entry.mode();
                    let id = entry.object_id();
                    if mode.is_tree() {
                        pending.push(id);
                    } else if !mode.is_commit() && known.insert(id) {
                        self.require_kind(id, Kind::Blob)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Checks `pack` as [`Store::take_history_pack`] does, writing it and its index into
/// `directory`, or only checking it with none; returns the `.keep` file written beside it,
/// if any, which the caller removes.
pub(crate) fn index_pack(
    pack: &[u8],
    directory: Option<&Path>,
    max_object_bytes: u64,
    interrupt: &AtomicBool,
) -> Result<Option<PathBuf>, StoreError> {
    let mut reader = pack;
    let outcome = Bundle::write_to_directory(
        &mut reader,
        directory,
        &mut gix::progress::Discard,
        interrupt,
        None::<gix::OdbHandle>,
        gix::hash::Kind::Sha1,
        Options {
            thread_limit: Some(1),
            iteration_mode: Mode::Verify,
            alloc_limit_bytes: Some(usize::try_from(max_object_bytes).unwrap_or(usize::MAX)),
            ..Options::default()
        },
    )
    .map_err(gix::Error::from)?;
    Ok(outcome.keep_path)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use gix::objs::tree::EntryKind;
    use mahi_core::{
        AgentSlot,
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use tempfile::TempDir;

    use super::*;

    const LIMITS: HistoryLimits = HistoryLimits {
        commits: 16,
        bytes: 1 << 20,
    };
    const TAKE: TakeLimits = TakeLimits {
        commits: 16,
        object_bytes: 1 << 20,
    };

    fn store() -> (TempDir, Store) {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn snapshots() -> ThreadRef {
        let slot: AgentSlot = "alice.claude".parse().unwrap();
        ThreadRef::new(ThreadId::random().unwrap(), RefKind::Snapshots(slot))
    }

    fn snapshot(store: &Store, at: &ThreadRef, parent: Option<ObjectId>, text: &str) -> ObjectId {
        let shared = store.write_blob(b"shared by every snapshot").unwrap();
        let own = store.write_blob(text.as_bytes()).unwrap();
        let tree = store
            .write_tree(&[
                ("own", EntryKind::Blob, own),
                ("shared", EntryKind::Blob, shared),
            ])
            .unwrap();
        store.append(at, parent, tree, "snapshot").unwrap()
    }

    fn packed(store: &Store, since: Option<ObjectId>, tip: ObjectId) -> (usize, Vec<u8>) {
        let mut pack = Vec::new();
        let commits = store
            .write_history_pack(since, tip, LIMITS, &mut pack, &AtomicBool::new(false))
            .unwrap();
        (commits, pack)
    }

    fn object_count(pack: &[u8]) -> u32 {
        u32::from_be_bytes(pack[8..12].try_into().unwrap())
    }

    fn keeps_a_pack(store: &Store) -> bool {
        fs::read_dir(store.common_dir().join("objects/pack"))
            .unwrap()
            .any(|entry| entry.unwrap().path().extension() == Some(OsStr::new("keep")))
    }

    #[test]
    fn a_history_packed_since_a_commit_brings_only_what_comes_after_it() {
        let (_alice_dir, alice) = store();
        let (_bob_dir, bob) = store();
        let at = snapshots();
        let first = snapshot(&alice, &at, None, "one");
        let second = snapshot(&alice, &at, Some(first), "two");
        let third = snapshot(&alice, &at, Some(second), "three");
        let never = AtomicBool::new(false);

        let (commits, pack) = packed(&alice, None, first);
        assert_eq!((commits, object_count(&pack)), (1, 4));
        bob.take_history_pack(&pack, None, first, TAKE, &never)
            .unwrap();
        assert!(bob.has_commit(first));
        assert!(!bob.has_commit(second));

        let (commits, pack) = packed(&alice, Some(first), third);
        assert_eq!((commits, object_count(&pack)), (2, 6));
        bob.take_history_pack(&pack, Some(first), third, TAKE, &never)
            .unwrap();
        assert_eq!(bob.parent(third).unwrap(), Some(second));
        let own = bob.read_entry(third, "own", 1 << 10).unwrap();
        assert_eq!(own.as_deref(), Some(b"three".as_slice()));
        assert!(!keeps_a_pack(&bob));

        assert_eq!(packed(&alice, Some(third), third), (0, Vec::new()));
        bob.take_history_pack(&[], Some(third), third, TAKE, &never)
            .unwrap();
    }

    #[test]
    fn a_history_too_long_too_large_or_not_after_the_commit_is_not_packed() {
        let (_dir, store) = store();
        let at = snapshots();
        let first = snapshot(&store, &at, None, "one");
        let second = snapshot(&store, &at, Some(first), "two");
        let elsewhere = snapshot(&store, &snapshots(), None, "elsewhere");
        let never = AtomicBool::new(false);
        let mut out = Vec::new();
        let few = HistoryLimits {
            commits: 1,
            ..LIMITS
        };
        let small = HistoryLimits {
            bytes: 64,
            ..LIMITS
        };
        assert!(matches!(
            store.write_history_pack(None, second, few, &mut out, &never),
            Err(StoreError::TooManyCommits(1))
        ));
        assert!(matches!(
            store.write_history_pack(None, second, small, &mut out, &never),
            Err(StoreError::TooLarge { limit: 64, .. })
        ));
        assert!(matches!(
            store.write_history_pack(Some(elsewhere), second, LIMITS, &mut out, &never),
            Err(StoreError::NotInHistory { commit, tip }) if commit == elsewhere && tip == second
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn a_pack_missing_part_of_the_history_or_an_object_over_the_limit_is_refused() {
        let (_alice_dir, alice) = store();
        let (_bob_dir, bob) = store();
        let at = snapshots();
        let commit = snapshot(&alice, &at, None, &"x".repeat(4096));
        let (_, pack) = packed(&alice, None, commit);
        let never = AtomicBool::new(false);
        let tight = TakeLimits {
            object_bytes: 1024,
            ..TAKE
        };
        assert!(matches!(
            bob.take_history_pack(&pack, None, commit, tight, &never),
            Err(StoreError::Git(_))
        ));
        assert!(!bob.has_commit(commit));
        let mut broken = pack.clone();
        let middle = broken.len() / 2;
        broken[middle] ^= 0xff;
        assert!(matches!(
            bob.take_history_pack(&broken, None, commit, TAKE, &never),
            Err(StoreError::Git(_))
        ));
        assert!(matches!(
            bob.take_history_pack(b"not a pack", None, commit, TAKE, &never),
            Err(StoreError::Git(_))
        ));
        assert!(!bob.has_commit(commit));
        assert!(matches!(
            bob.take_history_pack(&[], None, commit, TAKE, &never),
            Err(StoreError::WrongObject { id, .. }) if id == commit
        ));

        let mut commit_alone = Vec::new();
        alice
            .write_pack(&[commit], &mut commit_alone, &never)
            .unwrap();
        let tree = alice.commit_tree(commit).unwrap();
        assert!(matches!(
            bob.take_history_pack(&commit_alone, None, commit, TAKE, &never),
            Err(StoreError::WrongObject { id, .. }) if id == tree
        ));
        assert!(!keeps_a_pack(&bob));
    }
}
