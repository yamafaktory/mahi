use std::sync::atomic::AtomicBool;

use gix::{
    ObjectId,
    bstr::ByteSlice,
    object::Kind,
    protocol::transport::client::blocking_io::Transport,
    refs::{
        FullName,
        Target,
        transaction::{
            Change,
            LogChange,
            PreviousValue,
            RefEdit,
            RefLog,
        },
    },
    remote::{
        Direction,
        fetch::Tags,
        ref_map,
    },
};
use mahi_core::{
    THREADS_PREFIX,
    ThreadId,
    ThreadRef,
};

use crate::store::{
    Store,
    StoreError,
};

/// The prefix under which fetched thread refs wait until they are checked, as
/// `refs/mahi/fetched/<thread-id>/…` mirroring `refs/threads/<thread-id>/…` on the remote.
pub const FETCHED_PREFIX: &str = "refs/mahi/fetched/";
/// The most refs a thread may have fetched at once.
pub const MAX_FETCHED_REFS: usize = 4096;
/// The most commits walked to tell whether one commit descends from another, by
/// [`Store::descends_from`] or through one budget given to [`Store::descends_within`].
pub const MAX_HISTORY_WALK: usize = 1 << 20;

impl Store {
    /// Fetches `thread`'s refs from the remote `transport` reaches into
    /// `refs/mahi/fetched/<thread-id>/`, first removing what an earlier fetch left there, so the
    /// fetched refs mirror the remote's; a remote without the thread leaves none. Thread refs
    /// themselves are not touched.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Git`] if the fetch fails or is interrupted.
    pub fn fetch_thread<T: Transport>(
        &self,
        transport: T,
        thread: ThreadId,
        interrupt: &AtomicBool,
    ) -> Result<(), StoreError> {
        self.clear_fetched(thread)?;
        let url = transport.to_url().into_owned();
        let spec = format!("+{THREADS_PREFIX}{thread}/*:{FETCHED_PREFIX}{thread}/*");
        let remote = self
            .repo
            .remote_at(url.as_bstr())
            .map_err(gix::Error::from_error)?
            .with_fetch_tags(Tags::None)
            .with_refspecs([spec.as_str()], Direction::Fetch)
            .map_err(gix::Error::from_error)?;
        let prepared = remote
            .to_connection_with_transport(transport)
            .prepare_fetch(gix::progress::Discard, ref_map::Options::default())
            .map_err(gix::Error::from_error)?;
        if prepared.ref_map().mappings.is_empty() {
            return Ok(());
        }
        prepared
            .receive(gix::progress::Discard, interrupt)
            .map_err(gix::Error::from_error)?;
        Ok(())
    }

    /// Lists `thread`'s fetched refs, in name order, as the thread refs they mirror, with the
    /// object each points to. Names that do not follow the thread layout, and symbolic refs,
    /// are left out.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TooManyRefs`] if more than [`MAX_FETCHED_REFS`] were fetched, or
    /// [`StoreError::Git`] if the refs cannot be read.
    pub fn fetched_refs(&self, thread: ThreadId) -> Result<Vec<(ThreadRef, ObjectId)>, StoreError> {
        let fetched = self.fetched(thread)?;
        if fetched.len() > MAX_FETCHED_REFS {
            return Err(StoreError::TooManyRefs(fetched.len()));
        }
        let mut refs = Vec::new();
        for (name, target) in fetched {
            let Some(id) = target.try_id().map(ToOwned::to_owned) else {
                continue;
            };
            let Some(rest) = name.strip_prefix(FETCHED_PREFIX) else {
                continue;
            };
            let Ok(thread_ref) = format!("{THREADS_PREFIX}{rest}").parse::<ThreadRef>() else {
                continue;
            };
            if thread_ref.thread() == thread {
                refs.push((thread_ref, id));
            }
        }
        refs.sort();
        Ok(refs)
    }

    /// Returns whether `commit` is `ancestor` or has it among its parents, following mahi's
    /// linear histories through at most [`MAX_HISTORY_WALK`] commits.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotLinear`] if a commit on the way has several parents,
    /// [`StoreError::HistoryTooLong`] if the walk reaches its limit, or another [`StoreError`]
    /// if a commit cannot be read.
    pub fn descends_from(&self, commit: ObjectId, ancestor: ObjectId) -> Result<bool, StoreError> {
        let mut budget = MAX_HISTORY_WALK;
        self.descends_within(commit, ancestor, &mut budget)
    }

    /// Returns whether `commit` descends from `ancestor` as [`Store::descends_from`] does,
    /// taking each commit walked from `budget`, so several walks can share one limit.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::HistoryTooLong`] if `budget` runs out, or the other errors of
    /// [`Store::descends_from`].
    pub fn descends_within(
        &self,
        commit: ObjectId,
        ancestor: ObjectId,
        budget: &mut usize,
    ) -> Result<bool, StoreError> {
        let mut current = commit;
        loop {
            if current == ancestor {
                return Ok(true);
            }
            *budget = budget
                .checked_sub(1)
                .ok_or(StoreError::HistoryTooLong(commit))?;
            match self.parent(current)? {
                Some(parent) => current = parent,
                None => return Ok(false),
            }
        }
    }

    /// Moves `thread_ref` from `expected`, or creates it when `expected` is `None`, to the
    /// commit `new`, which must descend from `expected`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFastForward`] if `new` does not descend from `expected`,
    /// [`StoreError::Conflict`] if the ref no longer points at `expected`,
    /// [`StoreError::WrongObject`] if `new` is not a commit, or [`StoreError::Git`] if writing
    /// fails.
    pub fn fast_forward(
        &self,
        thread_ref: &ThreadRef,
        expected: Option<ObjectId>,
        new: ObjectId,
    ) -> Result<(), StoreError> {
        self.require_kind(new, Kind::Commit)?;
        if let Some(old) = expected
            && !self.descends_from(new, old)?
        {
            return Err(StoreError::NotFastForward(thread_ref.to_string()));
        }
        self.set_head(thread_ref, expected, new)
    }

    /// Moves `thread_ref` from `expected`, or creates it when `expected` is `None`, to the
    /// commit `new`, whatever their histories.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] if the ref no longer points at `expected`,
    /// [`StoreError::WrongObject`] if `new` is not a commit, or [`StoreError::Git`] if writing
    /// fails.
    pub fn set_head(
        &self,
        thread_ref: &ThreadRef,
        expected: Option<ObjectId>,
        new: ObjectId,
    ) -> Result<(), StoreError> {
        self.require_kind(new, Kind::Commit)?;
        let previous = match expected {
            Some(old) => PreviousValue::MustExistAndMatch(Target::Object(old)),
            None => PreviousValue::MustNotExist,
        };
        let name = FullName::try_from(thread_ref.to_string()).map_err(gix::Error::from_error)?;
        let edited = self.repo.edit_references_as(
            Some(RefEdit::new(
                name,
                Change::Update {
                    log: LogChange {
                        mode: RefLog::AndReference,
                        force_create_reflog: false,
                        message: "".into(),
                    },
                    expected: previous,
                    new: Target::Object(new),
                },
            )),
            None,
        );
        if let Err(error) = edited {
            let found = self.head(thread_ref)?;
            if found != expected {
                return Err(StoreError::Conflict {
                    name: thread_ref.to_string(),
                    expected,
                    found,
                });
            }
            return Err(error.into());
        }
        Ok(())
    }

    fn fetched(&self, thread: ThreadId) -> Result<Vec<(String, Target)>, StoreError> {
        let prefix = format!("{FETCHED_PREFIX}{thread}/");
        let platform = self.repo.references().map_err(gix::Error::from_error)?;
        let mut refs = Vec::new();
        for reference in platform
            .prefixed(prefix.as_str())
            .map_err(gix::Error::from_error)?
        {
            let reference = reference.map_err(gix::Error::from_error)?;
            let Ok(name) = std::str::from_utf8(reference.name().as_bstr()) else {
                continue;
            };
            refs.push((name.to_owned(), reference.target().into_owned()));
        }
        Ok(refs)
    }

    fn clear_fetched(&self, thread: ThreadId) -> Result<(), StoreError> {
        let mut edits = Vec::new();
        for (name, target) in self.fetched(thread)? {
            edits.push(RefEdit::new(
                FullName::try_from(name).map_err(gix::Error::from_error)?,
                Change::Delete {
                    expected: PreviousValue::MustExistAndMatch(target),
                    log: RefLog::AndReference,
                },
            ));
        }
        if !edits.is_empty() {
            self.repo.edit_references_as(edits, None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gix::objs::tree::EntryKind;
    use mahi_core::RefKind;

    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        gix::init_bare(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn commit(store: &Store, thread_ref: &ThreadRef, parent: Option<ObjectId>) -> ObjectId {
        let blob = store.write_blob(thread_ref.to_string().as_bytes()).unwrap();
        let tree = store.write_tree(&[("x", EntryKind::Blob, blob)]).unwrap();
        store.append(thread_ref, parent, tree, "m").unwrap()
    }

    #[test]
    fn a_ref_only_moves_forward_and_only_from_where_the_caller_saw_it() {
        let (_dir, store) = store();
        let thread = ThreadId::random().unwrap();
        let meta = ThreadRef::new(thread, RefKind::Meta);
        let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let first = commit(&store, &scratch, None);
        let second = commit(&store, &scratch, Some(first));
        let unrelated = commit(
            &store,
            &ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta),
            None,
        );
        store.fast_forward(&meta, None, first).unwrap();
        assert!(matches!(
            store.fast_forward(&meta, None, second),
            Err(StoreError::Conflict { .. })
        ));
        assert!(matches!(
            store.fast_forward(&meta, Some(first), unrelated),
            Err(StoreError::NotFastForward(_))
        ));
        store.fast_forward(&meta, Some(first), second).unwrap();
        assert_eq!(store.head(&meta).unwrap(), Some(second));
        assert!(store.descends_from(second, first).unwrap());
        assert!(!store.descends_from(first, second).unwrap());
        assert!(matches!(
            store.fast_forward(&meta, Some(second), store.commit_tree(second).unwrap()),
            Err(StoreError::WrongObject { .. })
        ));
    }

    #[test]
    fn long_histories_and_too_many_fetched_refs_are_refused() {
        let (dir, store) = store();
        let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let first = commit(&store, &scratch, None);
        let second = commit(&store, &scratch, Some(first));
        let third = commit(&store, &scratch, Some(second));
        let mut budget = 3;
        assert!(store.descends_within(third, first, &mut budget).unwrap());
        assert_eq!(budget, 1);
        assert!(matches!(
            store.descends_within(third, first, &mut budget),
            Err(StoreError::HistoryTooLong(id)) if id == third
        ));
        assert!(store.descends_within(first, first, &mut 0).unwrap());
        let thread = ThreadId::random().unwrap();
        let repo = gix::open(dir.path()).unwrap();
        let edits = (0..=MAX_FETCHED_REFS).map(|n| {
            RefEdit::new(
                FullName::try_from(format!("{FETCHED_PREFIX}{thread}/r{n}")).unwrap(),
                Change::Update {
                    log: LogChange::default(),
                    expected: PreviousValue::Any,
                    new: Target::Object(first),
                },
            )
        });
        repo.edit_references(edits).unwrap();
        assert!(matches!(
            store.fetched_refs(thread),
            Err(StoreError::TooManyRefs(count)) if count == MAX_FETCHED_REFS + 1
        ));
    }

    #[test]
    fn fetched_refs_of_other_threads_or_outside_the_layout_are_left_out() {
        let (dir, store) = store();
        let thread = ThreadId::random().unwrap();
        let other = ThreadId::random().unwrap();
        let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let id = commit(&store, &scratch, None);
        let repo = gix::open(dir.path()).unwrap();
        for name in [
            format!("{FETCHED_PREFIX}{thread}/meta"),
            format!("{FETCHED_PREFIX}{thread}/agents/bob.claude/snapshots"),
            format!("{FETCHED_PREFIX}{thread}/unknown"),
            format!("{FETCHED_PREFIX}{other}/meta"),
        ] {
            repo.reference(name, id, PreviousValue::Any, "test")
                .unwrap();
        }
        let listed: Vec<String> = store
            .fetched_refs(thread)
            .unwrap()
            .into_iter()
            .map(|(thread_ref, found)| {
                assert_eq!(found, id);
                thread_ref.to_string()
            })
            .collect();
        assert_eq!(
            listed,
            [
                format!("{THREADS_PREFIX}{thread}/meta"),
                format!("{THREADS_PREFIX}{thread}/agents/bob.claude/snapshots"),
            ]
        );
        repo.reference(
            format!("{FETCHED_PREFIX}{thread}/extra"),
            id,
            PreviousValue::Any,
            "test",
        )
        .unwrap();
        let symbolic =
            gix::refs::FullName::try_from(format!("{FETCHED_PREFIX}{thread}/link")).unwrap();
        repo.edit_reference(RefEdit::new(
            symbolic,
            Change::Update {
                log: LogChange::default(),
                expected: PreviousValue::Any,
                new: Target::Symbolic(format!("{FETCHED_PREFIX}{other}/meta").try_into().unwrap()),
            },
        ))
        .unwrap();
        assert_eq!(store.fetched_refs(thread).unwrap().len(), 2);
        store.clear_fetched(thread).unwrap();
        assert!(store.fetched(thread).unwrap().is_empty());
        assert_eq!(store.fetched(other).unwrap().len(), 1);
        assert_eq!(store.fetched_refs(other).unwrap().len(), 1);
    }
}
