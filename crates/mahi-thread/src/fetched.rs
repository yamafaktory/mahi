use mahi_core::{
    ParticipantName,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_store::{
    MAX_HISTORY_WALK,
    ObjectId,
    Store,
    StoreError,
};
use thiserror::Error;

use crate::{
    MAX_META_BYTES,
    ParticipantKey,
    PinError,
    ThreadError,
    VerifiedMeta,
    commits::signed_by,
    pins::Pins,
    thread::META_ENTRY,
};

/// Why a fetched agent ref was refused.
#[derive(Debug, Error)]
pub enum Refusal {
    /// Its history could not be read or checked, or the ref could not be moved.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A commit it adds is not signed by the key `meta` lists for the ref's participant.
    #[error("commit {0} is not signed by the participant's key")]
    NotSigned(ObjectId),
}

/// What accepting a thread's fetched refs changed.
#[derive(Debug, Default)]
pub struct Accepted {
    /// The thread refs that were created or moved to the fetched commit: forward for agent
    /// refs, and to the owner's history for `meta`.
    pub updated: Vec<ThreadRef>,
    /// The thread refs whose local and fetched histories went apart; the local one is kept.
    pub diverged: Vec<ThreadRef>,
    /// The fetched refs left alone: the local participant's own, those of a participant the
    /// signed `meta` does not list, and `state`, whose writers are not settled yet.
    pub skipped: Vec<ThreadRef>,
    /// The fetched refs that could not be checked or moved, or that add a commit their
    /// participant did not sign, with why.
    pub refused: Vec<(ThreadRef, Refusal)>,
}

enum Advance {
    Moved,
    Kept,
    Diverged,
}

/// Accepts the refs [`Store::fetch_thread`] fetched for `thread`, after checking them, on
/// behalf of the participant `local`.
///
/// The fetched `meta` comes first. Its document must be the thread's and signed by
/// `trusted_owner`; a newer generation than the local one, or the same document, then becomes
/// the local `meta`, under the pin's lock, which refuses another document of a generation
/// already seen. An older fetched document leaves the local one in place. Then each agent ref
/// of a participant the resulting `meta` lists, other than `local`, only moves forward: behind
/// moves to the fetched commit, ahead stays, and a history that went apart stays and is
/// reported. Moving forward also needs every commit the ref gains to be signed by the key that
/// `meta` lists for the participant, so that no one else can write in their name. A ref that
/// fails its checks is refused on its own, and the others go on. All the history walks
/// together go through at most [`MAX_HISTORY_WALK`] commits; once that is spent, the remaining
/// refs that need a walk are refused.
///
/// # Errors
///
/// Returns [`ThreadError::NotFound`] if nothing was fetched for `meta`,
/// [`ThreadError::FetchedMetaRefused`] if the fetched document is not the thread's or not
/// signed by `trusted_owner`, [`ThreadError::Pin`] if the pin refuses it, or
/// [`ThreadError::Store`] if the fetched refs or the local `meta` cannot be read, or `meta`
/// cannot be moved. In all these cases no ref moves, except that `meta` may have moved when
/// only writing the pin failed; the next [`crate::load_meta`] then pins it.
pub fn accept_fetched(
    store: &Store,
    thread: ThreadId,
    trusted_owner: &ParticipantKey,
    local: &ParticipantName,
) -> Result<Accepted, ThreadError> {
    let meta_ref = ThreadRef::new(thread, RefKind::Meta);
    let fetched = store.fetched_refs(thread)?;
    let meta = fetched
        .iter()
        .find(|(thread_ref, _)| *thread_ref == meta_ref)
        .map(|(_, commit)| *commit)
        .ok_or(ThreadError::NotFound(thread))?;
    let mut accepted = Accepted::default();
    let mut budget = MAX_HISTORY_WALK;
    let (moved, current) = accept_meta(store, thread, meta, trusted_owner)?;
    if moved {
        accepted.updated.push(meta_ref.clone());
    }
    for (thread_ref, commit) in fetched {
        let slot = match thread_ref.kind() {
            RefKind::Meta => continue,
            RefKind::State => None,
            RefKind::Snapshots(slot) | RefKind::Transcript(slot) | RefKind::Session(slot) => {
                Some(slot)
            }
        };
        let writer = slot
            .filter(|slot| slot.participant() != local)
            .and_then(|slot| {
                current
                    .participants()
                    .find(|listed| listed.name() == slot.participant())
            });
        let Some(writer) = writer else {
            accepted.skipped.push(thread_ref);
            continue;
        };
        match advance(store, &thread_ref, commit, writer.key(), &mut budget) {
            Ok(Advance::Moved) => accepted.updated.push(thread_ref),
            Ok(Advance::Diverged) => accepted.diverged.push(thread_ref),
            Ok(Advance::Kept) => {}
            Err(error) => accepted.refused.push((thread_ref, error)),
        }
    }
    Ok(accepted)
}

fn accept_meta(
    store: &Store,
    thread: ThreadId,
    commit: ObjectId,
    trusted_owner: &ParticipantKey,
) -> Result<(bool, VerifiedMeta), ThreadError> {
    let fetched =
        read_document(store, thread, commit, trusted_owner).map_err(|error| match error {
            ThreadError::Meta(source) => ThreadError::FetchedMetaRefused {
                thread,
                source: Box::new(source),
            },
            other => other,
        })?;
    let meta_ref = ThreadRef::new(thread, RefKind::Meta);
    let local = store.head(&meta_ref)?;
    if local == Some(commit) {
        return Ok((false, fetched));
    }
    if let Some(local) = local {
        let current = read_document(store, thread, local, trusted_owner)?;
        if current.generation() > fetched.generation() {
            return Ok((false, current));
        }
        if current.generation() == fetched.generation()
            && current.body_hash() != fetched.body_hash()
        {
            return Err(PinError::Equivocation {
                generation: fetched.generation(),
            }
            .into());
        }
    }
    Pins::new(store).accept_then(&fetched, || {
        store
            .set_head(&meta_ref, local, commit)
            .map_err(ThreadError::from)
    })?;
    Ok((true, fetched))
}

fn read_document(
    store: &Store,
    thread: ThreadId,
    commit: ObjectId,
    trusted_owner: &ParticipantKey,
) -> Result<VerifiedMeta, ThreadError> {
    let encoded = store
        .read_entry(commit, META_ENTRY, MAX_META_BYTES as u64)?
        .ok_or(ThreadError::MissingMetaEntry(thread))?;
    Ok(VerifiedMeta::decode(&encoded, thread, trusted_owner)?)
}

fn advance(
    store: &Store,
    thread_ref: &ThreadRef,
    commit: ObjectId,
    writer: &ParticipantKey,
    budget: &mut usize,
) -> Result<Advance, Refusal> {
    let local = store.head(thread_ref)?;
    let forward = match local {
        None => true,
        Some(local) if local == commit => return Ok(Advance::Kept),
        Some(local) => store.descends_within(commit, local, budget)?,
    };
    if forward {
        require_signed(store, commit, local, writer, budget)?;
        store.set_head(thread_ref, local, commit)?;
        return Ok(Advance::Moved);
    }
    match local {
        Some(local) if store.descends_within(local, commit, budget)? => Ok(Advance::Kept),
        _ => Ok(Advance::Diverged),
    }
}

fn require_signed(
    store: &Store,
    tip: ObjectId,
    until: Option<ObjectId>,
    writer: &ParticipantKey,
    budget: &mut usize,
) -> Result<(), Refusal> {
    let mut next = Some(tip);
    while let Some(commit) = next.filter(|commit| Some(*commit) != until) {
        *budget = budget
            .checked_sub(1)
            .ok_or(StoreError::HistoryTooLong(tip))?;
        if !signed_by(store, commit, writer)? {
            return Err(Refusal::NotSigned(commit));
        }
        next = store.parent(commit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use gix::refs::transaction::PreviousValue;
    use mahi_core::{
        AgentName,
        AgentSlot,
    };
    use mahi_crypto::ThreadKey;
    use mahi_store::{
        EntryKind,
        FETCHED_PREFIX,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;
    use crate::{
        GitSigner,
        PinError,
        create_thread,
        load_meta,
        record_meta,
        thread::tests::{
            Setup,
            draft,
            setup,
        },
    };

    fn set_ref(setup: &Setup, name: &str, id: ObjectId) {
        gix::open(setup.store.common_dir())
            .unwrap()
            .reference(name, id, PreviousValue::Any, "test")
            .unwrap();
    }

    fn stage(setup: &Setup, thread_ref: &ThreadRef, id: ObjectId) {
        let name = thread_ref
            .to_string()
            .replacen("refs/threads/", FETCHED_PREFIX, 1);
        set_ref(setup, &name, id);
    }

    fn commit(setup: &Setup, parent: Option<ObjectId>, entry: &str, content: &[u8]) -> ObjectId {
        commit_by(setup, &setup.owner, parent, entry, content)
    }

    fn commit_by(
        setup: &Setup,
        signer: &PrivateKey,
        parent: Option<ObjectId>,
        entry: &str,
        content: &[u8],
    ) -> ObjectId {
        let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        if let Some(parent) = parent {
            set_ref(setup, &scratch.to_string(), parent);
        }
        let blob = setup.store.write_blob(content).unwrap();
        let tree = setup
            .store
            .write_tree(&[(entry, EntryKind::Blob, blob)])
            .unwrap();
        setup
            .store
            .append_signed(&scratch, parent, tree, "m", &GitSigner(signer.clone()))
            .unwrap()
    }

    fn unsigned(setup: &Setup, parent: Option<ObjectId>, content: &[u8]) -> ObjectId {
        let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        if let Some(parent) = parent {
            set_ref(setup, &scratch.to_string(), parent);
        }
        let blob = setup.store.write_blob(content).unwrap();
        let tree = setup
            .store
            .write_tree(&[("f", EntryKind::Blob, blob)])
            .unwrap();
        setup.store.append(&scratch, parent, tree, "m").unwrap()
    }

    fn snapshots(setup: &Setup, participant: &str, agent: &str) -> ThreadRef {
        let slot = AgentSlot::new(
            ParticipantName::new(participant).unwrap(),
            AgentName::new(agent).unwrap(),
        );
        ThreadRef::new(setup.thread, RefKind::Snapshots(slot))
    }

    fn created(setup: &Setup) -> (ThreadKey, ObjectId) {
        let key = ThreadKey::generate();
        let first = create_thread(&setup.store, &draft(setup, 0, "t"), &key, &setup.owner).unwrap();
        (key, first)
    }

    fn load_pinned(setup: &Setup, encoded: &[u8]) -> VerifiedMeta {
        VerifiedMeta::decode(encoded, setup.thread, &setup.owner_key).unwrap()
    }

    fn accept(setup: &Setup) -> Result<Accepted, ThreadError> {
        accept_fetched(
            &setup.store,
            setup.thread,
            &setup.owner_key,
            &ParticipantName::new("bob").unwrap(),
        )
    }

    #[test]
    fn a_newer_meta_and_listed_participants_refs_move_forward_only() {
        let setup = setup();
        let (key, first) = created(&setup);
        let next = draft(&setup, 1, "t").sign(&key, &setup.owner).unwrap();
        let second = commit(&setup, Some(first), META_ENTRY, &next);
        let meta = ThreadRef::new(setup.thread, RefKind::Meta);
        stage(&setup, &meta, second);
        let (behind, new, ahead, apart) = (
            snapshots(&setup, "alice", "behind"),
            snapshots(&setup, "alice", "new"),
            snapshots(&setup, "alice", "ahead"),
            snapshots(&setup, "alice", "apart"),
        );
        let old = commit(&setup, None, "f", b"old");
        let newer = commit(&setup, Some(old), "f", b"newer");
        let other = commit(&setup, None, "f", b"other");
        set_ref(&setup, &behind.to_string(), old);
        stage(&setup, &behind, newer);
        stage(&setup, &new, old);
        set_ref(&setup, &ahead.to_string(), newer);
        stage(&setup, &ahead, old);
        set_ref(&setup, &apart.to_string(), old);
        stage(&setup, &apart, other);

        let accepted = accept(&setup).unwrap();

        assert_eq!(
            accepted.updated,
            [meta.clone(), behind.clone(), new.clone()]
        );
        assert_eq!(accepted.diverged, std::slice::from_ref(&apart));
        assert!(accepted.skipped.is_empty() && accepted.refused.is_empty());
        let head = |thread_ref| setup.store.head(thread_ref).unwrap();
        assert_eq!(head(&meta), Some(second));
        assert_eq!(head(&behind), Some(newer));
        assert_eq!(head(&new), Some(old));
        assert_eq!(head(&ahead), Some(newer));
        assert_eq!(head(&apart), Some(old));
        let loaded = load_meta(&setup.store, setup.thread, &setup.owner_key, 1).unwrap();
        assert_eq!(loaded.generation(), 1);
        let again = accept(&setup).unwrap();
        assert!(again.updated.is_empty());
        assert_eq!(again.diverged, [apart]);
    }

    #[test]
    fn the_local_participants_refs_unlisted_writers_and_state_are_left_alone() {
        let setup = setup();
        let (_key, first) = created(&setup);
        let meta = ThreadRef::new(setup.thread, RefKind::Meta);
        stage(&setup, &meta, first);
        let own = snapshots(&setup, "bob", "claude");
        let stranger = snapshots(&setup, "mallory", "claude");
        let state = ThreadRef::new(setup.thread, RefKind::State);
        let work = commit(&setup, None, "f", b"planted");
        for thread_ref in [&own, &stranger, &state] {
            stage(&setup, thread_ref, work);
        }
        let blob = setup.store.write_blob(b"not a commit").unwrap();
        let tree = setup
            .store
            .write_tree(&[("f", EntryKind::Blob, blob)])
            .unwrap();
        let broken = snapshots(&setup, "alice", "broken");
        stage(&setup, &broken, tree);
        let merge = snapshots(&setup, "alice", "merge");
        let repo = gix::open(setup.store.common_dir()).unwrap();
        let root = commit(&setup, None, "f", b"root");
        let side = commit(&setup, None, "f", b"side");
        let signature = gix::actor::Signature {
            name: "test".into(),
            email: "test@example.org".into(),
            time: gix::date::Time::default(),
        };
        let merged = repo
            .write_object(&gix::objs::Commit {
                tree: setup.store.commit_tree(root).unwrap(),
                parents: [root, side].into_iter().collect(),
                author: signature.clone(),
                committer: signature,
                encoding: None,
                message: "merge".into(),
                extra_headers: Vec::new(),
            })
            .unwrap()
            .detach();
        let child = commit(&setup, Some(merged), "f", b"child");
        set_ref(&setup, &merge.to_string(), root);
        stage(&setup, &merge, child);
        let fine = snapshots(&setup, "alice", "fine");
        stage(&setup, &fine, work);

        let accepted = accept(&setup).unwrap();

        assert_eq!(accepted.updated, std::slice::from_ref(&fine));
        assert_eq!(
            accepted.skipped,
            [state.clone(), own.clone(), stranger.clone()]
        );
        assert!(matches!(
            accepted.refused.as_slice(),
            [
                (first, Refusal::Store(StoreError::WrongObject { .. })),
                (second, Refusal::Store(StoreError::NotLinear(_))),
            ] if *first == broken && *second == merge
        ));
        for thread_ref in [&own, &stranger, &state, &broken] {
            assert_eq!(setup.store.head(thread_ref).unwrap(), None);
        }
        assert_eq!(setup.store.head(&merge).unwrap(), Some(root));
    }

    #[test]
    fn only_commits_the_participant_signed_move_their_refs() {
        let setup = setup();
        let (_key, first) = created(&setup);
        stage(&setup, &ThreadRef::new(setup.thread, RefKind::Meta), first);
        let stranger = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let (plain, forged, hidden, old_plain, middle) = (
            snapshots(&setup, "alice", "plain"),
            snapshots(&setup, "alice", "forged"),
            snapshots(&setup, "alice", "hidden"),
            snapshots(&setup, "alice", "old"),
            snapshots(&setup, "alice", "middle"),
        );
        let unsigned_root = unsigned(&setup, None, b"unsigned");
        stage(&setup, &plain, unsigned_root);
        stage(
            &setup,
            &forged,
            commit_by(&setup, &stranger, None, "f", b"forged"),
        );
        let signed_over_unsigned = commit(&setup, Some(unsigned_root), "f", b"on top");
        stage(&setup, &hidden, signed_over_unsigned);
        set_ref(&setup, &old_plain.to_string(), unsigned_root);
        stage(&setup, &old_plain, signed_over_unsigned);
        let base = commit(&setup, None, "f", b"base");
        let slipped_in = unsigned(&setup, Some(base), b"slipped in");
        let signed_tip = commit(&setup, Some(slipped_in), "f", b"tip");
        set_ref(&setup, &middle.to_string(), base);
        stage(&setup, &middle, signed_tip);

        let accepted = accept(&setup).unwrap();

        assert_eq!(accepted.updated, std::slice::from_ref(&old_plain));
        let refused: Vec<_> = accepted
            .refused
            .iter()
            .map(|(thread_ref, refusal)| match refusal {
                Refusal::NotSigned(commit) => (thread_ref.clone(), *commit),
                Refusal::Store(error) => panic!("{thread_ref}: {error}"),
            })
            .collect();
        assert_eq!(refused.len(), 4);
        assert!(refused.contains(&(middle.clone(), slipped_in)));
        assert_eq!(setup.store.head(&middle).unwrap(), Some(base));
        assert!(refused.contains(&(plain.clone(), unsigned_root)));
        assert!(refused.contains(&(hidden.clone(), unsigned_root)));
        assert!(refused.iter().any(|(thread_ref, _)| *thread_ref == forged));
        for thread_ref in [&plain, &forged, &hidden] {
            assert_eq!(setup.store.head(thread_ref).unwrap(), None);
        }
        assert_eq!(
            setup.store.head(&old_plain).unwrap(),
            Some(signed_over_unsigned)
        );
    }

    #[test]
    fn a_joiners_recorded_meta_gives_way_to_the_owners_history() {
        let owner = setup();
        let (key, first) = created(&owner);
        let next = draft(&owner, 1, "t").sign(&key, &owner.owner).unwrap();
        let joiner = Setup {
            thread: owner.thread,
            owner: owner.owner.clone(),
            owner_key: owner.owner_key.clone(),
            ..setup()
        };
        let meta = ThreadRef::new(joiner.thread, RefKind::Meta);
        record_meta(&joiner.store, joiner.thread, &next, &joiner.owner_key).unwrap();
        let recorded = joiner.store.head(&meta).unwrap();
        let first_document = owner
            .store
            .read_entry(first, META_ENTRY, MAX_META_BYTES as u64)
            .unwrap()
            .unwrap();
        let owners_first = commit(&joiner, None, META_ENTRY, &first_document);
        let owners_second = commit(&joiner, Some(owners_first), META_ENTRY, &next);
        stage(&joiner, &meta, owners_second);

        let accepted = accept(&joiner).unwrap();

        assert_ne!(recorded, Some(owners_second));
        assert_eq!(accepted.updated, std::slice::from_ref(&meta));
        assert_eq!(joiner.store.head(&meta).unwrap(), Some(owners_second));
    }

    #[test]
    fn a_forged_older_or_equivocating_meta_moves_nothing() {
        let setup = setup();
        let (key, first) = created(&setup);
        let meta = ThreadRef::new(setup.thread, RefKind::Meta);
        let agent = snapshots(&setup, "alice", "claude");
        stage(&setup, &agent, commit(&setup, None, "f", b"work"));
        let impostor = Setup {
            thread: setup.thread,
            ..crate::thread::tests::setup()
        };
        let forged = draft(&impostor, 1, "taken")
            .sign(&key, &impostor.owner)
            .unwrap();
        stage(
            &setup,
            &meta,
            commit(&setup, Some(first), META_ENTRY, &forged),
        );
        assert!(matches!(
            accept(&setup),
            Err(ThreadError::FetchedMetaRefused { thread, .. }) if thread == setup.thread
        ));
        let replaced = draft(&setup, 0, "other title")
            .sign(&key, &setup.owner)
            .unwrap();
        stage(&setup, &meta, commit(&setup, None, META_ENTRY, &replaced));
        assert!(matches!(
            accept(&setup),
            Err(ThreadError::Pin(PinError::Equivocation { generation: 0 }))
        ));
        assert_eq!(
            Pins::new(&setup.store)
                .get(setup.thread)
                .unwrap()
                .map(|(generation, _)| generation),
            Some(0)
        );
        assert_eq!(setup.store.head(&meta).unwrap(), Some(first));
        assert_eq!(setup.store.head(&agent).unwrap(), None);

        let next = draft(&setup, 1, "t").sign(&key, &setup.owner).unwrap();
        let second = commit(&setup, Some(first), META_ENTRY, &next);
        set_ref(&setup, &meta.to_string(), second);
        stage(&setup, &meta, first);
        let older = accept(&setup).unwrap();
        assert!(!older.updated.contains(&meta));
        assert_eq!(older.updated, [agent]);
        assert_eq!(setup.store.head(&meta).unwrap(), Some(second));

        let unpinned = draft(&setup, 1, "unpinned")
            .sign(&key, &setup.owner)
            .unwrap();
        stage(&setup, &meta, commit(&setup, None, META_ENTRY, &unpinned));
        assert!(matches!(
            accept(&setup),
            Err(ThreadError::Pin(PinError::Equivocation { generation: 1 }))
        ));
        let gone = ThreadRef::new(setup.thread, RefKind::Meta);
        gix::open(setup.store.common_dir())
            .unwrap()
            .find_reference(gone.to_string().as_str())
            .unwrap()
            .delete()
            .unwrap();
        Pins::new(&setup.store)
            .accept(&load_pinned(&setup, &next))
            .unwrap();
        stage(&setup, &meta, first);
        assert!(matches!(
            accept(&setup),
            Err(ThreadError::Pin(PinError::Rollback {
                pinned: 1,
                found: 0
            }))
        ));
        assert_eq!(setup.store.head(&gone).unwrap(), None);

        let unfetched = ThreadId::random().unwrap();
        assert!(matches!(
            accept_fetched(
                &setup.store,
                unfetched,
                &setup.owner_key,
                &ParticipantName::new("bob").unwrap()
            ),
            Err(ThreadError::NotFound(thread)) if thread == unfetched
        ));
    }
}
