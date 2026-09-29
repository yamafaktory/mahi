use mahi_core::{
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_crypto::ThreadKey;
use mahi_store::{
    EntryKind,
    ObjectId,
    Store,
    StoreError,
};
use thiserror::Error;

use crate::{
    MAX_META_BYTES,
    MetaDraft,
    MetaError,
    Participant,
    ParticipantKey,
    PinError,
    SshSigner,
    VerifiedMeta,
    pins::Pins,
};

/// The name of the file holding the meta document in each `meta` commit's tree.
pub const META_ENTRY: &str = "meta";

const META_MESSAGE: &str = "meta";

/// Creating, discarding or loading a thread failed.
#[derive(Debug, Error)]
pub enum ThreadError {
    /// Reading or writing the repository failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The meta document is invalid or not signed by the trusted owner.
    #[error(transparent)]
    Meta(#[from] MetaError),
    /// The meta document was refused by the pin.
    #[error(transparent)]
    Pin(#[from] PinError),
    /// The thread has no `meta` ref.
    #[error("thread {0} does not exist")]
    NotFound(ThreadId),
    /// The thread's `meta` commit has no meta document, which mahi never writes.
    #[error("thread {0}'s meta commit has no meta document")]
    MissingMetaEntry(ThreadId),
    /// The thread was created, but its meta document could not be pinned.
    ///
    /// The thread exists and is valid: the next [`load_meta`] pins it.
    #[error("thread created at {commit}, but its meta document could not be pinned")]
    CreatedButNotPinned {
        /// The `meta` commit that was written.
        commit: ObjectId,
        /// Why pinning failed.
        #[source]
        source: PinError,
    },
    /// A new thread's meta document must be generation 0.
    #[error("a new thread's meta document must be generation 0")]
    NotFirstGeneration,
    /// A thread with this id already exists.
    #[error("thread {0} already exists")]
    AlreadyExists(ThreadId),
    /// The meta document has reached the last generation a `u64` can count.
    #[error("thread {0}'s meta document has no next generation")]
    NoNextGeneration(ThreadId),
}

/// Creates the thread `draft` describes: signs its meta document with `owner_key`, commits it
/// as the first commit of `refs/threads/<id>/meta`, and pins it.
///
/// Returns the `meta` commit.
///
/// # Errors
///
/// Returns [`ThreadError::NotFirstGeneration`] if `draft` is not generation 0,
/// [`ThreadError::AlreadyExists`] if the thread's `meta` ref exists, or another
/// [`ThreadError`] if signing, writing or pinning fails.
pub fn create_thread(
    store: &Store,
    draft: &MetaDraft,
    thread_key: &ThreadKey,
    owner_key: &dyn SshSigner,
) -> Result<ObjectId, ThreadError> {
    if draft.generation() != 0 {
        return Err(ThreadError::NotFirstGeneration);
    }
    let thread = draft.thread();
    let meta_ref = ThreadRef::new(thread, RefKind::Meta);
    if store.head(&meta_ref)?.is_some() {
        return Err(ThreadError::AlreadyExists(thread));
    }
    let owner = ParticipantKey::from_public_key(owner_key.public_key()).map_err(MetaError::from)?;
    let encoded = draft.sign(thread_key, owner_key)?;
    let verified = VerifiedMeta::decode(&encoded, thread, &owner)?;

    let blob = store.write_blob(&encoded)?;
    let tree = store.write_tree(&[(META_ENTRY, EntryKind::Blob, blob)])?;
    let commit = match store.append(&meta_ref, None, tree, META_MESSAGE) {
        Err(StoreError::Conflict { .. }) => return Err(ThreadError::AlreadyExists(thread)),
        other => other?,
    };
    Pins::new(store)
        .accept(&verified)
        .map_err(|source| ThreadError::CreatedButNotPinned { commit, source })?;
    Ok(commit)
}

/// Discards a thread [`create_thread`] just created and nobody has used: deletes its `meta`
/// ref and its pin.
///
/// `created` is the `meta` commit [`create_thread`] returned. Nothing is deleted if the ref
/// has moved since, or if the pin has moved past generation 0, so a thread that anyone has
/// built on is never discarded and a pinned newer generation is never forgotten.
///
/// # Errors
///
/// Returns [`ThreadError::Store`] with [`StoreError::Conflict`] if the `meta` ref does not
/// point at `created`, including when it no longer exists, [`ThreadError::Pin`] with
/// [`PinError::Rollback`] if the pin is past generation 0, another [`ThreadError::Pin`] if the
/// pin cannot be locked or removed (the ref may already be gone), or another
/// [`ThreadError::Store`] if deleting the ref fails.
pub fn discard_thread(
    store: &Store,
    thread: ThreadId,
    created: ObjectId,
) -> Result<(), ThreadError> {
    Pins::new(store).forget_new(thread, || {
        store
            .remove(&ThreadRef::new(thread, RefKind::Meta), created)
            .map_err(ThreadError::from)
    })
}

/// Loads `thread`'s current meta document, checks that `trusted_owner` signed it, and checks it
/// against the pin, advancing the pin if the document is newer.
///
/// `min_generation` is the lowest generation the caller accepts, such as the one an invite
/// ticket carries: it protects the first load, when there is no pin yet.
///
/// # Errors
///
/// Returns [`ThreadError::NotFound`] if the thread has no `meta` ref,
/// [`ThreadError::MissingMetaEntry`] if its commit holds no meta document,
/// [`ThreadError::Meta`] if the document is invalid or not signed by `trusted_owner`,
/// [`ThreadError::Pin`] if it is below `min_generation`, older than, or conflicting with the
/// pinned document, or [`ThreadError::Store`] if reading fails.
pub fn load_meta(
    store: &Store,
    thread: ThreadId,
    trusted_owner: &ParticipantKey,
    min_generation: u64,
) -> Result<VerifiedMeta, ThreadError> {
    load_meta_document(store, thread, trusted_owner, min_generation).map(|(verified, _)| verified)
}

/// Loads `thread`'s current meta document like [`load_meta`], and also returns it as encoded,
/// signed bytes, as a host serves it to participants.
///
/// # Errors
///
/// Returns the errors of [`load_meta`].
pub fn load_meta_document(
    store: &Store,
    thread: ThreadId,
    trusted_owner: &ParticipantKey,
    min_generation: u64,
) -> Result<(VerifiedMeta, Vec<u8>), ThreadError> {
    let (_, verified, encoded) = read_meta(store, thread, trusted_owner)?;
    if verified.generation() < min_generation {
        return Err(PinError::BelowMinimum {
            required: min_generation,
            found: verified.generation(),
        }
        .into());
    }
    Pins::new(store).accept(&verified)?;
    Ok((verified, encoded))
}

/// Records a meta document obtained from the thread's host in this repository: checks it
/// against `trusted_owner`, pins it, and makes it the thread's `meta` ref, creating the ref or
/// moving it forward to a newer generation. A joiner keeps it this way until thread refs are
/// fetched.
///
/// # Errors
///
/// Returns [`ThreadError::Meta`] if the document is invalid or not signed by `trusted_owner`,
/// [`ThreadError::Pin`] if it is older than, or conflicts with, the pinned document, or
/// [`ThreadError::Store`] if writing fails, including with [`StoreError::Conflict`] when the
/// ref moved meanwhile.
pub fn record_meta(
    store: &Store,
    thread: ThreadId,
    encoded: &[u8],
    trusted_owner: &ParticipantKey,
) -> Result<VerifiedMeta, ThreadError> {
    let verified = VerifiedMeta::decode(encoded, thread, trusted_owner)?;
    let meta_ref = ThreadRef::new(thread, RefKind::Meta);
    let head = store.head(&meta_ref)?;
    if let Some(commit) = head {
        let current = store
            .read_entry(commit, META_ENTRY, MAX_META_BYTES as u64)?
            .ok_or(ThreadError::MissingMetaEntry(thread))?;
        let current = VerifiedMeta::decode(&current, thread, trusted_owner)?;
        if current.body_hash() == verified.body_hash() {
            return Ok(verified);
        }
        if current.generation() >= verified.generation() {
            return Err(PinError::Rollback {
                pinned: current.generation(),
                found: verified.generation(),
            }
            .into());
        }
    }
    Pins::new(store).accept(&verified)?;
    let blob = store.write_blob(encoded)?;
    let tree = store.write_tree(&[(META_ENTRY, EntryKind::Blob, blob)])?;
    store.append(&meta_ref, head, tree, META_MESSAGE)?;
    Ok(verified)
}

/// Adds `participant` to `thread`, which `owner_key` owns: signs the next generation of its
/// meta document, with the thread key also wrapped to the new participant, commits it on top of
/// the current `meta` commit, and pins it.
///
/// Returns the new document.
///
/// # Errors
///
/// Returns [`ThreadError::Meta`] if the current document is not signed by `owner_key`,
/// `thread_key` is not the thread's key, or the participant shares a name or key with one
/// already there, [`ThreadError::Pin`] if the current document is older than the pinned one,
/// [`ThreadError::Store`] with [`StoreError::Conflict`] if the `meta` ref moved meanwhile, or
/// another [`ThreadError`] if reading, signing or writing fails.
pub fn add_participant(
    store: &Store,
    thread: ThreadId,
    thread_key: &ThreadKey,
    owner_key: &dyn SshSigner,
    participant: Participant,
) -> Result<VerifiedMeta, ThreadError> {
    let owner = ParticipantKey::from_public_key(owner_key.public_key()).map_err(MetaError::from)?;
    let (commit, current, _) = read_meta(store, thread, &owner)?;
    let pins = Pins::new(store);
    pins.accept(&current)?;
    if !current.is_thread_key(thread_key) {
        return Err(MetaError::KeyMismatch.into());
    }
    let generation = current
        .generation()
        .checked_add(1)
        .ok_or(ThreadError::NoNextGeneration(thread))?;
    let mut participants: Vec<Participant> = current.participants().cloned().collect();
    participants.push(participant);
    let draft = MetaDraft::new(
        thread,
        generation,
        current.base(),
        current.owner().clone(),
        participants,
        current.private(thread_key)?,
    )?;
    let encoded = draft.sign(thread_key, owner_key)?;
    let verified = VerifiedMeta::decode(&encoded, thread, &owner)?;
    let blob = store.write_blob(&encoded)?;
    let tree = store.write_tree(&[(META_ENTRY, EntryKind::Blob, blob)])?;
    store.append(
        &ThreadRef::new(thread, RefKind::Meta),
        Some(commit),
        tree,
        META_MESSAGE,
    )?;
    pins.accept(&verified)?;
    Ok(verified)
}

fn read_meta(
    store: &Store,
    thread: ThreadId,
    trusted_owner: &ParticipantKey,
) -> Result<(ObjectId, VerifiedMeta, Vec<u8>), ThreadError> {
    let meta_ref = ThreadRef::new(thread, RefKind::Meta);
    let commit = store
        .head(&meta_ref)?
        .ok_or(ThreadError::NotFound(thread))?;
    let encoded = store
        .read_entry(commit, META_ENTRY, MAX_META_BYTES as u64)?
        .ok_or(ThreadError::MissingMetaEntry(thread))?;
    let verified = VerifiedMeta::decode(&encoded, thread, trusted_owner)?;
    Ok((commit, verified, encoded))
}

#[cfg(test)]
mod tests {
    use mahi_core::ParticipantName;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        Participant,
        PrivateMeta,
    };

    struct Setup {
        _dir: TempDir,
        store: Store,
        owner: PrivateKey,
        owner_key: ParticipantKey,
        mahi: age::x25519::Identity,
        thread: ThreadId,
    }

    fn setup() -> Setup {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let owner = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let owner_key = ParticipantKey::from_public_key(owner.public_key()).unwrap();
        Setup {
            _dir: dir,
            store,
            owner,
            owner_key,
            mahi: age::x25519::Identity::generate(),
            thread: ThreadId::random().unwrap(),
        }
    }

    fn draft(setup: &Setup, generation: u64, title: &str) -> MetaDraft {
        let alice = ParticipantName::new("alice").unwrap();
        MetaDraft::new(
            setup.thread,
            generation,
            ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap(),
            alice.clone(),
            vec![
                Participant::new(
                    alice,
                    setup.owner_key.clone(),
                    setup.mahi.to_public(),
                    crate::node::tests::random_node(),
                )
                .unwrap(),
            ],
            PrivateMeta::new(title, "main").unwrap(),
        )
        .unwrap()
    }

    fn put_meta(setup: &Setup, encoded: &[u8]) {
        let meta_ref = ThreadRef::new(setup.thread, RefKind::Meta);
        let head = setup.store.head(&meta_ref).unwrap();
        let blob = setup.store.write_blob(encoded).unwrap();
        let tree = setup
            .store
            .write_tree(&[(META_ENTRY, EntryKind::Blob, blob)])
            .unwrap();
        setup.store.append(&meta_ref, head, tree, "meta").unwrap();
    }

    #[test]
    fn a_created_thread_loads_back() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &thread_key,
            &setup.owner,
        )
        .unwrap();

        let meta = load_meta(&setup.store, setup.thread, &setup.owner_key, 0).unwrap();
        assert_eq!(meta.generation(), 0);
        let (same, encoded) =
            load_meta_document(&setup.store, setup.thread, &setup.owner_key, 0).unwrap();
        assert_eq!(same.body_hash(), meta.body_hash());
        let decoded = VerifiedMeta::decode(&encoded, setup.thread, &setup.owner_key).unwrap();
        assert_eq!(decoded.body_hash(), meta.body_hash());
        let key = meta
            .thread_key(&ParticipantName::new("alice").unwrap(), &setup.mahi)
            .unwrap();
        assert_eq!(meta.private(&key).unwrap().title(), "t");
        assert_eq!(
            Pins::new(&setup.store).get(setup.thread).unwrap(),
            Some((0, meta.body_hash()))
        );
    }

    #[test]
    fn a_discarded_thread_leaves_no_ref_or_pin() {
        let setup = setup();
        let created = create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &ThreadKey::generate(),
            &setup.owner,
        )
        .unwrap();
        discard_thread(&setup.store, setup.thread, created).unwrap();
        assert!(matches!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0),
            Err(ThreadError::NotFound(_))
        ));
        assert_eq!(Pins::new(&setup.store).get(setup.thread).unwrap(), None);
    }

    #[test]
    fn a_thread_that_moved_on_is_not_discarded() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        let created = create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &thread_key,
            &setup.owner,
        )
        .unwrap();
        let encoded = draft(&setup, 1, "u")
            .sign(&thread_key, &setup.owner)
            .unwrap();
        put_meta(&setup, &encoded);
        let pinned = Pins::new(&setup.store).get(setup.thread).unwrap();
        assert!(matches!(
            discard_thread(&setup.store, setup.thread, created),
            Err(ThreadError::Store(StoreError::Conflict { .. }))
        ));
        assert_eq!(Pins::new(&setup.store).get(setup.thread).unwrap(), pinned);
        assert_eq!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0)
                .unwrap()
                .generation(),
            1
        );
    }

    #[test]
    fn a_thread_pinned_past_its_first_generation_is_not_discarded() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        let created = create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &thread_key,
            &setup.owner,
        )
        .unwrap();
        let meta_ref = ThreadRef::new(setup.thread, RefKind::Meta);
        let encoded = draft(&setup, 1, "u")
            .sign(&thread_key, &setup.owner)
            .unwrap();
        put_meta(&setup, &encoded);
        let newer = load_meta(&setup.store, setup.thread, &setup.owner_key, 0).unwrap();
        gix::open(setup.store.common_dir())
            .unwrap()
            .reference(
                meta_ref.to_string().as_str(),
                created,
                gix::refs::transaction::PreviousValue::Any,
                "rolled back",
            )
            .unwrap();
        assert!(matches!(
            discard_thread(&setup.store, setup.thread, created),
            Err(ThreadError::Pin(PinError::Rollback {
                pinned: 1,
                found: 0
            }))
        ));
        assert_eq!(setup.store.head(&meta_ref).unwrap(), Some(created));
        assert_eq!(
            Pins::new(&setup.store).get(setup.thread).unwrap(),
            Some((1, newer.body_hash()))
        );
    }

    #[test]
    fn an_unpinned_or_missing_thread_is_handled() {
        let setup = setup();
        let created = create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &ThreadKey::generate(),
            &setup.owner,
        )
        .unwrap();
        std::fs::remove_file(
            setup
                .store
                .common_dir()
                .join("mahi/pins")
                .join(setup.thread.to_string()),
        )
        .unwrap();
        discard_thread(&setup.store, setup.thread, created).unwrap();
        assert_eq!(Pins::new(&setup.store).get(setup.thread).unwrap(), None);
        assert!(matches!(
            discard_thread(&setup.store, setup.thread, created),
            Err(ThreadError::Store(StoreError::Conflict { found: None, .. }))
        ));
    }

    #[test]
    fn a_thread_cannot_be_created_twice() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &thread_key,
            &setup.owner,
        )
        .unwrap();
        assert!(matches!(
            create_thread(
                &setup.store,
                &draft(&setup, 0, "u"),
                &thread_key,
                &setup.owner
            ),
            Err(ThreadError::AlreadyExists(_))
        ));
    }

    #[test]
    fn creation_needs_generation_zero() {
        let setup = setup();
        assert!(matches!(
            create_thread(
                &setup.store,
                &draft(&setup, 1, "t"),
                &ThreadKey::generate(),
                &setup.owner
            ),
            Err(ThreadError::NotFirstGeneration)
        ));
    }

    #[test]
    fn a_missing_thread_is_not_found() {
        let setup = setup();
        assert!(matches!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0),
            Err(ThreadError::NotFound(_))
        ));
    }

    #[test]
    fn a_newer_generation_advances_and_a_rollback_is_refused() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &thread_key,
            &setup.owner,
        )
        .unwrap();
        let old = draft(&setup, 0, "t")
            .sign(&thread_key, &setup.owner)
            .unwrap();

        put_meta(
            &setup,
            &draft(&setup, 1, "t")
                .sign(&thread_key, &setup.owner)
                .unwrap(),
        );
        assert_eq!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0)
                .unwrap()
                .generation(),
            1
        );

        put_meta(&setup, &old);
        assert!(matches!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0),
            Err(ThreadError::Pin(PinError::Rollback {
                pinned: 1,
                found: 0
            }))
        ));
    }

    #[test]
    fn a_different_document_with_the_pinned_generation_is_refused() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &thread_key,
            &setup.owner,
        )
        .unwrap();
        put_meta(
            &setup,
            &draft(&setup, 0, "other")
                .sign(&thread_key, &setup.owner)
                .unwrap(),
        );
        assert!(matches!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0),
            Err(ThreadError::Pin(PinError::Equivocation { generation: 0 }))
        ));
    }

    #[test]
    fn a_document_signed_by_someone_else_is_refused() {
        let setup = setup();
        let mallory = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mallory_key = ParticipantKey::from_public_key(mallory.public_key()).unwrap();
        let alice = ParticipantName::new("alice").unwrap();
        let forged = MetaDraft::new(
            setup.thread,
            5,
            ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap(),
            alice.clone(),
            vec![
                Participant::new(
                    alice,
                    mallory_key,
                    age::x25519::Identity::generate().to_public(),
                    crate::node::tests::random_node(),
                )
                .unwrap(),
            ],
            PrivateMeta::new("t", "main").unwrap(),
        )
        .unwrap()
        .sign(&ThreadKey::generate(), &mallory)
        .unwrap();
        put_meta(&setup, &forged);
        assert!(matches!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0),
            Err(ThreadError::Meta(MetaError::BadSignature))
        ));
        assert_eq!(Pins::new(&setup.store).get(setup.thread).unwrap(), None);
    }

    #[test]
    fn the_first_load_honours_the_minimum_generation() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        put_meta(
            &setup,
            &draft(&setup, 2, "t")
                .sign(&thread_key, &setup.owner)
                .unwrap(),
        );
        assert!(matches!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 3),
            Err(ThreadError::Pin(PinError::BelowMinimum {
                required: 3,
                found: 2
            }))
        ));
        assert_eq!(Pins::new(&setup.store).get(setup.thread).unwrap(), None);
        assert_eq!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 2)
                .unwrap()
                .generation(),
            2
        );
    }

    #[test]
    fn a_meta_commit_without_a_meta_document_is_reported() {
        let setup = setup();
        let meta_ref = ThreadRef::new(setup.thread, RefKind::Meta);
        let blob = setup.store.write_blob(b"x").unwrap();
        let tree = setup
            .store
            .write_tree(&[("other", EntryKind::Blob, blob)])
            .unwrap();
        setup.store.append(&meta_ref, None, tree, "meta").unwrap();
        assert!(matches!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0),
            Err(ThreadError::MissingMetaEntry(_))
        ));
    }

    #[test]
    fn an_oversized_meta_document_is_refused_before_it_is_read() {
        let setup = setup();
        put_meta(&setup, &vec![0; MAX_META_BYTES + 1]);
        assert!(matches!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 0),
            Err(ThreadError::Store(StoreError::TooLarge { .. }))
        ));
    }

    #[test]
    fn a_meta_copied_from_another_thread_is_refused() {
        let target = setup();
        let other = setup();
        let foreign = draft(&other, 0, "t")
            .sign(&ThreadKey::generate(), &other.owner)
            .unwrap();
        put_meta(&target, &foreign);
        assert!(matches!(
            load_meta(&target.store, target.thread, &other.owner_key, 0),
            Err(ThreadError::Meta(MetaError::ThreadMismatch))
        ));
    }

    fn person(name: &str) -> (Participant, age::x25519::Identity) {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mahi = age::x25519::Identity::generate();
        let participant = Participant::new(
            ParticipantName::new(name).unwrap(),
            ParticipantKey::from_public_key(key.public_key()).unwrap(),
            mahi.to_public(),
            crate::node::tests::random_node(),
        )
        .unwrap();
        (participant, mahi)
    }

    fn created(setup: &Setup) -> ThreadKey {
        let thread_key = ThreadKey::generate();
        create_thread(
            &setup.store,
            &draft(setup, 0, "t"),
            &thread_key,
            &setup.owner,
        )
        .unwrap();
        thread_key
    }

    #[test]
    fn an_added_participant_gets_the_thread_key_in_the_next_generation() {
        let setup = setup();
        let thread_key = created(&setup);
        let alice_before = load_meta(&setup.store, setup.thread, &setup.owner_key, 0)
            .unwrap()
            .participants()
            .next()
            .cloned()
            .unwrap();
        let (bob, bob_mahi) = person("bob");
        let added = add_participant(
            &setup.store,
            setup.thread,
            &thread_key,
            &setup.owner,
            bob.clone(),
        )
        .unwrap();
        assert_eq!(added.generation(), 1);

        let meta = load_meta(&setup.store, setup.thread, &setup.owner_key, 1).unwrap();
        assert_eq!(meta.body_hash(), added.body_hash());
        let names: Vec<&str> = meta.participants().map(|p| p.name().as_str()).collect();
        assert_eq!(names, ["alice", "bob"]);
        assert_eq!(meta.participants().next(), Some(&alice_before));
        assert_eq!(meta.participants().nth(1), Some(&bob));
        let bobs_key = meta.thread_key(bob.name(), &bob_mahi).unwrap();
        assert_eq!(
            bobs_key.recipient().to_string(),
            thread_key.recipient().to_string()
        );
        assert_eq!(meta.private(&bobs_key).unwrap().title(), "t");
        meta.thread_key(&ParticipantName::new("alice").unwrap(), &setup.mahi)
            .unwrap();
    }

    #[test]
    fn a_participant_already_there_a_wrong_key_or_another_owner_writes_nothing() {
        let setup = setup();
        let thread_key = created(&setup);
        let (bob, _) = person("bob");
        add_participant(
            &setup.store,
            setup.thread,
            &thread_key,
            &setup.owner,
            bob.clone(),
        )
        .unwrap();
        let meta_ref = ThreadRef::new(setup.thread, RefKind::Meta);
        let head = setup.store.head(&meta_ref).unwrap();

        assert!(matches!(
            add_participant(&setup.store, setup.thread, &thread_key, &setup.owner, bob),
            Err(ThreadError::Meta(MetaError::Invalid(
                crate::InvalidMeta::DuplicateName
            )))
        ));
        let (carol, _) = person("carol");
        assert!(matches!(
            add_participant(
                &setup.store,
                setup.thread,
                &ThreadKey::generate(),
                &setup.owner,
                carol.clone()
            ),
            Err(ThreadError::Meta(MetaError::KeyMismatch))
        ));
        let mallory = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert!(matches!(
            add_participant(
                &setup.store,
                setup.thread,
                &thread_key,
                &mallory,
                carol.clone()
            ),
            Err(ThreadError::Meta(MetaError::BadSignature))
        ));
        assert!(matches!(
            add_participant(
                &setup.store,
                ThreadId::random().unwrap(),
                &thread_key,
                &setup.owner,
                carol
            ),
            Err(ThreadError::NotFound(_))
        ));
        assert_eq!(setup.store.head(&meta_ref).unwrap(), head);
    }

    #[test]
    fn a_rolled_back_meta_ref_is_not_built_on() {
        let setup = setup();
        let thread_key = created(&setup);
        let meta_ref = ThreadRef::new(setup.thread, RefKind::Meta);
        let first = setup.store.head(&meta_ref).unwrap().unwrap();
        let first_meta = setup
            .store
            .read_entry(first, META_ENTRY, MAX_META_BYTES as u64)
            .unwrap()
            .unwrap();
        let (bob, _) = person("bob");
        add_participant(&setup.store, setup.thread, &thread_key, &setup.owner, bob).unwrap();
        put_meta(&setup, &first_meta);
        let rolled_back = setup.store.head(&meta_ref).unwrap();
        let (carol, _) = person("carol");
        assert!(matches!(
            add_participant(&setup.store, setup.thread, &thread_key, &setup.owner, carol),
            Err(ThreadError::Pin(PinError::Rollback { .. }))
        ));
        assert_eq!(setup.store.head(&meta_ref).unwrap(), rolled_back);
    }

    #[test]
    fn another_document_at_the_pinned_generation_is_not_built_on() {
        let setup = setup();
        let thread_key = created(&setup);
        let other = draft(&setup, 0, "other")
            .sign(&thread_key, &setup.owner)
            .unwrap();
        put_meta(&setup, &other);
        let meta_ref = ThreadRef::new(setup.thread, RefKind::Meta);
        let head = setup.store.head(&meta_ref).unwrap();
        let (bob, _) = person("bob");
        assert!(matches!(
            add_participant(&setup.store, setup.thread, &thread_key, &setup.owner, bob),
            Err(ThreadError::Pin(PinError::Equivocation { .. }))
        ));
        assert_eq!(setup.store.head(&meta_ref).unwrap(), head);
    }

    #[test]
    fn the_last_generation_has_no_next_one() {
        let setup = setup();
        let thread_key = created(&setup);
        let last = draft(&setup, u64::MAX, "t")
            .sign(&thread_key, &setup.owner)
            .unwrap();
        put_meta(&setup, &last);
        let (bob, _) = person("bob");
        assert!(matches!(
            add_participant(&setup.store, setup.thread, &thread_key, &setup.owner, bob),
            Err(ThreadError::NoNextGeneration(thread)) if thread == setup.thread
        ));
    }

    #[test]
    fn a_fetched_meta_is_recorded_once_and_moved_forward_only() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        let first = draft(&setup, 1, "t")
            .sign(&thread_key, &setup.owner)
            .unwrap();
        let second = draft(&setup, 2, "t")
            .sign(&thread_key, &setup.owner)
            .unwrap();
        record_meta(&setup.store, setup.thread, &first, &setup.owner_key).unwrap();
        let meta_ref = ThreadRef::new(setup.thread, RefKind::Meta);
        let head = setup.store.head(&meta_ref).unwrap();
        record_meta(&setup.store, setup.thread, &first, &setup.owner_key).unwrap();
        assert_eq!(setup.store.head(&meta_ref).unwrap(), head);
        record_meta(&setup.store, setup.thread, &second, &setup.owner_key).unwrap();
        assert_eq!(
            load_meta(&setup.store, setup.thread, &setup.owner_key, 2)
                .unwrap()
                .generation(),
            2
        );
        assert!(matches!(
            record_meta(&setup.store, setup.thread, &first, &setup.owner_key),
            Err(ThreadError::Pin(PinError::Rollback { .. }))
        ));
        let mallory = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mallory_key = ParticipantKey::from_public_key(mallory.public_key()).unwrap();
        assert!(matches!(
            record_meta(&setup.store, setup.thread, &second, &mallory_key),
            Err(ThreadError::Meta(_))
        ));
    }

    #[test]
    fn a_meta_from_another_owner_neither_replaces_nor_pins_over_the_local_one() {
        let setup = setup();
        let thread_key = ThreadKey::generate();
        create_thread(
            &setup.store,
            &draft(&setup, 0, "t"),
            &thread_key,
            &setup.owner,
        )
        .unwrap();
        let pinned = Pins::new(&setup.store).get(setup.thread).unwrap();
        let mallory = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mallory_key = ParticipantKey::from_public_key(mallory.public_key()).unwrap();
        let alice = ParticipantName::new("alice").unwrap();
        let hostile = MetaDraft::new(
            setup.thread,
            u64::MAX,
            ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap(),
            alice.clone(),
            vec![
                Participant::new(
                    alice,
                    mallory_key.clone(),
                    setup.mahi.to_public(),
                    crate::node::tests::random_node(),
                )
                .unwrap(),
            ],
            PrivateMeta::new("t", "main").unwrap(),
        )
        .unwrap()
        .sign(&ThreadKey::generate(), &mallory)
        .unwrap();
        assert!(matches!(
            record_meta(&setup.store, setup.thread, &hostile, &mallory_key),
            Err(ThreadError::Meta(_))
        ));
        assert_eq!(Pins::new(&setup.store).get(setup.thread).unwrap(), pinned);
        load_meta(&setup.store, setup.thread, &setup.owner_key, 0).unwrap();
    }
}
