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
    let meta_ref = ThreadRef::new(thread, RefKind::Meta);
    let commit = store
        .head(&meta_ref)?
        .ok_or(ThreadError::NotFound(thread))?;
    let encoded = store
        .read_entry(commit, META_ENTRY, MAX_META_BYTES as u64)?
        .ok_or(ThreadError::MissingMetaEntry(thread))?;
    let verified = VerifiedMeta::decode(&encoded, thread, trusted_owner)?;
    if verified.generation() < min_generation {
        return Err(PinError::BelowMinimum {
            required: min_generation,
            found: verified.generation(),
        }
        .into());
    }
    Pins::new(store).accept(&verified)?;
    Ok(verified)
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
            vec![Participant::new(alice, setup.owner_key.clone(), setup.mahi.to_public()).unwrap()],
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
}
