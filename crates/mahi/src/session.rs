use std::{
    path::{
        Path,
        PathBuf,
    },
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

use mahi_core::{
    AgentName,
    NameError,
    ParticipantName,
    RandomError,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_crypto::ThreadKey;
use mahi_identity::PublicIdentity;
use mahi_store::{
    ObjectId,
    Store,
    StoreError,
};
use mahi_thread::{
    InvalidMeta,
    KeyError,
    MetaDraft,
    MetaError,
    Participant,
    ParticipantKey,
    PrivateMeta,
    SshSigner,
    ThreadError,
    create_thread,
    discard_thread,
};
use thiserror::Error;

const WORKTREES: [&str; 2] = ["mahi", "worktrees"];

/// A thread `mahi run` started, and the worktree its agent works in.
#[derive(Debug)]
pub(crate) struct Started {
    pub(crate) thread: ThreadId,
    pub(crate) worktree: PathBuf,
    meta: ObjectId,
}

#[derive(Debug, Error)]
pub(crate) enum StartError {
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error("HEAD is not on a local branch; check out the branch the work should land on")]
    NoBranch,
    #[error("cannot draw a thread id")]
    Random(#[from] RandomError),
    #[error("the signing key cannot sign threads")]
    SigningKey(#[from] KeyError),
    #[error("cannot describe the thread")]
    Meta(#[from] MetaError),
    #[error("cannot describe the participant")]
    Participant(#[from] InvalidMeta),
    #[error("cannot create the thread")]
    Thread(#[from] ThreadError),
}

pub(crate) fn start(
    store: &Store,
    public: &PublicIdentity,
    signer: &dyn SshSigner,
    participant: ParticipantName,
    agent: &AgentName,
    interrupt: &AtomicBool,
) -> Result<Started, StartError> {
    let base = store.head_commit()?;
    let branch = store.head_branch()?.ok_or(StartError::NoBranch)?;
    let thread = ThreadId::random()?;
    let owner = Participant::new(
        participant.clone(),
        ParticipantKey::from_public_key(signer.public_key())?,
        public.recipient().clone(),
    )?;
    let title = format!("{} on {branch}", agent.as_str());
    let draft = MetaDraft::new(
        thread,
        0,
        base,
        participant,
        vec![owner],
        PrivateMeta::new(&title, &branch)?,
    )?;
    let name = thread.to_string();
    let path = WORKTREES
        .iter()
        .fold(store.common_dir().to_path_buf(), |path, part| {
            path.join(part)
        })
        .join(&name);
    let worktree = store.add_worktree(&name, &path, base, interrupt)?;
    if interrupt.load(Ordering::SeqCst) {
        remove_worktree_or_report(store, &name);
        return Err(StoreError::Interrupted.into());
    }
    match create_thread(store, &draft, &ThreadKey::generate(), signer) {
        Ok(meta) => {
            let started = Started {
                thread,
                worktree,
                meta,
            };
            if interrupt.load(Ordering::SeqCst) {
                started.discard_or_report(store);
                return Err(StoreError::Interrupted.into());
            }
            Ok(started)
        }
        Err(error) => {
            if let ThreadError::CreatedButNotPinned { commit, .. } = &error
                && discard_thread(store, thread, *commit).is_err()
            {
                let _ = store.remove(&ThreadRef::new(thread, RefKind::Meta), *commit);
            }
            remove_worktree_or_report(store, &name);
            Err(error.into())
        }
    }
}

fn remove_worktree_or_report(store: &Store, name: &str) {
    if let Err(error) = store.remove_worktree(name) {
        eprintln!("mahi: cannot remove worktree {name}: {error}");
    }
}

impl Started {
    /// Runs `start_agent`, and removes the thread and its worktree if it fails.
    pub(crate) fn launch<T, E>(
        &self,
        store: &Store,
        start_agent: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        start_agent().inspect_err(|_| self.discard_or_report(store))
    }

    /// Removes the thread and its worktree, and says on standard error if that fails.
    pub(crate) fn discard_or_report(&self, store: &Store) {
        if let Err(error) = self.discard(store) {
            eprintln!("mahi: cannot remove thread {}: {error}", self.thread);
        }
    }

    /// Removes the thread and its worktree, for an agent that never ran.
    pub(crate) fn discard(&self, store: &Store) -> Result<(), DiscardError> {
        let thread = discard_thread(store, self.thread, self.meta);
        let worktree = store.remove_worktree(&self.thread.to_string());
        thread?;
        worktree?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub(crate) enum DiscardError {
    #[error("cannot remove the worktree")]
    Worktree(#[from] StoreError),
    #[error("cannot remove the thread")]
    Thread(#[from] ThreadError),
}

/// Turns a login name or a program name into a mahi name: lowercase, with every other
/// character replaced by `-`, and no `-` at either end.
pub(crate) fn name_from(text: &str) -> String {
    let mapped: String = text
        .chars()
        .map(|character| {
            let lower = character.to_ascii_lowercase();
            if lower.is_ascii_lowercase() || lower.is_ascii_digit() {
                lower
            } else {
                '-'
            }
        })
        .collect();
    mapped.trim_matches('-').to_owned()
}

pub(crate) fn participant_from(user: Option<&str>) -> Result<ParticipantName, NameError> {
    ParticipantName::new(&name_from(user.unwrap_or_default()))
}

pub(crate) fn agent_from(program: &Path) -> AgentName {
    let file_name = program.file_name().unwrap_or_default().to_string_lossy();
    AgentName::new(&name_from(&file_name))
        .unwrap_or_else(|_| AgentName::new("agent").expect("\"agent\" is a valid agent name"))
}

#[cfg(test)]
mod tests {
    use gix::{
        actor::Signature,
        date::Time,
        objs::{
            Commit,
            Tree,
            tree::{
                Entry,
                EntryKind,
            },
        },
        refs::transaction::PreviousValue,
    };
    use mahi_identity::LocalIdentity;
    use mahi_thread::SignError;
    use ssh_key::{
        Algorithm,
        HashAlg,
        PrivateKey,
        PublicKey,
        SshSig,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;

    struct RefusingSigner(PrivateKey);

    impl SshSigner for RefusingSigner {
        fn public_key(&self) -> &PublicKey {
            self.0.public_key()
        }

        fn sign_sshsig(&self, _: &str, _: HashAlg, _: &[u8]) -> Result<SshSig, SignError> {
            Err(SignError::Key(ssh_key::Error::Crypto))
        }
    }

    fn repository_on_main() -> (TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init(dir.path()).unwrap();
        let readme = repo.write_blob(b"hello\n").unwrap().detach();
        let tree = Tree {
            entries: vec![Entry {
                mode: EntryKind::Blob.into(),
                filename: "README".into(),
                oid: readme,
            }],
        };
        let tree = repo.write_object(&tree).unwrap().detach();
        let signature = Signature {
            name: "tester".into(),
            email: "tester@example.com".into(),
            time: Time::new(0, 0),
        };
        let commit = Commit {
            tree,
            parents: std::iter::empty().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: "base".into(),
            extra_headers: Vec::new(),
        };
        let commit = repo.write_object(&commit).unwrap().detach();
        repo.reference("refs/heads/main", commit, PreviousValue::Any, "test")
            .unwrap();
        std::fs::write(repo.git_dir().join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn start_with(store: &Store, signer: &dyn SshSigner) -> Result<Started, StartError> {
        start_until(store, signer, &AtomicBool::new(false))
    }

    fn start_until(
        store: &Store,
        signer: &dyn SshSigner,
        interrupt: &AtomicBool,
    ) -> Result<Started, StartError> {
        start(
            store,
            &PublicIdentity::from(&LocalIdentity::generate()),
            signer,
            ParticipantName::new("alice").unwrap(),
            &agent_from(Path::new("claude")),
            interrupt,
        )
    }

    struct InterruptedWhileSigning<'a>(PrivateKey, &'a AtomicBool);

    impl SshSigner for InterruptedWhileSigning<'_> {
        fn public_key(&self) -> &PublicKey {
            self.0.public_key()
        }

        fn sign_sshsig(
            &self,
            namespace: &str,
            hash: HashAlg,
            message: &[u8],
        ) -> Result<SshSig, SignError> {
            self.1.store(true, Ordering::SeqCst);
            self.0.sign_sshsig(namespace, hash, message)
        }
    }

    fn no_thread_or_worktree(store: &Store) {
        let repo = gix::open(store.common_dir()).unwrap();
        let threads = repo
            .references()
            .unwrap()
            .prefixed("refs/threads/")
            .unwrap()
            .count();
        assert_eq!(threads, 0);
        let registered = store.common_dir().join("worktrees");
        for directory in [worktrees(store), registered] {
            assert_eq!(
                std::fs::read_dir(&directory).map_or(0, Iterator::count),
                0,
                "{}",
                directory.display()
            );
        }
    }

    #[test]
    fn an_interrupt_before_the_checkout_leaves_nothing() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert!(matches!(
            start_until(&store, &signer, &AtomicBool::new(true)),
            Err(StartError::Store(StoreError::Interrupted))
        ));
        no_thread_or_worktree(&store);
    }

    #[test]
    fn an_interrupt_while_the_thread_is_signed_discards_it() {
        let (_dir, store) = repository_on_main();
        let interrupt = AtomicBool::new(false);
        let signer = InterruptedWhileSigning(
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
            &interrupt,
        );
        assert!(matches!(
            start_until(&store, &signer, &interrupt),
            Err(StartError::Store(StoreError::Interrupted))
        ));
        no_thread_or_worktree(&store);
    }

    fn worktrees(store: &Store) -> PathBuf {
        store.common_dir().join("mahi").join("worktrees")
    }

    #[test]
    fn a_started_thread_has_a_worktree_at_head_under_the_git_directory() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let started = start_with(&store, &signer).unwrap();
        assert_eq!(
            started.worktree,
            std::fs::canonicalize(worktrees(&store))
                .unwrap()
                .join(started.thread.to_string())
        );
        assert_eq!(
            std::fs::read(started.worktree.join("README")).unwrap(),
            b"hello\n"
        );
        let meta = ThreadRef::new(started.thread, RefKind::Meta);
        assert_eq!(store.head(&meta).unwrap(), Some(started.meta));
    }

    #[test]
    fn a_discarded_start_leaves_no_thread_or_worktree() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let started = start_with(&store, &signer).unwrap();
        started.discard(&store).unwrap();
        assert!(!started.worktree.exists());
        let meta = ThreadRef::new(started.thread, RefKind::Meta);
        assert_eq!(store.head(&meta).unwrap(), None);
        assert!(
            !store
                .common_dir()
                .join("worktrees")
                .join(started.thread.to_string())
                .exists()
        );
    }

    #[test]
    fn an_agent_that_fails_to_launch_leaves_no_thread_or_worktree() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let started = start_with(&store, &signer).unwrap();
        assert_eq!(
            started.launch(&store, || Err::<(), _>("no sandbox")),
            Err("no sandbox")
        );
        assert!(!started.worktree.exists());
        let meta = ThreadRef::new(started.thread, RefKind::Meta);
        assert_eq!(store.head(&meta).unwrap(), None);
    }

    #[test]
    fn a_launched_agent_keeps_its_thread_and_worktree() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let started = start_with(&store, &signer).unwrap();
        assert_eq!(started.launch(&store, || Ok::<_, ()>(7)), Ok(7));
        assert!(started.worktree.join("README").exists());
        let meta = ThreadRef::new(started.thread, RefKind::Meta);
        assert_eq!(store.head(&meta).unwrap(), Some(started.meta));
    }

    #[test]
    fn a_thread_that_cannot_be_pinned_leaves_no_ref_or_worktree() {
        let (_dir, store) = repository_on_main();
        std::fs::create_dir_all(store.common_dir().join("mahi")).unwrap();
        std::fs::write(
            store.common_dir().join("mahi").join("pins"),
            b"not a directory",
        )
        .unwrap();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert!(matches!(
            start_with(&store, &signer),
            Err(StartError::Thread(ThreadError::CreatedButNotPinned { .. }))
        ));
        let repo = gix::open(store.common_dir()).unwrap();
        let threads = repo
            .references()
            .unwrap()
            .prefixed("refs/threads/")
            .unwrap()
            .count();
        assert_eq!(threads, 0);
        assert_eq!(std::fs::read_dir(worktrees(&store)).unwrap().count(), 0);
    }

    #[test]
    fn a_thread_that_cannot_be_signed_leaves_no_worktree() {
        let (_dir, store) = repository_on_main();
        let signer = RefusingSigner(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap());
        assert!(matches!(
            start_with(&store, &signer),
            Err(StartError::Thread(_))
        ));
        assert_eq!(std::fs::read_dir(worktrees(&store)).unwrap().count(), 0);
        assert!(
            std::fs::read_dir(store.common_dir().join("worktrees"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn names_are_made_from_login_and_program_names() {
        assert_eq!(name_from("Davy.Duperron"), "davy-duperron");
        assert_eq!(name_from("_claude_"), "claude");
        assert_eq!(participant_from(Some("Alice")).unwrap().as_str(), "alice");
        assert!(participant_from(None).is_err());
        assert!(participant_from(Some("…")).is_err());
        assert_eq!(agent_from(Path::new("claude")).as_str(), "claude");
        assert_eq!(
            agent_from(Path::new("/home/alice/.local/bin/claude")).as_str(),
            "claude"
        );
        assert_eq!(agent_from(Path::new("…")).as_str(), "agent");
        assert_eq!(agent_from(Path::new("lock")).as_str(), "agent");
        assert_eq!(agent_from(Path::new("/")).as_str(), "agent");
    }

    #[test]
    fn a_repository_without_a_commit_cannot_start_a_thread() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let result = start_with(&store, &signer);
        assert!(matches!(
            result,
            Err(StartError::Store(StoreError::NoCommit))
        ));
    }
}
