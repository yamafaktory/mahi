use std::{
    collections::BTreeSet,
    fs,
    io,
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
    AgentSlot,
    NameError,
    ParticipantName,
    RandomError,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_crypto::ThreadKey;
use mahi_identity::{
    LocalIdentity,
    PublicIdentity,
};
use mahi_store::{
    GlobalPatterns,
    ObjectId,
    SnapshotCache,
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
    TranscriptError,
    TranscriptTip,
    create_thread,
    discard_thread,
    load_meta,
    read_tip,
};
use thiserror::Error;

const WORKTREES: [&str; 2] = ["mahi", "worktrees"];
const STATE: [&str; 2] = ["mahi", "state"];
pub(crate) const SNAPSHOT_MESSAGE: &str = "snapshot";

/// A thread `mahi run` started, the worktree its agent works in, and the worktree's first
/// snapshot.
#[derive(Debug)]
pub(crate) struct Started {
    pub(crate) thread: ThreadId,
    pub(crate) worktree: PathBuf,
    pub(crate) snapshots: ThreadRef,
    pub(crate) first_snapshot: Option<Recorded>,
    pub(crate) slot: AgentSlot,
    pub(crate) key: Option<ThreadKey>,
    pub(crate) tip: Option<TranscriptTip>,
    created: Option<ObjectId>,
}

/// The newest snapshot commit of a worktree, the tree it records, and the cache that took it.
#[derive(Debug)]
pub(crate) struct Recorded {
    pub(crate) commit: ObjectId,
    pub(crate) tree: ObjectId,
    pub(crate) cache: SnapshotCache,
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
    globals: &GlobalPatterns,
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
    let slot = AgentSlot::new(participant.clone(), agent.clone());
    let snapshots = ThreadRef::new(thread, RefKind::Snapshots(slot.clone()));
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
    let key = ThreadKey::generate();
    match create_thread(store, &draft, &key, signer) {
        Ok(meta) => {
            let mut started = Started {
                thread,
                worktree,
                snapshots,
                first_snapshot: None,
                slot,
                key: Some(key),
                tip: None,
                created: Some(meta),
            };
            let recorded =
                take_first_snapshot(store, &name, &started.snapshots, globals, interrupt);
            match recorded {
                Ok(recorded) if !interrupt.load(Ordering::SeqCst) => {
                    started.first_snapshot = Some(recorded);
                    Ok(started)
                }
                Ok(_) => {
                    started.discard_or_report(store);
                    Err(StoreError::Interrupted.into())
                }
                Err(error) => {
                    started.discard_or_report(store);
                    Err(error.into())
                }
            }
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

#[derive(Debug, Error)]
pub(crate) enum ResumeError {
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error("cannot open thread {0}; only a thread you started can be resumed for now")]
    Meta(ThreadId, #[source] Box<ThreadError>),
    #[error("you are not a participant of thread {0}")]
    NotParticipant(ThreadId, #[source] Box<MetaError>),
    #[error("thread {0} has no agent of yours")]
    NoAgent(ThreadId),
    #[error("thread {thread} has several agents of yours ({agents}); pick one with --agent")]
    SeveralAgents { thread: ThreadId, agents: String },
    #[error("thread {0} has no agent of yours called {1}")]
    UnknownAgent(ThreadId, AgentName),
    #[error("the worktree of thread {0} is gone, and rebuilding it is not supported yet")]
    NoWorktree(ThreadId, #[source] StoreError),
    #[error("cannot read the thread's transcript")]
    Transcript(#[source] Box<TranscriptError>),
}

/// What `mahi resume` needs to reopen a thread: who the user is and which agent to resume.
#[derive(Debug)]
pub(crate) struct Reopen<'a> {
    pub(crate) thread: ThreadId,
    pub(crate) owner: &'a ParticipantKey,
    pub(crate) identity: &'a LocalIdentity,
    pub(crate) participant: &'a ParticipantName,
    pub(crate) agent: Option<&'a AgentName>,
}

/// Reopens a thread the user started: checks its `meta` against the user's own signing key,
/// unwraps the thread key, finds the user's agent and its registered worktree, and continues
/// its snapshots and transcript where they stopped.
pub(crate) fn resume(
    store: &Store,
    reopen: &Reopen<'_>,
    globals: &GlobalPatterns,
    interrupt: &AtomicBool,
) -> Result<Started, ResumeError> {
    let thread = reopen.thread;
    let meta = load_meta(store, thread, reopen.owner, 0)
        .map_err(|error| ResumeError::Meta(thread, Box::new(error)))?;
    let key = meta
        .thread_key(reopen.participant, reopen.identity.as_age())
        .map_err(|error| ResumeError::NotParticipant(thread, Box::new(error)))?;
    let slot = pick_slot(store, thread, reopen.participant, reopen.agent)?;
    let name = thread.to_string();
    let worktree = store
        .worktree_dir(&name)
        .map_err(|error| ResumeError::NoWorktree(thread, error))?;
    let snapshots = ThreadRef::new(thread, RefKind::Snapshots(slot.clone()));
    let first_snapshot = match store.head(&snapshots)? {
        Some(commit) => Recorded {
            commit,
            tree: store.commit_tree(commit)?,
            cache: SnapshotCache::default(),
        },
        None => take_first_snapshot(store, &name, &snapshots, globals, interrupt)?,
    };
    let tip = read_tip(store, &key, thread, &slot)
        .map_err(|error| ResumeError::Transcript(Box::new(error)))?;
    Ok(Started {
        thread,
        worktree,
        snapshots,
        first_snapshot: Some(first_snapshot),
        slot,
        key: Some(key),
        tip,
        created: None,
    })
}

/// Finds the user's agent in `thread`: the one named `agent`, or the only one.
pub(crate) fn pick_slot(
    store: &Store,
    thread: ThreadId,
    participant: &ParticipantName,
    agent: Option<&AgentName>,
) -> Result<AgentSlot, ResumeError> {
    let mut mine = BTreeSet::new();
    for (thread_ref, _) in store.thread_refs()? {
        if thread_ref.thread() != thread {
            continue;
        }
        if let RefKind::Snapshots(slot) | RefKind::Transcript(slot) | RefKind::Session(slot) =
            thread_ref.kind()
            && slot.participant() == participant
        {
            mine.insert(slot.clone());
        }
    }
    if let Some(agent) = agent {
        return mine
            .into_iter()
            .find(|slot| slot.agent() == agent)
            .ok_or_else(|| ResumeError::UnknownAgent(thread, agent.clone()));
    }
    let mut slots = mine.into_iter();
    match (slots.next(), slots.next()) {
        (Some(slot), None) => Ok(slot),
        (None, _) => Err(ResumeError::NoAgent(thread)),
        (Some(first), Some(second)) => {
            let agents: Vec<String> = [first, second]
                .into_iter()
                .chain(slots)
                .map(|slot| slot.agent().as_str().to_owned())
                .collect();
            Err(ResumeError::SeveralAgents {
                thread,
                agents: agents.join(", "),
            })
        }
    }
}

fn take_first_snapshot(
    store: &Store,
    name: &str,
    snapshots: &ThreadRef,
    globals: &GlobalPatterns,
    interrupt: &AtomicBool,
) -> Result<Recorded, StoreError> {
    let mut cache = SnapshotCache::default();
    let tree = store.snapshot(name, globals, &mut cache, interrupt)?.tree;
    let commit = store.append(snapshots, None, tree, SNAPSHOT_MESSAGE)?;
    Ok(Recorded {
        commit,
        tree,
        cache,
    })
}

fn remove_worktree_or_report(store: &Store, name: &str) {
    if let Err(error) = store.remove_worktree(name) {
        eprintln!("mahi: cannot remove worktree {name}: {error}");
    }
}

impl Started {
    /// Returns where the agent keeps its own state for this thread, such as Claude Code's
    /// config directory: `<common git dir>/mahi/state/<thread>/<participant>.<agent>`.
    pub(crate) fn state_dir(&self, store: &Store) -> PathBuf {
        self.state_root(store).join(format!(
            "{}.{}",
            self.slot.participant().as_str(),
            self.slot.agent().as_str()
        ))
    }

    fn state_root(&self, store: &Store) -> PathBuf {
        store
            .common_dir()
            .join(STATE[0])
            .join(STATE[1])
            .join(self.thread.to_string())
    }

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
        let Some(created) = self.created else {
            return Ok(());
        };
        let snapshots = match store.head(&self.snapshots) {
            Ok(Some(head)) => store.remove(&self.snapshots, head),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        let thread = discard_thread(store, self.thread, created);
        let worktree = store.remove_worktree(&self.thread.to_string());
        let state = match fs::remove_dir_all(self.state_root(store)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        };
        snapshots?;
        thread?;
        worktree?;
        state.map_err(DiscardError::State)
    }
}

#[derive(Debug, Error)]
pub(crate) enum DiscardError {
    #[error("cannot remove the worktree")]
    Worktree(#[from] StoreError),
    #[error("cannot remove the thread")]
    Thread(#[from] ThreadError),
    #[error("cannot remove the agent's state")]
    State(#[source] io::Error),
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
pub(crate) mod tests {
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

    pub(crate) fn repository_on_main() -> (TempDir, Store) {
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
        std::fs::write(
            repo.git_dir().join("refs/heads/main"),
            format!("{commit}\n"),
        )
        .unwrap();
        std::fs::write(repo.git_dir().join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    pub(crate) fn start_with(store: &Store, signer: &dyn SshSigner) -> Result<Started, StartError> {
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
            &GlobalPatterns::default(),
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
        assert_eq!(store.head(&meta).unwrap(), started.created);
        let first = started.first_snapshot.as_ref().unwrap();
        assert_eq!(store.head(&started.snapshots).unwrap(), Some(first.commit));
        let repo = gix::open(store.common_dir()).unwrap();
        let base_tree = repo.head_commit().unwrap().tree_id().unwrap().detach();
        assert_eq!(first.tree, base_tree);
        assert_eq!(
            started.snapshots.to_string(),
            format!(
                "refs/threads/{}/agents/alice.claude/snapshots",
                started.thread
            )
        );
    }

    #[test]
    fn a_discarded_start_leaves_no_thread_or_worktree() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let started = start_with(&store, &signer).unwrap();
        let state = started.state_dir(&store);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("settings.json"), "{}").unwrap();
        started.discard(&store).unwrap();
        assert!(!started.worktree.exists());
        assert!(!state.exists());
        assert!(!state.parent().unwrap().exists());
        assert_eq!(store.head(&started.snapshots).unwrap(), None);
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
        assert_eq!(store.head(&meta).unwrap(), started.created);
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
    fn the_users_only_agent_is_picked_or_the_one_named() {
        let (_dir, store) = repository_on_main();
        let tree = store.write_tree(&[]).unwrap();
        let thread = ThreadId::random().unwrap();
        let slot = |participant: &str, agent: &str| {
            AgentSlot::new(
                ParticipantName::new(participant).unwrap(),
                AgentName::new(agent).unwrap(),
            )
        };
        let alice = ParticipantName::new("alice").unwrap();
        let claude = AgentName::new("claude").unwrap();
        assert!(matches!(
            pick_slot(&store, thread, &alice, None),
            Err(ResumeError::NoAgent(_))
        ));
        for thread_ref in [
            ThreadRef::new(thread, RefKind::Snapshots(slot("alice", "claude"))),
            ThreadRef::new(thread, RefKind::Transcript(slot("alice", "claude"))),
            ThreadRef::new(thread, RefKind::Snapshots(slot("bob", "codex"))),
            ThreadRef::new(
                ThreadId::random().unwrap(),
                RefKind::Snapshots(slot("alice", "sh")),
            ),
        ] {
            store.append(&thread_ref, None, tree, "test").unwrap();
        }
        assert_eq!(
            pick_slot(&store, thread, &alice, None).unwrap(),
            slot("alice", "claude")
        );
        store
            .append(
                &ThreadRef::new(thread, RefKind::Transcript(slot("alice", "codex"))),
                None,
                tree,
                "test",
            )
            .unwrap();
        assert!(matches!(
            pick_slot(&store, thread, &alice, None),
            Err(ResumeError::SeveralAgents { ref agents, .. }) if agents == "claude, codex"
        ));
        assert_eq!(
            pick_slot(&store, thread, &alice, Some(&claude)).unwrap(),
            slot("alice", "claude")
        );
        assert!(matches!(
            pick_slot(&store, thread, &alice, Some(&AgentName::new("sh").unwrap())),
            Err(ResumeError::UnknownAgent(..))
        ));
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
