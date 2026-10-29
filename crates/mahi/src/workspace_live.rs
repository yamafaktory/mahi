use std::{
    collections::{
        BTreeSet,
        HashMap,
        HashSet,
    },
    fmt::Write as _,
    io,
    path::{
        Path,
        PathBuf,
    },
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
        mpsc,
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
};
use mahi_crypto::ThreadKey;
use mahi_identity::{
    ConfigDir,
    IdentityError,
    LocalIdentity,
    NodeKey,
    SigningKey,
};
use mahi_live::{
    FrameError,
    LiveKeys,
    Relays,
};
use mahi_store::{
    ObjectId,
    Store,
    StoreError,
};
use mahi_thread::{
    MetaError,
    NodeId,
    OwnerError,
    ParticipantKey,
    ThreadError,
    VerifiedMeta,
    load_meta,
};
use thiserror::Error;

use crate::{
    claims::Claims,
    environment::{
        Environment,
        LiveMode,
    },
    hub::Hub,
    live::{
        self,
        HostError,
        HostRole,
        LiveHost,
        LiveSetup,
        SharedNode,
    },
    mcp,
    session,
    sync::{
        self as remote_sync,
        Reach,
    },
    teammates::Teammates,
    thread_lock::{
        LiveLock,
        LockError,
    },
    threads,
    unlocked,
};

/// How often the workspace checks whether the owner purged a thread it only watches, while
/// none of its teammates' agents is online.
const PURGE_CHECK_EVERY: Duration = Duration::from_secs(10);

/// Hosting a thread's live layer for the workspace failed.
#[derive(Debug, Error)]
pub(crate) enum WorkspaceLiveError {
    #[error("your mahi key is not unlocked")]
    Locked,
    #[error("cannot open the repository")]
    Store(#[from] StoreError),
    #[error("cannot take the live layer's lock")]
    Lock(#[from] LockError),
    #[error("cannot tell who owns the thread")]
    Owner(#[from] OwnerError),
    #[error("cannot read the thread's meta")]
    Meta(#[from] ThreadError),
    #[error("cannot read mahi's keys")]
    Keys(#[from] IdentityError),
    #[error("this machine's node is not a participant of the thread")]
    NotParticipant,
    #[error("cannot open the thread key")]
    ThreadKey(#[from] MetaError),
    #[error("cannot prepare the live frames")]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("cannot open the socket the workspace's agents reach the host on")]
    Hub(#[source] io::Error),
}

/// The live layer the workspace hosts for the threads its tabs show, on one node, so the
/// user's node key is bound once however many threads are open; its children hand it their
/// agents over each thread's local socket.
#[derive(Debug)]
pub(crate) struct WorkspaceLive {
    config: ConfigDir,
    runtime: PathBuf,
    relays: Relays,
    git_dir: PathBuf,
    shared: Option<SharedNode>,
    hosted: HashMap<ThreadId, Hosted>,
    reach: Reach,
    purge_checks: PurgeChecks,
}

/// A thread the workspace hosts: its host, the socket its agents reach it on, and the
/// teammates' agents it watches.
#[derive(Debug)]
struct Hosted {
    host: LiveHost,
    hub: Hub,
    teammates: Teammates,
    key: ThreadKey,
    base: ObjectId,
    owner: ParticipantKey,
}

impl WorkspaceLive {
    /// Prepares the workspace's live layer for the repository at `git_dir`, with mahi's keys
    /// in `config`, unless `MAHI_LIVE` turns it off; the keys are read when a thread is hosted,
    /// so a setup the workspace's first agent makes is used.
    pub(crate) fn new(
        environment: &Environment,
        config: &ConfigDir,
        git_dir: &Path,
    ) -> Option<Self> {
        let relays = match environment.live {
            LiveMode::Local => Relays::Disabled,
            LiveMode::Public => Relays::Public,
            LiveMode::Off | LiveMode::Unknown => return None,
        };
        Some(Self {
            config: config.clone(),
            runtime: environment.runtime_dir(),
            relays,
            git_dir: git_dir.to_path_buf(),
            shared: None,
            hosted: HashMap::new(),
            reach: Reach::gather(environment),
            purge_checks: PurgeChecks::default(),
        })
    }

    /// Hosts `thread`'s live layer with the mahi key the workspace keeps; a thread already
    /// hosted here, or by another of the user's mahis, is left as it is.
    pub(crate) fn host(&mut self, thread: ThreadId) -> Result<(), WorkspaceLiveError> {
        if self.hosted.contains_key(&thread) {
            return Ok(());
        }
        let identity =
            unlocked::current(&self.config.identity_file()).ok_or(WorkspaceLiveError::Locked)?;
        self.host_unlocked(thread, &identity)
    }

    fn host_unlocked(
        &mut self,
        thread: ThreadId,
        identity: &LocalIdentity,
    ) -> Result<(), WorkspaceLiveError> {
        if self.hosted.contains_key(&thread) {
            return Ok(());
        }
        let Some(lock) = LiveLock::try_acquire(&self.config, thread)? else {
            return Ok(());
        };
        let signing = SigningKey::load(&self.config.signing_key_file())?;
        let own = ParticipantKey::from_public_key(signing.public_key())
            .map_err(|_| WorkspaceLiveError::Keys(IdentityError::Malformed))?;
        let store = Store::open(&self.git_dir)?;
        let owner = session::thread_owner(&store, thread, own)?;
        let meta = load_meta(&store, thread, &owner, 0)?;
        let node_key = NodeKey::load(&self.config.node_key_file())?;
        let node = NodeId::from_bytes(node_key.public())
            .map_err(|_| WorkspaceLiveError::NotParticipant)?;
        let participant = meta
            .participants()
            .find(|participant| *participant.node() == node)
            .map(|participant| participant.name().clone())
            .ok_or(WorkspaceLiveError::NotParticipant)?;
        let key = meta.thread_key(&participant, identity.as_age())?;
        let keys = LiveKeys::derive(&key, thread)?;
        let shared = if let Some(shared) = &self.shared {
            shared.clone()
        } else {
            let bound = SharedNode::bind(&node_key, self.relays)?;
            self.shared = Some(bound.clone());
            bound
        };
        let setup = LiveSetup {
            config: self.config.clone(),
            runtime: self.runtime.clone(),
            node_key,
            owner: owner.clone(),
            relays: self.relays,
            bootstrap: live::bootstrap(&store, thread),
        };
        let host = LiveHost::start_on(
            (&shared, lock),
            &setup,
            (store.common_dir(), &keys),
            HostRole::Workspace,
            Arc::new(Claims::default()),
        )?;
        let hub = live::hub_socket(&self.runtime, thread)
            .and_then(|socket| Hub::start(socket, host.handle()));
        match hub {
            Ok(hub) => {
                let mut teammates = Teammates::new(participant);
                teammates.add_offline(&known_agents(&store, &meta));
                self.hosted.insert(
                    thread,
                    Hosted {
                        host,
                        hub,
                        teammates,
                        key,
                        base: meta.base(),
                        owner,
                    },
                );
                Ok(())
            }
            Err(error) => {
                host.stop();
                Err(WorkspaceLiveError::Hub(error))
            }
        }
    }

    /// Returns whether the workspace hosts `thread`.
    pub(crate) fn hosts(&self, thread: ThreadId) -> bool {
        self.hosted.contains_key(&thread)
    }

    /// Takes at `now` what the teammates' hosts sent in every thread the workspace hosts, and
    /// asks them for their agents' screens when they are wanted; returns whether what the
    /// teammates' agents show in `shown`, the thread whose tab is shown, changed.
    pub(crate) fn watch(&mut self, now: Instant, shown: Option<ThreadId>) -> bool {
        let mut changed = false;
        for (thread, hosted) in &mut self.hosted {
            if let Some(watch) = hosted.host.watch() {
                changed |= watch.update(&mut hosted.teammates, now) && Some(*thread) == shown;
            }
        }
        changed
    }

    /// Returns the teammates' agents the workspace watches in `thread`, while it hosts it.
    pub(crate) fn teammates(&self, thread: ThreadId) -> Option<&Teammates> {
        self.hosted.get(&thread).map(|hosted| &hosted.teammates)
    }

    /// Shows the record of the work of `slot`'s agent in `thread`, its latest turns and the
    /// files it changed, as `read_transcript` and `read_diff` read them, on a screen of `size`,
    /// when the agent is offline and none is shown yet; returns whether it shows one now.
    pub(crate) fn show_record(
        &mut self,
        thread: ThreadId,
        slot: &AgentSlot,
        size: (u16, u16),
    ) -> bool {
        let Some(hosted) = self.hosted.get_mut(&thread) else {
            return false;
        };
        if !hosted.teammates.wants_record(slot) {
            return false;
        }
        let record = record(&self.git_dir, (thread, &hosted.key, hosted.base), slot);
        hosted.teammates.set_record(slot, &record, size);
        true
    }

    /// Forgets the records shown of offline agents' work, so they are read again at another
    /// size.
    pub(crate) fn forget_records(&mut self) {
        for hosted in self.hosted.values_mut() {
            hosted.teammates.forget_records();
        }
    }

    /// Checks at `now`, off this thread and at most every [`PURGE_CHECK_EVERY`], whether the
    /// owner purged each thread of `watched` the workspace hosts while none of its teammates'
    /// agents is online, by fetching its `meta` alone; returns the threads found purged since
    /// the last call. A check that fails says nothing, and the next one tries again.
    pub(crate) fn take_purged(
        &mut self,
        now: Instant,
        watched: impl IntoIterator<Item = ThreadId>,
    ) -> Vec<ThreadId> {
        for thread in watched {
            let Some(hosted) = self.hosted.get(&thread) else {
                continue;
            };
            if hosted.teammates.any_online() || !self.purge_checks.due(now, thread) {
                continue;
            }
            let (git_dir, reach, owner) = (
                self.git_dir.clone(),
                self.reach.clone(),
                hosted.owner.clone(),
            );
            self.purge_checks.start(now, thread, move |interrupt| {
                Store::open(&git_dir).is_ok_and(|store| {
                    remote_sync::fetch_purged(&store, &reach, (thread, &owner), interrupt)
                        .unwrap_or(false)
                })
            });
        }
        self.purge_checks.take_found()
    }

    /// Stops hosting `thread`, once none of its tabs is open, and closes the node once it
    /// hosts no thread, so it no longer publishes where it is.
    pub(crate) fn release(&mut self, thread: ThreadId) {
        if let Some(hosted) = self.hosted.remove(&thread) {
            stop(hosted);
        }
        self.purge_checks.forget(thread);
        if self.hosted.is_empty() {
            self.shared = None;
        }
    }
}

/// The checks the workspace runs, each on a thread of its own, of whether a thread's owner
/// purged it.
#[derive(Debug)]
struct PurgeChecks {
    sender: mpsc::Sender<(ThreadId, bool)>,
    receiver: mpsc::Receiver<(ThreadId, bool)>,
    running: HashSet<ThreadId>,
    started: HashMap<ThreadId, Instant>,
    interrupt: Arc<AtomicBool>,
}

impl Default for PurgeChecks {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            sender,
            receiver,
            running: HashSet::new(),
            started: HashMap::new(),
            interrupt: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl PurgeChecks {
    /// Starts `check` on a thread of its own for `thread` at `now`, unless one still runs for
    /// it or the last one started less than [`PURGE_CHECK_EVERY`] ago; `check` stops soon
    /// once the flag it gets is set, and returns whether the thread was purged.
    fn start(
        &mut self,
        now: Instant,
        thread: ThreadId,
        check: impl FnOnce(&Arc<AtomicBool>) -> bool + Send + 'static,
    ) {
        if !self.due(now, thread) {
            return;
        }
        let (sender, interrupt) = (self.sender.clone(), Arc::clone(&self.interrupt));
        let spawned = thread::Builder::new()
            .name("mahi-purge-check".to_owned())
            .spawn(move || {
                let mut told = CheckEnded {
                    sender,
                    thread,
                    purged: false,
                };
                told.purged = check(&interrupt);
            });
        if spawned.is_ok() {
            self.running.insert(thread);
        }
        self.started.insert(thread, now);
    }

    /// Says whether a check of `thread` may start at `now`: none runs for it, and the last
    /// one started at least [`PURGE_CHECK_EVERY`] ago.
    fn due(&self, now: Instant, thread: ThreadId) -> bool {
        let recent = self
            .started
            .get(&thread)
            .is_some_and(|at| now.saturating_duration_since(*at) < PURGE_CHECK_EVERY);
        !recent && !self.running.contains(&thread)
    }

    /// Forgets when `thread` was last checked, once the workspace no longer hosts it; a check
    /// still running for it ends on its own.
    fn forget(&mut self, thread: ThreadId) {
        self.started.remove(&thread);
    }

    /// Returns the threads the checks that ended since the last call found purged.
    fn take_found(&mut self) -> Vec<ThreadId> {
        let mut found = Vec::new();
        while let Ok((thread, purged)) = self.receiver.try_recv() {
            self.running.remove(&thread);
            if purged {
                found.push(thread);
            }
        }
        found
    }
}

/// Sends what a check of `thread` found once it ends, even when it panics, so the thread is
/// checked again.
struct CheckEnded {
    sender: mpsc::Sender<(ThreadId, bool)>,
    thread: ThreadId,
    purged: bool,
}

impl Drop for CheckEnded {
    fn drop(&mut self) {
        let _ = self.sender.send((self.thread, self.purged));
    }
}

impl Drop for PurgeChecks {
    fn drop(&mut self) {
        self.interrupt.store(true, Ordering::SeqCst);
    }
}

impl Drop for WorkspaceLive {
    fn drop(&mut self) {
        let stopping: Vec<_> = self
            .hosted
            .drain()
            .map(|(_, hosted)| thread::spawn(move || stop(hosted)))
            .collect();
        for stopped in stopping {
            let _ = stopped.join();
        }
    }
}

/// Returns the record of the work of `slot`'s agent in the thread of the repository at
/// `git_dir`, whose records `key` opens and whose base is `base`: its latest turns, then the
/// files it changed, or why each cannot be read.
fn record(
    git_dir: &Path,
    (thread, key, base): (ThreadId, &ThreadKey, ObjectId),
    slot: &AgentSlot,
) -> String {
    let store = match Store::open(git_dir) {
        Ok(store) => store,
        Err(error) => {
            return format!("the repository cannot be read: {}", crate::describe(&error));
        }
    };
    let mut record = mcp::transcript_text(&store, key, thread, slot, mcp::DEFAULT_TURNS)
        .unwrap_or_else(|error| format!("{slot}'s turns cannot be read: {error}"));
    record.push_str("\n\n");
    match mcp::changes_text(&store, thread, base, slot) {
        Ok(changes) => record.push_str(&changes),
        Err(error) => {
            let _ = write!(record, "{slot}'s changes cannot be read: {error}");
        }
    }
    record
}

/// Returns the agents of the participants `meta` lists that the thread's refs name here, its
/// own and those fetched, which anyone who can push to the remote chooses; none when the refs
/// cannot be read, since each agent is listed anyway once its host is heard from.
fn known_agents(store: &Store, meta: &VerifiedMeta) -> BTreeSet<AgentSlot> {
    let thread = meta.thread();
    let fetched = store.fetched_refs(thread).unwrap_or_default();
    let own = threads::thread_agents(store, thread).unwrap_or_default();
    fetched
        .iter()
        .filter_map(|(thread_ref, _)| match thread_ref.kind() {
            RefKind::Snapshots(slot) | RefKind::Transcript(slot) | RefKind::Session(slot) => {
                Some(slot.clone())
            }
            RefKind::Meta | RefKind::State => None,
        })
        .chain(own)
        .filter(|slot| {
            meta.participants()
                .any(|participant| participant.name() == slot.participant())
        })
        .collect()
}

fn stop(hosted: Hosted) {
    hosted.hub.stop();
    hosted.host.stop();
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::AtomicBool,
    };

    use mahi_core::ParticipantName;
    use mahi_identity::PublicIdentity;
    use mahi_store::GlobalPatterns;
    use mahi_term::TeammateState;
    use mahi_thread::{
        Participant,
        Role,
        add_participant,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::session::{
        CommitKey,
        NewThread,
        agent_from,
        tests::repository_on_main,
    };

    pub(crate) struct Setup {
        _repo: TempDir,
        _dirs: TempDir,
        _runtime: TempDir,
        pub(crate) store: Store,
        pub(crate) config: ConfigDir,
        pub(crate) environment: Environment,
        identity: LocalIdentity,
        owner_key: PrivateKey,
        pub(crate) thread: ThreadId,
    }

    impl Setup {
        pub(crate) fn owner(&self) -> ParticipantKey {
            ParticipantKey::from_public_key(self.owner_key.public_key()).unwrap()
        }
    }

    pub(crate) fn hosting(setup: &Setup) -> WorkspaceLive {
        let mut live =
            WorkspaceLive::new(&setup.environment, &setup.config, setup.store.common_dir())
                .unwrap();
        live.host_unlocked(setup.thread, &setup.identity).unwrap();
        live
    }

    pub(crate) fn setup() -> Setup {
        let (repo, store) = repository_on_main();
        let dirs = TempDir::new().unwrap();
        let config_path = dirs.path().join("config");
        std::fs::create_dir(&config_path).unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = ConfigDir::resolve(Some(&config_path), Some(&config_path)).unwrap();
        std::fs::create_dir_all(config.path()).unwrap();
        std::fs::set_permissions(config.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let node_key = NodeKey::generate().unwrap();
        node_key.save(&config.node_key_file()).unwrap();
        let owner_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        SigningKey::try_from(owner_key.public_key().clone())
            .unwrap()
            .save(&config.signing_key_file())
            .unwrap();
        let identity = LocalIdentity::generate();
        let worktrees = TempDir::new().unwrap();
        let started = session::start(
            &store,
            NewThread {
                public: &PublicIdentity::from(&identity),
                node: NodeId::from_bytes(node_key.public()).unwrap(),
                signer: &owner_key,
                commits: &CommitKey::new(owner_key.clone()).unwrap(),
                participant: ParticipantName::new("alice").unwrap(),
                agent: &agent_from(Path::new("claude")),
                worktrees: worktrees.path(),
            },
            &GlobalPatterns::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        let runtime = tempfile::Builder::new()
            .prefix("m")
            .tempdir_in("/tmp")
            .unwrap();
        let environment = Environment {
            live: LiveMode::Local,
            xdg_runtime_dir: Some(runtime.path().to_path_buf()),
            ..Environment::default()
        };
        Setup {
            _repo: repo,
            _dirs: dirs,
            _runtime: runtime,
            store,
            config,
            environment,
            identity,
            owner_key,
            thread: started.thread,
        }
    }

    fn found_once_ended(checks: &mut PurgeChecks) -> Vec<ThreadId> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut found = Vec::new();
        while !checks.running.is_empty() && Instant::now() < deadline {
            found.extend(checks.take_found());
            thread::sleep(Duration::from_millis(5));
        }
        found
    }

    #[test]
    fn a_purge_check_runs_again_only_once_the_last_ended_and_its_interval_passed() {
        let mut checks = PurgeChecks::default();
        let thread = ThreadId::random().unwrap();
        let start = Instant::now();
        let (release, held) = mpsc::channel::<()>();
        checks.start(start, thread, move |_| held.recv().is_ok());
        checks.start(start + PURGE_CHECK_EVERY * 2, thread, |_| true);
        release.send(()).unwrap();
        assert_eq!(found_once_ended(&mut checks), [thread]);
        checks.start(start + PURGE_CHECK_EVERY / 2, thread, |_| true);
        assert!(checks.running.is_empty());
        checks.start(start + PURGE_CHECK_EVERY, thread, |_| false);
        assert!(checks.running.contains(&thread));
        assert!(found_once_ended(&mut checks).is_empty());
        assert!(checks.running.is_empty());
    }

    #[test]
    fn a_purge_check_that_panics_is_counted_as_ended() {
        let mut checks = PurgeChecks::default();
        let thread = ThreadId::random().unwrap();
        checks.start(Instant::now(), thread, |_| panic!("the check failed"));
        assert!(found_once_ended(&mut checks).is_empty());
        assert!(checks.running.is_empty());
    }

    #[test]
    fn dropping_the_purge_checks_tells_a_running_check_to_stop() {
        let mut checks = PurgeChecks::default();
        let thread = ThreadId::random().unwrap();
        let (told, stopped) = mpsc::channel();
        checks.start(Instant::now(), thread, move |interrupt| {
            while !interrupt.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(5));
            }
            told.send(()).unwrap();
            false
        });
        drop(checks);
        assert!(stopped.recv_timeout(Duration::from_secs(10)).is_ok());
    }

    #[test]
    fn the_workspace_hosts_a_thread_once_with_its_hub_and_releases_it() {
        let setup = setup();
        let mut live =
            WorkspaceLive::new(&setup.environment, &setup.config, setup.store.common_dir())
                .unwrap();
        live.host_unlocked(setup.thread, &setup.identity).unwrap();
        live.host_unlocked(setup.thread, &setup.identity).unwrap();
        assert_eq!(live.hosted.len(), 1);
        assert!(
            LiveLock::try_acquire(&setup.config, setup.thread)
                .unwrap()
                .is_none()
        );
        let socket = live::hub_socket(&setup.environment.runtime_dir(), setup.thread).unwrap();
        assert!(socket.exists());
        live.release(setup.thread);
        assert!(live.hosted.is_empty());
        assert!(live.shared.is_none());
        assert!(
            LiveLock::try_acquire(&setup.config, setup.thread)
                .unwrap()
                .is_some()
        );
    }

    pub(crate) fn add_bob(setup: &Setup, role: Role) -> Participant {
        let bob = Participant::new(
            "bob".parse().unwrap(),
            ParticipantKey::from_public_key(
                PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                    .unwrap()
                    .public_key(),
            )
            .unwrap(),
            age::x25519::Identity::generate().to_public(),
            NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap(),
        )
        .unwrap()
        .with_role(role);
        sign_participant(setup, bob.clone());
        bob
    }

    pub(crate) fn sign_participant(setup: &Setup, participant: Participant) {
        let thread_key = load_meta(&setup.store, setup.thread, &setup.owner(), 0)
            .unwrap()
            .thread_key(&"alice".parse().unwrap(), setup.identity.as_age())
            .unwrap();
        add_participant(
            &setup.store,
            setup.thread,
            &thread_key,
            &setup.owner_key,
            participant,
        )
        .unwrap();
    }

    #[test]
    fn an_offline_teammates_agent_shows_its_turns_and_changes_as_the_tools_read_them() {
        let setup = setup();
        add_bob(&setup, Role::Collaborator);
        let bob: AgentSlot = "bob.codex".parse().unwrap();
        let snapshots = mahi_core::ThreadRef::new(setup.thread, RefKind::Snapshots(bob.clone()));
        let tree = setup.store.write_tree(&[]).unwrap();
        setup.store.append(&snapshots, None, tree, "test").unwrap();
        let mut live =
            WorkspaceLive::new(&setup.environment, &setup.config, setup.store.common_dir())
                .unwrap();
        live.host_unlocked(setup.thread, &setup.identity).unwrap();
        assert!(live.show_record(setup.thread, &bob, (20, 80)));
        assert!(!live.show_record(setup.thread, &bob, (20, 80)));
        let shown = live
            .teammates(setup.thread)
            .unwrap()
            .screen(&bob)
            .unwrap()
            .contents();
        assert!(
            shown.contains("bob.codex has no recorded turns here"),
            "{shown}"
        );
        assert!(
            shown.contains("Files bob.codex's latest snapshot changed from the thread's base:"),
            "{shown}"
        );
        live.forget_records();
        assert!(live.show_record(setup.thread, &bob, (10, 40)));
        let size = live
            .teammates(setup.thread)
            .unwrap()
            .screen(&bob)
            .unwrap()
            .size();
        assert_eq!(size, (10, 40));
    }

    #[test]
    fn a_hosted_threads_teammates_agents_from_its_refs_are_listed_offline() {
        let setup = setup();
        let tree = setup.store.write_tree(&[]).unwrap();
        add_bob(&setup, Role::Collaborator);
        for slot in ["bob.codex", "mallory.claude"] {
            let slot: AgentSlot = slot.parse().unwrap();
            let agent = mahi_core::ThreadRef::new(setup.thread, RefKind::Transcript(slot));
            setup.store.append(&agent, None, tree, "test").unwrap();
        }
        let mut live =
            WorkspaceLive::new(&setup.environment, &setup.config, setup.store.common_dir())
                .unwrap();
        live.host_unlocked(setup.thread, &setup.identity).unwrap();
        let listed: Vec<(String, TeammateState)> = live
            .teammates(setup.thread)
            .unwrap()
            .agents()
            .map(|(slot, state)| (slot.to_string(), state))
            .collect();
        assert_eq!(listed, [("bob.codex".to_owned(), TeammateState::Offline)]);
    }

    #[test]
    fn a_key_that_opens_no_thread_key_leaves_the_thread_unhosted_and_its_lock_free() {
        let setup = setup();
        let mut live =
            WorkspaceLive::new(&setup.environment, &setup.config, setup.store.common_dir())
                .unwrap();
        let stranger = LocalIdentity::generate();
        assert!(matches!(
            live.host_unlocked(setup.thread, &stranger),
            Err(WorkspaceLiveError::ThreadKey(_))
        ));
        assert!(live.hosted.is_empty());
        assert!(
            LiveLock::try_acquire(&setup.config, setup.thread)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_thread_another_mahi_hosts_is_left_and_no_live_layer_is_kept_when_it_is_off() {
        let setup = setup();
        let mut live =
            WorkspaceLive::new(&setup.environment, &setup.config, setup.store.common_dir())
                .unwrap();
        let other = LiveLock::try_acquire(&setup.config, setup.thread)
            .unwrap()
            .unwrap();
        live.host_unlocked(setup.thread, &setup.identity).unwrap();
        assert!(live.hosted.is_empty());
        drop(other);
        let off = Environment {
            live: LiveMode::Off,
            ..Environment::default()
        };
        assert!(WorkspaceLive::new(&off, &setup.config, setup.store.common_dir()).is_none());
    }
}
