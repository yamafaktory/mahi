use std::{
    collections::HashMap,
    io,
    path::{
        Path,
        PathBuf,
    },
    sync::Arc,
    thread,
    time::Instant,
};

use mahi_core::ThreadId;
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
    Store,
    StoreError,
};
use mahi_thread::{
    MetaError,
    NodeId,
    OwnerError,
    ParticipantKey,
    ThreadError,
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
    session,
    teammates::Teammates,
    thread_lock::{
        LiveLock,
        LockError,
    },
    unlocked,
};

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
}

/// A thread the workspace hosts: its host, the socket its agents reach it on, and the
/// teammates' agents it watches.
#[derive(Debug)]
struct Hosted {
    host: LiveHost,
    hub: Hub,
    teammates: Teammates,
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
        let keys = LiveKeys::derive(&meta.thread_key(&participant, identity.as_age())?, thread)?;
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
            owner,
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
                let teammates = Teammates::new(participant);
                self.hosted.insert(
                    thread,
                    Hosted {
                        host,
                        hub,
                        teammates,
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
    /// teammates' agents show changed.
    #[expect(
        dead_code,
        reason = "the workspace's tabs list and draw teammates' agents next"
    )]
    pub(crate) fn watch(&mut self, now: Instant) -> bool {
        let mut changed = false;
        for hosted in self.hosted.values_mut() {
            if let Some(watch) = hosted.host.watch() {
                changed |= watch.update(&mut hosted.teammates, now);
            }
        }
        changed
    }

    /// Returns the teammates' agents the workspace watches in `thread`, while it hosts it.
    #[expect(
        dead_code,
        reason = "the workspace's tabs list and draw teammates' agents next"
    )]
    pub(crate) fn teammates(&self, thread: ThreadId) -> Option<&Teammates> {
        self.hosted.get(&thread).map(|hosted| &hosted.teammates)
    }

    /// Stops hosting `thread`, once none of its tabs is open, and closes the node once it
    /// hosts no thread, so it no longer publishes where it is.
    pub(crate) fn release(&mut self, thread: ThreadId) {
        if let Some(hosted) = self.hosted.remove(&thread) {
            stop(hosted);
        }
        if self.hosted.is_empty() {
            self.shared = None;
        }
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
        pub(crate) thread: ThreadId,
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
            thread: started.thread,
        }
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
