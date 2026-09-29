use std::{
    fmt::Write as _,
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
        mpsc::{
            self,
            Receiver,
            SyncSender,
            TrySendError,
        },
    },
    thread::{
        self,
        JoinHandle,
    },
};

use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_ssh::{
    KnownHosts,
    KnownHostsError,
    SshError,
    SshRemote,
    SshTransport,
};
use mahi_store::{
    Pushed,
    Store,
    StoreError,
    Transport,
};
use thiserror::Error;

use crate::{
    environment::Environment,
    remote::{
        self,
        RemoteName,
        Visibility,
    },
};

const SYSTEM_KNOWN_HOSTS: [&str; 2] = ["/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"];

/// Where and how a run pushes its thread refs, gathered before the agent starts.
#[derive(Debug, Clone)]
pub(crate) struct SyncSetup {
    pub(crate) name: RemoteName,
    remote: SshRemote,
    visibility: Visibility,
    owns_meta: bool,
    known_hosts: Vec<PathBuf>,
    agent: PathBuf,
    user: String,
}

#[derive(Debug, Error)]
pub(crate) enum PushError {
    #[error("cannot open the repository")]
    Open(#[source] StoreError),
    #[error("the push failed")]
    Push(#[source] StoreError),
    #[error("cannot read known_hosts")]
    KnownHosts(#[from] KnownHostsError),
    #[error("cannot reach the remote")]
    Ssh(#[from] SshError),
}

/// Pushes a run's refs on its own thread each time it is poked, a burst of pokes being one
/// push, and once more when the run finishes.
#[derive(Debug)]
pub(crate) struct Pusher {
    pokes: SyncSender<()>,
    worker: JoinHandle<Pushes>,
    interrupt: Arc<AtomicBool>,
}

/// Asks the [`Pusher`] to push soon; it never blocks.
#[derive(Debug, Clone)]
pub(crate) struct PushPoker(SyncSender<()>);

/// What the last push did, and how many pushes ran.
#[derive(Debug, Default)]
pub(crate) struct Pushes {
    count: u64,
    last: Option<Result<Vec<(ThreadRef, Pushed)>, PushError>>,
    crashed: bool,
}

impl SyncSetup {
    /// Returns how the clone around `store` pushes, or `None` if no remote was chosen. A
    /// chosen remote that cannot be used is reported and treated as none, since pushing is
    /// never worth stopping a run for.
    pub(crate) fn gather(
        store: &Store,
        environment: &Environment,
        owns_meta: bool,
    ) -> Option<Self> {
        let chosen = remote::sync_remote(store)
            .and_then(|chosen| {
                chosen
                    .map(|chosen| {
                        remote::ssh_push_url(store, &chosen.name).map(|url| (chosen, url))
                    })
                    .transpose()
            })
            .inspect_err(|error| crate::report_with("threads are not pushed", error))
            .ok()??;
        let (chosen, remote) = chosen;
        let Some(agent) = environment.ssh_auth_sock.clone() else {
            eprintln!("mahi: threads are not pushed: ssh-agent is not running");
            return None;
        };
        let Some(user) = environment.user.clone() else {
            eprintln!("mahi: threads are not pushed: USER is not set");
            return None;
        };
        let mut known_hosts: Vec<PathBuf> = environment
            .home
            .iter()
            .flat_map(|home| {
                ["known_hosts", "known_hosts2"].map(|name| home.join(".ssh").join(name))
            })
            .collect();
        known_hosts.extend(SYSTEM_KNOWN_HOSTS.iter().map(PathBuf::from));
        Some(Self {
            name: chosen.name,
            remote,
            visibility: chosen.visibility,
            owns_meta,
            known_hosts,
            agent,
            user,
        })
    }

    /// Returns the thread refs a run of `slot` in `thread` pushes.
    pub(crate) fn refs(&self, thread: ThreadId, slot: &AgentSlot) -> Vec<ThreadRef> {
        pushed_refs(thread, slot, self.visibility, self.owns_meta)
    }

    /// Connects to the remote over SSH.
    pub(crate) fn connect(&self) -> Result<SshTransport, PushError> {
        let paths: Vec<&Path> = self.known_hosts.iter().map(PathBuf::as_path).collect();
        let known_hosts = KnownHosts::read(&paths)?;
        Ok(SshTransport::connect(
            self.remote.clone(),
            &known_hosts,
            &self.agent,
            &self.user,
        )?)
    }
}

fn pushed_refs(
    thread: ThreadId,
    slot: &AgentSlot,
    visibility: Visibility,
    owns_meta: bool,
) -> Vec<ThreadRef> {
    let mut refs = Vec::new();
    if owns_meta {
        refs.push(ThreadRef::new(thread, RefKind::Meta));
    }
    refs.push(ThreadRef::new(thread, RefKind::Transcript(slot.clone())));
    refs.push(ThreadRef::new(thread, RefKind::Session(slot.clone())));
    if visibility == Visibility::Private {
        refs.push(ThreadRef::new(thread, RefKind::Snapshots(slot.clone())));
    }
    refs
}

impl Pusher {
    /// Starts the pushing thread for `refs` of the repository at `git_dir`, reaching the remote
    /// with `connect`.
    pub(crate) fn start<T, C>(git_dir: PathBuf, refs: Vec<ThreadRef>, connect: C) -> Self
    where
        T: Transport,
        C: Fn() -> Result<T, PushError> + Send + 'static,
    {
        let (pokes, received) = mpsc::sync_channel(1);
        let interrupt = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&interrupt);
        let worker =
            thread::spawn(move || push_on_pokes(&git_dir, &refs, &connect, &received, &flag));
        Self {
            pokes,
            worker,
            interrupt,
        }
    }

    /// Returns a handle that asks for a push.
    pub(crate) fn poker(&self) -> PushPoker {
        PushPoker(self.pokes.clone())
    }

    /// Returns the flag that cuts a push short.
    pub(crate) fn interrupt_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.interrupt)
    }

    /// Pushes once more, waits for it, and returns what the pushes did.
    pub(crate) fn finish(self) -> Pushes {
        let _ = self.pokes.send(());
        drop(self.pokes);
        self.worker.join().unwrap_or_else(|_| Pushes {
            crashed: true,
            ..Pushes::default()
        })
    }
}

impl PushPoker {
    /// Asks for a push; a push already asked for covers this one.
    pub(crate) fn poke(&self) {
        match self.0.try_send(()) {
            Ok(()) | Err(TrySendError::Full(()) | TrySendError::Disconnected(())) => {}
        }
    }
}

fn push_on_pokes<T: Transport>(
    git_dir: &Path,
    refs: &[ThreadRef],
    connect: &dyn Fn() -> Result<T, PushError>,
    pokes: &Receiver<()>,
    interrupt: &AtomicBool,
) -> Pushes {
    let mut pushes = Pushes::default();
    while pokes.recv().is_ok() {
        pushes.count += 1;
        pushes.last = Some(push_once(git_dir, refs, connect, interrupt));
    }
    pushes
}

fn push_once<T: Transport>(
    git_dir: &Path,
    refs: &[ThreadRef],
    connect: &dyn Fn() -> Result<T, PushError>,
    interrupt: &AtomicBool,
) -> Result<Vec<(ThreadRef, Pushed)>, PushError> {
    let interrupted = || {
        if interrupt.load(Ordering::SeqCst) {
            Err(PushError::Push(StoreError::Interrupted))
        } else {
            Ok(())
        }
    };
    interrupted()?;
    let store = Store::open(git_dir).map_err(PushError::Open)?;
    let transport = connect()?;
    interrupted()?;
    store
        .push_refs(transport, refs, interrupt)
        .map_err(PushError::Push)
}

impl Pushes {
    /// Returns what to tell the user about the pushes to the remote `name`, if anything.
    pub(crate) fn report(&self, name: &RemoteName) -> Option<String> {
        let mut text = String::new();
        if self.crashed {
            return Some(format!("mahi: pushing to {name} stopped unexpectedly\n"));
        }
        match self.last.as_ref()? {
            Err(PushError::Push(StoreError::Interrupted)) => {
                let _ = writeln!(text, "mahi: stopped before the last push to {name}");
            }
            Err(error) => {
                let mut message = format!("mahi: cannot push to {name}: {error}");
                let mut cause = std::error::Error::source(error);
                while let Some(source) = cause {
                    let _ = write!(message, ": {source}");
                    cause = source.source();
                }
                let _ = writeln!(text, "{message}");
            }
            Ok(outcomes) => {
                for (thread_ref, outcome) in outcomes {
                    match outcome {
                        Pushed::Updated | Pushed::UpToDate => {}
                        Pushed::Behind => {
                            let _ = writeln!(
                                text,
                                "mahi: {thread_ref} moved on {name} to a commit this clone does \
                                 not have; it was not pushed"
                            );
                        }
                        Pushed::Unchecked(reason) => {
                            let _ = writeln!(text, "mahi: {thread_ref} was not pushed: {reason}");
                        }
                        Pushed::Refused(reason) => {
                            let _ = writeln!(text, "mahi: {name} refused {thread_ref}: {reason}");
                        }
                    }
                }
                if text.is_empty() {
                    let _ = writeln!(text, "mahi: pushed to {name}");
                }
            }
        }
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    use mahi_core::{
        AgentName,
        ParticipantName,
    };

    use super::*;

    fn slot() -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("claude").unwrap(),
        )
    }

    #[test]
    fn snapshots_go_only_to_a_private_remote_and_meta_only_from_its_owner() {
        let thread = ThreadId::random().unwrap();
        let names = |visibility, owns_meta| -> Vec<String> {
            pushed_refs(thread, &slot(), visibility, owns_meta)
                .iter()
                .map(|thread_ref| {
                    thread_ref
                        .to_string()
                        .rsplit('/')
                        .next()
                        .unwrap()
                        .to_owned()
                })
                .collect()
        };
        assert_eq!(
            names(Visibility::Private, true),
            ["meta", "transcript", "session", "snapshots"]
        );
        assert_eq!(
            names(Visibility::Public, true),
            ["meta", "transcript", "session"]
        );
        assert_eq!(names(Visibility::Public, false), ["transcript", "session"]);
    }

    #[test]
    fn what_the_last_push_did_is_told_briefly() {
        let name: RemoteName = "origin".parse().unwrap();
        let thread_ref = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let report = |outcome| {
            Pushes {
                count: 1,
                last: Some(Ok(vec![(thread_ref.clone(), outcome)])),
                crashed: false,
            }
            .report(&name)
            .unwrap()
        };
        assert_eq!(report(Pushed::Updated), "mahi: pushed to origin\n");
        assert!(report(Pushed::Behind).contains("moved on origin"));
        assert!(report(Pushed::Refused("hook declined".to_owned())).contains("hook declined"));
        assert_eq!(Pushes::default().report(&name), None);
        let failed = Pushes {
            count: 1,
            last: Some(Err(PushError::Push(StoreError::PushFailed(
                "bad pack".to_owned(),
            )))),
            crashed: false,
        };
        assert_eq!(
            failed.report(&name).unwrap(),
            "mahi: cannot push to origin: the push failed: push failed: bad pack\n"
        );
        let crashed = Pushes {
            crashed: true,
            ..Pushes::default()
        };
        assert!(
            crashed
                .report(&name)
                .unwrap()
                .contains("stopped unexpectedly")
        );
    }
}

#[cfg(test)]
mod git_tests {
    use std::process::Command;

    use gix::protocol::transport::{
        Protocol,
        client::blocking_io::file,
    };
    use mahi_store::EntryKind;

    use super::*;

    fn git(repository: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .output()
            .expect("git is installed");
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn pokes_push_the_refs_and_finishing_pushes_the_last_state() {
        let dir = tempfile::tempdir().unwrap();
        let (local, remote) = (dir.path().join("local"), dir.path().join("remote.git"));
        gix::init(&local).unwrap();
        std::fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare"]);
        let store = Store::open(&local).unwrap();
        let meta = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let append = |parent| {
            let blob = store.write_blob(format!("{parent:?}").as_bytes()).unwrap();
            let tree = store.write_tree(&[("m", EntryKind::Blob, blob)]).unwrap();
            store.append(&meta, parent, tree, "m").unwrap()
        };
        let first = append(None);
        let target = remote.clone();
        let pusher = Pusher::start(local.clone(), vec![meta.clone()], move || {
            Ok(
                file::connect(target.as_os_str().as_encoded_bytes(), Protocol::V1, false)
                    .unwrap_or_else(|never| match never {}),
            )
        });
        pusher.poker().poke();
        let second = append(Some(first));
        let finished = pusher.finish();
        assert!((1..=2).contains(&finished.count), "{}", finished.count);
        assert!(matches!(finished.last, Some(Ok(_))));
        assert_eq!(
            git(&remote, &["rev-parse", &meta.to_string()]),
            second.to_string()
        );

        let unreachable = Pusher::start(local.clone(), vec![meta.clone()], || {
            Err::<file::SpawnProcessOnDemand, _>(PushError::Ssh(SshError::Timeout(
                "example.org".to_owned(),
            )))
        });
        let failed = unreachable.finish();
        assert!(matches!(failed.last, Some(Err(PushError::Ssh(_)))));
        let target = remote.clone();
        let stopped = Pusher::start(local.clone(), vec![meta.clone()], move || {
            Ok(
                file::connect(target.as_os_str().as_encoded_bytes(), Protocol::V1, false)
                    .unwrap_or_else(|never| match never {}),
            )
        });
        append(Some(second));
        stopped.interrupt_flag().store(true, Ordering::SeqCst);
        let name: RemoteName = "origin".parse().unwrap();
        assert_eq!(
            stopped.finish().report(&name).unwrap(),
            "mahi: stopped before the last push to origin\n"
        );
        assert_eq!(
            git(&remote, &["rev-parse", &meta.to_string()]),
            second.to_string()
        );
    }
}
