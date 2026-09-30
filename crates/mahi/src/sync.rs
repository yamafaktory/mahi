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
    ParticipantName,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_sandbox::{
    Termination,
    TerminationSignals,
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
use mahi_thread::{
    Accepted,
    ParticipantKey,
    ThreadError,
    accept_fetched,
};
use thiserror::Error;

use crate::{
    environment::Environment,
    remote::{
        self,
        RemoteError,
        RemoteName,
        Visibility,
    },
    run::until_stopped,
};

const MAX_CAUSE_CHARS: usize = 300;
const SYSTEM_KNOWN_HOSTS: [&str; 2] = ["/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"];

/// Where and how a run pushes its thread refs, gathered before the agent starts.
#[derive(Debug, Clone)]
pub(crate) struct SyncSetup {
    pub(crate) name: RemoteName,
    remote: SshRemote,
    visibility: Visibility,
    owns_meta: bool,
    access: SshAccess,
}

/// What reaching a remote over SSH needs from the environment.
#[derive(Debug, Clone)]
struct SshAccess {
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
    #[error(transparent)]
    Connect(#[from] ConnectError),
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
        let access = SshAccess::gather(environment)
            .inspect_err(|missing| eprintln!("mahi: threads are not pushed: {missing}"))
            .ok()?;
        Some(Self {
            name: chosen.name,
            remote,
            visibility: chosen.visibility,
            owns_meta,
            access,
        })
    }

    /// Returns the thread refs a run of `slot` in `thread` pushes.
    pub(crate) fn refs(&self, thread: ThreadId, slot: &AgentSlot) -> Vec<ThreadRef> {
        pushed_refs(thread, slot, self.visibility, self.owns_meta)
    }

    /// Connects to the remote over SSH, stopping once `interrupt` is set.
    pub(crate) fn connect(&self, interrupt: &Arc<AtomicBool>) -> Result<SshTransport, PushError> {
        Ok(self.access.connect(&self.remote, interrupt)?)
    }
}

impl SshAccess {
    fn gather(environment: &Environment) -> Result<Self, &'static str> {
        let agent = environment
            .ssh_auth_sock
            .clone()
            .ok_or("ssh-agent is not running")?;
        let user = environment.user.clone().ok_or("USER is not set")?;
        let mut known_hosts: Vec<PathBuf> = environment
            .home
            .iter()
            .flat_map(|home| {
                ["known_hosts", "known_hosts2"].map(|name| home.join(".ssh").join(name))
            })
            .collect();
        known_hosts.extend(SYSTEM_KNOWN_HOSTS.iter().map(PathBuf::from));
        Ok(Self {
            known_hosts,
            agent,
            user,
        })
    }

    fn connect(
        &self,
        remote: &SshRemote,
        interrupt: &Arc<AtomicBool>,
    ) -> Result<SshTransport, ConnectError> {
        let paths: Vec<&Path> = self.known_hosts.iter().map(PathBuf::as_path).collect();
        let known_hosts = KnownHosts::read(&paths)?;
        Ok(SshTransport::connect(
            remote.clone(),
            &known_hosts,
            &self.agent,
            &self.user,
            Some(Arc::clone(interrupt)),
        )?)
    }
}

#[derive(Debug, Error)]
pub(crate) enum ConnectError {
    #[error("cannot read known_hosts")]
    KnownHosts(#[from] KnownHostsError),
    #[error("cannot reach the remote")]
    Ssh(#[from] SshError),
}

#[derive(Debug, Error)]
pub(crate) enum FetchError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("the fetch failed")]
    Fetch(#[from] StoreError),
    #[error("the fetched thread was not accepted")]
    Accept(#[from] ThreadError),
}

/// Fetches `thread` from the clone's chosen remote, or else from `origin`, accepts what
/// checks out for the participant `local` trusting `owner`, and tells the user what changed.
/// Once `interrupt` is set, the fetch stops within 100 ms, and nothing is accepted unless
/// accepting had already begun.
/// A remote that is not chosen and not an SSH remote is skipped quietly, and a thread the
/// remote does not have leaves everything as it was.
pub(crate) fn fetch_thread(
    store: &Store,
    environment: &Environment,
    thread: ThreadId,
    owner: &ParticipantKey,
    local: &ParticipantName,
    interrupt: &Arc<AtomicBool>,
) {
    let (name, url, chosen) = match fetch_source(store) {
        Ok(Some(source)) => source,
        Ok(None) => return,
        Err(error) => {
            crate::report_with("the thread is not fetched", &error);
            return;
        }
    };
    let access = match SshAccess::gather(environment) {
        Ok(access) => access,
        Err(missing) => {
            if chosen {
                eprintln!("mahi: the thread is not fetched: {missing}");
            }
            return;
        }
    };
    eprintln!("mahi: fetching the thread from {name}");
    let outcome = access
        .connect(&url, interrupt)
        .map_err(FetchError::from)
        .and_then(|transport| fetch_and_accept(store, transport, thread, owner, local, interrupt));
    if let Some(told) = fetch_report(&outcome, &name) {
        eprint!("{told}");
    }
}

/// Returns the remote to fetch from and its URL, and whether it was chosen: the chosen remote
/// at the URL it pushes to, where its threads are, or else `origin` when it fetches over SSH.
fn fetch_source(store: &Store) -> Result<Option<(RemoteName, SshRemote, bool)>, RemoteError> {
    if let Some(chosen) = remote::sync_remote(store)? {
        let url = remote::ssh_push_url(store, &chosen.name)?;
        return Ok(Some((chosen.name, url, true)));
    }
    let Ok(origin) = "origin".parse::<RemoteName>() else {
        return Ok(None);
    };
    Ok(remote::ssh_fetch_url(store, &origin)
        .ok()
        .map(|url| (origin, url, false)))
}

/// Fetches as [`fetch_thread`] does while listening for stop signals, and returns the one that
/// stopped it, if any; the signals go back to their usual handling afterwards. When the
/// signals cannot be listened to, the fetch runs without them.
pub(crate) fn fetch_until_stopped(
    store: &Store,
    environment: &Environment,
    thread: ThreadId,
    owner: &ParticipantKey,
    local: &ParticipantName,
) -> Option<Termination> {
    let Ok(termination) = TerminationSignals::listen() else {
        let never = Arc::new(AtomicBool::new(false));
        fetch_thread(store, environment, thread, owner, local, &never);
        return None;
    };
    let ((), caught) = until_stopped(&termination, |interrupt| {
        fetch_thread(store, environment, thread, owner, local, interrupt);
    });
    caught
}

fn fetch_and_accept<T: Transport>(
    store: &Store,
    transport: T,
    thread: ThreadId,
    owner: &ParticipantKey,
    local: &ParticipantName,
    interrupt: &AtomicBool,
) -> Result<Option<Accepted>, FetchError> {
    let fetched = store.fetch_thread(transport, thread, interrupt);
    if interrupt.load(Ordering::SeqCst) {
        return Err(StoreError::Interrupted.into());
    }
    fetched?;
    match accept_fetched(store, thread, owner, local) {
        Ok(accepted) => Ok(Some(accepted)),
        Err(ThreadError::NotFound(_)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn fetch_report(
    outcome: &Result<Option<Accepted>, FetchError>,
    name: &RemoteName,
) -> Option<String> {
    let mut text = String::new();
    match outcome {
        Err(
            FetchError::Fetch(StoreError::Interrupted)
            | FetchError::Connect(ConnectError::Ssh(SshError::Interrupted)),
        ) => {
            let _ = writeln!(text, "mahi: stopped fetching the thread from {name}");
        }
        Err(error) => {
            let mut message = format!("mahi: cannot fetch the thread from {name}: {error}");
            let mut cause = std::error::Error::source(error);
            while let Some(source) = cause {
                let said: String = source
                    .to_string()
                    .chars()
                    .take(MAX_CAUSE_CHARS)
                    .flat_map(char::escape_debug)
                    .collect();
                let _ = write!(message, ": {said}");
                cause = source.source();
            }
            let _ = writeln!(text, "{message}");
        }
        Ok(None) => return None,
        Ok(Some(accepted)) => {
            match accepted.updated.len() {
                0 => {}
                1 => {
                    let _ = writeln!(text, "mahi: fetched 1 ref of the thread from {name}");
                }
                count => {
                    let _ = writeln!(text, "mahi: fetched {count} refs of the thread from {name}");
                }
            }
            for thread_ref in &accepted.diverged {
                let _ = writeln!(
                    text,
                    "mahi: {thread_ref} on {name} has a history that went apart from the local \
                     one; the local one is kept"
                );
            }
            for (thread_ref, error) in &accepted.refused {
                let _ = writeln!(text, "mahi: refused {thread_ref} from {name}: {error}");
            }
        }
    }
    (!text.is_empty()).then_some(text)
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
        C: Fn(&Arc<AtomicBool>) -> Result<T, PushError> + Send + 'static,
    {
        let (pokes, received) = mpsc::sync_channel(1);
        let interrupt = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&interrupt);
        let worker = thread::spawn(move || {
            push_on_pokes(&git_dir, &refs, &|| connect(&flag), &received, &flag)
        });
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
    let pushed = connect().and_then(|transport| {
        interrupted()?;
        store
            .push_refs(transport, refs, interrupt)
            .map_err(PushError::Push)
    });
    interrupted()?;
    pushed
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
    fn what_a_fetch_changed_is_told_and_a_thread_not_there_says_nothing() {
        let name: RemoteName = "origin".parse().unwrap();
        let thread = ThreadId::random().unwrap();
        let meta = ThreadRef::new(thread, RefKind::Meta);
        assert_eq!(fetch_report(&Ok(None), &name), None);
        assert_eq!(fetch_report(&Ok(Some(Accepted::default())), &name), None);
        let accepted = Accepted {
            updated: vec![meta.clone()],
            diverged: vec![meta.clone()],
            refused: vec![(meta, mahi_thread::Refusal::Store(StoreError::Interrupted))],
            ..Accepted::default()
        };
        let told = fetch_report(&Ok(Some(accepted)), &name).unwrap();
        assert!(
            told.starts_with("mahi: fetched 1 ref of the thread from origin\n"),
            "{told}"
        );
        assert!(told.contains("went apart"), "{told}");
        let hostile = fetch_report(
            &Err(FetchError::Fetch(StoreError::PushFailed(
                "\x1b[2Jgone".to_owned(),
            ))),
            &name,
        )
        .unwrap();
        assert!(!hostile.contains('\x1b'), "{hostile}");
        assert!(told.contains("refused"), "{told}");
        let failed = fetch_report(&Err(FetchError::Fetch(StoreError::NoCommit)), &name).unwrap();
        assert!(failed.starts_with("mahi: cannot fetch the thread from origin: the fetch failed"));
        let stopped = fetch_report(&Err(FetchError::Fetch(StoreError::Interrupted)), &name);
        assert_eq!(
            stopped.as_deref(),
            Some("mahi: stopped fetching the thread from origin\n")
        );
    }

    #[test]
    fn the_chosen_remote_is_fetched_where_it_pushes_or_else_an_ssh_origin() {
        let store_with = |remotes: &str| {
            let dir = tempfile::tempdir().unwrap();
            gix::init(dir.path()).unwrap();
            let config = dir.path().join(".git").join("config");
            let mut text = std::fs::read_to_string(&config).unwrap();
            text.push_str(remotes);
            std::fs::write(&config, text).unwrap();
            let store = Store::open(dir.path()).unwrap();
            (dir, store)
        };
        let source = |store: &Store| {
            fetch_source(store).map(|found| {
                found.map(|(name, url, chosen)| (name.to_string(), url.to_string(), chosen))
            })
        };
        let (_dir, store) = store_with(
            "[remote \"origin\"]\n\turl = https://example.org/r.git\n\tpushurl = git@example.org:r.git\n",
        );
        assert!(matches!(source(&store), Ok(None)));
        let (_dir, store) = store_with("[remote \"origin\"]\n\turl = git@example.org:r.git\n");
        assert_eq!(
            source(&store).unwrap(),
            Some((
                "origin".to_owned(),
                "git@example.org:r.git".to_owned(),
                false
            ))
        );
        let (_dir, store) = store_with(
            "[remote \"mirror\"]\n\turl = https://example.org/r.git\n\tpushurl = git@example.org:r.git\n",
        );
        assert!(matches!(source(&store), Ok(None)));
        std::fs::create_dir_all(store.common_dir().join("mahi").join("sync")).unwrap();
        std::fs::write(
            store.common_dir().join("mahi").join("sync").join("remote"),
            "private mirror\n",
        )
        .unwrap();
        assert_eq!(
            source(&store).unwrap(),
            Some((
                "mirror".to_owned(),
                "git@example.org:r.git".to_owned(),
                true
            ))
        );
        let (_dir, store) = store_with("[remote \"web\"]\n\turl = https://example.org/r.git\n");
        std::fs::create_dir_all(store.common_dir().join("mahi").join("sync")).unwrap();
        std::fs::write(
            store.common_dir().join("mahi").join("sync").join("remote"),
            "public web\n",
        )
        .unwrap();
        assert!(matches!(source(&store), Err(RemoteError::NotSsh { .. })));
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
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

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
        let pusher = Pusher::start(local.clone(), vec![meta.clone()], move |_| {
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

        let unreachable = Pusher::start(local.clone(), vec![meta.clone()], |_| {
            Err::<file::SpawnProcessOnDemand, _>(PushError::Connect(ConnectError::Ssh(
                SshError::Timeout("example.org".to_owned()),
            )))
        });
        let failed = unreachable.finish();
        assert!(matches!(failed.last, Some(Err(PushError::Connect(_)))));
        let stopped_while_connecting = Pusher::start(local.clone(), vec![meta.clone()], |_| {
            Err::<file::SpawnProcessOnDemand, _>(PushError::Connect(ConnectError::Ssh(
                SshError::Timeout("example.org".to_owned()),
            )))
        });
        stopped_while_connecting
            .interrupt_flag()
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            stopped_while_connecting.finish().last,
            Some(Err(PushError::Push(StoreError::Interrupted)))
        ));
        let target = remote.clone();
        let stopped = Pusher::start(local.clone(), vec![meta.clone()], move |_| {
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

    #[test]
    fn a_thread_pushed_by_its_owner_is_fetched_and_accepted_in_another_clone() {
        let (_owner_dir, owner_store) = crate::session::tests::repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let owner = ParticipantKey::from_public_key(signer.public_key()).unwrap();
        let started = crate::session::tests::start_with(&owner_store, &signer).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("remote.git");
        std::fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare"]);
        let connect = || {
            file::connect(remote.as_os_str().as_encoded_bytes(), Protocol::V1, false)
                .unwrap_or_else(|never| match never {})
        };
        let meta = ThreadRef::new(started.thread, RefKind::Meta);
        owner_store
            .push_refs(
                connect(),
                &[meta.clone(), started.snapshots.clone()],
                &AtomicBool::new(false),
            )
            .unwrap();
        let (_clone_dir, clone) = crate::session::tests::repository_on_main();
        let bob = ParticipantName::new("bob").unwrap();
        let accepted = fetch_and_accept(
            &clone,
            connect(),
            started.thread,
            &owner,
            &bob,
            &AtomicBool::new(false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(accepted.updated, [meta.clone(), started.snapshots.clone()]);
        assert_eq!(clone.head(&meta).unwrap(), owner_store.head(&meta).unwrap());
        let again = fetch_and_accept(
            &clone,
            connect(),
            started.thread,
            &owner,
            &bob,
            &AtomicBool::new(false),
        )
        .unwrap()
        .unwrap();
        assert!(again.updated.is_empty());
        let elsewhere = ThreadId::random().unwrap();
        assert!(
            fetch_and_accept(
                &clone,
                connect(),
                elsewhere,
                &owner,
                &bob,
                &AtomicBool::new(false)
            )
            .unwrap()
            .is_none()
        );
        let (_stopped_dir, stopped) = crate::session::tests::repository_on_main();
        assert!(matches!(
            fetch_and_accept(
                &stopped,
                connect(),
                started.thread,
                &owner,
                &bob,
                &AtomicBool::new(true)
            ),
            Err(FetchError::Fetch(StoreError::Interrupted))
        ));
        assert_eq!(stopped.head(&meta).unwrap(), None);
        let impostor = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let wrong = ParticipantKey::from_public_key(impostor.public_key()).unwrap();
        let (_other_dir, other) = crate::session::tests::repository_on_main();
        assert!(matches!(
            fetch_and_accept(
                &other,
                connect(),
                started.thread,
                &wrong,
                &bob,
                &AtomicBool::new(false)
            ),
            Err(FetchError::Accept(ThreadError::FetchedMetaRefused { .. }))
        ));
        assert_eq!(other.head(&meta).unwrap(), None);
    }
}
