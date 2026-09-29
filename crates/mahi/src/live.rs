use std::{
    collections::{
        HashMap,
        VecDeque,
    },
    fs::File,
    io::{
        self,
        Read,
    },
    os::fd::OwnedFd,
    path::{
        Path,
        PathBuf,
    },
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicBool,
            Ordering,
        },
        mpsc::{
            self,
            Receiver,
            SyncSender,
        },
    },
    thread::{
        self,
        JoinHandle,
    },
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    AgentSlot,
    ParticipantName,
    ThreadId,
};
use mahi_crypto::ThreadKey;
use mahi_identity::{
    ConfigDir,
    NodeKey,
};
use mahi_live::{
    Body,
    FrameError,
    FrameReceiver,
    FrameSender,
    HostAddress,
    LiveError,
    LiveKeys,
    LiveNode,
    LiveTopic,
    MAX_CHUNK_BYTES,
    MAX_SCREEN_PARTS,
    Peers,
    Relays,
};
use mahi_sandbox::WindowSize;
use mahi_store::{
    Store,
    StoreError,
};
use mahi_thread::{
    NodeId,
    ParticipantKey,
    ThreadError,
    load_meta_document,
};
use rustix::fs::{
    AtFlags,
    Mode,
    OFlags,
};
use thiserror::Error;

use crate::profile;

/// How often a host rereads its `meta` at most, whoever asks.
pub(crate) const REREAD_EVERY: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub(crate) enum HostError {
    #[error("cannot open the repository")]
    Store(#[from] StoreError),
    #[error("cannot read the thread's meta")]
    Meta(#[from] ThreadError),
    #[error("the screen is too large to send")]
    ScreenTooLarge,
    #[error("cannot open the live layer")]
    Live(#[from] LiveError),
    #[error("cannot prepare the live frames")]
    Frame(#[from] FrameError),
}

/// How many chunks of output wait for the broadcaster before newer ones are dropped.
const TAP_QUEUE: usize = 1024;
/// How often a host answers the screen requests of one requester at most.
const SCREEN_EVERY: Duration = Duration::from_secs(1);
/// How many screen requests from different requesters wait to be answered together.
const PENDING_SCREENS: usize = 8;
const LISTEN_PAUSE: Duration = Duration::from_millis(200);
const UNASKED: [u8; 16] = [0; 16];
const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);

const PUBLISHED: &str = "live";
const MAX_PUBLISHED_BYTES: u64 = 4096;
const PUBLISH_EVERY: Duration = Duration::from_secs(2);

/// What a host needs to open the live layer, gathered before the agent starts.
#[derive(Debug)]
pub(crate) struct LiveSetup {
    pub(crate) config: ConfigDir,
    pub(crate) node_key: NodeKey,
    pub(crate) owner: ParticipantKey,
    pub(crate) relays: Relays,
}

fn published_dir(config: &ConfigDir) -> io::Result<OwnedFd> {
    profile::create_private_dir(config.path())?;
    let parent = rustix::fs::open(
        config.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    profile::open_private_dir(&parent, PUBLISHED)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the live directory is not a private directory",
        )
    })
}

/// Publishes where the running host of `thread` can be reached, for `mahi invite`.
pub(crate) fn publish_address(
    config: &ConfigDir,
    thread: ThreadId,
    address: &HostAddress,
) -> io::Result<()> {
    let bytes = address
        .to_bytes()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    profile::replace(&published_dir(config)?, &thread.to_string(), &bytes)
}

/// Returns where the running host of `thread` said it can be reached, if it did.
pub(crate) fn published_address(config: &ConfigDir, thread: ThreadId) -> Option<HostAddress> {
    let directory = published_dir(config).ok()?;
    let file = rustix::fs::openat(
        &directory,
        thread.to_string().as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let mut bytes = Vec::new();
    File::from(file)
        .take(MAX_PUBLISHED_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    HostAddress::from_bytes(&bytes).ok()
}

fn withdraw_address(config: &ConfigDir, thread: ThreadId) {
    if let Ok(directory) = published_dir(config) {
        let _ = rustix::fs::unlinkat(&directory, thread.to_string().as_str(), AtFlags::empty());
    }
}

/// The host's copy of the agent's screen, and how many chunks of output and resizes it has
/// taken, so a snapshot says which queued chunks it already holds.
struct Screen {
    parser: vt100::Parser,
    taken: u64,
}

/// Where the agent's terminal is copied for teammates: the host's own screen, fed as the
/// output goes by, and the queue of numbered chunks to broadcast. It never blocks: when the
/// network falls behind, chunks are dropped and the broadcaster sends the whole screen again.
#[derive(Clone)]
pub(crate) struct OutputTap {
    screen: Arc<Mutex<Screen>>,
    queue: SyncSender<Tapped>,
    dropped: Arc<AtomicBool>,
}

impl std::fmt::Debug for OutputTap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputTap").finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum Tapped {
    Output(u64, Vec<u8>),
    Resize(u64, WindowSize),
}

impl OutputTap {
    /// Takes a chunk of the agent's output.
    pub(crate) fn output(&self, bytes: &[u8]) {
        for chunk in bytes.chunks(MAX_CHUNK_BYTES) {
            let Ok(mut screen) = self.screen.lock() else {
                return;
            };
            screen.parser.process(chunk);
            screen.taken += 1;
            let taken = screen.taken;
            self.enqueue(Tapped::Output(taken, chunk.to_vec()));
        }
    }

    /// Takes a new size of the agent's terminal.
    pub(crate) fn resize(&self, size: WindowSize) {
        let Ok(mut screen) = self.screen.lock() else {
            return;
        };
        screen.parser.screen_mut().set_size(size.rows, size.cols);
        screen.taken += 1;
        let taken = screen.taken;
        self.enqueue(Tapped::Resize(taken, size));
    }

    fn enqueue(&self, tapped: Tapped) {
        if self.queue.try_send(tapped).is_err() {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
}

/// The live layer of a thread's host: its node, the topic its agent's terminal goes to, and
/// the threads that broadcast it and answer screen requests.
#[derive(Debug)]
pub(crate) struct LiveHost {
    node: Arc<LiveNode>,
    tap: OutputTap,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    config: ConfigDir,
    thread: ThreadId,
}

impl LiveHost {
    /// Opens the live layer for `slot`'s agent in `thread`, whose `meta` is read from
    /// `git_dir`, with the agent's terminal at `size`.
    pub(crate) fn start(
        setup: &LiveSetup,
        git_dir: &Path,
        thread: ThreadId,
        slot: AgentSlot,
        thread_key: &ThreadKey,
        size: WindowSize,
    ) -> Result<Self, HostError> {
        withdraw_address(&setup.config, thread);
        let peers = Arc::new(HostPeers::new(
            git_dir.to_path_buf(),
            thread,
            setup.owner.clone(),
            REREAD_EVERY,
        )?);
        let node = Arc::new(LiveNode::bind_live(
            setup.node_key.secret(),
            setup.relays,
            Arc::clone(&peers) as Arc<dyn Peers>,
        )?);
        let topic =
            Arc::new(node.join(LiveKeys::derive(thread_key, thread)?.topic(), &[], None)?);
        let sender = FrameSender::new(
            LiveKeys::derive(thread_key, thread)?,
            setup.node_key.secret(),
        )?;
        let receiver =
            FrameReceiver::new(LiveKeys::derive(thread_key, thread)?, peers.participants());
        let screen = Arc::new(Mutex::new(Screen {
            parser: vt100::Parser::new(size.rows, size.cols, 0),
            taken: 0,
        }));
        let (queue, tapped) = mpsc::sync_channel(TAP_QUEUE);
        let dropped = Arc::new(AtomicBool::new(false));
        let wanted = Arc::new(Mutex::new(VecDeque::with_capacity(PENDING_SCREENS)));
        let stop = Arc::new(AtomicBool::new(false));
        let broadcaster = Broadcaster {
            topic: Arc::clone(&topic),
            sender,
            slot,
            screen: Arc::clone(&screen),
            tapped,
            dropped: Arc::clone(&dropped),
            wanted: Arc::clone(&wanted),
            stop: Arc::clone(&stop),
            held_through: 0,
            sent_at: Instant::now(),
        };
        let listener = Listener {
            topic,
            receiver,
            peers,
            wanted,
            stop: Arc::clone(&stop),
        };
        let publisher = {
            let (node, stop, config) = (Arc::clone(&node), Arc::clone(&stop), setup.config.clone());
            thread::spawn(move || publish(&node, &stop, &config, thread))
        };
        Ok(Self {
            node,
            tap: OutputTap {
                screen,
                queue,
                dropped,
            },
            stop,
            workers: vec![
                thread::spawn(move || broadcaster.run()),
                thread::spawn(move || listener.run()),
                publisher,
            ],
            config: setup.config.clone(),
            thread,
        })
    }

    /// Returns where the agent's terminal is copied.
    pub(crate) fn tap(&self) -> OutputTap {
        self.tap.clone()
    }

    /// Stops the live layer once the agent is gone: output still queued is dropped.
    pub(crate) fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in self.workers {
            let _ = worker.join();
        }
        withdraw_address(&self.config, self.thread);
        if let Ok(node) = Arc::try_unwrap(self.node) {
            let _ = node.close();
        }
    }
}

/// Keeps the host's published address current: the relay it reaches, and its direct addresses.
fn publish(node: &LiveNode, stop: &AtomicBool, config: &ConfigDir, thread: ThreadId) {
    let mut published: Option<HostAddress> = None;
    while !stop.load(Ordering::SeqCst) {
        if let Ok(address) = node.address(Duration::ZERO)
            && published.as_ref() != Some(&address)
            && publish_address(config, thread, &address).is_ok()
        {
            published = Some(address);
        }
        let deadline = Instant::now() + PUBLISH_EVERY;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(LISTEN_PAUSE);
        }
    }
}

/// Sends the agent's terminal in order: output and resizes as they were taken, and whole
/// screens when asked or after chunks were dropped, skipping the chunks a screen holds.
struct Broadcaster {
    topic: Arc<LiveTopic>,
    sender: FrameSender,
    slot: AgentSlot,
    screen: Arc<Mutex<Screen>>,
    tapped: Receiver<Tapped>,
    dropped: Arc<AtomicBool>,
    wanted: Arc<Mutex<VecDeque<[u8; 16]>>>,
    stop: Arc<AtomicBool>,
    held_through: u64,
    sent_at: Instant,
}

impl Broadcaster {
    fn run(mut self) {
        while !self.stopping() {
            self.send_screen_if_needed();
            if self.sent_at.elapsed() >= HEARTBEAT_EVERY {
                let beat = Body::Heartbeat {
                    slot: self.slot.clone(),
                };
                self.send(&beat);
                self.sent_at = Instant::now();
            }
            let Ok(tapped) = self.tapped.recv_timeout(LISTEN_PAUSE) else {
                continue;
            };
            self.send_screen_if_needed();
            let (taken, body) = match tapped {
                Tapped::Output(taken, bytes) => (
                    taken,
                    Body::Output {
                        slot: self.slot.clone(),
                        bytes,
                    },
                ),
                Tapped::Resize(taken, size) => (
                    taken,
                    Body::Resize {
                        slot: self.slot.clone(),
                        rows: size.rows,
                        columns: size.cols,
                    },
                ),
            };
            if taken > self.held_through && !self.send(&body) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn send_screen_if_needed(&mut self) {
        let mut challenges: Vec<[u8; 16]> = self
            .wanted
            .lock()
            .map(|mut wanted| wanted.drain(..).collect())
            .unwrap_or_default();
        if self.dropped.swap(false, Ordering::SeqCst) && challenges.is_empty() {
            challenges.push(UNASKED);
        }
        if challenges.is_empty() {
            return;
        }
        let (state, size, taken) = match self.screen.lock() {
            Ok(screen) => (
                screen.parser.screen().state_formatted(),
                screen.parser.screen().size(),
                screen.taken,
            ),
            Err(_) => return,
        };
        let mut screens = Vec::with_capacity(challenges.len());
        for challenge in challenges {
            let Ok(parts) = screen_parts(&self.slot, challenge, size, &state) else {
                return;
            };
            screens.push(parts);
        }
        self.held_through = taken;
        for parts in &screens {
            for part in parts {
                if self.stopping() || !self.send(part) {
                    self.dropped.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }
    }

    fn send(&mut self, body: &Body) -> bool {
        let sent = self
            .sender
            .seal(body)
            .is_ok_and(|frame| self.topic.broadcast(frame).is_ok());
        if sent {
            self.sent_at = Instant::now();
        }
        sent
    }
}

/// Reads the topic and passes the screen requests of participants to the broadcaster, at
/// most one per second from each.
struct Listener {
    topic: Arc<LiveTopic>,
    receiver: FrameReceiver,
    peers: Arc<HostPeers>,
    wanted: Arc<Mutex<VecDeque<[u8; 16]>>>,
    stop: Arc<AtomicBool>,
}

impl Listener {
    fn run(mut self) {
        let mut answered: HashMap<NodeId, Instant> = HashMap::new();
        let mut participants_at = Instant::now();
        while !self.stop.load(Ordering::SeqCst) {
            if participants_at.elapsed() >= REREAD_EVERY {
                self.receiver.set_participants(self.peers.participants());
                participants_at = Instant::now();
            }
            let Ok(Some(frame)) = self.topic.receive(LISTEN_PAUSE) else {
                continue;
            };
            let Ok(received) = self.receiver.open(&frame) else {
                continue;
            };
            let Body::ScreenRequest { challenge } = received.body else {
                continue;
            };
            answered.retain(|_, at| at.elapsed() < SCREEN_EVERY);
            if answered.contains_key(&received.sender) {
                continue;
            }
            if let Ok(mut wanted) = self.wanted.lock()
                && wanted.len() < PENDING_SCREENS
            {
                wanted.push_back(challenge);
                answered.insert(received.sender, Instant::now());
            }
        }
    }
}

/// The participants a host deals with and the `meta` it serves them, read from the
/// repository and reread at most every [`REREAD_EVERY`].
#[derive(Debug)]
pub(crate) struct HostPeers {
    git_dir: PathBuf,
    thread: ThreadId,
    owner: ParticipantKey,
    reread_every: Duration,
    cache: Mutex<Cache>,
}

#[derive(Debug)]
struct Cache {
    participants: HashMap<NodeId, ParticipantName>,
    document: Vec<u8>,
    read_at: Instant,
}

impl HostPeers {
    /// Reads `thread`'s `meta`, owned by `owner`, from the repository at `git_dir`.
    pub(crate) fn new(
        git_dir: PathBuf,
        thread: ThreadId,
        owner: ParticipantKey,
        reread_every: Duration,
    ) -> Result<Self, HostError> {
        let cache = read(&git_dir, thread, &owner)?;
        Ok(Self {
            git_dir,
            thread,
            owner,
            reread_every,
            cache: Mutex::new(cache),
        })
    }

    /// Returns the participants' nodes and names, as the host's `meta` lists them now.
    pub(crate) fn participants(&self) -> Vec<(NodeId, ParticipantName)> {
        self.cache
            .lock()
            .map(|cache| {
                cache
                    .participants
                    .iter()
                    .map(|(node, name)| (*node, name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn reread_if_due(&self) {
        let due = self.cache.lock().is_ok_and(|mut cache| {
            let due = cache.read_at.elapsed() >= self.reread_every;
            if due {
                cache.read_at = Instant::now();
            }
            due
        });
        if !due {
            return;
        }
        if let Ok(fresh) = read(&self.git_dir, self.thread, &self.owner)
            && let Ok(mut cache) = self.cache.lock()
        {
            *cache = fresh;
        }
    }
}

impl Peers for HostPeers {
    fn admits(&self, node: &NodeId) -> bool {
        self.cache
            .lock()
            .is_ok_and(|cache| cache.participants.contains_key(node))
    }

    fn meta_for(&self, thread: ThreadId, node: &NodeId) -> Option<Vec<u8>> {
        if thread != self.thread {
            return None;
        }
        if !self.admits(node) {
            self.reread_if_due();
        }
        let cache = self.cache.lock().ok()?;
        cache
            .participants
            .contains_key(node)
            .then(|| cache.document.clone())
    }
}

fn read(git_dir: &Path, thread: ThreadId, owner: &ParticipantKey) -> Result<Cache, HostError> {
    let store = Store::open(git_dir)?;
    let (meta, document) = load_meta_document(&store, thread, owner, 0)?;
    Ok(Cache {
        participants: meta
            .participants()
            .map(|participant| (*participant.node(), participant.name().clone()))
            .collect(),
        document,
        read_at: Instant::now(),
    })
}

/// Splits `screen`, the escape sequences that redraw an agent's screen, into the bodies that
/// answer the screen request carrying `challenge`.
pub(crate) fn screen_parts(
    slot: &AgentSlot,
    challenge: [u8; 16],
    (rows, columns): (u16, u16),
    screen: &[u8],
) -> Result<Vec<Body>, HostError> {
    let chunks: Vec<&[u8]> = if screen.is_empty() {
        vec![&[]]
    } else {
        screen.chunks(MAX_CHUNK_BYTES).collect()
    };
    let parts = u16::try_from(chunks.len())
        .ok()
        .filter(|&parts| parts <= MAX_SCREEN_PARTS)
        .ok_or(HostError::ScreenTooLarge)?;
    Ok((0..parts)
        .zip(chunks)
        .map(|(part, bytes)| Body::Screen {
            slot: slot.clone(),
            rows,
            columns,
            challenge,
            part,
            parts,
            bytes: bytes.to_vec(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use mahi_core::AgentName;
    use mahi_identity::{
        LocalIdentity,
        NodeKey,
        PublicIdentity,
    };
    use mahi_store::GlobalPatterns;
    use mahi_thread::{
        Participant,
        VerifiedMeta,
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
        self,
        NewThread,
        agent_from,
        tests::repository_on_main,
    };

    struct Hosted {
        _repo: TempDir,
        store: Store,
        owner_key: PrivateKey,
        owner: ParticipantKey,
        owner_node: NodeId,
        thread: ThreadId,
        thread_key: mahi_crypto::ThreadKey,
    }

    fn hosted() -> Hosted {
        let (repo, store) = repository_on_main();
        let identity = LocalIdentity::generate();
        let owner_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let owner_node = NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap();
        let worktrees = TempDir::new().unwrap();
        let started = session::start(
            &store,
            NewThread {
                public: &PublicIdentity::from(&identity),
                node: owner_node,
                signer: &owner_key,
                participant: ParticipantName::new("alice").unwrap(),
                agent: &agent_from(std::path::Path::new("claude")),
                worktrees: worktrees.path(),
            },
            &GlobalPatterns::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        let owner = ParticipantKey::from_public_key(owner_key.public_key()).unwrap();
        Hosted {
            _repo: repo,
            store,
            owner_key,
            owner,
            owner_node,
            thread: started.thread,
            thread_key: started.key.unwrap(),
        }
    }

    fn bob() -> Participant {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        Participant::new(
            ParticipantName::new("bob").unwrap(),
            ParticipantKey::from_public_key(key.public_key()).unwrap(),
            age::x25519::Identity::generate().to_public(),
            NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap(),
        )
        .unwrap()
    }

    fn peers(hosted: &Hosted, reread_every: Duration) -> HostPeers {
        HostPeers::new(
            hosted.store.common_dir().to_path_buf(),
            hosted.thread,
            hosted.owner.clone(),
            reread_every,
        )
        .unwrap()
    }

    #[test]
    fn a_host_serves_its_participants_the_signed_meta_and_no_one_else() {
        let hosted = hosted();
        let peers = peers(&hosted, REREAD_EVERY);
        assert!(peers.admits(&hosted.owner_node));
        let document = peers.meta_for(hosted.thread, &hosted.owner_node).unwrap();
        let meta = VerifiedMeta::decode(&document, hosted.thread, &hosted.owner).unwrap();
        assert_eq!(meta.generation(), 0);
        let stranger = *bob().node();
        assert!(!peers.admits(&stranger));
        assert!(peers.meta_for(hosted.thread, &stranger).is_none());
        assert!(
            peers
                .meta_for(ThreadId::random().unwrap(), &hosted.owner_node)
                .is_none()
        );
        assert_eq!(
            peers.participants(),
            [(hosted.owner_node, ParticipantName::new("alice").unwrap())]
        );
    }

    #[test]
    fn an_invitee_added_while_hosting_is_served_after_a_reread_that_is_rate_limited() {
        let hosted = hosted();
        let bob = bob();
        let slow = peers(&hosted, Duration::from_secs(3600));
        let quick = peers(&hosted, Duration::ZERO);
        add_participant(
            &hosted.store,
            hosted.thread,
            &hosted.thread_key,
            &hosted.owner_key,
            bob.clone(),
        )
        .unwrap();
        assert!(slow.meta_for(hosted.thread, bob.node()).is_none());
        let document = quick.meta_for(hosted.thread, bob.node()).unwrap();
        let meta = VerifiedMeta::decode(&document, hosted.thread, &hosted.owner).unwrap();
        assert_eq!(meta.generation(), 1);
        assert!(quick.admits(bob.node()));
    }

    #[test]
    fn a_screen_is_split_into_numbered_parts_that_fit_a_frame() {
        let slot = AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("claude").unwrap(),
        );
        let screen = vec![b'x'; MAX_CHUNK_BYTES * 2 + 10];
        let parts = screen_parts(&slot, [3; 16], (24, 80), &screen).unwrap();
        assert_eq!(parts.len(), 3);
        let mut joined = Vec::new();
        for (index, body) in (0_u16..).zip(&parts) {
            let Body::Screen {
                part,
                parts: total,
                bytes,
                challenge,
                ..
            } = body
            else {
                panic!("not a screen");
            };
            assert_eq!((*part, *total, *challenge), (index, 3, [3; 16]));
            assert!(bytes.len() <= MAX_CHUNK_BYTES);
            joined.extend_from_slice(bytes);
        }
        assert_eq!(joined, screen);
        assert_eq!(
            screen_parts(&slot, [0; 16], (24, 80), b"").unwrap().len(),
            1
        );
        let huge = vec![0; MAX_CHUNK_BYTES * usize::from(MAX_SCREEN_PARTS) + 1];
        assert!(matches!(
            screen_parts(&slot, [0; 16], (24, 80), &huge),
            Err(HostError::ScreenTooLarge)
        ));
    }

    #[test]
    fn the_tap_numbers_what_the_screen_took_and_flags_what_the_queue_dropped() {
        let (queue, tapped) = mpsc::sync_channel(2);
        let tap = OutputTap {
            screen: Arc::new(Mutex::new(Screen {
                parser: vt100::Parser::new(24, 80, 0),
                taken: 0,
            })),
            queue,
            dropped: Arc::new(AtomicBool::new(false)),
        };
        tap.output(b"hello");
        tap.resize(WindowSize {
            rows: 30,
            cols: 100,
        });
        assert!(!tap.dropped.load(Ordering::SeqCst));
        tap.output(b" world");
        assert!(tap.dropped.load(Ordering::SeqCst));
        let screen = tap.screen.lock().unwrap();
        assert_eq!(screen.taken, 3);
        assert_eq!(screen.parser.screen().size(), (30, 100));
        assert!(screen.parser.screen().contents().contains("hello world"));
        drop(screen);
        assert!(matches!(tapped.try_recv(), Ok(Tapped::Output(1, bytes)) if bytes == b"hello"));
        assert!(matches!(tapped.try_recv(), Ok(Tapped::Resize(2, _))));
        assert!(tapped.try_recv().is_err());
    }

    fn private_config() -> (TempDir, ConfigDir) {
        let dir = TempDir::new().unwrap();
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        (dir, config)
    }

    fn some_address() -> HostAddress {
        HostAddress::new(
            NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap(),
            None,
            vec!["192.0.2.7:50000".parse().unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn a_published_address_reads_back_and_is_withdrawn() {
        let (_dir, config) = private_config();
        let thread = ThreadId::random().unwrap();
        assert!(published_address(&config, thread).is_none());
        let address = some_address();
        publish_address(&config, thread, &address).unwrap();
        assert_eq!(published_address(&config, thread), Some(address.clone()));
        let newer = some_address();
        publish_address(&config, thread, &newer).unwrap();
        assert_eq!(published_address(&config, thread), Some(newer));
        withdraw_address(&config, thread);
        assert!(published_address(&config, thread).is_none());
    }

    #[test]
    fn planted_links_are_not_followed_for_published_addresses() {
        use std::os::unix::fs::symlink;

        let (dir, config) = private_config();
        let thread = ThreadId::random().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(
            elsewhere.join(thread.to_string()),
            some_address().to_bytes().unwrap(),
        )
        .unwrap();
        crate::profile::create_private_dir(config.path()).unwrap();
        symlink(&elsewhere, config.path().join(PUBLISHED)).unwrap();
        assert!(published_address(&config, thread).is_none());
        assert!(publish_address(&config, thread, &some_address()).is_err());

        std::fs::remove_file(config.path().join(PUBLISHED)).unwrap();
        let live = config.path().join(PUBLISHED);
        crate::profile::create_private_dir(&live).unwrap();
        symlink(
            elsewhere.join(thread.to_string()),
            live.join(thread.to_string()),
        )
        .unwrap();
        assert!(published_address(&config, thread).is_none());
    }
}
