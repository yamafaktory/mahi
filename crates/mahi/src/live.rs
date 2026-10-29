use std::{
    collections::{
        HashMap,
        HashSet,
        VecDeque,
    },
    fs::{
        self,
        File,
    },
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
        MutexGuard,
        atomic::{
            AtomicBool,
            AtomicUsize,
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
        SystemTime,
    },
};

use mahi_core::{
    AgentSlot,
    ParticipantName,
    RefKind,
    ThreadId,
    ThreadRef,
};
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
    Received,
    Relays,
    SnapshotsAnswer,
    SnapshotsRequest,
    StateEntry,
    TurnEnd,
    TurnState,
};
use mahi_sandbox::WindowSize;
use mahi_store::{
    HistoryLimits,
    ObjectId,
    Store,
    StoreError,
};
use mahi_thread::{
    NodeId,
    ParticipantKey,
    Role,
    ThreadError,
    load_meta_document,
};
use rustix::fs::{
    AtFlags,
    Mode,
    OFlags,
};
use thiserror::Error;

use crate::{
    catch_up::{
        CatchUp,
        Heard,
    },
    claims::Claims,
    profile,
    run,
    settings::Settings,
    teammates::Teammates,
    thread_lock::{
        LiveLock,
        LockError,
    },
    turn_end::{
        self,
        LatestTurnEnds,
    },
};

/// The most snapshots a host sends in one answer.
const MAX_SERVED_COMMITS: usize = 4096;
/// The most bytes a host builds for one answer, whatever its `fetch-limit`, since it holds the
/// answer in memory.
const MAX_SERVED_BYTES: u64 = 256 << 20;

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
    #[error("another of your mahis hosts this thread's live layer")]
    AnotherHost,
    #[error("a thread panicked while it changed the threads this node hosts")]
    HostedPoisoned,
    #[error("the agent is already served by this host")]
    SlotTaken,
    #[error("an agent of another participant cannot be served by this host")]
    NotOwnSlot,
    #[error("cannot open the socket the user's other mahis reach the host on")]
    Hub(#[source] io::Error),
    #[error("cannot take the live layer's lock")]
    Lock(#[from] LockError),
    #[error("this node is not a participant of the thread")]
    NotParticipant,
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
/// How often a host sends its claims again when they did not change.
const CLAIMS_EVERY: Duration = Duration::from_secs(10);

const PUBLISHED: &str = "live";
#[cfg(target_os = "macos")]
const MAX_SOCKET_PATH: usize = 103;
#[cfg(not(target_os = "macos"))]
const MAX_SOCKET_PATH: usize = 107;
const HOSTS: &str = "hosts";
const PEERS: &str = "peers";
/// The most participants' nodes remembered for one thread.
const MAX_REMEMBERED_PEERS: usize = 32;
const NODE_NAME_BYTES: usize = 64;
/// The most entries of a thread's peers directory read, whatever they are.
const MAX_SCANNED_ENTRIES: usize = 256;
const MAX_PUBLISHED_BYTES: u64 = 4096;
const PUBLISH_EVERY: Duration = Duration::from_secs(2);
/// The most frames of teammates' agents the workspace's host keeps until the workspace reads
/// them.
const WATCH_QUEUE: usize = 1024;
/// The most bytes of teammates' agents' terminals the workspace's host keeps until the
/// workspace reads them.
const WATCH_BYTES: usize = 4 * 1024 * 1024;

/// What a host needs to open the live layer, gathered before the agent starts.
#[derive(Debug)]
pub(crate) struct LiveSetup {
    pub(crate) config: ConfigDir,
    pub(crate) runtime: PathBuf,
    pub(crate) node_key: NodeKey,
    pub(crate) owner: ParticipantKey,
    pub(crate) relays: Relays,
    pub(crate) bootstrap: Vec<HostAddress>,
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
    read_address(&directory, &thread.to_string())
}

fn mahi_dir(git_dir: &Path) -> io::Result<OwnedFd> {
    let parent = git_dir.join("mahi");
    profile::create_private_dir(&parent)?;
    Ok(rustix::fs::open(
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

fn private_dir(parent: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    profile::open_private_dir(parent, name)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mahi's directory of remembered addresses is not a private directory",
        )
    })
}

fn hosts_dir(store: &Store) -> io::Result<OwnedFd> {
    private_dir(&mahi_dir(store.common_dir())?, HOSTS)
}

fn peers_dir(git_dir: &Path, thread: ThreadId) -> io::Result<OwnedFd> {
    let peers = private_dir(&mahi_dir(git_dir)?, PEERS)?;
    private_dir(&peers, &thread.to_string())
}

/// Keeps, in the git directory `git_dir`, where a participant's node was last reached in
/// `thread`, so the thread's topic is rejoined through it later; at most
/// [`MAX_REMEMBERED_PEERS`] are kept for a thread, the one remembered longest ago going first.
pub(crate) fn remember_peer(
    git_dir: &Path,
    thread: ThreadId,
    address: &HostAddress,
) -> io::Result<()> {
    let bytes = address
        .to_bytes()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let directory = peers_dir(git_dir, thread)?;
    let name = address.node().to_string();
    let path = git_dir.join("mahi").join(PEERS).join(thread.to_string());
    let mut known = remembered_names(&path);
    if !known.iter().any(|(known, _)| *known == name) {
        known.sort_by_key(|(_, at)| *at);
        let over = (known.len() + 1).saturating_sub(MAX_REMEMBERED_PEERS);
        for (oldest, _) in known.iter().take(over) {
            rustix::fs::unlinkat(&directory, oldest.as_str(), rustix::fs::AtFlags::empty())?;
        }
    }
    profile::replace(&directory, &name, &bytes)
}

/// Returns where the participants' nodes were last reached in `thread`, as the git directory
/// `git_dir` remembers them.
pub(crate) fn remembered_peers(git_dir: &Path, thread: ThreadId) -> Vec<HostAddress> {
    let path = git_dir.join("mahi").join(PEERS).join(thread.to_string());
    if !path.is_dir() {
        return Vec::new();
    }
    let Ok(directory) = peers_dir(git_dir, thread) else {
        return Vec::new();
    };
    remembered_names(&path)
        .iter()
        .filter_map(|(name, _)| {
            read_address(&directory, name).filter(|address| address.node().to_string() == *name)
        })
        .take(MAX_REMEMBERED_PEERS)
        .collect()
}

/// Returns the peers to join `thread`'s topic through: the host of the ticket it was joined
/// with, then every participant's node remembered, each once.
pub(crate) fn bootstrap(store: &Store, thread: ThreadId) -> Vec<HostAddress> {
    let mut found: Vec<HostAddress> = remembered_host(store, thread).into_iter().collect();
    for peer in remembered_peers(store.common_dir(), thread) {
        if !found.iter().any(|known| known.node() == peer.node()) {
            found.push(peer);
        }
    }
    found
}

/// Forgets every address remembered for `thread`, as purging it does.
pub(crate) fn forget_addresses(store: &Store, thread: ThreadId) {
    if let Ok(hosts) = hosts_dir(store) {
        let _ = rustix::fs::unlinkat(
            &hosts,
            thread.to_string().as_str(),
            rustix::fs::AtFlags::empty(),
        );
    }
    let path = store
        .common_dir()
        .join("mahi")
        .join(PEERS)
        .join(thread.to_string());
    let _ = fs::remove_dir_all(path);
}

fn remembered_names(path: &Path) -> Vec<(String, SystemTime)> {
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .take(MAX_SCANNED_ENTRIES)
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let metadata = entry.metadata().ok()?;
            (name.len() == NODE_NAME_BYTES
                && name.bytes().all(|byte| byte.is_ascii_hexdigit())
                && metadata.is_file())
            .then(|| Some((name, metadata.modified().ok()?)))
            .flatten()
        })
        .collect()
}

/// Keeps, in the repository's git directory, where the host of a joined thread was last
/// reached, so resuming the user's own agent there rejoins the thread's topic through it.
pub(crate) fn remember_host(store: &Store, thread: ThreadId, host: &HostAddress) -> io::Result<()> {
    let bytes = host
        .to_bytes()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    profile::replace(&hosts_dir(store)?, &thread.to_string(), &bytes)
}

/// Returns where the host of a joined thread was last reached, if it was joined here.
pub(crate) fn remembered_host(store: &Store, thread: ThreadId) -> Option<HostAddress> {
    let directory = hosts_dir(store).ok()?;
    read_address(&directory, &thread.to_string())
}

fn read_address(directory: &OwnedFd, name: &str) -> Option<HostAddress> {
    let file = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let stat = rustix::fs::fstat(&file).ok()?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return None;
    }
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

/// A copy of an agent's screen, and how many chunks of output and resizes it has taken, so a
/// snapshot says which queued chunks it already holds.
struct Screen {
    parser: vt100::Parser,
    taken: u64,
}

/// Which of the agents a host serves a chunk belongs to.
type AgentId = u32;

/// Where an agent's terminal is copied for teammates: the host's copy of its screen, fed as
/// the output goes by, and the queue of numbered chunks to broadcast. It never blocks: when the
/// network falls behind, chunks are dropped and the broadcaster sends the whole screens again.
#[derive(Clone)]
pub(crate) struct HostTap {
    agent: AgentId,
    screen: Arc<Mutex<Screen>>,
    queue: SyncSender<Tapped>,
    dropped: Arc<AtomicBool>,
    registry: Arc<Mutex<Registry>>,
}

impl std::fmt::Debug for HostTap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostTap").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) enum Tapped {
    Output(AgentId, u64, Vec<u8>),
    Resize(AgentId, u64, WindowSize),
}

impl HostTap {
    /// Takes a chunk of the agent's output.
    pub(crate) fn output(&self, bytes: &[u8]) {
        for chunk in bytes.chunks(MAX_CHUNK_BYTES) {
            let Ok(mut screen) = self.screen.lock() else {
                return;
            };
            screen.parser.process(chunk);
            screen.taken += 1;
            let taken = screen.taken;
            self.enqueue(Tapped::Output(self.agent, taken, chunk.to_vec()));
        }
    }

    /// Takes a new size of the agent's terminal.
    pub(crate) fn resize(&self, size: WindowSize) {
        let Ok(mut screen) = self.screen.lock() else {
            return;
        };
        mahi_term::resize_screen(&mut screen.parser, size.rows, size.cols);
        screen.taken += 1;
        let taken = screen.taken;
        self.enqueue(Tapped::Resize(self.agent, taken, size));
    }

    /// Replaces the copy of the agent's screen with `screen`, drawn at `size`, and has the
    /// whole screens sent again.
    pub(crate) fn reset(&self, size: WindowSize, screen: &[u8]) {
        let Ok(mut copy) = self.screen.lock() else {
            return;
        };
        copy.parser = mahi_term::new_screen(size.rows, size.cols);
        copy.parser.process(screen);
        copy.taken += 1;
        self.dropped.store(true, Ordering::SeqCst);
    }

    /// Takes the agent's new state, which the host tells teammates.
    pub(crate) fn turn(&self, state: TurnState) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(hosted) = registry.get(self.agent)
            && hosted.state.is_none_or(|told| told.state != state)
        {
            hosted.state = Some(Told { state, sent: false });
        }
    }

    fn enqueue(&self, tapped: Tapped) {
        if self.queue.try_send(tapped).is_err() {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
}

struct Hosted {
    id: AgentId,
    slot: AgentSlot,
    screen: Arc<Mutex<Screen>>,
    held_through: u64,
    state: Option<Told>,
}

/// An agent's latest state, and whether a frame told it yet.
#[derive(Debug, Clone, Copy)]
struct Told {
    state: TurnState,
    sent: bool,
}

/// The agents a host serves: its own, and those of the user's other mahis in the thread.
#[derive(Default)]
struct Registry {
    agents: Vec<Hosted>,
    next: AgentId,
}

impl Registry {
    fn add(&mut self, slot: AgentSlot, size: WindowSize) -> Option<(AgentId, Arc<Mutex<Screen>>)> {
        if self.agents.iter().any(|hosted| hosted.slot == slot) {
            return None;
        }
        let id = self.next;
        self.next = self.next.checked_add(1)?;
        let screen = Arc::new(Mutex::new(Screen {
            parser: mahi_term::new_screen(size.rows, size.cols),
            taken: 0,
        }));
        self.agents.push(Hosted {
            id,
            slot,
            screen: Arc::clone(&screen),
            held_through: 0,
            state: None,
        });
        Some((id, screen))
    }

    fn get(&mut self, id: AgentId) -> Option<&mut Hosted> {
        self.agents.iter_mut().find(|hosted| hosted.id == id)
    }
}

/// An agent of another of the user's mahis in the thread, which this host serves while that
/// mahi stays connected: its output and resizes go through `tap`. Dropping it stops serving
/// the agent.
pub(crate) struct Guest {
    id: AgentId,
    registry: Arc<Mutex<Registry>>,
    pub(crate) tap: HostTap,
}

impl std::fmt::Debug for Guest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guest").finish_non_exhaustive()
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.agents.retain(|hosted| hosted.id != self.id);
        }
    }
}

/// The live layer of a thread's host: its node, the topic its agents' terminals go to, and
/// the threads that broadcast them and answer screen requests.
#[derive(Debug)]
pub(crate) struct LiveHost {
    _hosting: LiveLock,
    shared: SharedNode,
    tap: Option<HostTap>,
    stop: Arc<AtomicBool>,
    stop_broadcast: Arc<AtomicBool>,
    listener: JoinHandle<()>,
    publisher: JoinHandle<()>,
    catch_up: JoinHandle<()>,
    broadcaster: JoinHandle<()>,
    config: ConfigDir,
    thread: ThreadId,
    owner: ParticipantName,
    claims: Arc<Claims>,
    me: Option<AgentSlot>,
    registry: Arc<Mutex<Registry>>,
    queue: SyncSender<Tapped>,
    dropped: Arc<AtomicBool>,
    watch: Option<Watch>,
}

/// What a host serves besides the agents the user's other mahis hand it.
#[derive(Debug)]
pub(crate) enum HostRole<'a> {
    /// The agent this mahi runs itself.
    Agent(OwnAgent<'a>),
    /// No agent of its own: the workspace's host, which passes on what the teammates' hosts
    /// send, so the workspace watches their agents.
    Workspace,
}

impl<'a> HostRole<'a> {
    fn into_own(self) -> Option<OwnAgent<'a>> {
        match self {
            Self::Agent(own) => Some(own),
            Self::Workspace => None,
        }
    }
}

/// What the workspace's host passes on of the frames the teammates' hosts send, and how the
/// workspace asks them for their agents' screens.
#[derive(Debug)]
pub(crate) struct Watch {
    frames: Receiver<Received>,
    lost: Arc<AtomicBool>,
    ask: Arc<AtomicBool>,
    queued: Arc<AtomicUsize>,
}

impl Watch {
    /// Opens a watch, and the listener's half of it, which hands its screen requests to the
    /// broadcaster through `request`.
    fn open(request: &Arc<Mutex<Vec<Body>>>) -> (Self, Watching) {
        let (passed, frames) = mpsc::sync_channel(WATCH_QUEUE);
        let (lost, ask) = (Arc::<AtomicBool>::default(), Arc::<AtomicBool>::default());
        let queued = Arc::<AtomicUsize>::default();
        let watching = Watching {
            frames: passed,
            lost: Arc::clone(&lost),
            ask: Arc::clone(&ask),
            request: Arc::clone(request),
            queued: Arc::clone(&queued),
        };
        let watch = Self {
            frames,
            lost,
            ask,
            queued,
        };
        (watch, watching)
    }

    /// Applies to `teammates` at `now` what their hosts sent since the last call, and asks
    /// for their agents' screens when `teammates` wants them; returns whether what
    /// `teammates` shows changed.
    pub(crate) fn update(&self, teammates: &mut Teammates, now: Instant) -> bool {
        let mut changed = teammates.expire(now);
        for received in self.frames.try_iter().take(WATCH_QUEUE) {
            self.queued
                .fetch_sub(drawn_bytes(&received.body), Ordering::SeqCst);
            changed |= teammates.apply(&received.participant, received.body, now);
        }
        if self.lost.swap(false, Ordering::SeqCst) {
            teammates.lose();
        }
        if teammates.take_wants_screen(now) {
            self.ask.store(true, Ordering::SeqCst);
        }
        changed
    }
}

/// Returns how many bytes of an agent's terminal `body` carries.
fn drawn_bytes(body: &Body) -> usize {
    match body {
        Body::Output { bytes, .. } | Body::Screen { bytes, .. } => bytes.len(),
        _ => 0,
    }
}

/// The listener's half of a [`Watch`]: where it passes the teammates' frames on, and the
/// screen request it hands the broadcaster when the workspace asks for one.
#[derive(Debug)]
struct Watching {
    frames: SyncSender<Received>,
    lost: Arc<AtomicBool>,
    ask: Arc<AtomicBool>,
    request: Arc<Mutex<Vec<Body>>>,
    queued: Arc<AtomicUsize>,
}

impl Watching {
    /// Passes on the whole list of `states` a claims frame from `participant`'s node `sender`
    /// told, as one claims frame that holds only them, when the participant is not `owner`.
    fn pass_states(
        &self,
        (sender, participant): (NodeId, &ParticipantName),
        states: Vec<StateEntry>,
        owner: &ParticipantName,
    ) {
        if participant == owner {
            return;
        }
        self.queue(Received {
            sender,
            participant: participant.clone(),
            body: Body::Claims {
                claims: Vec::new(),
                turn_ends: Vec::new(),
                states,
            },
            told_states: true,
        });
    }

    /// Takes `received` when it draws an agent or tells its state, passing it on when the
    /// agent is a participant's other than `owner`, and noting that frames were lost when
    /// there is no room for it; returns any other frame.
    fn pass(&self, received: Received, owner: &ParticipantName) -> Option<Received> {
        if !matches!(
            received.body,
            Body::Screen { .. }
                | Body::Output { .. }
                | Body::Resize { .. }
                | Body::Heartbeat { .. }
                | Body::State(_)
        ) {
            return Some(received);
        }
        if &received.participant != owner {
            self.queue(received);
        }
        None
    }

    /// Queues `received` for the workspace, or notes that frames were lost when there is no
    /// room for it.
    fn queue(&self, received: Received) {
        let bytes = drawn_bytes(&received.body);
        let held = self.queued.fetch_add(bytes, Ordering::SeqCst) + bytes;
        if held > WATCH_BYTES || self.frames.try_send(received).is_err() {
            self.queued.fetch_sub(bytes, Ordering::SeqCst);
            self.lost.store(true, Ordering::SeqCst);
        }
    }

    /// Notes that frames were lost when the topic's count of frames it dropped, `dropped`,
    /// grew past `seen`.
    fn note_dropped(&self, dropped: u64, seen: &mut u64) {
        if dropped != *seen {
            *seen = dropped;
            self.lost.store(true, Ordering::SeqCst);
        }
    }

    /// Hands the broadcaster a request for the agents' screens, made by `receiver` so that it
    /// anchors the runs that answer, when the workspace asked for one.
    fn ask_if_wanted(&self, receiver: &mut FrameReceiver) {
        if !self.ask.swap(false, Ordering::SeqCst) {
            return;
        }
        if let (Ok(request), Ok(mut queue)) = (receiver.request_screen(), self.request.lock()) {
            queue.push(request);
        }
    }
}

/// The agent a host runs itself: its slot, its terminal's size and what it drew.
#[derive(Debug)]
pub(crate) struct OwnAgent<'a> {
    pub(crate) slot: AgentSlot,
    pub(crate) size: WindowSize,
    pub(crate) drawn: &'a [u8],
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("agents", &self.agents.len())
            .field("next", &self.next)
            .finish()
    }
}

impl LiveHost {
    /// Opens the live layer for `slot`'s agent in `thread`, whose `meta` is read from
    /// `git_dir`, with the agent's terminal at `size`.
    pub(crate) fn start(
        setup: &LiveSetup,
        git_dir: &Path,
        (slot, keys): (AgentSlot, &LiveKeys),
        (size, drawn): (WindowSize, &[u8]),
        claims: Arc<Claims>,
    ) -> Result<Self, HostError> {
        let hosting =
            LiveLock::try_acquire(&setup.config, keys.thread())?.ok_or(HostError::AnotherHost)?;
        let shared = SharedNode::bind(&setup.node_key, setup.relays)?;
        let own = OwnAgent { slot, size, drawn };
        Self::start_on(
            (&shared, hosting),
            setup,
            (git_dir, keys),
            HostRole::Agent(own),
            claims,
        )
    }

    /// Opens the live layer as [`LiveHost::start`] does, on the node `shared`, which may host
    /// other threads too, under the live-layer lock `hosting` already taken for the thread,
    /// for what `role` says, and the agents the user's other mahis hand it.
    pub(crate) fn start_on(
        (shared, hosting): (&SharedNode, LiveLock),
        setup: &LiveSetup,
        (git_dir, keys): (&Path, &LiveKeys),
        role: HostRole<'_>,
        claims: Arc<Claims>,
    ) -> Result<Self, HostError> {
        let watches = matches!(role, HostRole::Workspace);
        let own = role.into_own();
        let thread = keys.thread();
        let peers = Arc::new(HostPeers::new(
            git_dir.to_path_buf(),
            thread,
            setup.owner.clone(),
            REREAD_EVERY,
        )?);
        let participants = peers.participants();
        let owner = host_owner(own.as_ref(), &setup.node_key, &participants)?;
        withdraw_address(&setup.config, thread);
        let shared = shared.clone();
        let node = Arc::clone(&shared.node);
        let topic = Arc::new(node.join(keys.topic(), &listed(setup, &participants), None)?);
        let sender = FrameSender::new(keys.clone(), setup.node_key.secret())?;
        let receiver = FrameReceiver::new(keys.clone(), participants);
        let registry = Arc::new(Mutex::new(Registry::default()));
        let (me, own_tap) = match own {
            Some(own) => (Some(own.slot.clone()), Some(register_own(&registry, own)?)),
            None => (None, None),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let hosting_thread = Hosting::new(&peers, &registry, &setup.config);
        shared.threads.add(thread, hosting_thread.clone())?;
        let (catch_up, heard) = hosting_thread.catch_up(&node, &owner, &stop);
        let (queue, tapped) = mpsc::sync_channel(TAP_QUEUE);
        let dropped = Arc::new(AtomicBool::new(false));
        let wanted = Arc::new(Mutex::new(VecDeque::with_capacity(PENDING_SCREENS)));
        let stop_broadcast = Arc::new(AtomicBool::new(false));
        let request = Arc::new(Mutex::new(Vec::new()));
        let (watch, watching) = watches.then(|| Watch::open(&request)).unzip();
        let broadcaster = Broadcaster {
            topic: Arc::clone(&topic),
            sender,
            registry: Arc::clone(&registry),
            tapped,
            dropped: Arc::clone(&dropped),
            wanted: Arc::clone(&wanted),
            stop: Arc::clone(&stop_broadcast),
            sent_at: Instant::now(),
            claims: (Arc::clone(&claims), me.clone(), None),
            request,
            turn_ends: TurnEnds::new(git_dir, thread),
        };
        let listener = Listener {
            topic,
            receiver,
            owner: owner.clone(),
            watching,
            peers: Arc::clone(&peers),
            wanted,
            stop: Arc::clone(&stop),
            claims: Arc::clone(&claims),
            heard,
        };
        let publisher = {
            let (node, stop, config) = (Arc::clone(&node), Arc::clone(&stop), setup.config.clone());
            let (git_dir, peers) = (git_dir.to_path_buf(), Arc::clone(&peers));
            thread::spawn(move || publish(&node, &stop, (&config, &git_dir), (thread, &peers)))
        };
        Ok(Self {
            _hosting: hosting,
            shared,
            tap: own_tap.map(|(agent, screen)| HostTap {
                agent,
                screen,
                queue: queue.clone(),
                dropped: Arc::clone(&dropped),
                registry: Arc::clone(&registry),
            }),
            stop,
            stop_broadcast,
            broadcaster: thread::spawn(move || broadcaster.run()),
            listener: thread::spawn(move || listener.run()),
            publisher,
            catch_up,
            config: setup.config.clone(),
            thread,
            owner,
            claims,
            me,
            registry,
            queue,
            dropped,
            watch,
        })
    }

    /// Returns what passes on the teammates' frames, on the workspace's host.
    pub(crate) fn watch(&self) -> Option<&Watch> {
        self.watch.as_ref()
    }

    /// Returns where the agent this mahi runs copies its terminal, if it runs one.
    pub(crate) fn tap(&self) -> Option<HostTap> {
        self.tap.clone()
    }

    /// Returns what serves the agents of the user's other mahis in the thread.
    pub(crate) fn handle(&self) -> HostHandle {
        HostHandle {
            owner: self.owner.clone(),
            registry: Arc::clone(&self.registry),
            queue: self.queue.clone(),
            dropped: Arc::clone(&self.dropped),
            claims: Arc::clone(&self.claims),
            me: self.me.clone(),
        }
    }

    /// Stops the live layer once the agent it runs, if it runs one, is gone: output still
    /// queued is dropped.
    pub(crate) fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.listener.join();
        let _ = self.publisher.join();
        run::join_within(self.catch_up, run::THREAD_STOP_WAIT);
        self.stop_broadcast.store(true, Ordering::SeqCst);
        let _ = self.broadcaster.join();
        withdraw_address(&self.config, self.thread);
        self.shared.threads.remove(self.thread);
        if let Ok(node) = Arc::try_unwrap(self.shared.node) {
            let _ = node.close();
        }
    }
}

/// Returns the addresses of `setup`'s bootstrap that belong to `participants`.
fn listed(setup: &LiveSetup, participants: &[(NodeId, ParticipantName)]) -> Vec<HostAddress> {
    setup
        .bootstrap
        .iter()
        .filter(|peer| participants.iter().any(|(node, _)| node == peer.node()))
        .cloned()
        .collect()
}

/// Returns the participant a host serves the agents of: the one whose agent `own` it runs, or
/// else the participant of `participants` whose node `node_key` is.
fn host_owner(
    own: Option<&OwnAgent<'_>>,
    node_key: &NodeKey,
    participants: &[(NodeId, ParticipantName)],
) -> Result<ParticipantName, HostError> {
    if let Some(own) = own {
        return Ok(own.slot.participant().clone());
    }
    let node = NodeId::from_bytes(node_key.public()).map_err(|_| HostError::NotParticipant)?;
    participants
        .iter()
        .find(|(participant, _)| *participant == node)
        .map(|(_, name)| name.clone())
        .ok_or(HostError::NotParticipant)
}

/// Adds the agent `own` a host runs to `registry`, with what it drew so far.
fn register_own(
    registry: &Mutex<Registry>,
    own: OwnAgent<'_>,
) -> Result<(AgentId, Arc<Mutex<Screen>>), HostError> {
    let (agent, screen) = registry
        .lock()
        .ok()
        .and_then(|mut registry| registry.add(own.slot, own.size))
        .ok_or(HostError::SlotTaken)?;
    if let Ok(mut copy) = screen.lock() {
        copy.parser.process(own.drawn);
    }
    Ok((agent, screen))
}

/// A live node and the threads it hosts, shared by the hosts of one process, so the user's
/// node key is bound by one endpoint however many threads it hosts.
#[derive(Debug, Clone)]
pub(crate) struct SharedNode {
    node: Arc<LiveNode>,
    threads: Arc<HostedThreads>,
}

impl SharedNode {
    /// Binds a node with `node_key`, reaching relays as `relays` says, that hosts no thread yet.
    pub(crate) fn bind(node_key: &NodeKey, relays: Relays) -> Result<Self, HostError> {
        let threads = Arc::new(HostedThreads::default());
        let node = Arc::new(LiveNode::bind_host(
            node_key.secret(),
            relays,
            Arc::clone(&threads) as Arc<dyn Peers>,
        )?);
        Ok(Self { node, threads })
    }
}

/// The participants and `meta` of each thread a node hosts: the node admits a participant of
/// any of them, since each topic's frames are still checked against its own thread's `meta`,
/// and serves each thread's `meta` only to that thread's participants.
#[derive(Debug, Default)]
pub(crate) struct HostedThreads {
    threads: Mutex<HashMap<ThreadId, Hosting>>,
}

/// What a node hosts of one thread: its participants and `meta`, the agents it serves, and
/// the most bytes it sends of their snapshots in one answer.
#[derive(Debug, Clone)]
struct Hosting {
    peers: Arc<HostPeers>,
    registry: Arc<Mutex<Registry>>,
    fetch_limit: u64,
}

impl Hosting {
    fn new(peers: &Arc<HostPeers>, registry: &Arc<Mutex<Registry>>, config: &ConfigDir) -> Self {
        Self {
            peers: Arc::clone(peers),
            registry: Arc::clone(registry),
            fetch_limit: Settings::load(config)
                .map_or(Settings::default().fetch_limit, |settings| {
                    settings.fetch_limit
                }),
        }
    }

    /// Starts catching up with the turn ends the host hears of teammates' agents, as `local`,
    /// until `stop` is set; returns the thread doing it and where to note what is heard.
    fn catch_up(
        &self,
        node: &Arc<LiveNode>,
        local: &ParticipantName,
        stop: &Arc<AtomicBool>,
    ) -> (JoinHandle<()>, Arc<Heard>) {
        let heard = Arc::new(Heard::default());
        let catch_up = CatchUp {
            node: Arc::clone(node),
            git_dir: self.peers.git_dir.clone(),
            thread: self.peers.thread,
            owner: self.peers.owner.clone(),
            local: local.clone(),
            heard: Arc::clone(&heard),
            fetch_limit: self.fetch_limit,
        };
        (catch_up.start(Arc::clone(stop)), heard)
    }

    fn serves(&self, slot: &AgentSlot) -> bool {
        self.registry
            .lock()
            .is_ok_and(|registry| registry.agents.iter().any(|hosted| &hosted.slot == slot))
    }

    fn snapshots(&self, request: &SnapshotsRequest) -> Option<SnapshotsAnswer> {
        let store = Store::open(&self.peers.git_dir).ok()?;
        let snapshots = ThreadRef::new(request.thread, RefKind::Snapshots(request.slot.clone()));
        let head = store.head(&snapshots).ok()??;
        let tip = turn_end::latest(&store, &request.slot, head)?;
        let since = match request.since {
            Some(since) => Some(ObjectId::try_from(since.as_slice()).ok()?),
            None => None,
        };
        let mut pack = Vec::new();
        let limits = HistoryLimits {
            commits: MAX_SERVED_COMMITS,
            bytes: self.fetch_limit.min(MAX_SERVED_BYTES),
        };
        store
            .write_history_pack(since, tip, limits, &mut pack, &AtomicBool::new(false))
            .ok()?;
        Some(SnapshotsAnswer {
            tip: tip.as_bytes().try_into().ok()?,
            pack,
        })
    }
}

impl HostedThreads {
    fn threads(&self) -> Option<MutexGuard<'_, HashMap<ThreadId, Hosting>>> {
        self.threads.lock().ok()
    }

    fn add(&self, thread: ThreadId, hosting: Hosting) -> Result<(), HostError> {
        let mut threads = self.threads().ok_or(HostError::HostedPoisoned)?;
        if threads.contains_key(&thread) {
            return Err(HostError::AnotherHost);
        }
        threads.insert(thread, hosting);
        Ok(())
    }

    fn remove(&self, thread: ThreadId) {
        if let Some(mut threads) = self.threads() {
            threads.remove(&thread);
        }
    }

    fn of(&self, thread: ThreadId) -> Option<Hosting> {
        self.threads()?.get(&thread).cloned()
    }
}

impl Peers for HostedThreads {
    fn admits(&self, node: &NodeId) -> bool {
        self.threads()
            .is_some_and(|threads| threads.values().any(|hosting| hosting.peers.admits(node)))
    }

    fn meta_for(&self, thread: ThreadId, node: &NodeId) -> Option<Vec<u8>> {
        self.of(thread)?.peers.meta_for(thread, node)
    }

    fn serves_snapshots(&self, node: &NodeId, request: &SnapshotsRequest) -> bool {
        self.of(request.thread).is_some_and(|hosting| {
            hosting.peers.is_collaborator(node) && hosting.serves(&request.slot)
        })
    }

    fn snapshots_for(&self, node: &NodeId, request: &SnapshotsRequest) -> Option<SnapshotsAnswer> {
        let hosting = self.of(request.thread)?;
        hosting.peers.reread_if_due();
        (hosting.peers.is_collaborator(node) && hosting.serves(&request.slot))
            .then(|| hosting.snapshots(request))?
    }
}

/// What serves the agents of the user's other mahis in the thread, while the host runs.
#[derive(Clone)]
pub(crate) struct HostHandle {
    owner: ParticipantName,
    registry: Arc<Mutex<Registry>>,
    queue: SyncSender<Tapped>,
    dropped: Arc<AtomicBool>,
    claims: Arc<Claims>,
    me: Option<AgentSlot>,
}

impl std::fmt::Debug for HostHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostHandle").finish_non_exhaustive()
    }
}

impl HostHandle {
    /// A handle for tests, with no live layer behind it: what its agents send goes to the
    /// returned queue, and the screens can be read back.
    #[cfg(test)]
    pub(crate) fn for_tests(owner: ParticipantName) -> (Self, Receiver<Tapped>) {
        let (queue, tapped) = mpsc::sync_channel(TAP_QUEUE);
        (
            Self {
                me: Some(AgentSlot::new(
                    owner.clone(),
                    mahi_core::AgentName::new("host").unwrap(),
                )),
                owner,
                registry: Arc::new(Mutex::new(Registry::default())),
                queue,
                dropped: Arc::new(AtomicBool::new(false)),
                claims: Arc::new(Claims::default()),
            },
            tapped,
        )
    }

    /// Returns the contents of the screen of the agent `slot` this handle serves, for tests.
    #[cfg(test)]
    pub(crate) fn screen_of(&self, slot: &AgentSlot) -> Option<String> {
        let registry = self.registry.lock().ok()?;
        let hosted = registry.agents.iter().find(|hosted| &hosted.slot == slot)?;
        let screen = hosted.screen.lock().ok()?;
        Some(screen.parser.screen().contents())
    }

    /// Returns the state the agent `slot` this handle serves told last, for tests.
    #[cfg(test)]
    pub(crate) fn state_of(&self, slot: &AgentSlot) -> Option<TurnState> {
        let registry = self.registry.lock().ok()?;
        let hosted = registry.agents.iter().find(|hosted| &hosted.slot == slot)?;
        Some(hosted.state?.state)
    }

    /// Returns how many agents this handle serves, for tests.
    #[cfg(test)]
    pub(crate) fn served(&self) -> usize {
        self.registry
            .lock()
            .map(|registry| registry.agents.len())
            .unwrap_or_default()
    }

    /// Returns the claims this host keeps, and its own agent, if it runs one, whose claims
    /// they are first.
    pub(crate) fn claims(&self) -> (&Arc<Claims>, Option<&AgentSlot>) {
        (&self.claims, self.me.as_ref())
    }

    /// Starts serving `slot`'s agent, which another mahi of the user runs, with its terminal at
    /// `size`. The slot must be the user's, and not one already served.
    pub(crate) fn serve(&self, slot: AgentSlot, size: WindowSize) -> Result<Guest, HostError> {
        if slot.participant() != &self.owner {
            return Err(HostError::NotOwnSlot);
        }
        let (id, screen) = self
            .registry
            .lock()
            .ok()
            .and_then(|mut registry| registry.add(slot, size))
            .ok_or(HostError::SlotTaken)?;
        self.dropped.store(true, Ordering::SeqCst);
        Ok(Guest {
            id,
            registry: Arc::clone(&self.registry),
            tap: HostTap {
                agent: id,
                screen,
                queue: self.queue.clone(),
                dropped: Arc::clone(&self.dropped),
                registry: Arc::clone(&self.registry),
            },
        })
    }
}

/// Returns the path of the socket the host of `thread`'s live layer serves the user's other
/// mahis on, in mahi's private directory in `runtime`, creating that directory.
pub(crate) fn hub_socket(runtime: &Path, thread: ThreadId) -> io::Result<PathBuf> {
    private_socket(runtime, &format!("{thread}.sock"))
}

/// Returns the path of the socket `name` in mahi's private directory in `runtime`, creating
/// that directory, or an error when the path is too long for a socket.
fn private_socket(runtime: &Path, name: &str) -> io::Result<PathBuf> {
    let parent = rustix::fs::open(
        runtime,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let directory = format!("mahi-{}", rustix::process::geteuid().as_raw());
    profile::open_private_dir(&parent, &directory)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mahi's runtime directory is not a private directory",
        )
    })?;
    let socket = runtime.join(directory).join(name);
    if socket.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path of mahi's socket is too long",
        ));
    }
    Ok(socket)
}

/// Keeps the host's published address current, the relay it reaches and its direct
/// addresses, and remembers where each of the thread's participants is reached.
fn publish(
    node: &LiveNode,
    stop: &AtomicBool,
    (config, git_dir): (&ConfigDir, &Path),
    (thread, peers): (ThreadId, &HostPeers),
) {
    let mut published: Option<HostAddress> = None;
    let mut remembered: HashMap<NodeId, HostAddress> = HashMap::new();
    while !stop.load(Ordering::SeqCst) {
        if let Ok(address) = node.address(Duration::ZERO)
            && published.as_ref() != Some(&address)
            && publish_address(config, thread, &address).is_ok()
        {
            published = Some(address);
        }
        for (participant, _) in peers.participants() {
            if let Some(address) = node.reached(&participant)
                && remembered.get(&participant) != Some(&address)
                && remember_peer(git_dir, thread, &address).is_ok()
            {
                remembered.insert(participant, address);
            }
        }
        let deadline = Instant::now() + PUBLISH_EVERY;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(LISTEN_PAUSE);
        }
    }
}

/// Sends the agents' terminals in order: output and resizes as they were taken, and whole
/// screens when asked or after chunks were dropped, skipping the chunks a screen holds.
struct Broadcaster {
    topic: Arc<LiveTopic>,
    sender: FrameSender,
    registry: Arc<Mutex<Registry>>,
    tapped: Receiver<Tapped>,
    dropped: Arc<AtomicBool>,
    wanted: Arc<Mutex<VecDeque<[u8; 16]>>>,
    stop: Arc<AtomicBool>,
    sent_at: Instant,
    claims: (Arc<Claims>, Option<AgentSlot>, Option<Instant>),
    request: Arc<Mutex<Vec<Body>>>,
    turn_ends: TurnEnds,
}

/// Where the broadcaster reads the turn-end snapshots of the agents it serves, what it read,
/// and when.
struct TurnEnds {
    git_dir: PathBuf,
    latest: LatestTurnEnds,
    read_at: Option<Instant>,
}

impl TurnEnds {
    fn new(git_dir: &Path, thread: ThreadId) -> Self {
        Self {
            git_dir: git_dir.to_path_buf(),
            latest: LatestTurnEnds::new(thread),
            read_at: None,
        }
    }
}

impl Broadcaster {
    fn run(mut self) {
        let store = Store::open(&self.turn_ends.git_dir).ok();
        while !self.stopping() {
            self.send_screens_if_needed();
            self.send_request_if_any();
            self.send_turn_ends_if_any(store.as_ref());
            self.send_states_if_changed();
            self.send_claims_if_needed();
            if self.sent_at.elapsed() >= HEARTBEAT_EVERY {
                for slot in self.slots() {
                    self.send(&Body::Heartbeat { slot });
                }
                self.sent_at = Instant::now();
            }
            let Ok(tapped) = self.tapped.recv_timeout(LISTEN_PAUSE) else {
                continue;
            };
            self.send_screens_if_needed();
            let (agent, taken) = match &tapped {
                Tapped::Output(agent, taken, _) | Tapped::Resize(agent, taken, _) => {
                    (*agent, *taken)
                }
            };
            let Some((slot, held_through)) = self.registry.lock().ok().and_then(|mut registry| {
                registry
                    .get(agent)
                    .map(|hosted| (hosted.slot.clone(), hosted.held_through))
            }) else {
                continue;
            };
            let body = match tapped {
                Tapped::Output(_, _, bytes) => Body::Output { slot, bytes },
                Tapped::Resize(_, _, size) => Body::Resize {
                    slot,
                    rows: size.rows,
                    columns: size.cols,
                },
            };
            if taken > held_through && !self.send(&body) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        self.send(&Body::Claims {
            claims: Vec::new(),
            turn_ends: self.turn_ends.latest.known(),
            states: Vec::new(),
        });
    }

    /// Tells each state of the agents this host serves that no frame told yet; one whose
    /// frame was not sent is told again on the next pass.
    fn send_states_if_changed(&mut self) {
        let changed: Vec<StateEntry> = self
            .registry
            .lock()
            .map(|registry| {
                registry
                    .agents
                    .iter()
                    .filter_map(|hosted| {
                        let told = hosted.state.filter(|told| !told.sent)?;
                        Some(StateEntry {
                            slot: hosted.slot.clone(),
                            state: told.state,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        for entry in changed {
            if !self.send(&Body::State(entry.clone())) {
                continue;
            }
            if let Ok(mut registry) = self.registry.lock()
                && let Some(told) = registry
                    .agents
                    .iter_mut()
                    .find(|hosted| hosted.slot == entry.slot)
                    .and_then(|hosted| hosted.state.as_mut())
                && told.state == entry.state
            {
                told.sent = true;
            }
        }
    }

    /// Returns the state of each agent this host serves that told one.
    fn states(&self) -> Vec<StateEntry> {
        self.registry
            .lock()
            .map(|registry| {
                registry
                    .agents
                    .iter()
                    .filter_map(|hosted| {
                        Some(StateEntry {
                            slot: hosted.slot.clone(),
                            state: hosted.state?.state,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Announces each turn-end snapshot new among the agents this host serves, reading their
    /// snapshots at most every [`LISTEN_PAUSE`].
    fn send_turn_ends_if_any(&mut self, store: Option<&Store>) {
        let Some(store) = store else {
            return;
        };
        if self
            .turn_ends
            .read_at
            .is_some_and(|at| at.elapsed() < LISTEN_PAUSE)
        {
            return;
        }
        self.turn_ends.read_at = Some(Instant::now());
        let slots = self.slots();
        let new = self.turn_ends.latest.refresh(store, &slots);
        for ended in new {
            self.send(&Body::TurnEnded(ended));
        }
    }

    /// Sends the claims of the agents this host serves when they changed, and every
    /// [`CLAIMS_EVERY`] so others keep them.
    fn send_claims_if_needed(&mut self) {
        let (claims, me, sent_at) = &self.claims;
        let due = sent_at.is_none_or(|at| at.elapsed() >= CLAIMS_EVERY);
        if !claims.take_hosted_changed() && !due {
            return;
        }
        let body = Body::Claims {
            claims: claims.hosted(me.as_ref()),
            turn_ends: self.turn_ends.latest.known(),
            states: self.states(),
        };
        if self.send(&body) {
            self.claims.2 = Some(Instant::now());
        }
    }

    /// Sends the screen request the workspace asked for, if any.
    fn send_request_if_any(&mut self) {
        let requests = self
            .request
            .lock()
            .map(|mut queue| std::mem::take(&mut *queue))
            .unwrap_or_default();
        for request in &requests {
            self.send(request);
        }
    }

    fn slots(&self) -> Vec<AgentSlot> {
        self.registry
            .lock()
            .map(|registry| {
                registry
                    .agents
                    .iter()
                    .map(|hosted| hosted.slot.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn send_screens_if_needed(&mut self) {
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
        let mut screens = Vec::new();
        if let Ok(mut registry) = self.registry.lock() {
            for hosted in &mut registry.agents {
                let Ok(screen) = hosted.screen.lock() else {
                    continue;
                };
                let (state, size, taken) = (
                    screen.parser.screen().state_formatted(),
                    screen.parser.screen().size(),
                    screen.taken,
                );
                drop(screen);
                for challenge in &challenges {
                    if let Ok(parts) = screen_parts(&hosted.slot, *challenge, size, &state) {
                        screens.push(parts);
                    }
                }
                hosted.held_through = taken;
                if let Some(told) = &mut hosted.state {
                    told.sent = false;
                }
            }
        }
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

/// Reads the topic, passes the screen requests of participants to the broadcaster, at most
/// one per second from each.
struct Listener {
    topic: Arc<LiveTopic>,
    receiver: FrameReceiver,
    owner: ParticipantName,
    watching: Option<Watching>,
    peers: Arc<HostPeers>,
    wanted: Arc<Mutex<VecDeque<[u8; 16]>>>,
    stop: Arc<AtomicBool>,
    claims: Arc<Claims>,
    heard: Arc<Heard>,
}

impl Listener {
    fn run(mut self) {
        let mut answered: HashMap<NodeId, Instant> = HashMap::new();
        let mut participants_at = Instant::now();
        let mut dropped = self.topic.dropped();
        while !self.stop.load(Ordering::SeqCst) {
            if participants_at.elapsed() >= REREAD_EVERY {
                self.receiver.set_participants(self.peers.participants());
                participants_at = Instant::now();
            }
            if let Some(watching) = &self.watching {
                watching.note_dropped(self.topic.dropped(), &mut dropped);
                watching.ask_if_wanted(&mut self.receiver);
            }
            let Ok(Some(frame)) = self.topic.receive(LISTEN_PAUSE) else {
                continue;
            };
            let received = match self.receiver.open(&frame) {
                Ok(received) => received,
                Err(FrameError::Unanchored) => {
                    if let Some(watching) = &self.watching {
                        watching.lost.store(true, Ordering::SeqCst);
                    }
                    continue;
                }
                Err(_) => continue,
            };
            let received = match &self.watching {
                Some(watching) => match watching.pass(received, &self.owner) {
                    Some(received) => received,
                    None => continue,
                },
                None => received,
            };
            let challenge = match received.body {
                Body::ScreenRequest { challenge } => challenge,
                Body::Claims {
                    claims,
                    turn_ends,
                    states,
                } => {
                    if received.told_states
                        && let Some(watching) = &self.watching
                    {
                        let teller = (received.sender, &received.participant);
                        watching.pass_states(teller, states, &self.owner);
                    }
                    self.claims.hear(received.sender, claims);
                    self.hear_turn_ends(&received.participant, received.sender, &turn_ends);
                    continue;
                }
                Body::TurnEnded(ended) => {
                    self.hear_turn_ends(&received.participant, received.sender, &[ended]);
                    continue;
                }
                Body::Output { .. }
                | Body::Resize { .. }
                | Body::Heartbeat { .. }
                | Body::Screen { .. }
                | Body::State(_) => continue,
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

    fn hear_turn_ends(&self, participant: &ParticipantName, sender: NodeId, turn_ends: &[TurnEnd]) {
        if participant == &self.owner {
            return;
        }
        for ended in turn_ends {
            self.heard.hear(sender, ended);
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
    collaborators: HashSet<NodeId>,
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

    /// Says whether `node` is a collaborator's, as the host's `meta` lists it now.
    fn is_collaborator(&self, node: &NodeId) -> bool {
        self.cache
            .lock()
            .is_ok_and(|cache| cache.collaborators.contains(node))
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
        let fresh = read(&self.git_dir, self.thread, &self.owner);
        if let Ok(mut cache) = self.cache.lock() {
            match fresh {
                Ok(fresh) => *cache = fresh,
                Err(_) => cache.collaborators.clear(),
            }
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
        collaborators: meta
            .participants()
            .filter(|participant| participant.role() == Role::Collaborator)
            .map(|participant| *participant.node())
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
    use mahi_store::{
        EntryKind,
        GlobalPatterns,
        TakeLimits,
    };
    use mahi_term::AgentState;
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
        CommitKey,
        NewThread,
        agent_from,
        tests::repository_on_main,
    };

    struct Hosted {
        repo: TempDir,
        node_keys: TempDir,
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
        let node_key = NodeKey::generate().unwrap();
        let owner_node = NodeId::from_bytes(node_key.public()).unwrap();
        let node_keys = TempDir::new().unwrap();
        node_key.save(&node_keys.path().join("node.key")).unwrap();
        let worktrees = TempDir::new().unwrap();
        let started = session::start(
            &store,
            NewThread {
                public: &PublicIdentity::from(&identity),
                node: owner_node,
                signer: &owner_key,
                commits: &CommitKey::new(owner_key.clone()).unwrap(),
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
            repo,
            node_keys,
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

    fn bare(hosted: &Hosted) -> Hosting {
        Hosting {
            peers: Arc::new(peers(hosted, REREAD_EVERY)),
            registry: Arc::default(),
            fetch_limit: 1 << 20,
        }
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
    fn one_node_admits_every_hosted_threads_participants_and_serves_each_only_its_own_meta() {
        let (first, second) = (hosted(), hosted());
        let threads = HostedThreads::default();
        threads.add(first.thread, bare(&first)).unwrap();
        assert!(matches!(
            threads.add(first.thread, bare(&first)),
            Err(HostError::AnotherHost)
        ));
        threads.add(second.thread, bare(&second)).unwrap();
        assert!(threads.admits(&first.owner_node));
        assert!(threads.admits(&second.owner_node));
        assert!(!threads.admits(bob().node()));
        let document = threads.meta_for(first.thread, &first.owner_node).unwrap();
        VerifiedMeta::decode(&document, first.thread, &first.owner).unwrap();
        assert!(threads.meta_for(first.thread, &second.owner_node).is_none());
        assert!(threads.meta_for(second.thread, &first.owner_node).is_none());
        threads.remove(first.thread);
        assert!(!threads.admits(&first.owner_node));
        assert!(threads.meta_for(first.thread, &first.owner_node).is_none());
        assert!(threads.admits(&second.owner_node));
    }

    #[test]
    fn poisoned_hosted_threads_admit_no_one_and_host_nothing_more() {
        let (first, second) = (hosted(), hosted());
        let threads = HostedThreads::default();
        threads.add(first.thread, bare(&first)).unwrap();
        std::thread::scope(|scope| {
            let _ = scope
                .spawn(|| {
                    let _guard = threads.threads.lock();
                    panic!("poison the lock");
                })
                .join();
        });
        assert!(!threads.admits(&first.owner_node));
        assert!(threads.meta_for(first.thread, &first.owner_node).is_none());
        assert!(matches!(
            threads.add(second.thread, bare(&second)),
            Err(HostError::HostedPoisoned)
        ));
        threads.remove(first.thread);
    }

    #[test]
    fn hosts_of_two_threads_share_one_node_and_one_stops_without_the_other() {
        let (first, second) = (hosted(), hosted());
        let dir = TempDir::new().unwrap();
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        let shared = SharedNode::bind(&NodeKey::generate().unwrap(), Relays::Disabled).unwrap();
        let start = |hosted: &Hosted| {
            let setup = LiveSetup {
                config: config.clone(),
                runtime: dir.path().to_path_buf(),
                node_key: NodeKey::generate().unwrap(),
                owner: hosted.owner.clone(),
                relays: Relays::Disabled,
                bootstrap: Vec::new(),
            };
            let lock = LiveLock::try_acquire(&config, hosted.thread)
                .unwrap()
                .unwrap();
            let slot = AgentSlot::new(
                ParticipantName::new("alice").unwrap(),
                AgentName::new("claude").unwrap(),
            );
            let own = OwnAgent {
                slot,
                size: WindowSize { rows: 24, cols: 80 },
                drawn: b"",
            };
            LiveHost::start_on(
                (&shared, lock),
                &setup,
                (
                    hosted.store.common_dir(),
                    &LiveKeys::derive(&hosted.thread_key, hosted.thread).unwrap(),
                ),
                HostRole::Agent(own),
                Arc::new(Claims::default()),
            )
            .unwrap()
        };
        let one = start(&first);
        let two = start(&second);
        assert!(shared.threads.admits(&first.owner_node));
        assert!(shared.threads.admits(&second.owner_node));
        one.stop();
        assert!(!shared.threads.admits(&first.owner_node));
        assert!(
            shared
                .threads
                .meta_for(second.thread, &second.owner_node)
                .is_some()
        );
        assert!(shared.node.node().is_ok());
        let again = start(&first);
        assert!(shared.threads.admits(&first.owner_node));
        again.stop();
        two.stop();
        assert!(!shared.threads.admits(&second.owner_node));
    }

    #[test]
    fn a_host_with_no_agent_of_its_own_serves_the_users_other_mahis_only_in_its_threads() {
        let hosted = hosted();
        let dir = TempDir::new().unwrap();
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        let shared = SharedNode::bind(&NodeKey::generate().unwrap(), Relays::Disabled).unwrap();
        let keys = LiveKeys::derive(&hosted.thread_key, hosted.thread).unwrap();
        let start = |node_key: NodeKey| {
            let setup = LiveSetup {
                config: config.clone(),
                runtime: dir.path().to_path_buf(),
                node_key,
                owner: hosted.owner.clone(),
                relays: Relays::Disabled,
                bootstrap: Vec::new(),
            };
            let lock = LiveLock::try_acquire(&config, hosted.thread)
                .unwrap()
                .unwrap();
            LiveHost::start_on(
                (&shared, lock),
                &setup,
                (hosted.store.common_dir(), &keys),
                HostRole::Workspace,
                Arc::new(Claims::default()),
            )
        };
        assert!(matches!(
            start(NodeKey::generate().unwrap()),
            Err(HostError::NotParticipant)
        ));
        let host =
            start(NodeKey::load(&hosted.node_keys.path().join("node.key")).unwrap()).unwrap();
        assert!(host.tap().is_none());
        let handle = host.handle();
        assert!(handle.claims().1.is_none());
        let size = WindowSize { rows: 24, cols: 80 };
        let own = AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("codex").unwrap(),
        );
        let guest = handle.serve(own.clone(), size).unwrap();
        assert_eq!(handle.served(), 1);
        assert!(matches!(handle.serve(own, size), Err(HostError::SlotTaken)));
        let bobs = AgentSlot::new(
            ParticipantName::new("bob").unwrap(),
            AgentName::new("claude").unwrap(),
        );
        assert!(matches!(
            handle.serve(bobs, size),
            Err(HostError::NotOwnSlot)
        ));
        drop(guest);
        host.stop();
        assert!(!shared.threads.admits(&hosted.owner_node));
    }

    fn host_on(
        hosted: &Hosted,
        dir: &TempDir,
        node_key: &Path,
        (bootstrap, role): (Vec<HostAddress>, HostRole<'_>),
    ) -> (SharedNode, LiveHost) {
        host_in(
            hosted,
            hosted.store.common_dir(),
            (dir, node_key),
            (bootstrap, role),
        )
    }

    fn host_in(
        hosted: &Hosted,
        git_dir: &Path,
        (dir, node_key): (&TempDir, &Path),
        (bootstrap, role): (Vec<HostAddress>, HostRole<'_>),
    ) -> (SharedNode, LiveHost) {
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        let shared = SharedNode::bind(&NodeKey::load(node_key).unwrap(), Relays::Disabled).unwrap();
        let setup = LiveSetup {
            config: config.clone(),
            runtime: dir.path().to_path_buf(),
            node_key: NodeKey::load(node_key).unwrap(),
            owner: hosted.owner.clone(),
            relays: Relays::Disabled,
            bootstrap,
        };
        let lock = LiveLock::try_acquire(&config, hosted.thread)
            .unwrap()
            .unwrap();
        let keys = LiveKeys::derive(&hosted.thread_key, hosted.thread).unwrap();
        let host = LiveHost::start_on(
            (&shared, lock),
            &setup,
            (git_dir, &keys),
            role,
            Arc::new(Claims::default()),
        )
        .unwrap();
        (shared, host)
    }

    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    #[test]
    fn a_collaborators_host_fetches_and_accepts_a_teammates_announced_turn_end() {
        let hosted = hosted();
        let bob_signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let bob_node = NodeKey::generate().unwrap();
        let bob = Participant::new(
            ParticipantName::new("bob").unwrap(),
            ParticipantKey::from_public_key(bob_signer.public_key()).unwrap(),
            age::x25519::Identity::generate().to_public(),
            NodeId::from_bytes(bob_node.public()).unwrap(),
        )
        .unwrap();
        relist(&hosted, &bob, Role::Collaborator);
        let bobs_clone = TempDir::new().unwrap();
        copy_dir(hosted.repo.path(), bobs_clone.path());
        let bob_store = Store::open(bobs_clone.path()).unwrap();
        let slot = agent("bob");
        let snapshots = ThreadRef::new(hosted.thread, RefKind::Snapshots(slot.clone()));
        let work = bob_store.write_blob(b"bob's work").unwrap();
        let tree = bob_store
            .write_tree(&[("work", EntryKind::Blob, work)])
            .unwrap();
        let commits = CommitKey::new(bob_signer).unwrap();
        let ended = bob_store
            .append_signed(
                &snapshots,
                None,
                tree,
                &turn_end::message(&slot),
                commits.signer(),
            )
            .unwrap();

        let (bob_dir, alice_dir) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let bob_key_file = bob_dir.path().join("node.key");
        bob_node.save(&bob_key_file).unwrap();
        let (bob_shared, bob_host) = host_in(
            &hosted,
            bob_store.common_dir(),
            (&bob_dir, &bob_key_file),
            (
                Vec::new(),
                HostRole::Agent(OwnAgent {
                    slot: slot.clone(),
                    size: WindowSize { rows: 4, cols: 40 },
                    drawn: b"bob's agent",
                }),
            ),
        );
        let address = bob_shared.node.address(Duration::from_secs(1)).unwrap();
        let (_alice_shared, alice_host) = host_on(
            &hosted,
            &alice_dir,
            &hosted.node_keys.path().join("node.key"),
            (
                vec![address],
                HostRole::Agent(OwnAgent {
                    slot: agent("alice"),
                    size: WindowSize { rows: 4, cols: 40 },
                    drawn: b"alice's agent",
                }),
            ),
        );

        let deadline = Instant::now() + Duration::from_secs(40);
        while hosted.store.head(&snapshots).unwrap() != Some(ended) {
            assert!(
                Instant::now() < deadline,
                "bob's turn end never reached alice"
            );
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            hosted
                .store
                .read_entry(ended, "work", 64)
                .unwrap()
                .as_deref(),
            Some(b"bob's work".as_slice())
        );
        alice_host.stop();
        bob_host.stop();
    }

    fn watched_until(
        watch: &Watch,
        teammates: &mut Teammates,
        slot: &AgentSlot,
        text: &str,
    ) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            watch.update(teammates, Instant::now());
            let contents = teammates
                .screen(slot)
                .map(vt100::Screen::contents)
                .unwrap_or_default();
            if contents.contains(text) || Instant::now() >= deadline {
                return contents;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn the_workspaces_host_watches_a_teammates_agent() {
        let hosted = hosted();
        let bob_node = NodeKey::generate().unwrap();
        let bob_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let bob = Participant::new(
            ParticipantName::new("bob").unwrap(),
            ParticipantKey::from_public_key(bob_key.public_key()).unwrap(),
            age::x25519::Identity::generate().to_public(),
            NodeId::from_bytes(bob_node.public()).unwrap(),
        )
        .unwrap();
        add_participant(
            &hosted.store,
            hosted.thread,
            &hosted.thread_key,
            &hosted.owner_key,
            bob,
        )
        .unwrap();
        let alice_node = hosted.node_keys.path().join("node.key");
        let (alice_dir, bob_dir) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let bob_key_file = bob_dir.path().join("node.key");
        bob_node.save(&bob_key_file).unwrap();
        let (alice_shared, alice) = host_on(
            &hosted,
            &alice_dir,
            &alice_node,
            (Vec::new(), HostRole::Workspace),
        );
        assert!(alice.tap().is_none());
        let address = alice_shared.node.address(Duration::from_secs(1)).unwrap();
        let slot = AgentSlot::new(
            ParticipantName::new("bob").unwrap(),
            AgentName::new("claude").unwrap(),
        );
        let own = OwnAgent {
            slot: slot.clone(),
            size: WindowSize { rows: 4, cols: 40 },
            drawn: b"bob's agent",
        };
        let (_bob_shared, bob) = host_on(
            &hosted,
            &bob_dir,
            &bob_key_file,
            (vec![address], HostRole::Agent(own)),
        );
        assert!(bob.watch().is_none());
        let watch = alice.watch().unwrap();
        let mut teammates = Teammates::new(ParticipantName::new("alice").unwrap());
        let shown = watched_until(watch, &mut teammates, &slot, "bob's agent");
        assert!(shown.contains("bob's agent"), "{shown:?}");
        bob.tap().unwrap().output(b" works");
        let shown = watched_until(watch, &mut teammates, &slot, "bob's agent works");
        assert!(shown.contains("bob's agent works"), "{shown:?}");
        bob.tap().unwrap().turn(TurnState::Asks);
        let deadline = Instant::now() + Duration::from_secs(30);
        while teammates.agents().next().map(|(_, state)| state) != Some(AgentState::Asks) {
            assert!(Instant::now() < deadline, "the state never showed");
            watch.update(&mut teammates, Instant::now());
            thread::sleep(Duration::from_millis(50));
        }
        bob.stop();
        alice.stop();
    }

    #[test]
    fn the_states_a_claims_frame_tells_reach_the_workspace_but_not_the_users_own() {
        let (watch, watching) = Watch::open(&Arc::default());
        let node = NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap();
        let alice = ParticipantName::new("alice").unwrap();
        let bob = ParticipantName::new("bob").unwrap();
        let entry = |participant: &ParticipantName| StateEntry {
            slot: AgentSlot::new(participant.clone(), AgentName::new("claude").unwrap()),
            state: TurnState::Done,
        };
        watching.pass_states((node, &alice), vec![entry(&alice)], &alice);
        watching.pass_states((node, &bob), vec![entry(&bob)], &alice);
        let mut teammates = Teammates::new(alice.clone());
        assert!(watch.update(&mut teammates, Instant::now()));
        assert_eq!(
            teammates
                .agents()
                .map(|(slot, state)| (slot.to_string(), state))
                .collect::<Vec<_>>(),
            [("bob.claude".to_owned(), AgentState::Done)]
        );
    }

    /// Bob, a participant of `hosted`, hosting his agent `bob.claude`, and Alice's node in
    /// the thread's topic, with her sender and receiver.
    struct BobHosting {
        _dir: TempDir,
        _shared: SharedNode,
        host: LiveHost,
        slot: AgentSlot,
        _alice: LiveNode,
        topic: LiveTopic,
        sender: FrameSender,
        receiver: FrameReceiver,
    }

    fn bob_hosting(hosted: &Hosted) -> BobHosting {
        let bob_node = NodeKey::generate().unwrap();
        let bob_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let bob = Participant::new(
            ParticipantName::new("bob").unwrap(),
            ParticipantKey::from_public_key(bob_key.public_key()).unwrap(),
            age::x25519::Identity::generate().to_public(),
            NodeId::from_bytes(bob_node.public()).unwrap(),
        )
        .unwrap();
        add_participant(
            &hosted.store,
            hosted.thread,
            &hosted.thread_key,
            &hosted.owner_key,
            bob,
        )
        .unwrap();
        let bob_dir = TempDir::new().unwrap();
        let bob_key_file = bob_dir.path().join("node.key");
        bob_node.save(&bob_key_file).unwrap();
        let slot = AgentSlot::new(
            ParticipantName::new("bob").unwrap(),
            AgentName::new("claude").unwrap(),
        );
        let own = OwnAgent {
            slot: slot.clone(),
            size: WindowSize { rows: 4, cols: 40 },
            drawn: b"bob's agent",
        };
        let (bob_shared, bob_host) = host_on(
            hosted,
            &bob_dir,
            &bob_key_file,
            (Vec::new(), HostRole::Agent(own)),
        );
        let address = bob_shared.node.address(Duration::from_secs(1)).unwrap();
        let alice_key = NodeKey::load(&hosted.node_keys.path().join("node.key")).unwrap();
        let alice = LiveNode::bind_live(
            alice_key.secret(),
            Relays::Disabled,
            Arc::new(peers(hosted, REREAD_EVERY)),
        )
        .unwrap();
        let keys = LiveKeys::derive(&hosted.thread_key, hosted.thread).unwrap();
        let topic = alice
            .join(keys.topic(), &[address], Some(Duration::from_secs(20)))
            .unwrap();
        let sender = FrameSender::new(keys.clone(), alice_key.secret()).unwrap();
        let receiver = FrameReceiver::new(keys, peers(hosted, REREAD_EVERY).participants());
        BobHosting {
            _dir: bob_dir,
            _shared: bob_shared,
            host: bob_host,
            slot,
            _alice: alice,
            topic,
            sender,
            receiver,
        }
    }

    #[test]
    fn a_host_announces_its_agents_new_turn_end_snapshot() {
        let hosted = hosted();
        let mut bob = bob_hosting(&hosted);
        let slot = bob.slot.clone();

        let snapshots = ThreadRef::new(hosted.thread, RefKind::Snapshots(slot.clone()));
        let tree = hosted.store.write_tree(&[]).unwrap();
        let mut ended = None;
        let mut anchored = false;
        let mut announced = None;
        let deadline = Instant::now() + Duration::from_secs(30);
        while announced.is_none() {
            assert!(Instant::now() < deadline, "no turn end was announced");
            if !anchored {
                let request = bob.receiver.request_screen().unwrap();
                bob.topic
                    .broadcast(bob.sender.seal(&request).unwrap())
                    .unwrap();
            }
            let Ok(Some(frame)) = bob.topic.receive(Duration::from_millis(200)) else {
                continue;
            };
            let Ok(opened) = bob.receiver.open(&frame) else {
                continue;
            };
            match opened.body {
                Body::Screen { .. } if !anchored => {
                    anchored = true;
                    ended = Some(
                        hosted
                            .store
                            .append(&snapshots, None, tree, &crate::turn_end::message(&slot))
                            .unwrap(),
                    );
                }
                Body::TurnEnded(turn_end) => announced = Some(turn_end),
                _ => {}
            }
        }
        let announced = announced.unwrap();
        assert_eq!(announced.slot, slot);
        assert_eq!(announced.commit.as_slice(), ended.unwrap().as_bytes());
        bob.host.stop();
    }

    #[test]
    fn a_host_tells_its_agents_new_state_once_again_with_its_screens_and_in_its_claims() {
        let hosted = hosted();
        let mut bob = bob_hosting(&hosted);
        let told = StateEntry {
            slot: bob.slot.clone(),
            state: TurnState::Working,
        };
        let mut asked = None;
        let mut frames_told = 0;
        let mut claimed = false;
        let deadline = Instant::now() + Duration::from_secs(40);
        while !claimed {
            assert!(Instant::now() < deadline, "no claims frame told the state");
            let ask_again = frames_told == 1
                && asked.is_some_and(|at: Instant| at.elapsed() > SCREEN_EVERY * 2);
            if asked.is_none() || ask_again {
                let request = bob.receiver.request_screen().unwrap();
                bob.topic
                    .broadcast(bob.sender.seal(&request).unwrap())
                    .unwrap();
                asked = Some(Instant::now());
            }
            let Ok(Some(frame)) = bob.topic.receive(Duration::from_millis(200)) else {
                continue;
            };
            let Ok(opened) = bob.receiver.open(&frame) else {
                continue;
            };
            match opened.body {
                Body::Screen { .. } if frames_told == 0 => {
                    bob.host.tap().unwrap().turn(TurnState::Working);
                }
                Body::State(state) => {
                    assert_eq!(state, told);
                    frames_told += 1;
                }
                Body::Claims { states, .. } if frames_told == 2 => {
                    assert_eq!(states, std::slice::from_ref(&told));
                    claimed = true;
                }
                _ => {}
            }
        }
        assert_eq!(frames_told, 2);
        bob.host.stop();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "no last claims frame");
            let Ok(Some(frame)) = bob.topic.receive(Duration::from_millis(200)) else {
                continue;
            };
            if let Ok(Received {
                body: Body::Claims { claims, states, .. },
                ..
            }) = bob.receiver.open(&frame)
                && claims.is_empty()
            {
                assert!(states.is_empty());
                break;
            }
        }
    }

    #[test]
    fn a_state_told_again_unchanged_is_not_sent_again() {
        let (handle, _tapped) = HostHandle::for_tests(ParticipantName::new("alice").unwrap());
        let codex = AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("codex").unwrap(),
        );
        let guest = handle
            .serve(codex, WindowSize { rows: 24, cols: 80 })
            .unwrap();
        let sent = || {
            handle.registry.lock().unwrap().agents[0]
                .state
                .unwrap()
                .sent
        };
        let mark_sent = || {
            handle.registry.lock().unwrap().agents[0]
                .state
                .as_mut()
                .unwrap()
                .sent = true;
        };
        guest.tap.turn(TurnState::Working);
        assert!(!sent());
        mark_sent();
        guest.tap.turn(TurnState::Working);
        assert!(sent());
        guest.tap.turn(TurnState::Done);
        assert!(!sent());
    }

    fn list(hosted: &Hosted, name: &str, node: &NodeKey, role: Role) -> Participant {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let participant = Participant::new(
            ParticipantName::new(name).unwrap(),
            ParticipantKey::from_public_key(key.public_key()).unwrap(),
            age::x25519::Identity::generate().to_public(),
            NodeId::from_bytes(node.public()).unwrap(),
        )
        .unwrap();
        relist(hosted, &participant, role);
        participant
    }

    fn relist(hosted: &Hosted, participant: &Participant, role: Role) {
        add_participant(
            &hosted.store,
            hosted.thread,
            &hosted.thread_key,
            &hosted.owner_key,
            participant.clone().with_role(role),
        )
        .unwrap();
    }

    fn agent(name: &str) -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new(name).unwrap(),
            AgentName::new("claude").unwrap(),
        )
    }

    fn serving(hosted: &Hosted, slots: &[&AgentSlot]) -> HostedThreads {
        let hosting = Hosting {
            peers: Arc::new(peers(hosted, Duration::ZERO)),
            registry: Arc::default(),
            fetch_limit: 1 << 20,
        };
        for slot in slots {
            hosting
                .registry
                .lock()
                .unwrap()
                .add((*slot).clone(), WindowSize { rows: 4, cols: 40 })
                .unwrap();
        }
        let threads = HostedThreads::default();
        threads.add(hosted.thread, hosting).unwrap();
        threads
    }

    #[test]
    fn a_host_serves_only_a_current_collaborator_the_agents_it_serves() {
        let hosted = hosted();
        let bob_node = NodeKey::generate().unwrap();
        let bob = list(&hosted, "bob", &bob_node, Role::Collaborator);
        let bob_id = NodeId::from_bytes(bob_node.public()).unwrap();
        let (served, other) = (agent("frank"), agent("dave"));
        let ended = ended_snapshots(&hosted, &served);
        ended_snapshots(&hosted, &other);
        let threads = serving(&hosted, &[&served]);
        let ask = |slot: &AgentSlot| SnapshotsRequest {
            thread: hosted.thread,
            slot: slot.clone(),
            since: None,
        };

        assert!(threads.serves_snapshots(&bob_id, &ask(&served)));
        let answer = threads.snapshots_for(&bob_id, &ask(&served)).unwrap();
        assert_eq!(answer.tip.as_slice(), ended.as_bytes());
        assert!(!threads.serves_snapshots(&bob_id, &ask(&other)));
        assert!(threads.snapshots_for(&bob_id, &ask(&other)).is_none());

        relist(&hosted, &bob, Role::Watcher);
        assert!(threads.snapshots_for(&bob_id, &ask(&served)).is_none());
        assert!(!threads.serves_snapshots(&bob_id, &ask(&served)));
    }

    #[test]
    fn a_host_that_cannot_read_meta_again_serves_no_one() {
        let hosted = hosted();
        let bob_node = NodeKey::generate().unwrap();
        list(&hosted, "bob", &bob_node, Role::Collaborator);
        let bob_id = NodeId::from_bytes(bob_node.public()).unwrap();
        let served = agent("frank");
        ended_snapshots(&hosted, &served);
        let threads = serving(&hosted, &[&served]);
        let ask = SnapshotsRequest {
            thread: hosted.thread,
            slot: served,
            since: None,
        };
        assert!(threads.snapshots_for(&bob_id, &ask).is_some());

        gix::open(hosted.store.common_dir())
            .unwrap()
            .find_reference(
                ThreadRef::new(hosted.thread, RefKind::Meta)
                    .to_string()
                    .as_str(),
            )
            .unwrap()
            .delete()
            .unwrap();
        assert!(threads.snapshots_for(&bob_id, &ask).is_none());
        assert!(!threads.serves_snapshots(&bob_id, &ask));
    }

    #[test]
    fn a_host_answers_with_what_follows_the_askers_commit_and_needs_a_turn_end() {
        let hosted = hosted();
        let bob_node = NodeKey::generate().unwrap();
        list(&hosted, "bob", &bob_node, Role::Collaborator);
        let bob_id = NodeId::from_bytes(bob_node.public()).unwrap();
        let (served, unfinished) = (agent("frank"), agent("dave"));
        let ended = ended_snapshots(&hosted, &served);
        let tree = hosted.store.write_tree(&[]).unwrap();
        hosted
            .store
            .append(
                &ThreadRef::new(hosted.thread, RefKind::Snapshots(unfinished.clone())),
                None,
                tree,
                session::SNAPSHOT_MESSAGE,
            )
            .unwrap();
        let threads = serving(&hosted, &[&served, &unfinished]);
        let ask = |slot: &AgentSlot, since: Option<ObjectId>| SnapshotsRequest {
            thread: hosted.thread,
            slot: slot.clone(),
            since: since.map(|since| since.as_bytes().try_into().unwrap()),
        };

        let same = threads
            .snapshots_for(&bob_id, &ask(&served, Some(ended)))
            .unwrap();
        assert_eq!(same.tip.as_slice(), ended.as_bytes());
        assert!(same.pack.is_empty());
        let unrelated = hosted.store.write_tree(&[]).unwrap();
        let elsewhere = hosted
            .store
            .append(
                &ThreadRef::new(hosted.thread, RefKind::Snapshots(agent("erin"))),
                None,
                unrelated,
                "snapshot",
            )
            .unwrap();
        assert!(
            threads
                .snapshots_for(&bob_id, &ask(&served, Some(elsewhere)))
                .is_none()
        );
        assert!(
            threads
                .snapshots_for(&bob_id, &ask(&unfinished, None))
                .is_none()
        );
    }

    fn ended_snapshots(hosted: &Hosted, slot: &AgentSlot) -> ObjectId {
        let snapshots = ThreadRef::new(hosted.thread, RefKind::Snapshots(slot.clone()));
        let readme = hosted.store.write_blob(b"bob's work").unwrap();
        let tree = hosted
            .store
            .write_tree(&[("README", EntryKind::Blob, readme)])
            .unwrap();
        let ended = hosted
            .store
            .append(&snapshots, None, tree, &turn_end::message(slot))
            .unwrap();
        hosted
            .store
            .append(&snapshots, Some(ended), tree, session::SNAPSHOT_MESSAGE)
            .unwrap();
        ended
    }

    fn ask_as(
        key: &NodeKey,
        host: &HostAddress,
        (thread, slot): (ThreadId, &AgentSlot),
    ) -> Result<SnapshotsAnswer, LiveError> {
        let node = LiveNode::bind(key.secret(), Relays::Disabled).unwrap();
        let answer = node.fetch_snapshots(
            host,
            &SnapshotsRequest {
                thread,
                slot: slot.clone(),
                since: None,
            },
            1 << 20,
        );
        node.close().unwrap();
        answer
    }

    #[test]
    fn a_host_serves_its_agents_turn_end_snapshots_to_collaborators_only() {
        let hosted = hosted();
        let (bob_node, carol_node) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        list(&hosted, "bob", &bob_node, Role::Collaborator);
        list(&hosted, "carol", &carol_node, Role::Watcher);
        let bob_dir = TempDir::new().unwrap();
        let bob_key_file = bob_dir.path().join("node.key");
        bob_node.save(&bob_key_file).unwrap();
        let slot = AgentSlot::new(
            ParticipantName::new("bob").unwrap(),
            AgentName::new("claude").unwrap(),
        );
        let ended = ended_snapshots(&hosted, &slot);
        let own = OwnAgent {
            slot: slot.clone(),
            size: WindowSize { rows: 4, cols: 40 },
            drawn: b"bob's agent",
        };
        let (bob_shared, bob_host) = host_on(
            &hosted,
            &bob_dir,
            &bob_key_file,
            (Vec::new(), HostRole::Agent(own)),
        );
        let address = bob_shared.node.address(Duration::from_secs(1)).unwrap();
        let alice = NodeKey::load(&hosted.node_keys.path().join("node.key")).unwrap();
        let alices = AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("claude").unwrap(),
        );

        let watcher = ask_as(&carol_node, &address, (hosted.thread, &slot));
        assert!(matches!(watcher, Err(LiveError::Refused)), "{watcher:?}");
        let not_served = ask_as(&alice, &address, (hosted.thread, &alices));
        assert!(
            matches!(not_served, Err(LiveError::Refused)),
            "{not_served:?}"
        );
        let answer = ask_as(&alice, &address, (hosted.thread, &slot)).unwrap();
        assert_eq!(answer.tip.as_slice(), ended.as_bytes());
        let (_elsewhere, clone) = repository_on_main();
        let limits = TakeLimits {
            commits: 16,
            object_bytes: 1 << 20,
        };
        clone
            .take_history_pack(&answer.pack, None, ended, limits, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(
            clone.read_entry(ended, "README", 64).unwrap().as_deref(),
            Some(b"bob's work".as_slice())
        );
        bob_host.stop();
    }

    fn watching(queue: usize) -> (Watching, Receiver<Received>) {
        let (passed, frames) = mpsc::sync_channel(queue);
        let watching = Watching {
            frames: passed,
            lost: Arc::default(),
            ask: Arc::default(),
            request: Arc::default(),
            queued: Arc::default(),
        };
        (watching, frames)
    }

    fn received(participant: &str, body: Body) -> Received {
        Received {
            sender: NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap(),
            participant: ParticipantName::new(participant).unwrap(),
            body,
            told_states: false,
        }
    }

    fn output(participant: &str, bytes: usize) -> Body {
        Body::Output {
            slot: AgentSlot::new(
                ParticipantName::new(participant).unwrap(),
                AgentName::new("claude").unwrap(),
            ),
            bytes: vec![b'x'; bytes],
        }
    }

    #[test]
    fn the_workspaces_host_passes_on_only_teammates_drawing_frames() {
        let (watching, frames) = watching(8);
        let alice = ParticipantName::new("alice").unwrap();
        assert!(
            watching
                .pass(received("alice", output("alice", 10)), &alice)
                .is_none()
        );
        assert!(frames.try_recv().is_err());
        let request = Body::ScreenRequest { challenge: [1; 16] };
        let returned = watching.pass(received("bob", request.clone()), &alice);
        assert_eq!(returned.map(|received| received.body), Some(request));
        assert!(
            watching
                .pass(received("bob", output("bob", 10)), &alice)
                .is_none()
        );
        assert_eq!(frames.try_recv().unwrap().participant.as_str(), "bob");
        assert!(!watching.lost.load(Ordering::SeqCst));
    }

    #[test]
    fn frames_past_the_queues_bytes_are_dropped_and_noted_as_lost() {
        let (watching, frames) = watching(WATCH_QUEUE);
        let alice = ParticipantName::new("alice").unwrap();
        for _ in 0..=WATCH_BYTES / MAX_CHUNK_BYTES {
            watching.pass(received("bob", output("bob", MAX_CHUNK_BYTES)), &alice);
        }
        assert!(watching.lost.load(Ordering::SeqCst));
        let held: usize = frames
            .try_iter()
            .map(|received| match received.body {
                Body::Output { bytes, .. } => bytes.len(),
                _ => 0,
            })
            .sum();
        assert!(held <= WATCH_BYTES);
    }

    #[test]
    fn frames_the_topic_dropped_are_noted_as_lost_once() {
        let (watching, _frames) = watching(8);
        let mut seen = 0;
        watching.note_dropped(0, &mut seen);
        assert!(!watching.lost.load(Ordering::SeqCst));
        watching.note_dropped(3, &mut seen);
        assert!(watching.lost.swap(false, Ordering::SeqCst));
        watching.note_dropped(3, &mut seen);
        assert!(!watching.lost.load(Ordering::SeqCst));
    }

    fn peer_addresses(count: usize) -> Vec<HostAddress> {
        (0..count)
            .map(|_| {
                let node = NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap();
                HostAddress::new(
                    node,
                    Some("https://relay.example/".parse().unwrap()),
                    Vec::new(),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn the_peers_of_a_thread_are_remembered_at_most_32_the_oldest_going_first() {
        let hosted = hosted();
        let git_dir = hosted.store.common_dir();
        let addresses = peer_addresses(33);
        remember_peer(git_dir, hosted.thread, &addresses[0]).unwrap();
        let first = git_dir
            .join("mahi")
            .join(PEERS)
            .join(hosted.thread.to_string())
            .join(addresses[0].node().to_string());
        File::options()
            .write(true)
            .open(first)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        for address in &addresses[1..] {
            remember_peer(git_dir, hosted.thread, address).unwrap();
        }
        let peers = remembered_peers(git_dir, hosted.thread);
        assert_eq!(peers.len(), MAX_REMEMBERED_PEERS);
        assert!(!peers.contains(&addresses[0]));
        assert!(peers.contains(&addresses[32]));
        assert!(remembered_peers(git_dir, ThreadId::random().unwrap()).is_empty());
    }

    #[test]
    fn a_remembered_peer_is_read_only_under_its_own_node_and_purging_forgets_it() {
        let hosted = hosted();
        let git_dir = hosted.store.common_dir();
        let addresses = peer_addresses(3);
        let (host, peer, other) = (&addresses[0], &addresses[1], &addresses[2]);
        remember_host(&hosted.store, hosted.thread, host).unwrap();
        remember_peer(git_dir, hosted.thread, host).unwrap();
        remember_peer(git_dir, hosted.thread, peer).unwrap();
        let directory = git_dir
            .join("mahi")
            .join(PEERS)
            .join(hosted.thread.to_string());
        fs::copy(
            directory.join(peer.node().to_string()),
            directory.join(other.node().to_string()),
        )
        .unwrap();
        fs::write(directory.join("notes"), b"x").unwrap();
        assert_eq!(remembered_peers(git_dir, hosted.thread).len(), 2);
        assert_eq!(
            bootstrap(&hosted.store, hosted.thread),
            [host.clone(), peer.clone()]
        );
        forget_addresses(&hosted.store, hosted.thread);
        assert!(bootstrap(&hosted.store, hosted.thread).is_empty());
        assert!(!directory.exists());
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
        let tap = HostTap {
            agent: 7,
            screen: Arc::new(Mutex::new(Screen {
                parser: vt100::Parser::new(24, 80, 0),
                taken: 0,
            })),
            queue,
            dropped: Arc::new(AtomicBool::new(false)),
            registry: Arc::default(),
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
        assert!(matches!(tapped.try_recv(), Ok(Tapped::Output(7, 1, bytes)) if bytes == b"hello"));
        assert!(matches!(tapped.try_recv(), Ok(Tapped::Resize(7, 2, _))));
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

    #[test]
    fn a_served_slot_is_refused_again_until_its_guest_leaves() {
        let alice = ParticipantName::new("alice").unwrap();
        let codex = AgentSlot::new(alice.clone(), AgentName::new("codex").unwrap());
        let size = WindowSize { rows: 24, cols: 80 };
        let (handle, _tapped) = HostHandle::for_tests(alice);
        let guest = handle.serve(codex.clone(), size).unwrap();
        assert_eq!(handle.served(), 1);
        assert!(handle.serve(codex.clone(), size).is_err());
        drop(guest);
        assert_eq!(handle.served(), 0);
        let guest = handle.serve(codex, size).unwrap();
        assert_eq!(handle.served(), 1);
        drop(guest);
        assert!(handle.registry.lock().unwrap().agents.is_empty());
    }

    #[test]
    fn the_hub_socket_is_in_a_private_runtime_directory_and_a_long_path_is_refused() {
        use std::os::unix::fs::{
            PermissionsExt,
            symlink,
        };

        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let thread = ThreadId::random().unwrap();
        let socket = hub_socket(dir.path(), thread).unwrap();
        let private = socket.parent().unwrap();
        assert_eq!(private.parent(), Some(dir.path()));
        assert_eq!(
            std::fs::metadata(private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(socket.ends_with(format!("{thread}.sock")));

        let planted = TempDir::new().unwrap();
        std::fs::remove_dir(private).unwrap();
        symlink(planted.path(), private).unwrap();
        assert!(hub_socket(dir.path(), thread).is_err());

        let deep = dir.path().join("d".repeat(MAX_SOCKET_PATH));
        std::fs::create_dir(&deep).unwrap();
        let error = hub_socket(&deep, thread).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_joined_threads_host_is_remembered_in_the_git_directory() {
        let (_repo, store) = crate::session::tests::repository_on_main();
        let thread = ThreadId::random().unwrap();
        assert!(remembered_host(&store, thread).is_none());
        let host = some_address();
        remember_host(&store, thread, &host).unwrap();
        assert_eq!(remembered_host(&store, thread), Some(host));
        let newer = some_address();
        remember_host(&store, thread, &newer).unwrap();
        assert_eq!(remembered_host(&store, thread), Some(newer));

        let other = ThreadId::random().unwrap();
        let hosts = store.common_dir().join("mahi").join(HOSTS);
        let elsewhere = hosts.join("elsewhere");
        std::fs::write(&elsewhere, some_address().to_bytes().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, hosts.join(other.to_string())).unwrap();
        assert!(remembered_host(&store, other).is_none());
        #[cfg(target_os = "linux")]
        {
            let fifo = ThreadId::random().unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                hosts.join(fifo.to_string()),
                rustix::fs::FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap();
            assert!(remembered_host(&store, fifo).is_none());
        }
    }
}
