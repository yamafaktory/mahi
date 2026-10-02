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
    PROMPT_ID_BYTES,
    Peers,
    PromptOutcome,
    PromptText,
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

use crate::{
    profile,
    prompts::{
        Answer,
        Prompts,
    },
    thread_lock::{
        LiveLock,
        LockError,
    },
};

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
    #[error("the agent is already served by this host")]
    SlotTaken,
    #[error("an agent of another participant cannot be served by this host")]
    NotOwnSlot,
    #[error("cannot open the socket the user's other mahis reach the host on")]
    Hub(#[source] io::Error),
    #[error("cannot take the live layer's lock")]
    Lock(#[from] LockError),
}

/// How many chunks of output wait for the broadcaster before newer ones are dropped.
const TAP_QUEUE: usize = 1024;
/// How many prompts for another mahi's agent wait for it to take them.
const GUEST_OFFERS: usize = 32;
/// How often a host answers the screen requests of one requester at most.
const SCREEN_EVERY: Duration = Duration::from_secs(1);
/// How many screen requests from different requesters wait to be answered together.
const PENDING_SCREENS: usize = 8;
const LISTEN_PAUSE: Duration = Duration::from_millis(200);
const UNASKED: [u8; 16] = [0; 16];
const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);

const PUBLISHED: &str = "live";
#[cfg(target_os = "macos")]
const MAX_SOCKET_PATH: usize = 103;
#[cfg(not(target_os = "macos"))]
const MAX_SOCKET_PATH: usize = 107;
const HOSTS: &str = "hosts";
const MAX_PUBLISHED_BYTES: u64 = 4096;
const PUBLISH_EVERY: Duration = Duration::from_secs(2);
/// How long a host that stops keeps telling senders their prompts were dropped.
const LAST_ANSWERS_WAIT: Duration = Duration::from_secs(2);
/// The most answers a host keeps to send again after the network failed it.
const MAX_UNSENT_ANSWERS: usize = 256;

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
    read_address(&directory, thread)
}

fn hosts_dir(store: &Store) -> io::Result<OwnedFd> {
    let parent = store.common_dir().join("mahi");
    profile::create_private_dir(&parent)?;
    let parent = rustix::fs::open(
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    profile::open_private_dir(&parent, HOSTS)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the hosts directory is not a private directory",
        )
    })
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
    read_address(&directory, thread)
}

fn read_address(directory: &OwnedFd, thread: ThreadId) -> Option<HostAddress> {
    let file = rustix::fs::openat(
        directory,
        thread.to_string().as_str(),
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
        screen.parser.screen_mut().set_size(size.rows, size.cols);
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
        copy.parser = vt100::Parser::new(size.rows, size.cols, 0);
        copy.parser.process(screen);
        copy.taken += 1;
        self.dropped.store(true, Ordering::SeqCst);
    }

    fn enqueue(&self, tapped: Tapped) {
        if self.queue.try_send(tapped).is_err() {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
}

/// A prompt a teammate sent an agent another mahi of the user runs, for that mahi to offer
/// its agent.
#[derive(Debug)]
pub(crate) struct Offer {
    pub(crate) from: ParticipantName,
    pub(crate) id: [u8; PROMPT_ID_BYTES],
    pub(crate) text: PromptText,
}

/// Where the prompts for one of the agents a host serves go, and its answers come from.
enum Inbox {
    Local(Arc<Prompts>),
    Remote {
        offers: SyncSender<Offer>,
        answers: Arc<Mutex<VecDeque<Answer>>>,
    },
}

struct Hosted {
    id: AgentId,
    slot: AgentSlot,
    screen: Arc<Mutex<Screen>>,
    inbox: Inbox,
    held_through: u64,
    unsent: Vec<Answer>,
    leaving: Option<Instant>,
}

impl Hosted {
    fn is_leaving(&self) -> bool {
        self.leaving.is_some()
    }

    fn owes_answers(&self) -> bool {
        !self.unsent.is_empty()
            || match &self.inbox {
                Inbox::Local(_) => false,
                Inbox::Remote { answers, .. } => {
                    answers.lock().is_ok_and(|answers| !answers.is_empty())
                }
            }
    }

    fn take_unsent(&mut self) -> Vec<Answer> {
        let mut answers = std::mem::take(&mut self.unsent);
        if let Inbox::Remote {
            answers: queued, ..
        } = &self.inbox
            && let Ok(mut queued) = queued.lock()
        {
            answers.extend(queued.drain(..));
        }
        answers.truncate(MAX_UNSENT_ANSWERS);
        answers
    }
}

/// The agents a host serves: its own, and those of the user's other mahis in the thread.
#[derive(Default)]
struct Registry {
    agents: Vec<Hosted>,
    next: AgentId,
}

impl Registry {
    fn add(
        &mut self,
        slot: AgentSlot,
        size: WindowSize,
        inbox: Inbox,
    ) -> Option<(AgentId, Arc<Mutex<Screen>>)> {
        let mut unsent = Vec::new();
        if let Some(index) = self.agents.iter().position(|hosted| hosted.slot == slot) {
            let left = self.agents.get_mut(index)?;
            if !left.is_leaving() {
                return None;
            }
            unsent = left.take_unsent();
            self.agents.swap_remove(index);
        }
        let id = self.next;
        self.next = self.next.checked_add(1)?;
        let screen = Arc::new(Mutex::new(Screen {
            parser: vt100::Parser::new(size.rows, size.cols, 0),
            taken: 0,
        }));
        self.agents.push(Hosted {
            id,
            slot,
            screen: Arc::clone(&screen),
            inbox,
            held_through: 0,
            unsent,
            leaving: None,
        });
        Some((id, screen))
    }

    fn get(&mut self, id: AgentId) -> Option<&mut Hosted> {
        self.agents.iter_mut().find(|hosted| hosted.id == id)
    }

    fn forget_left(&mut self, now: Instant) {
        self.agents.retain(|hosted| {
            hosted
                .leaving
                .is_none_or(|until| now < until && hosted.owes_answers())
        });
    }
}

/// An agent of another of the user's mahis in the thread, which this host serves while that
/// mahi stays connected: its output and resizes go through `tap`, the prompts teammates send it
/// arrive on `offers`, and its answers go to `answers`. Dropping it stops serving the agent,
/// once the answers it passed on are sent or [`LAST_ANSWERS_WAIT`] is over.
pub(crate) struct Guest {
    id: AgentId,
    registry: Arc<Mutex<Registry>>,
    pub(crate) tap: HostTap,
    offers: Option<Receiver<Offer>>,
    answers: Arc<Mutex<VecDeque<Answer>>>,
}

impl Guest {
    /// Hands over the prompts teammates send the agent, once.
    pub(crate) fn take_offers(&mut self) -> Option<Receiver<Offer>> {
        self.offers.take()
    }

    /// Passes on what became of a prompt, for its sender; past 256 unsent, answers are lost.
    pub(crate) fn answer(&self, answer: Answer) {
        if let Ok(mut answers) = self.answers.lock()
            && answers.len() < MAX_UNSENT_ANSWERS
        {
            answers.push_back(answer);
        }
    }
}

impl std::fmt::Debug for Guest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guest").finish_non_exhaustive()
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(hosted) = registry.get(self.id)
        {
            hosted.leaving = Some(Instant::now() + LAST_ANSWERS_WAIT);
        }
    }
}

/// The live layer of a thread's host: its node, the topic its agents' terminals go to, and
/// the threads that broadcast them and answer screen requests.
#[derive(Debug)]
pub(crate) struct LiveHost {
    _hosting: LiveLock,
    node: Arc<LiveNode>,
    tap: HostTap,
    stop: Arc<AtomicBool>,
    stop_broadcast: Arc<AtomicBool>,
    listener: JoinHandle<()>,
    publisher: JoinHandle<()>,
    broadcaster: JoinHandle<()>,
    config: ConfigDir,
    thread: ThreadId,
    owner: ParticipantName,
    prompts: Arc<Prompts>,
    registry: Arc<Mutex<Registry>>,
    queue: SyncSender<Tapped>,
    dropped: Arc<AtomicBool>,
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
        prompts: Arc<Prompts>,
    ) -> Result<Self, HostError> {
        let thread = keys.thread();
        let hosting =
            LiveLock::try_acquire(&setup.config, thread)?.ok_or(HostError::AnotherHost)?;
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
        let topic = Arc::new(node.join(keys.topic(), &setup.bootstrap, None)?);
        let sender = FrameSender::new(keys.clone(), setup.node_key.secret())?;
        let mut receiver = FrameReceiver::new(keys.clone(), peers.participants());
        let owner = slot.participant().clone();
        receiver.take_prompts_for(&sender, owner.clone());
        let registry = Arc::new(Mutex::new(Registry::default()));
        let (agent, screen) = registry
            .lock()
            .ok()
            .and_then(|mut registry| registry.add(slot, size, Inbox::Local(Arc::clone(&prompts))))
            .ok_or(HostError::SlotTaken)?;
        if let Ok(mut copy) = screen.lock() {
            copy.parser.process(drawn);
        }
        let (queue, tapped) = mpsc::sync_channel(TAP_QUEUE);
        let dropped = Arc::new(AtomicBool::new(false));
        let wanted = Arc::new(Mutex::new(VecDeque::with_capacity(PENDING_SCREENS)));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_broadcast = Arc::new(AtomicBool::new(false));
        let broadcaster = Broadcaster {
            topic: Arc::clone(&topic),
            sender,
            registry: Arc::clone(&registry),
            tapped,
            dropped: Arc::clone(&dropped),
            wanted: Arc::clone(&wanted),
            stop: Arc::clone(&stop_broadcast),
            sent_at: Instant::now(),
        };
        let listener = Listener {
            topic,
            receiver,
            registry: Arc::clone(&registry),
            peers,
            wanted,
            stop: Arc::clone(&stop),
        };
        let publisher = {
            let (node, stop, config) = (Arc::clone(&node), Arc::clone(&stop), setup.config.clone());
            thread::spawn(move || publish(&node, &stop, &config, thread))
        };
        Ok(Self {
            _hosting: hosting,
            node,
            tap: HostTap {
                agent,
                screen,
                queue: queue.clone(),
                dropped: Arc::clone(&dropped),
            },
            stop,
            stop_broadcast,
            broadcaster: thread::spawn(move || broadcaster.run()),
            listener: thread::spawn(move || listener.run()),
            publisher,
            config: setup.config.clone(),
            thread,
            owner,
            prompts,
            registry,
            queue,
            dropped,
        })
    }

    /// Returns where the agent's terminal is copied.
    pub(crate) fn tap(&self) -> HostTap {
        self.tap.clone()
    }

    /// Returns what serves the agents of the user's other mahis in the thread.
    pub(crate) fn handle(&self) -> HostHandle {
        HostHandle {
            owner: self.owner.clone(),
            registry: Arc::clone(&self.registry),
            queue: self.queue.clone(),
            dropped: Arc::clone(&self.dropped),
        }
    }

    /// Stops the live layer once the agent is gone: output still queued is dropped, and so
    /// are the prompts waiting, whose senders are told.
    pub(crate) fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.listener.join();
        let _ = self.publisher.join();
        self.prompts.close();
        self.stop_broadcast.store(true, Ordering::SeqCst);
        let _ = self.broadcaster.join();
        withdraw_address(&self.config, self.thread);
        if let Ok(node) = Arc::try_unwrap(self.node) {
            let _ = node.close();
        }
    }
}

/// What serves the agents of the user's other mahis in the thread, while the host runs.
#[derive(Clone)]
pub(crate) struct HostHandle {
    owner: ParticipantName,
    registry: Arc<Mutex<Registry>>,
    queue: SyncSender<Tapped>,
    dropped: Arc<AtomicBool>,
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
                owner,
                registry: Arc::new(Mutex::new(Registry::default())),
                queue,
                dropped: Arc::new(AtomicBool::new(false)),
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

    /// Offers a teammate's prompt to the agent `slot` as a received frame would, for tests.
    #[cfg(test)]
    pub(crate) fn offer(
        &self,
        slot: &AgentSlot,
        from: ParticipantName,
        id: [u8; PROMPT_ID_BYTES],
        text: PromptText,
    ) {
        let registry = self.registry.lock().unwrap();
        let hosted = registry
            .agents
            .iter()
            .find(|hosted| &hosted.slot == slot)
            .unwrap();
        if let Inbox::Remote { offers, .. } = &hosted.inbox {
            offers.try_send(Offer { from, id, text }).unwrap();
        }
    }

    /// Takes the answers the agent `slot` sent back, for tests.
    #[cfg(test)]
    pub(crate) fn answers_of(&self, slot: &AgentSlot) -> Vec<Answer> {
        let registry = self.registry.lock().unwrap();
        let hosted = registry
            .agents
            .iter()
            .find(|hosted| &hosted.slot == slot)
            .unwrap();
        match &hosted.inbox {
            Inbox::Remote { answers, .. } => answers.lock().unwrap().drain(..).collect(),
            Inbox::Local(_) => Vec::new(),
        }
    }

    /// Returns how many agents this handle serves, for tests.
    #[cfg(test)]
    pub(crate) fn served(&self) -> usize {
        self.registry
            .lock()
            .map(|registry| {
                registry
                    .agents
                    .iter()
                    .filter(|hosted| !hosted.is_leaving())
                    .count()
            })
            .unwrap_or_default()
    }

    /// Starts serving `slot`'s agent, which another mahi of the user runs, with its terminal at
    /// `size`. The slot must be the user's, and not one already served.
    pub(crate) fn serve(&self, slot: AgentSlot, size: WindowSize) -> Result<Guest, HostError> {
        if slot.participant() != &self.owner {
            return Err(HostError::NotOwnSlot);
        }
        let (offers, offered) = mpsc::sync_channel(GUEST_OFFERS);
        let answers = Arc::new(Mutex::new(VecDeque::new()));
        let inbox = Inbox::Remote {
            offers,
            answers: Arc::clone(&answers),
        };
        let (id, screen) = self
            .registry
            .lock()
            .ok()
            .and_then(|mut registry| registry.add(slot, size, inbox))
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
            },
            offers: Some(offered),
            answers,
        })
    }
}

/// Returns the path of the socket the host of `thread`'s live layer serves the user's other
/// mahis on, in mahi's private directory in `runtime`, creating that directory.
pub(crate) fn hub_socket(runtime: &Path, thread: ThreadId) -> io::Result<PathBuf> {
    let parent = rustix::fs::open(
        runtime,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let name = format!("mahi-{}", rustix::process::geteuid().as_raw());
    profile::open_private_dir(&parent, &name)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mahi's runtime directory is not a private directory",
        )
    })?;
    let socket = runtime.join(name).join(format!("{thread}.sock"));
    if socket.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path of the socket for the user's other mahis is too long",
        ));
    }
    Ok(socket)
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
}

impl Broadcaster {
    fn run(mut self) {
        while !self.stopping() {
            self.send_screens_if_needed();
            self.send_answers(None);
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
        self.send_answers(Some(Instant::now() + LAST_ANSWERS_WAIT));
    }

    fn slots(&self) -> Vec<AgentSlot> {
        self.registry
            .lock()
            .map(|registry| {
                registry
                    .agents
                    .iter()
                    .filter(|hosted| !hosted.is_leaving())
                    .map(|hosted| hosted.slot.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn send_answers(&mut self, deadline: Option<Instant>) {
        let mut owed: Vec<(AgentId, AgentSlot, Vec<Answer>)> = match self.registry.lock() {
            Ok(mut registry) => registry
                .agents
                .iter_mut()
                .map(|hosted| {
                    let mut answers = hosted.take_unsent();
                    if let Inbox::Local(prompts) = &hosted.inbox {
                        prompts.take_answers(&mut answers);
                    }
                    (hosted.id, hosted.slot.clone(), answers)
                })
                .collect(),
            Err(_) => return,
        };
        let mut failed = false;
        for (_, slot, answers) in &mut owed {
            let mut sent = 0;
            for answer in answers.iter() {
                if failed || deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    break;
                }
                let body = Body::PromptAnswer {
                    slot: slot.clone(),
                    id: answer.id,
                    outcome: answer.outcome,
                };
                if !self.send(&body) {
                    failed = true;
                    break;
                }
                sent += 1;
            }
            answers.drain(..sent);
            answers.truncate(MAX_UNSENT_ANSWERS);
        }
        if let Ok(mut registry) = self.registry.lock() {
            for (id, _, answers) in owed {
                if let Some(hosted) = registry.get(id) {
                    hosted.unsent = answers;
                }
            }
            registry.forget_left(Instant::now());
        }
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
            for hosted in registry
                .agents
                .iter_mut()
                .filter(|hosted| !hosted.is_leaving())
            {
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
/// one per second from each, and takes the prompts they send the host's agents.
struct Listener {
    topic: Arc<LiveTopic>,
    receiver: FrameReceiver,
    registry: Arc<Mutex<Registry>>,
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
            let challenge = match received.body {
                Body::ScreenRequest { challenge } => challenge,
                Body::Prompt { slot, id, text, .. } => {
                    self.offer(&slot, received.participant, id, text);
                    continue;
                }
                _ => continue,
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

    fn offer(
        &self,
        slot: &AgentSlot,
        from: ParticipantName,
        id: [u8; PROMPT_ID_BYTES],
        text: PromptText,
    ) {
        let Ok(registry) = self.registry.lock() else {
            return;
        };
        let Some(hosted) = registry.agents.iter().find(|hosted| &hosted.slot == slot) else {
            return;
        };
        match &hosted.inbox {
            Inbox::Local(prompts) => {
                prompts.offer(from, id, text);
            }
            Inbox::Remote { offers, answers } => {
                if offers.try_send(Offer { from, id, text }).is_err()
                    && let Ok(mut answers) = answers.lock()
                    && answers.len() < MAX_UNSENT_ANSWERS
                {
                    answers.push_back(Answer {
                        id,
                        outcome: PromptOutcome::Dropped,
                    });
                }
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
        CommitKey,
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
        let tap = HostTap {
            agent: 7,
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
    fn a_leaving_guest_is_kept_until_its_answers_are_sent_and_its_slot_can_come_back() {
        let alice = ParticipantName::new("alice").unwrap();
        let codex = AgentSlot::new(alice.clone(), AgentName::new("codex").unwrap());
        let size = WindowSize { rows: 24, cols: 80 };
        let (handle, _tapped) = HostHandle::for_tests(alice);
        let dropped = Answer {
            id: [1; 16],
            outcome: PromptOutcome::Dropped,
        };
        let guest = handle.serve(codex.clone(), size).unwrap();
        guest.answer(dropped);
        drop(guest);
        assert_eq!(handle.served(), 0);
        handle.registry.lock().unwrap().forget_left(Instant::now());
        assert_eq!(handle.registry.lock().unwrap().agents.len(), 1);

        let guest = handle.serve(codex.clone(), size).unwrap();
        {
            let registry = handle.registry.lock().unwrap();
            assert_eq!(registry.agents.len(), 1);
            assert_eq!(registry.agents.first().unwrap().unsent, [dropped]);
        }
        assert!(handle.serve(codex.clone(), size).is_err());
        drop(guest);
        handle.registry.lock().unwrap().forget_left(Instant::now());
        assert_eq!(handle.registry.lock().unwrap().agents.len(), 1);
        handle
            .registry
            .lock()
            .unwrap()
            .forget_left(Instant::now() + LAST_ANSWERS_WAIT);
        assert!(handle.registry.lock().unwrap().agents.is_empty());

        let guest = handle.serve(codex, size).unwrap();
        drop(guest);
        handle.registry.lock().unwrap().forget_left(Instant::now());
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
