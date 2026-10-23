use std::{
    collections::{
        HashMap,
        HashSet,
    },
    sync::{
        Arc,
        Mutex,
    },
    time::{
        Duration,
        Instant,
    },
};

use iroh::{
    Endpoint,
    endpoint::{
        Connection,
        ConnectionError,
        ReadError,
        ReadToEndError,
        RecvStream,
        SendStream,
        VarInt,
    },
    protocol::{
        AcceptError,
        ProtocolHandler,
    },
};
use mahi_core::{
    AgentSlot,
    ThreadId,
};
use mahi_thread::NodeId;
use serde::{
    Deserialize,
    Serialize,
};
use tokio::sync::Semaphore;

use crate::{
    COMMIT_BYTES,
    HostAddress,
    LiveError,
    Peers,
    meta::endpoint_address,
};

/// The ALPN of the protocol a host serves its agents' turn-end snapshots on.
pub const SNAPSHOTS_ALPN: &[u8] = b"mahi/snapshots/1";
/// The largest request for snapshots, in bytes.
pub const MAX_SNAPSHOTS_REQUEST_BYTES: usize = 256;

const THREAD_ID_BYTES: usize = 16;
const REQUEST_WAIT: Duration = Duration::from_secs(5);
const ANSWER_WAIT: Duration = Duration::from_secs(60);
const DELIVERY_WAIT: Duration = Duration::from_secs(10);
const SLOT_EVERY: Duration = Duration::from_secs(5);
const DONE: u32 = 0;
const REFUSED: u32 = 1;
const UNAVAILABLE: u32 = 2;
const BUILDERS: usize = 2;

/// What a collaborator asks a host for: the turn-end snapshots of the agent `slot`, after
/// `since`, the last commit of that agent they hold, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotsRequest {
    /// The thread.
    pub thread: ThreadId,
    /// The agent whose snapshots are asked for.
    pub slot: AgentSlot,
    /// The last commit of that agent the asker holds.
    pub since: Option<[u8; COMMIT_BYTES]>,
}

/// A host's answer: the latest turn-end snapshot of the agent asked for, and a pack of its
/// history since the commit the request named.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotsAnswer {
    /// The latest turn-end snapshot.
    pub tip: [u8; COMMIT_BYTES],
    /// The pack.
    pub pack: Vec<u8>,
}

impl std::fmt::Debug for SnapshotsAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotsAnswer")
            .field("pack_bytes", &self.pack.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct WireRequest<'a> {
    thread: [u8; THREAD_ID_BYTES],
    slot: &'a str,
    since: Option<[u8; COMMIT_BYTES]>,
}

impl SnapshotsRequest {
    /// Encodes the request.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::Malformed`] if it takes more than
    /// [`MAX_SNAPSHOTS_REQUEST_BYTES`], which a valid slot never does.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LiveError> {
        let slot = self.slot.to_string();
        let bytes = postcard::to_allocvec(&WireRequest {
            thread: *self.thread.as_bytes(),
            slot: &slot,
            since: self.since,
        })
        .map_err(|_| LiveError::Malformed)?;
        if bytes.len() > MAX_SNAPSHOTS_REQUEST_BYTES {
            return Err(LiveError::Malformed);
        }
        Ok(bytes)
    }

    /// Decodes a request a peer sent.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::Malformed`] if `bytes` is not exactly one request naming a valid
    /// slot, or is longer than [`MAX_SNAPSHOTS_REQUEST_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LiveError> {
        if bytes.len() > MAX_SNAPSHOTS_REQUEST_BYTES {
            return Err(LiveError::Malformed);
        }
        let (wire, rest): (WireRequest<'_>, _) =
            postcard::take_from_bytes(bytes).map_err(|_| LiveError::Malformed)?;
        if !rest.is_empty() {
            return Err(LiveError::Malformed);
        }
        Ok(Self {
            thread: ThreadId::from_bytes(wire.thread),
            slot: wire.slot.parse().map_err(|_| LiveError::Malformed)?,
            since: wire.since,
        })
    }
}

impl SnapshotsAnswer {
    /// Decodes an answer a host sent, the tip's id then the pack, keeping the pack where it
    /// already is.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::Malformed`] if `bytes` is too short to hold the tip.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, LiveError> {
        let tip = *bytes
            .first_chunk::<COMMIT_BYTES>()
            .ok_or(LiveError::Malformed)?;
        bytes.drain(..COMMIT_BYTES);
        Ok(Self { tip, pack: bytes })
    }
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    Refused,
    Unavailable,
}

impl Failure {
    fn code(self) -> u32 {
        match self {
            Self::Refused => REFUSED,
            Self::Unavailable => UNAVAILABLE,
        }
    }
}

/// Serves the turn-end snapshots a host's [`Peers`] gives: only to a node it admits and for
/// a request it would serve, one request at a time for each peer, at most one every 5 s for
/// each agent, and at most two built at once, each holding its peer's turn until its build
/// ends, even after the answer timed out.
#[derive(Debug)]
pub(crate) struct SnapshotsHandler {
    source: Arc<dyn Peers>,
    busy: Arc<Mutex<HashSet<NodeId>>>,
    asked: Mutex<HashMap<(ThreadId, AgentSlot), Instant>>,
    builders: Arc<Semaphore>,
}

/// Lets the peer ask again once its request is over, however it ends.
struct Serving {
    busy: Arc<Mutex<HashSet<NodeId>>>,
    node: NodeId,
}

impl Drop for Serving {
    fn drop(&mut self) {
        if let Ok(mut busy) = self.busy.lock() {
            busy.remove(&self.node);
        }
    }
}

impl SnapshotsHandler {
    pub(crate) fn new(source: Arc<dyn Peers>) -> Self {
        Self {
            source,
            busy: Arc::default(),
            asked: Mutex::default(),
            builders: Arc::new(Semaphore::new(BUILDERS)),
        }
    }

    fn start(&self, node: NodeId) -> Result<Serving, Failure> {
        let mut busy = self.busy.lock().map_err(|_| Failure::Unavailable)?;
        if !busy.insert(node) {
            return Err(Failure::Unavailable);
        }
        Ok(Serving {
            busy: Arc::clone(&self.busy),
            node,
        })
    }

    fn take_turn(&self, request: &SnapshotsRequest) -> Result<(), Failure> {
        let mut asked = self.asked.lock().map_err(|_| Failure::Unavailable)?;
        let now = Instant::now();
        asked.retain(|_, at| now.duration_since(*at) < SLOT_EVERY);
        let key = (request.thread, request.slot.clone());
        if asked.contains_key(&key) {
            return Err(Failure::Unavailable);
        }
        asked.insert(key, now);
        Ok(())
    }

    async fn answer(&self, connection: &Connection) -> Result<(), Failure> {
        let node =
            NodeId::from_bytes(*connection.remote_id().as_bytes()).map_err(|_| Failure::Refused)?;
        if !self.source.admits(&node) {
            return Err(Failure::Refused);
        }
        let serving = self.start(node)?;
        let (mut send, mut receive) = tokio::time::timeout(REQUEST_WAIT, connection.accept_bi())
            .await
            .map_err(|_| Failure::Unavailable)?
            .map_err(|_| Failure::Unavailable)?;
        let answered = tokio::time::timeout(
            ANSWER_WAIT,
            self.serve((node, serving), &mut send, &mut receive),
        )
        .await
        .unwrap_or(Err(Failure::Unavailable));
        if let Err(failure) = answered {
            let _ = send.reset(VarInt::from_u32(failure.code()));
        }
        answered
    }

    async fn serve(
        &self,
        (node, serving): (NodeId, Serving),
        send: &mut SendStream,
        receive: &mut RecvStream,
    ) -> Result<(), Failure> {
        let request = tokio::time::timeout(
            REQUEST_WAIT,
            receive.read_to_end(MAX_SNAPSHOTS_REQUEST_BYTES),
        )
        .await
        .map_err(|_| Failure::Refused)?
        .map_err(|_| Failure::Refused)?;
        let request = SnapshotsRequest::from_bytes(&request).map_err(|_| Failure::Refused)?;
        if !self.source.serves_snapshots(&node, &request) {
            return Err(Failure::Refused);
        }
        let permit = Arc::clone(&self.builders)
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        self.take_turn(&request)?;
        let source = Arc::clone(&self.source);
        let answer = tokio::task::spawn_blocking(move || {
            let answer = source.snapshots_for(&node, &request);
            drop((permit, serving));
            answer
        })
        .await
        .map_err(|_| Failure::Unavailable)?
        .ok_or(Failure::Refused)?;
        send.write_all(&answer.tip)
            .await
            .map_err(|_| Failure::Unavailable)?;
        send.write_all(&answer.pack)
            .await
            .map_err(|_| Failure::Unavailable)?;
        send.finish().map_err(|_| Failure::Unavailable)
    }
}

impl ProtocolHandler for SnapshotsHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        match self.answer(&connection).await {
            Ok(()) => {
                let _ = tokio::time::timeout(DELIVERY_WAIT, connection.closed()).await;
            }
            Err(Failure::Refused) => connection.close(VarInt::from_u32(REFUSED), b"refused"),
            Err(Failure::Unavailable) => {
                connection.close(VarInt::from_u32(UNAVAILABLE), b"unavailable");
            }
        }
        Ok(())
    }
}

/// Asks the host at `host` for the snapshots `request` names, reading at most `max_bytes` of
/// its answer, as the node `endpoint` speaks as.
pub(crate) async fn fetch(
    endpoint: &Endpoint,
    host: &HostAddress,
    request: &SnapshotsRequest,
    max_bytes: usize,
) -> Result<SnapshotsAnswer, LiveError> {
    let bytes = request.to_bytes()?;
    let connection = endpoint
        .connect(endpoint_address(host)?, SNAPSHOTS_ALPN)
        .await
        .map_err(|error| LiveError::Connect(Box::new(error)))?;
    let fetched = match ask(&connection, &bytes, max_bytes).await {
        Err(LiveError::Stream(error)) => {
            Err(closed_by_host(&connection).unwrap_or(LiveError::Stream(error)))
        }
        fetched => fetched,
    };
    connection.close(VarInt::from_u32(DONE), b"done");
    SnapshotsAnswer::from_bytes(fetched?)
}

fn closed_by_host(connection: &Connection) -> Option<LiveError> {
    match connection.close_reason()? {
        ConnectionError::ApplicationClosed(close) if close.error_code != VarInt::from_u32(DONE) => {
            Some(failure(close.error_code))
        }
        _ => None,
    }
}

async fn ask(
    connection: &Connection,
    request: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, LiveError> {
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|error| LiveError::Stream(Box::new(error)))?;
    send.write_all(request)
        .await
        .map_err(|error| LiveError::Stream(Box::new(error)))?;
    send.finish()
        .map_err(|error| LiveError::Stream(Box::new(error)))?;
    match receive.read_to_end(max_bytes).await {
        Ok(answer) => Ok(answer),
        Err(ReadToEndError::Read(ReadError::Reset(code))) => Err(failure(code)),
        Err(ReadToEndError::Read(ReadError::ConnectionLost(
            ConnectionError::ApplicationClosed(close),
        ))) if close.error_code != VarInt::from_u32(DONE) => Err(failure(close.error_code)),
        Err(ReadToEndError::TooLong) => Err(LiveError::TooLarge),
        Err(error) => Err(LiveError::Stream(Box::new(error))),
    }
}

fn failure(code: VarInt) -> LiveError {
    if code == VarInt::from_u32(REFUSED) {
        LiveError::Refused
    } else {
        LiveError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{
            AtomicUsize,
            Ordering,
        },
        mpsc,
    };

    use super::*;
    use crate::{
        LiveNode,
        Relays,
        testing::random_secret,
    };

    const WAIT: Duration = Duration::from_secs(30);

    #[derive(Debug)]
    struct Collaborators {
        nodes: Vec<NodeId>,
        watcher: NodeId,
        served: AtomicUsize,
        entered: Mutex<mpsc::Sender<()>>,
        gate: Option<Mutex<mpsc::Receiver<()>>>,
    }

    impl Peers for Collaborators {
        fn admits(&self, node: &NodeId) -> bool {
            self.nodes.contains(node) || node == &self.watcher
        }

        fn meta_for(&self, _: ThreadId, _: &NodeId) -> Option<Vec<u8>> {
            None
        }

        fn serves_snapshots(&self, node: &NodeId, request: &SnapshotsRequest) -> bool {
            self.nodes.contains(node) && request.slot.participant().as_str() == "alice"
        }

        fn snapshots_for(&self, _: &NodeId, request: &SnapshotsRequest) -> Option<SnapshotsAnswer> {
            self.served.fetch_add(1, Ordering::SeqCst);
            let _ = self.entered.lock().unwrap().send(());
            if let Some(gate) = &self.gate {
                gate.lock().unwrap().recv_timeout(WAIT).unwrap();
            }
            (request.slot.agent().as_str() == "claude").then(|| SnapshotsAnswer {
                tip: [7; COMMIT_BYTES],
                pack: request
                    .since
                    .map_or(b"whole".to_vec(), |_| b"since".to_vec()),
            })
        }
    }

    struct Hosted {
        host: LiveNode,
        source: Arc<Collaborators>,
        collaborators: Vec<LiveNode>,
        watcher: LiveNode,
        stranger: LiveNode,
        address: HostAddress,
        entered: Mutex<mpsc::Receiver<()>>,
        release: mpsc::Sender<()>,
    }

    fn node() -> LiveNode {
        LiveNode::bind(&random_secret(), Relays::Disabled).unwrap()
    }

    fn hosted(gated: bool) -> Hosted {
        let collaborators: Vec<LiveNode> = (0..3).map(|_| node()).collect();
        let (watcher, stranger) = (node(), node());
        let (sender, entered) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let source = Arc::new(Collaborators {
            nodes: collaborators
                .iter()
                .map(|node| node.node().unwrap())
                .collect(),
            watcher: watcher.node().unwrap(),
            served: AtomicUsize::new(0),
            entered: Mutex::new(sender),
            gate: gated.then(|| Mutex::new(gate)),
        });
        let host = LiveNode::bind_live(
            &random_secret(),
            Relays::Disabled,
            Arc::clone(&source) as Arc<dyn Peers>,
        )
        .unwrap();
        let address = host.address(Duration::ZERO).unwrap();
        Hosted {
            host,
            source,
            collaborators,
            watcher,
            stranger,
            address,
            entered: Mutex::new(entered),
            release,
        }
    }

    impl Hosted {
        fn collaborator(&self, index: usize) -> &LiveNode {
            &self.collaborators[index]
        }

        fn fetch(&self, node: &LiveNode, slot: &str) -> Result<SnapshotsAnswer, LiveError> {
            node.fetch_snapshots(&self.address, &request(slot, None), 1024)
        }

        fn wait_for_a_build(&self) {
            self.entered.lock().unwrap().recv_timeout(WAIT).unwrap();
        }

        fn served(&self) -> usize {
            self.source.served.load(Ordering::SeqCst)
        }

        fn close(self) {
            for node in self.collaborators {
                node.close().unwrap();
            }
            self.watcher.close().unwrap();
            self.stranger.close().unwrap();
            self.host.close().unwrap();
        }
    }

    fn request(slot: &str, since: Option<[u8; COMMIT_BYTES]>) -> SnapshotsRequest {
        SnapshotsRequest {
            thread: ThreadId::from_bytes([1; THREAD_ID_BYTES]),
            slot: slot.parse().unwrap(),
            since,
        }
    }

    #[test]
    fn a_request_reads_back_the_same_and_odd_bytes_are_refused() {
        let asked = request("alice.claude", Some([3; COMMIT_BYTES]));
        let bytes = asked.to_bytes().unwrap();
        assert_eq!(SnapshotsRequest::from_bytes(&bytes).unwrap(), asked);
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(SnapshotsRequest::from_bytes(&longer).is_err());
        assert!(SnapshotsRequest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(SnapshotsRequest::from_bytes(&[0; MAX_SNAPSHOTS_REQUEST_BYTES + 1]).is_err());
        let odd_slot = postcard::to_allocvec(&WireRequest {
            thread: [1; THREAD_ID_BYTES],
            slot: "no dot here",
            since: None,
        })
        .unwrap();
        assert!(SnapshotsRequest::from_bytes(&odd_slot).is_err());
        assert!(SnapshotsAnswer::from_bytes(vec![0; COMMIT_BYTES - 1]).is_err());
        let answer = SnapshotsAnswer::from_bytes(vec![9; COMMIT_BYTES + 2]).unwrap();
        assert_eq!((answer.tip, answer.pack), ([9; COMMIT_BYTES], vec![9, 9]));
    }

    #[test]
    fn a_collaborator_gets_the_snapshots_and_anyone_else_is_refused() {
        let hosted = hosted(false);
        let whole = hosted
            .fetch(hosted.collaborator(0), "alice.claude")
            .unwrap();
        assert_eq!(
            (whole.tip, whole.pack.as_slice()),
            ([7; COMMIT_BYTES], b"whole".as_slice())
        );
        for (node, slot) in [
            (&hosted.stranger, "alice.claude"),
            (&hosted.watcher, "alice.claude"),
            (hosted.collaborator(0), "bob.claude"),
            (hosted.collaborator(0), "alice.codex"),
        ] {
            let refused = hosted.fetch(node, slot);
            assert!(matches!(refused, Err(LiveError::Refused)), "{refused:?}");
        }
        let since = hosted.collaborator(0).fetch_snapshots(
            &hosted.address,
            &request("alice.gemini", Some([1; COMMIT_BYTES])),
            1024,
        );
        assert!(matches!(since, Err(LiveError::Refused)), "{since:?}");
        assert_eq!(hosted.served(), 3);
        hosted.close();
    }

    #[test]
    fn a_request_since_a_commit_is_answered_with_what_follows_it() {
        let hosted = hosted(false);
        let since = hosted
            .collaborator(0)
            .fetch_snapshots(
                &hosted.address,
                &request("alice.claude", Some([1; COMMIT_BYTES])),
                1024,
            )
            .unwrap();
        assert_eq!(since.pack, b"since");
        hosted.close();
    }

    #[test]
    fn a_refused_request_takes_no_agents_turn() {
        let hosted = hosted(false);
        let refused = hosted.fetch(&hosted.watcher, "alice.claude");
        assert!(matches!(refused, Err(LiveError::Refused)), "{refused:?}");
        assert!(hosted.fetch(hosted.collaborator(0), "alice.claude").is_ok());
        hosted.close();
    }

    #[test]
    fn an_agent_is_served_at_most_once_every_five_seconds() {
        let hosted = hosted(false);
        assert!(hosted.fetch(hosted.collaborator(0), "alice.claude").is_ok());
        let again = hosted.fetch(hosted.collaborator(0), "alice.claude");
        assert!(matches!(again, Err(LiveError::Unavailable)), "{again:?}");
        assert_eq!(hosted.served(), 1);
        hosted.close();
    }

    #[test]
    fn a_peer_is_served_one_request_at_a_time() {
        let hosted = hosted(true);
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| hosted.fetch(hosted.collaborator(0), "alice.claude"));
            hosted.wait_for_a_build();
            let second = hosted.fetch(hosted.collaborator(0), "alice.codex");
            hosted.release.send(()).unwrap();
            (first.join().unwrap(), second)
        });
        assert!(first.is_ok(), "{first:?}");
        assert!(matches!(second, Err(LiveError::Unavailable)), "{second:?}");
        assert_eq!(hosted.served(), 1);
        hosted.close();
    }

    #[test]
    fn at_most_two_answers_are_built_at_once() {
        let hosted = hosted(true);
        let third = std::thread::scope(|scope| {
            let builds: Vec<_> = ["alice.claude", "alice.codex"]
                .into_iter()
                .enumerate()
                .map(|(index, slot)| {
                    let hosted = &hosted;
                    let build = scope.spawn(move || hosted.fetch(hosted.collaborator(index), slot));
                    hosted.wait_for_a_build();
                    build
                })
                .collect();
            let third = hosted.fetch(hosted.collaborator(2), "alice.gemini");
            for _ in &builds {
                hosted.release.send(()).unwrap();
            }
            for build in builds {
                let _ = build.join().unwrap();
            }
            third
        });
        assert!(matches!(third, Err(LiveError::Unavailable)), "{third:?}");
        assert_eq!(hosted.served(), 2);
        hosted.close();
    }

    #[test]
    fn an_answer_past_the_askers_limit_is_not_taken() {
        let hosted = hosted(false);
        let fetched = hosted.collaborator(0).fetch_snapshots(
            &hosted.address,
            &request("alice.claude", None),
            COMMIT_BYTES + 2,
        );
        assert!(matches!(fetched, Err(LiveError::TooLarge)), "{fetched:?}");
        hosted.close();
    }
}
