use std::{
    fmt,
    sync::{
        Arc,
        atomic::{
            AtomicU64,
            Ordering,
        },
        mpsc::{
            self,
            Receiver,
            RecvTimeoutError,
            SyncSender,
            TrySendError,
        },
    },
    time::Duration,
};

use bytes::Bytes;
use iroh::{
    endpoint::{
        Connection,
        VarInt,
    },
    protocol::{
        AcceptError,
        ProtocolHandler,
    },
};
use iroh_gossip::{
    Gossip,
    api::{
        Event,
        GossipReceiver,
        GossipSender,
    },
};
use mahi_thread::NodeId;
use n0_future::StreamExt;
use tokio::runtime::Handle;

use crate::{
    LiveError,
    MAX_FRAME_BYTES,
    Peers,
};

/// How many received frames wait for the reader before newer ones are dropped.
pub const RECEIVED_FRAMES: usize = 256;
/// The largest message iroh-gossip carries: a frame and its own framing.
pub(crate) const MAX_GOSSIP_MESSAGE_BYTES: usize = MAX_FRAME_BYTES + 4096;

const NOT_ADMITTED: u32 = 1;
const BROADCAST_WAIT: Duration = Duration::from_secs(2);

/// Hands incoming gossip connections to iroh-gossip only from the nodes `peers` admits.
#[derive(Debug, Clone)]
pub(crate) struct GossipGate {
    pub(crate) gossip: Gossip,
    pub(crate) peers: Arc<dyn Peers>,
}

impl ProtocolHandler for GossipGate {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let admitted = NodeId::from_bytes(*connection.remote_id().as_bytes())
            .is_ok_and(|node| self.peers.admits(&node));
        if !admitted {
            connection.close(VarInt::from_u32(NOT_ADMITTED), b"not admitted");
            return Ok(());
        }
        self.gossip
            .handle_connection(connection)
            .await
            .map_err(AcceptError::from_err)
    }

    async fn shutdown(&self) {
        let _ = self.gossip.shutdown().await;
    }
}

/// A thread's live topic, joined: frames to broadcast and the frames other nodes sent.
pub struct LiveTopic {
    sender: GossipSender,
    received: Receiver<Vec<u8>>,
    dropped: Arc<AtomicU64>,
    handle: Handle,
}

impl fmt::Debug for LiveTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveTopic").finish_non_exhaustive()
    }
}

impl LiveTopic {
    pub(crate) fn new(sender: GossipSender, receiver: GossipReceiver, handle: Handle) -> Self {
        let (queue, frames) = mpsc::sync_channel(RECEIVED_FRAMES);
        let dropped = Arc::new(AtomicU64::new(0));
        handle.spawn(forward(receiver, queue, Arc::clone(&dropped)));
        Self {
            sender,
            received: frames,
            dropped,
            handle,
        }
    }

    /// Sends `frame` to the other nodes of the topic, waiting at most 2 s for the topic to
    /// take it, so a peer that stops reading cannot hold the sender up.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::FrameTooLarge`] if the frame is over [`MAX_FRAME_BYTES`],
    /// [`LiveError::InsideRuntime`] if called from inside an async runtime,
    /// [`LiveError::TimedOut`] if the topic did not take the frame in time, or
    /// [`LiveError::TopicClosed`] if the topic or its node is closed.
    pub fn broadcast(&self, frame: Vec<u8>) -> Result<(), LiveError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(LiveError::FrameTooLarge);
        }
        if Handle::try_current().is_ok() {
            return Err(LiveError::InsideRuntime);
        }
        let sender = self.sender.clone();
        self.handle
            .block_on(async move {
                tokio::time::timeout(BROADCAST_WAIT, sender.broadcast(Bytes::from(frame))).await
            })
            .map_err(|_| LiveError::TimedOut)?
            .map_err(|_| LiveError::TopicClosed)
    }

    /// Returns how many received frames were dropped so far, because the reader or gossip
    /// fell behind. A viewer that sees it grow asks for the screen again.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Waits up to `wait` for the next frame another node sent, or returns `None`.
    ///
    /// Frames are handed over as received, unchecked; frames beyond [`RECEIVED_FRAMES`] that
    /// the reader has not taken yet are dropped.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::Gossip`] if the topic is gone.
    pub fn receive(&self, wait: Duration) -> Result<Option<Vec<u8>>, LiveError> {
        match self.received.recv_timeout(wait) {
            Ok(frame) => Ok(Some(frame)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(LiveError::TopicClosed),
        }
    }
}

async fn forward(
    mut receiver: GossipReceiver,
    queue: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
) {
    while let Some(event) = receiver.next().await {
        let message = match event {
            Ok(Event::Received(message)) => message,
            Ok(Event::Lagged) => {
                dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            _ => continue,
        };
        if message.content.len() > MAX_FRAME_BYTES {
            continue;
        }
        match queue.try_send(message.content.to_vec()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        time::Instant,
    };

    use mahi_core::ThreadId;

    use super::*;
    use crate::{
        HostAddress,
        LiveNode,
        Relays,
        testing::random_secret,
    };

    #[derive(Debug)]
    struct Admits(HashSet<NodeId>);

    impl Peers for Admits {
        fn admits(&self, node: &NodeId) -> bool {
            self.0.contains(node)
        }

        fn meta_for(&self, _thread: ThreadId, _node: &NodeId) -> Option<Vec<u8>> {
            None
        }
    }

    fn node_id(secret: &[u8; 32]) -> NodeId {
        NodeId::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(secret)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
    }

    fn live(secret: &[u8; 32], admitted: &[&[u8; 32]]) -> LiveNode {
        let peers = Admits(admitted.iter().map(|other| node_id(other)).collect());
        LiveNode::bind_live(secret, Relays::Disabled, Arc::new(peers)).unwrap()
    }

    fn next_frame(topic: &LiveTopic) -> Option<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(frame) = topic.receive(Duration::from_millis(100)).unwrap() {
                return Some(frame);
            }
        }
        None
    }

    #[test]
    fn admitted_nodes_exchange_frames_on_the_topic() {
        let (host_secret, viewer_secret) = (random_secret(), random_secret());
        let host = live(&host_secret, &[&viewer_secret]);
        let viewer = live(&viewer_secret, &[&host_secret]);
        let address: HostAddress = host.address(Duration::ZERO).unwrap();
        let topic = [4; 32];
        let host_topic = host.join(topic, &[], None).unwrap();
        let viewer_topic = viewer
            .join(topic, &[address], Some(Duration::from_secs(10)))
            .unwrap();
        host_topic.broadcast(b"from the host".to_vec()).unwrap();
        assert_eq!(next_frame(&viewer_topic).unwrap(), b"from the host");
        viewer_topic.broadcast(b"from the viewer".to_vec()).unwrap();
        assert_eq!(next_frame(&host_topic).unwrap(), b"from the viewer");
        viewer.close().unwrap();
        host.close().unwrap();
    }

    #[test]
    fn a_node_the_host_does_not_admit_cannot_join() {
        let (host_secret, stranger_secret) = (random_secret(), random_secret());
        let host = live(&host_secret, &[]);
        let stranger = live(&stranger_secret, &[&host_secret]);
        let address = host.address(Duration::ZERO).unwrap();
        let _host_topic = host.join([5; 32], &[], None).unwrap();
        assert!(matches!(
            stranger.join([5; 32], &[address], Some(Duration::from_secs(3))),
            Err(LiveError::TimedOut)
        ));
        stranger.close().unwrap();
        host.close().unwrap();
    }

    #[test]
    fn a_full_queue_drops_frames_and_counts_them_and_a_closed_topic_says_so() {
        let (host_secret, viewer_secret) = (random_secret(), random_secret());
        let host = live(&host_secret, &[&viewer_secret]);
        let viewer = live(&viewer_secret, &[&host_secret]);
        let address = host.address(Duration::ZERO).unwrap();
        let host_topic = host.join([7; 32], &[], None).unwrap();
        let viewer_topic = viewer
            .join([7; 32], &[address], Some(Duration::from_secs(10)))
            .unwrap();
        assert!(matches!(
            host_topic.broadcast(vec![0; MAX_FRAME_BYTES + 1]),
            Err(LiveError::FrameTooLarge)
        ));
        let sent = u64::try_from(RECEIVED_FRAMES).unwrap() + 50;
        for index in 0..sent {
            host_topic.broadcast(index.to_le_bytes().to_vec()).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while viewer_topic.dropped() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(viewer_topic.dropped() > 0);
        let mut kept = 0_u64;
        while viewer_topic
            .receive(Duration::from_millis(200))
            .unwrap()
            .is_some()
        {
            kept += 1;
        }
        assert!(kept <= u64::try_from(RECEIVED_FRAMES).unwrap());
        assert!(kept + viewer_topic.dropped() <= sent);

        host.close().unwrap();
        assert!(matches!(
            host_topic.broadcast(b"late".to_vec()),
            Err(LiveError::TopicClosed)
        ));
        viewer.close().unwrap();
    }

    #[test]
    fn a_node_bound_without_peers_cannot_join() {
        let node = LiveNode::bind(&random_secret(), Relays::Disabled).unwrap();
        assert!(matches!(
            node.join([6; 32], &[], None),
            Err(LiveError::NotLive)
        ));
        node.close().unwrap();
    }
}
