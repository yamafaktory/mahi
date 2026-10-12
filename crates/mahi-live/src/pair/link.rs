use std::{
    fmt,
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicBool,
            Ordering,
        },
        mpsc,
    },
    time::Duration,
};

use iroh::{
    endpoint::{
        Connection,
        RecvStream,
        SendStream,
        VarInt,
    },
    protocol::{
        AcceptError,
        ProtocolHandler,
        Router,
    },
};
use mahi_thread::NodeId;

use super::MAX_SEALED_BYTES;
use crate::{
    HostAddress,
    LiveError,
    LiveNode,
    Relays,
    meta::endpoint_address,
};

/// The ALPN of the pairing protocol.
pub const PAIR_ALPN: &[u8] = b"mahi/pair/1";
/// How long one step of a pairing may take once the two sides are connected.
pub const STEP_WAIT: Duration = Duration::from_secs(15);
const TAKEN: u32 = 1;
const DONE: u32 = 0;

type Accepted = (Connection, SendStream, RecvStream);

/// The owner's side of a pairing: an endpoint with a key made for this pairing alone, which
/// takes the first connection that opens a stream; a connection that opens none within
/// [`STEP_WAIT`] is closed without using the pairing up, and every one after the first that
/// does is closed at once.
pub struct PairListener {
    accepted: Mutex<mpsc::Receiver<Accepted>>,
    router: Option<Router>,
    node: LiveNode,
}

impl fmt::Debug for PairListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairListener")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct FirstOnly {
    taken: AtomicBool,
    accepted: Mutex<Option<mpsc::SyncSender<Accepted>>>,
}

impl ProtocolHandler for FirstOnly {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let Ok(Ok((send, receive))) = tokio::time::timeout(STEP_WAIT, connection.accept_bi()).await
        else {
            connection.close(VarInt::from_u32(TAKEN), b"no stream");
            return Ok(());
        };
        if self.taken.swap(true, Ordering::SeqCst) {
            connection.close(VarInt::from_u32(TAKEN), b"taken");
            return Ok(());
        }
        let sender = self.accepted.lock().ok().and_then(|mut held| held.take());
        if let Some(sender) = sender {
            let kept = connection.clone();
            if sender.send((connection, send, receive)).is_ok() {
                let _ = kept.closed().await;
            }
        }
        Ok(())
    }
}

impl PairListener {
    /// Binds an endpoint with a fresh key and waits for a pairing on it.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`LiveNode::bind`], or [`LiveError::Runtime`] when the system
    /// gives no random bytes for the key.
    pub fn bind(relays: Relays) -> Result<Self, LiveError> {
        let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
        getrandom::fill(secret.as_mut())
            .map_err(|error| LiveError::Runtime(std::io::Error::other(error)))?;
        let node = LiveNode::bind(&secret, relays)?;
        let (sender, accepted) = mpsc::sync_channel(1);
        let handler = FirstOnly {
            taken: AtomicBool::new(false),
            accepted: Mutex::new(Some(sender)),
        };
        let endpoint = node.endpoint().clone();
        let router = node.block_on(async move {
            Router::builder(endpoint)
                .accept(PAIR_ALPN, Arc::new(handler))
                .spawn()
        })?;
        Ok(Self {
            node,
            router: Some(router),
            accepted: Mutex::new(accepted),
        })
    }

    /// Returns where the listener can be reached, after waiting up to `wait` for its relay.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`LiveNode::address`].
    pub fn address(&self, wait: Duration) -> Result<HostAddress, LiveError> {
        self.node.address(wait)
    }

    /// Waits up to `wait` for the first connection, and returns the link to it.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::TimedOut`] if no one connected in time, or [`LiveError::Closed`]
    /// if a connection was already taken.
    pub fn accept(&self, wait: Duration) -> Result<PairLink<'_>, LiveError> {
        let accepted = self.accepted.lock().map_err(|_| LiveError::Closed)?;
        let (connection, send, receive) =
            accepted.recv_timeout(wait).map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => LiveError::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => LiveError::Closed,
            })?;
        let peer = NodeId::from_bytes(*connection.remote_id().as_bytes())?;
        Ok(PairLink {
            node: &self.node,
            connection,
            send,
            receive,
            peer,
        })
    }
}

impl Drop for PairListener {
    fn drop(&mut self) {
        if let Some(router) = self.router.take() {
            let _ = self
                .node
                .block_on(async move { tokio::time::timeout(STEP_WAIT, router.shutdown()).await });
        }
    }
}

impl LiveNode {
    /// Connects to the owner waiting for a pairing at `owner`, as this node.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::TimedOut`] if the owner is not reached and the stream opened within
    /// [`STEP_WAIT`], [`LiveError::Connect`] if the owner cannot be reached, or
    /// [`LiveError::Stream`] if the stream cannot be opened.
    pub fn connect_pairing(&self, owner: &HostAddress) -> Result<PairLink<'_>, LiveError> {
        let address = endpoint_address(owner)?;
        let endpoint = self.endpoint().clone();
        let (connection, send, receive) = self.block_on(async move {
            tokio::time::timeout(STEP_WAIT, async move {
                let connection = endpoint
                    .connect(address, PAIR_ALPN)
                    .await
                    .map_err(|error| LiveError::Connect(Box::new(error)))?;
                let (send, receive) = connection
                    .open_bi()
                    .await
                    .map_err(|error| LiveError::Stream(Box::new(error)))?;
                Ok::<_, LiveError>((connection, send, receive))
            })
            .await
            .map_err(|_| LiveError::TimedOut)?
        })??;
        let peer = NodeId::from_bytes(*connection.remote_id().as_bytes())?;
        Ok(PairLink {
            node: self,
            connection,
            send,
            receive,
            peer,
        })
    }
}

/// A connected pairing: messages each way, framed as a two-byte big-endian length and at most
/// [`MAX_SEALED_BYTES`], each step within [`STEP_WAIT`]. Dropping it closes the connection, so
/// the other side learns at once that the pairing ended.
pub struct PairLink<'a> {
    node: &'a LiveNode,
    connection: Connection,
    send: SendStream,
    receive: RecvStream,
    peer: NodeId,
}

impl fmt::Debug for PairLink<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairLink")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl PairLink<'_> {
    /// Returns the node at the other end, as iroh's TLS authenticated it.
    #[must_use]
    pub fn peer(&self) -> &NodeId {
        &self.peer
    }

    /// Sends one message.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::FrameTooLarge`] if it is larger than [`MAX_SEALED_BYTES`],
    /// [`LiveError::TimedOut`] if it is not sent within [`STEP_WAIT`], or
    /// [`LiveError::Stream`] if the stream broke.
    pub fn send(&mut self, message: &[u8]) -> Result<(), LiveError> {
        let length = u16::try_from(message.len())
            .ok()
            .filter(|_| message.len() <= MAX_SEALED_BYTES)
            .ok_or(LiveError::FrameTooLarge)?;
        let send = &mut self.send;
        self.node.block_on(async move {
            tokio::time::timeout(STEP_WAIT, async {
                send.write_all(&length.to_be_bytes()).await?;
                send.write_all(message).await
            })
            .await
            .map_err(|_| LiveError::TimedOut)?
            .map_err(|error| LiveError::Stream(Box::new(error)))
        })?
    }

    /// Receives one message, waiting up to `wait`.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::TooLarge`] if the other side announces more than
    /// [`MAX_SEALED_BYTES`], [`LiveError::TimedOut`] if nothing whole came within `wait`, or
    /// [`LiveError::Stream`] if the stream broke.
    pub fn receive(&mut self, wait: Duration) -> Result<Vec<u8>, LiveError> {
        let receive = &mut self.receive;
        self.node.block_on(async move {
            tokio::time::timeout(wait, async {
                let mut length = [0_u8; 2];
                receive
                    .read_exact(&mut length)
                    .await
                    .map_err(|error| LiveError::Stream(Box::new(error)))?;
                let length = usize::from(u16::from_be_bytes(length));
                if length > MAX_SEALED_BYTES {
                    return Err(LiveError::TooLarge);
                }
                let mut message = vec![0_u8; length];
                receive
                    .read_exact(&mut message)
                    .await
                    .map_err(|error| LiveError::Stream(Box::new(error)))?;
                Ok(message)
            })
            .await
            .map_err(|_| LiveError::TimedOut)?
        })?
    }

    /// Waits up to `wait` for the other side to close the connection, after the last message,
    /// so that its last frames are acknowledged before this side goes.
    pub fn wait_closed(self, wait: Duration) {
        let connection = self.connection.clone();
        let _ = self.node.block_on(async move {
            let _ = tokio::time::timeout(wait, connection.closed()).await;
        });
    }

    /// Returns whether the connection is still open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// Ends the pairing: closes the stream, waits up to [`STEP_WAIT`] for the other side to
    /// acknowledge everything sent, then closes the connection, and says whether it did.
    #[must_use]
    pub fn finish(mut self) -> bool {
        let _ = self.send.finish();
        let send = &mut self.send;
        let connection = self.connection.clone();
        self.node
            .block_on(async move {
                let stopped = tokio::time::timeout(STEP_WAIT, send.stopped()).await;
                connection.close(VarInt::from_u32(DONE), b"done");
                matches!(stopped, Ok(Ok(None)))
            })
            .unwrap_or(false)
    }
}

impl Drop for PairLink<'_> {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(DONE), b"done");
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use crate::testing::random_secret;

    #[test]
    fn the_first_connection_pairs_and_messages_go_both_ways_framed() {
        let listener = PairListener::bind(Relays::Disabled).unwrap();
        let owner = listener.address(Duration::ZERO).unwrap();
        let joiner = LiveNode::bind(&random_secret(), Relays::Disabled).unwrap();
        let joiner_node = joiner.node().unwrap();
        let other = LiveNode::bind(&random_secret(), Relays::Disabled).unwrap();
        let talking = thread::spawn(move || {
            let mut link = joiner.connect_pairing(&owner).unwrap();
            link.send(b"spake").unwrap();
            assert_eq!(link.receive(STEP_WAIT).unwrap(), b"answer");
            link.send(&[9; MAX_SEALED_BYTES]).unwrap();
            assert!(matches!(
                link.send(&vec![0; MAX_SEALED_BYTES + 1]),
                Err(LiveError::FrameTooLarge)
            ));
            let _ = link.finish();
            joiner
        });
        let mut link = listener.accept(STEP_WAIT).unwrap();
        assert_eq!(link.peer(), &joiner_node);
        assert_eq!(link.receive(STEP_WAIT).unwrap(), b"spake");
        link.send(b"answer").unwrap();
        assert_eq!(link.receive(STEP_WAIT).unwrap().len(), MAX_SEALED_BYTES);
        let _joiner = talking.join().unwrap();

        let second = listener.address(Duration::ZERO).unwrap();
        let refused = other.connect_pairing(&second).and_then(|mut link| {
            link.send(b"late")?;
            link.receive(Duration::from_secs(5))
        });
        assert!(matches!(refused, Err(LiveError::Stream(_))), "{refused:?}");
        assert!(matches!(
            listener.accept(Duration::from_millis(100)),
            Err(LiveError::Closed)
        ));
    }

    #[test]
    fn a_connection_that_opens_no_stream_does_not_use_the_pairing_up() {
        let listener = PairListener::bind(Relays::Disabled).unwrap();
        let owner = listener.address(Duration::ZERO).unwrap();
        let silent = LiveNode::bind(&random_secret(), Relays::Disabled).unwrap();
        let address = endpoint_address(&owner).unwrap();
        let endpoint = silent.endpoint().clone();
        let _idle = silent.run(async move { endpoint.connect(address, PAIR_ALPN).await.unwrap() });
        let joiner = LiveNode::bind(&random_secret(), Relays::Disabled).unwrap();
        let joiner_node = joiner.node().unwrap();
        let talking = thread::spawn(move || {
            let mut link = joiner.connect_pairing(&owner).unwrap();
            link.send(b"hello").unwrap();
            let _ = link.finish();
            joiner
        });
        let mut link = listener.accept(STEP_WAIT).unwrap();
        assert_eq!(link.peer(), &joiner_node);
        assert_eq!(link.receive(STEP_WAIT).unwrap(), b"hello");
        let _joiner = talking.join().unwrap();
    }

    #[test]
    fn an_oversized_frame_is_refused() {
        let listener = PairListener::bind(Relays::Disabled).unwrap();
        let owner = listener.address(Duration::ZERO).unwrap();
        let joiner = LiveNode::bind(&random_secret(), Relays::Disabled).unwrap();
        let talking = thread::spawn(move || {
            let mut link = joiner.connect_pairing(&owner).unwrap();
            link.send(b"first").unwrap();
            let send = &mut link.send;
            link.node.run(async move {
                send.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
            });
            thread::sleep(Duration::from_millis(500));
            drop(link);
            joiner
        });
        let mut link = listener.accept(STEP_WAIT).unwrap();
        assert_eq!(link.receive(STEP_WAIT).unwrap(), b"first");
        assert!(matches!(link.receive(STEP_WAIT), Err(LiveError::TooLarge)));
        let _joiner = talking.join().unwrap();
        assert!(matches!(
            listener.accept(Duration::from_millis(50)),
            Err(LiveError::TimedOut | LiveError::Closed)
        ));
    }
}
