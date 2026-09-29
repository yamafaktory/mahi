use std::{
    fmt,
    sync::Arc,
    time::Duration,
};

use iroh::{
    Endpoint,
    EndpointAddr,
    PublicKey,
    endpoint::{
        Connection,
        ConnectionError,
        ReadError,
        ReadToEndError,
        VarInt,
    },
    protocol::{
        AcceptError,
        ProtocolHandler,
    },
};
use mahi_core::ThreadId;
use mahi_thread::{
    MAX_META_BYTES,
    NodeId,
};
use tokio::sync::Semaphore;

use crate::{
    HostAddress,
    LiveError,
};

/// The ALPN of the protocol a host serves `meta` on.
pub const META_ALPN: &[u8] = b"mahi/meta/1";

const THREAD_ID_BYTES: usize = 16;
const REQUEST_WAIT: Duration = Duration::from_secs(5);
const DELIVERY_WAIT: Duration = Duration::from_secs(10);
const DONE: u32 = 0;
const REFUSED: u32 = 1;
const UNAVAILABLE: u32 = 2;
const READERS: usize = 2;

/// Where a host finds the `meta` it serves.
///
/// Any node that knows the host's address can ask, with as many fresh node keys as it likes,
/// so a source answers unknown nodes from what it already holds, rereading the repository at
/// most every few seconds whoever asks. The handler also runs at most two reads at once.
pub trait MetaSource: Send + Sync + fmt::Debug + 'static {
    /// Returns the current signed `meta` document of `thread` when `node` is one of its
    /// participants, or `None` to refuse. It may block, as it reads the repository.
    fn meta_for(&self, thread: ThreadId, node: &NodeId) -> Option<Vec<u8>>;
}

#[derive(Debug)]
pub(crate) struct MetaHandler {
    source: Arc<dyn MetaSource>,
    readers: Arc<Semaphore>,
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    Refused,
    Unavailable,
}

impl MetaHandler {
    pub(crate) fn new(source: Arc<dyn MetaSource>) -> Self {
        Self {
            source,
            readers: Arc::new(Semaphore::new(READERS)),
        }
    }

    async fn answer(&self, connection: &Connection) -> Result<(), Failure> {
        let node =
            NodeId::from_bytes(*connection.remote_id().as_bytes()).map_err(|_| Failure::Refused)?;
        let (mut send, mut receive) = connection
            .accept_bi()
            .await
            .map_err(|_| Failure::Unavailable)?;
        let request = receive
            .read_to_end(THREAD_ID_BYTES)
            .await
            .map_err(|_| Failure::Refused)?;
        let thread = ThreadId::from_bytes(
            <[u8; THREAD_ID_BYTES]>::try_from(request).map_err(|_| Failure::Refused)?,
        );
        let permit = Arc::clone(&self.readers)
            .try_acquire_owned()
            .map_err(|_| Failure::Unavailable)?;
        let source = Arc::clone(&self.source);
        let meta = tokio::task::spawn_blocking(move || {
            let meta = source.meta_for(thread, &node);
            drop(permit);
            meta
        })
        .await
        .map_err(|_| Failure::Unavailable)?
        .ok_or(Failure::Refused)?;
        if meta.len() > MAX_META_BYTES {
            return Err(Failure::Unavailable);
        }
        send.write_all(&meta)
            .await
            .map_err(|_| Failure::Unavailable)?;
        send.finish().map_err(|_| Failure::Unavailable)
    }
}

impl ProtocolHandler for MetaHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let served = tokio::time::timeout(REQUEST_WAIT, self.answer(&connection))
            .await
            .unwrap_or(Err(Failure::Unavailable));
        match served {
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

/// Asks the host at `host` for `thread`'s `meta`, as the node `endpoint` speaks as.
pub(crate) async fn fetch(
    endpoint: &Endpoint,
    host: &HostAddress,
    thread: ThreadId,
) -> Result<Vec<u8>, LiveError> {
    let connection = endpoint
        .connect(endpoint_address(host)?, META_ALPN)
        .await
        .map_err(|error| LiveError::Connect(Box::new(error)))?;
    let fetched = request(&connection, thread).await;
    connection.close(VarInt::from_u32(DONE), b"done");
    fetched
}

async fn request(connection: &Connection, thread: ThreadId) -> Result<Vec<u8>, LiveError> {
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|error| LiveError::Stream(Box::new(error)))?;
    send.write_all(thread.as_bytes())
        .await
        .map_err(|error| LiveError::Stream(Box::new(error)))?;
    send.finish()
        .map_err(|error| LiveError::Stream(Box::new(error)))?;
    match receive.read_to_end(MAX_META_BYTES).await {
        Ok(meta) => Ok(meta),
        Err(ReadToEndError::Read(ReadError::ConnectionLost(
            ConnectionError::ApplicationClosed(close),
        ))) if close.error_code == VarInt::from_u32(REFUSED) => Err(LiveError::Refused),
        Err(ReadToEndError::Read(ReadError::ConnectionLost(
            ConnectionError::ApplicationClosed(close),
        ))) if close.error_code == VarInt::from_u32(UNAVAILABLE) => Err(LiveError::Unavailable),
        Err(ReadToEndError::TooLong) => Err(LiveError::TooLarge),
        Err(error) => Err(LiveError::Stream(Box::new(error))),
    }
}

pub(crate) fn endpoint_address(host: &HostAddress) -> Result<EndpointAddr, LiveError> {
    let id = PublicKey::from_bytes(host.node().as_bytes()).map_err(|_| LiveError::HostKey)?;
    let mut address = EndpointAddr::new(id);
    if let Some(relay) = host.relay() {
        address = address.with_relay_url(relay.clone());
    }
    for direct in host.direct() {
        address = address.with_ip_addr(*direct);
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LiveNode,
        Relays,
    };

    #[derive(Debug)]
    struct OneParticipant {
        thread: ThreadId,
        node: NodeId,
        meta: Vec<u8>,
    }

    impl MetaSource for OneParticipant {
        fn meta_for(&self, thread: ThreadId, node: &NodeId) -> Option<Vec<u8>> {
            (thread == self.thread && node == &self.node).then(|| self.meta.clone())
        }
    }

    struct Pair {
        host: LiveNode,
        joiner: LiveNode,
        stranger: LiveNode,
        address: HostAddress,
        thread: ThreadId,
    }

    fn pair(meta: Vec<u8>) -> Pair {
        let joiner = LiveNode::bind(&[2; 32], Relays::Disabled).unwrap();
        let stranger = LiveNode::bind(&[3; 32], Relays::Disabled).unwrap();
        let thread = ThreadId::random().unwrap();
        let source = OneParticipant {
            thread,
            node: joiner.node().unwrap(),
            meta,
        };
        let host = LiveNode::bind_host(&[1; 32], Relays::Disabled, Arc::new(source)).unwrap();
        let address = host.address(Duration::ZERO).unwrap();
        Pair {
            host,
            joiner,
            stranger,
            address,
            thread,
        }
    }

    impl Pair {
        fn close(self) {
            self.joiner.close().unwrap();
            self.stranger.close().unwrap();
            self.host.close().unwrap();
        }
    }

    #[test]
    fn a_participant_gets_the_meta_and_anyone_else_is_refused() {
        let pair = pair(b"signed meta".to_vec());
        assert_eq!(
            pair.joiner.fetch_meta(&pair.address, pair.thread).unwrap(),
            b"signed meta"
        );
        assert!(matches!(
            pair.stranger.fetch_meta(&pair.address, pair.thread),
            Err(LiveError::Refused)
        ));
        assert!(matches!(
            pair.joiner
                .fetch_meta(&pair.address, ThreadId::random().unwrap()),
            Err(LiveError::Refused)
        ));
        pair.close();
    }

    #[test]
    fn a_document_over_the_meta_limit_is_not_served() {
        let pair = pair(vec![0; MAX_META_BYTES + 1]);
        let fetched = pair.joiner.fetch_meta(&pair.address, pair.thread);
        assert!(
            matches!(fetched, Err(LiveError::Unavailable)),
            "{fetched:?}"
        );
        pair.close();
    }

    fn closed_with(node: &LiveNode, address: &HostAddress, request: Option<&[u8]>) -> VarInt {
        let address = endpoint_address(address).unwrap();
        node.run(async {
            let connection = node.endpoint().connect(address, META_ALPN).await.unwrap();
            if let Some(request) = request {
                let (mut send, _receive) = connection.open_bi().await.unwrap();
                send.write_all(request).await.unwrap();
                send.finish().unwrap();
            }
            let closed = tokio::time::timeout(REQUEST_WAIT * 2, connection.closed())
                .await
                .unwrap();
            let ConnectionError::ApplicationClosed(close) = closed else {
                panic!("{closed:?}");
            };
            close.error_code
        })
    }

    #[test]
    fn a_silent_peer_is_let_go_and_an_empty_request_is_refused() {
        let pair = pair(b"signed meta".to_vec());
        assert_eq!(
            closed_with(&pair.joiner, &pair.address, None),
            VarInt::from_u32(UNAVAILABLE)
        );
        assert_eq!(
            closed_with(&pair.joiner, &pair.address, Some(b"")),
            VarInt::from_u32(REFUSED)
        );
        pair.close();
    }

    #[derive(Debug)]
    struct Hostile;

    impl ProtocolHandler for Hostile {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            if let Ok((mut send, mut receive)) = connection.accept_bi().await {
                let _ = receive.read_to_end(THREAD_ID_BYTES).await;
                let _ = send.write_all(&vec![0; MAX_META_BYTES + 1]).await;
                let _ = send.finish();
                let _ = connection.closed().await;
            }
            Ok(())
        }
    }

    #[test]
    fn a_host_that_sends_too_much_is_cut_off() {
        let host = LiveNode::bind(&[7; 32], Relays::Disabled).unwrap();
        let _router = host.run(async {
            iroh::protocol::Router::builder(host.endpoint().clone())
                .accept(META_ALPN, Hostile)
                .spawn()
        });
        let joiner = LiveNode::bind(&[8; 32], Relays::Disabled).unwrap();
        let address = host.address(Duration::ZERO).unwrap();
        assert!(matches!(
            joiner.fetch_meta(&address, ThreadId::random().unwrap()),
            Err(LiveError::TooLarge)
        ));
    }

    #[derive(Debug)]
    struct Slow {
        pause: Duration,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl MetaSource for Slow {
        fn meta_for(&self, _thread: ThreadId, _node: &NodeId) -> Option<Vec<u8>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(self.pause);
            Some(b"meta".to_vec())
        }
    }

    #[test]
    fn a_busy_host_answers_two_reads_at_once_and_closes_in_bounded_time() {
        let slow = Arc::new(Slow {
            pause: Duration::from_millis(1500),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let source: Arc<dyn MetaSource> = Arc::clone(&slow) as Arc<dyn MetaSource>;
        let host = LiveNode::bind_host(&[9; 32], Relays::Disabled, source).unwrap();
        let address = host.address(Duration::ZERO).unwrap();
        let joiners: Vec<LiveNode> = (10..14)
            .map(|seed| LiveNode::bind(&[seed; 32], Relays::Disabled).unwrap())
            .collect();
        let results: Vec<Result<Vec<u8>, LiveError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = joiners
                .iter()
                .map(|joiner| {
                    let address = address.clone();
                    scope.spawn(move || joiner.fetch_meta(&address, ThreadId::random().unwrap()))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        let served = results.iter().filter(|result| result.is_ok()).count();
        let busy = results
            .iter()
            .filter(|result| matches!(result, Err(LiveError::Unavailable)))
            .count();
        assert_eq!(
            (served, busy),
            (READERS, joiners.len() - READERS),
            "{results:?}"
        );
        assert_eq!(
            slow.calls.load(std::sync::atomic::Ordering::SeqCst),
            READERS
        );

        let stuck = Arc::new(Slow {
            pause: Duration::from_secs(60),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let host = LiveNode::bind_host(
            &[20; 32],
            Relays::Disabled,
            Arc::clone(&stuck) as Arc<dyn MetaSource>,
        )
        .unwrap();
        let address = host.address(Duration::ZERO).unwrap();
        let joiner = LiveNode::bind(&[21; 32], Relays::Disabled).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| joiner.fetch_meta(&address, ThreadId::random().unwrap()));
            while stuck.calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(10));
            }
            let started = std::time::Instant::now();
            host.close().unwrap();
            assert!(started.elapsed() < Duration::from_secs(12));
        });
    }

    #[test]
    fn a_request_that_is_not_one_thread_id_is_refused() {
        let pair = pair(b"signed meta".to_vec());
        let address = endpoint_address(&pair.address).unwrap();
        for request in [
            vec![0_u8; THREAD_ID_BYTES + 1],
            vec![0_u8; THREAD_ID_BYTES - 1],
        ] {
            let refused = pair.joiner.run(async {
                let connection = pair
                    .joiner
                    .endpoint()
                    .connect(address.clone(), META_ALPN)
                    .await
                    .unwrap();
                let (mut send, mut receive) = connection.open_bi().await.unwrap();
                send.write_all(&request).await.unwrap();
                send.finish().unwrap();
                matches!(
                    receive.read_to_end(MAX_META_BYTES).await,
                    Err(ReadToEndError::Read(ReadError::ConnectionLost(
                        ConnectionError::ApplicationClosed(close)
                    ))) if close.error_code == VarInt::from_u32(REFUSED)
                )
            });
            assert!(refused, "{} bytes", request.len());
        }
        pair.close();
    }
}
