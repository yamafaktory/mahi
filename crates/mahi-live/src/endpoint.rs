use std::{
    fmt,
    io,
    net::{
        Ipv4Addr,
        Ipv6Addr,
        SocketAddr,
    },
    sync::Arc,
    time::Duration,
};

use iroh::{
    Endpoint,
    RelayMode,
    SecretKey,
    endpoint::{
        BindError,
        BindOpts,
        Builder,
        ConnectError,
        InvalidSocketAddr,
    },
    protocol::Router,
};
use mahi_core::ThreadId;
use mahi_thread::{
    NodeId,
    NodeIdError,
};
use thiserror::Error;
use tokio::runtime::{
    self,
    Handle,
    Runtime,
};

use crate::{
    AddressError,
    HostAddress,
    MAX_DIRECT_ADDRESSES,
    MetaSource,
    is_reachable,
    meta::{
        self,
        META_ALPN,
        MetaHandler,
    },
};

const WORKER_THREADS: usize = 2;
const FIRST_STABLE_PORT: u16 = 49_152;
const STABLE_PORTS: u16 = 16_384;
const CLOSE_WAIT: Duration = Duration::from_secs(5);
const FETCH_WAIT: Duration = Duration::from_secs(20);

/// Which relays an endpoint uses to reach peers it cannot reach directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relays {
    /// n0's public relays, which only forward ciphertext.
    Public,
    /// No relay: only direct addresses, as on a local network or in tests.
    Disabled,
}

/// The user's machine on the live layer: an iroh endpoint with their node key, on
/// `mahi-tls`, with the runtime that drives it.
///
/// It blocks on its own runtime, so it is used, and dropped, outside any async runtime.
pub struct LiveNode {
    router: Option<Router>,
    endpoint: Endpoint,
    runtime: Option<Runtime>,
    relays: Relays,
}

/// Starting or using the live node failed.
#[derive(Debug, Error)]
pub enum LiveError {
    /// The async runtime could not start.
    #[error("cannot start the live layer's runtime")]
    Runtime(#[source] io::Error),
    /// The live node was used from inside an async runtime, where it cannot block.
    #[error("the live node cannot be used from inside an async runtime")]
    InsideRuntime,
    /// The endpoint could not bind its sockets.
    #[error("cannot open the live layer's endpoint")]
    Bind(#[source] Box<BindError>),
    /// iroh refused a socket address, which it never does for the unspecified addresses used.
    #[error("cannot choose the live layer's sockets")]
    SocketAddress(#[source] InvalidSocketAddr),
    /// iroh reports a node id that is not a usable key, which it never does.
    #[error("the endpoint's node id is not usable")]
    Node(#[from] NodeIdError),
    /// The endpoint's address cannot go into a ticket.
    #[error("the endpoint's address cannot go into a ticket")]
    Address(#[from] AddressError),
    /// The host could not be reached.
    #[error("cannot reach the host")]
    Connect(#[source] Box<ConnectError>),
    /// The connection to the host broke.
    #[error("the connection to the host broke")]
    Stream(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The live node was already closed, which a caller holding it never sees.
    #[error("the live node is closed")]
    Closed,
    /// The host's node id is not a usable key, which a checked host address never holds.
    #[error("the host's node id is not a usable key")]
    HostKey,
    /// The host could not answer now: it is busy, or reading its `meta` failed or was slow.
    #[error("the host cannot answer now; try again")]
    Unavailable,
    /// The host refused: the thread is unknown to it, or this node is not a participant.
    #[error(
        "the host refused: this node is not a participant of the thread, or the host does not have it"
    )]
    Refused,
    /// The host sent more than a `meta` document can hold.
    #[error("the host sent a meta document that is too large")]
    TooLarge,
    /// The host did not answer in time.
    #[error("the host did not answer in time")]
    TimedOut,
}

impl fmt::Debug for LiveNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveNode")
            .field("node", &self.endpoint.id())
            .field("relays", &self.relays)
            .finish_non_exhaustive()
    }
}

impl LiveNode {
    /// Binds an endpoint with the node key whose secret is `secret`.
    ///
    /// It listens on the node's [`stable_port`], so the direct addresses in a ticket still
    /// reach a host started later, or on a random port when that one is taken.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::InsideRuntime`] if called from inside an async runtime,
    /// [`LiveError::Runtime`] if the runtime cannot start, or [`LiveError::Bind`] if the
    /// endpoint cannot bind its sockets.
    pub fn bind(secret: &[u8; 32], relays: Relays) -> Result<Self, LiveError> {
        Self::bind_with(secret, relays, None)
    }

    /// Binds an endpoint like [`LiveNode::bind`] that also hosts: it serves `meta` from
    /// `source` to the nodes `source` accepts.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`LiveNode::bind`].
    pub fn bind_host(
        secret: &[u8; 32],
        relays: Relays,
        source: Arc<dyn MetaSource>,
    ) -> Result<Self, LiveError> {
        Self::bind_with(secret, relays, Some(source))
    }

    fn bind_with(
        secret: &[u8; 32],
        relays: Relays,
        source: Option<Arc<dyn MetaSource>>,
    ) -> Result<Self, LiveError> {
        outside_runtime()?;
        let runtime = runtime::Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .enable_all()
            .build()
            .map_err(LiveError::Runtime)?;
        let relay_mode = match relays {
            Relays::Public => RelayMode::Default,
            Relays::Disabled => RelayMode::Disabled,
        };
        let secret_key = SecretKey::from_bytes(secret);
        let port = NodeId::from_bytes(*secret_key.public().as_bytes())
            .map_or(0, |node| stable_port(&node));
        let stable = builder(&secret_key, relay_mode.clone(), port)?;
        let endpoint = match runtime.block_on(stable.bind()) {
            Ok(endpoint) => endpoint,
            Err(_) => runtime
                .block_on(builder(&secret_key, relay_mode, 0)?.bind())
                .map_err(|error| LiveError::Bind(Box::new(error)))?,
        };
        let router = source.map(|source| {
            let endpoint = endpoint.clone();
            runtime.block_on(async move {
                Router::builder(endpoint)
                    .accept(META_ALPN, MetaHandler::new(source))
                    .spawn()
            })
        });
        Ok(Self {
            router,
            endpoint,
            runtime: Some(runtime),
            relays,
        })
    }

    /// Returns the node id the endpoint speaks as.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::Node`] if iroh reports an unusable key, which it never does.
    pub fn node(&self) -> Result<NodeId, LiveError> {
        Ok(NodeId::from_bytes(*self.endpoint.id().as_bytes())?)
    }

    /// Returns where the endpoint can be reached, after waiting up to `wait` for its relay
    /// when it uses one.
    ///
    /// A relay that is not reached in time is left out, and so are direct addresses that
    /// cannot reach a peer (see [`is_reachable`]) and those beyond [`MAX_DIRECT_ADDRESSES`].
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::InsideRuntime`] if called from inside an async runtime, or
    /// [`LiveError::Node`] or [`LiveError::Address`] if the address cannot go into a ticket.
    pub fn address(&self, wait: Duration) -> Result<HostAddress, LiveError> {
        outside_runtime()?;
        if self.relays == Relays::Public {
            let _ = self
                .runtime()?
                .block_on(async { tokio::time::timeout(wait, self.endpoint.online()).await });
        }
        let address = self.endpoint.addr();
        Ok(HostAddress::new(
            self.node()?,
            address.relay_urls().next().cloned(),
            address
                .ip_addrs()
                .filter(|address| is_reachable(address))
                .take(MAX_DIRECT_ADDRESSES)
                .copied()
                .collect(),
        )?)
    }

    /// Asks the host at `host` for `thread`'s signed `meta`, waiting up to 20 s.
    ///
    /// The document is returned unchecked: the caller verifies it against the owner key it
    /// trusts.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::Refused`] if the host refuses, [`LiveError::TimedOut`] if it does
    /// not answer in time, [`LiveError::TooLarge`] if it sends too much, or another
    /// [`LiveError`] if it cannot be reached.
    pub fn fetch_meta(&self, host: &HostAddress, thread: ThreadId) -> Result<Vec<u8>, LiveError> {
        outside_runtime()?;
        self.runtime()?
            .block_on(async {
                tokio::time::timeout(FETCH_WAIT, meta::fetch(&self.endpoint, host, thread)).await
            })
            .map_err(|_| LiveError::TimedOut)?
    }

    /// Closes the endpoint, telling connected peers, and stops the runtime, in about 10 s at
    /// most: work still running then, such as a slow `meta` read, is left behind.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::InsideRuntime`] if called from inside an async runtime, where the
    /// node is dropped without telling its peers.
    pub fn close(mut self) -> Result<(), LiveError> {
        outside_runtime()?;
        self.shut_down();
        Ok(())
    }

    fn runtime(&self) -> Result<&Runtime, LiveError> {
        self.runtime.as_ref().ok_or(LiveError::Closed)
    }

    fn shut_down(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        if Handle::try_current().is_ok() {
            runtime.shutdown_background();
            return;
        }
        let router = self.router.take();
        let endpoint = self.endpoint.clone();
        let _ = runtime.block_on(async move {
            tokio::time::timeout(CLOSE_WAIT, async move {
                if let Some(router) = router {
                    let _ = router.shutdown().await;
                }
                endpoint.close().await;
            })
            .await
        });
        runtime.shutdown_timeout(CLOSE_WAIT);
    }
}

impl Drop for LiveNode {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// Returns the UDP port a node listens on when it is free: one of the 16384 dynamic ports,
/// chosen by the node id, so it stays the same from one run to the next.
#[must_use]
pub fn stable_port(node: &NodeId) -> u16 {
    let [first, second, ..] = *node.as_bytes();
    FIRST_STABLE_PORT + u16::from_le_bytes([first, second]) % STABLE_PORTS
}

fn builder(secret_key: &SecretKey, relay_mode: RelayMode, port: u16) -> Result<Builder, LiveError> {
    Builder::empty()
        .secret_key(secret_key.clone())
        .crypto_provider(Arc::new(mahi_tls::provider()))
        .relay_mode(relay_mode)
        .clear_ip_transports()
        .bind_addr_with_opts(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            BindOpts::default(),
        )
        .and_then(|builder| {
            builder.bind_addr_with_opts(
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
                BindOpts::default().set_is_required(false),
            )
        })
        .map_err(LiveError::SocketAddress)
}

#[cfg(test)]
impl LiveNode {
    pub(crate) fn run<F: std::future::Future>(&self, future: F) -> F::Output {
        self.runtime()
            .expect("a node in a test is open")
            .block_on(future)
    }

    pub(crate) fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

fn outside_runtime() -> Result<(), LiveError> {
    if Handle::try_current().is_ok() {
        return Err(LiveError::InsideRuntime);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::random_secret;

    #[test]
    fn a_node_speaks_as_its_key_and_is_reachable_directly_without_relays() {
        let secret = [9_u8; 32];
        let node = LiveNode::bind(&secret, Relays::Disabled).unwrap();
        let expected =
            NodeId::from_bytes(*SecretKey::from_bytes(&secret).public().as_bytes()).unwrap();
        assert_eq!(node.node().unwrap(), expected);
        let address = node.address(Duration::ZERO).unwrap();
        assert_eq!(address.node(), &expected);
        assert!(address.relay().is_none());
        assert!(!address.direct().is_empty());
        assert!(address.direct().len() <= MAX_DIRECT_ADDRESSES);
        let hex = "09".repeat(secret.len());
        assert!(!format!("{node:?}").contains(&hex));
        node.close().unwrap();
    }

    #[test]
    fn a_node_listens_on_its_stable_port_unless_it_is_taken() {
        let secret = random_secret();
        let first = LiveNode::bind(&secret, Relays::Disabled).unwrap();
        let port = stable_port(&first.node().unwrap());
        assert!((FIRST_STABLE_PORT..=u16::MAX).contains(&port));
        let ports = |node: &LiveNode| -> Vec<u16> {
            node.address(Duration::ZERO)
                .unwrap()
                .direct()
                .iter()
                .map(SocketAddr::port)
                .collect()
        };
        assert!(ports(&first).iter().all(|&used| used == port));
        let second = LiveNode::bind(&secret, Relays::Disabled).unwrap();
        assert!(ports(&second).iter().all(|&used| used != port));
        second.close().unwrap();
        first.close().unwrap();
        let again = LiveNode::bind(&secret, Relays::Disabled).unwrap();
        assert!(ports(&again).iter().all(|&used| used == port));
        again.close().unwrap();
    }

    #[test]
    fn a_node_refuses_to_block_inside_an_async_runtime() {
        let node = LiveNode::bind(&random_secret(), Relays::Disabled).unwrap();
        let other = runtime::Builder::new_current_thread().build().unwrap();
        other.block_on(async {
            assert!(matches!(
                LiveNode::bind(&random_secret(), Relays::Disabled),
                Err(LiveError::InsideRuntime)
            ));
            assert!(matches!(
                node.address(Duration::ZERO),
                Err(LiveError::InsideRuntime)
            ));
        });
        node.close().unwrap();
    }
}
