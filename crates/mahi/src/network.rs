use std::{
    fmt,
    io,
    net::TcpListener,
    sync::{
        Arc,
        mpsc::{
            self,
            Receiver,
        },
    },
    thread,
};

use mahi_proxy::{
    Allowlist,
    HostName,
    Proxy,
    ProxyToken,
    PublicConnector,
};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
const PROXY_PORT: u16 = 3128;

/// The proxy that is the agent's only way out, prepared before the agent starts.
pub(crate) struct Network {
    allowlist: Allowlist,
    port: u16,
    url: Zeroizing<String>,
    token: Option<ProxyToken>,
    host_listeners: Vec<TcpListener>,
}

#[derive(Debug, Error)]
pub(crate) enum NetworkError {
    #[cfg_attr(
        target_os = "linux",
        expect(dead_code, reason = "only macOS listens on the host's loopback")
    )]
    #[error("cannot listen for the agent's connections")]
    Listen(#[source] io::Error),
    #[cfg_attr(
        target_os = "linux",
        expect(dead_code, reason = "only macOS protects the proxy with a password")
    )]
    #[error("cannot draw the proxy password")]
    Random(#[source] getrandom::Error),
    #[error("the sandbox did not hand over the proxy's listener")]
    NoListener,
    #[error("cannot start the proxy")]
    Thread(#[source] io::Error),
}

/// The running proxy: tells, when mahi ends, why a listener stopped serving.
#[derive(Debug)]
pub(crate) struct Running {
    stopped: Receiver<io::Error>,
}

impl Running {
    /// Returns the errors that stopped a listener, once the agent is gone.
    pub(crate) fn stopped(self) -> Vec<io::Error> {
        self.stopped.try_iter().collect()
    }
}

impl fmt::Debug for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Network")
            .field("allowlist", &self.allowlist)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Network {
    /// Prepares a proxy for `hosts`, or returns `None` when there is none, so the agent gets
    /// no network at all.
    pub(crate) fn prepare(hosts: &[HostName]) -> Result<Option<Self>, NetworkError> {
        if hosts.is_empty() {
            return Ok(None);
        }
        prepare(Allowlist::new(hosts.to_vec())).map(Some)
    }

    /// Returns the loopback port the agent reaches the proxy on.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Returns the proxy URL the agent uses, which holds the proxy password on macOS.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// Starts serving the agent, on `handed_over`, the listener the Linux sandbox created on
    /// the agent's loopback, and on the host listeners made in [`Network::prepare`].
    pub(crate) fn start(self, handed_over: Option<TcpListener>) -> Result<Running, NetworkError> {
        let mut listeners = self.host_listeners;
        listeners.extend(handed_over);
        if listeners.is_empty() {
            return Err(NetworkError::NoListener);
        }
        let proxy = Arc::new(Proxy::new(
            self.allowlist,
            Box::new(PublicConnector),
            self.token,
        ));
        let (report, stopped) = mpsc::channel();
        for listener in listeners {
            let proxy = Arc::clone(&proxy);
            let report = report.clone();
            thread::Builder::new()
                .spawn(move || {
                    let _ = report.send(mahi_proxy::serve(&listener, &proxy));
                })
                .map_err(NetworkError::Thread)?;
        }
        Ok(Running { stopped })
    }
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the macOS version listens and draws a password, which can fail"
)]
fn prepare(allowlist: Allowlist) -> Result<Network, NetworkError> {
    Ok(Network {
        allowlist,
        port: PROXY_PORT,
        url: Zeroizing::new(format!("http://127.0.0.1:{PROXY_PORT}")),
        token: None,
        host_listeners: Vec::new(),
    })
}

#[cfg(target_os = "macos")]
fn prepare(allowlist: Allowlist) -> Result<Network, NetworkError> {
    let (v4, v6, port) = bind_both_loopbacks()?;
    let mut secret = Zeroizing::new([0_u8; 32]);
    getrandom::fill(secret.as_mut_slice()).map_err(NetworkError::Random)?;
    let mut password = Zeroizing::new(String::with_capacity(64));
    for byte in secret.iter() {
        password.push(char::from(HEX[usize::from(byte >> 4)]));
        password.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    let token = ProxyToken::new(&password);
    let url = Zeroizing::new(format!(
        "http://{}:{}@127.0.0.1:{port}",
        mahi_proxy::PROXY_USER,
        password.as_str()
    ));
    Ok(Network {
        allowlist,
        port,
        url,
        token: Some(token),
        host_listeners: vec![v4, v6],
    })
}

#[cfg(target_os = "macos")]
fn bind_both_loopbacks() -> Result<(TcpListener, TcpListener, u16), NetworkError> {
    use std::net::{
        Ipv4Addr,
        Ipv6Addr,
    };

    let mut attempts = BIND_ATTEMPTS;
    loop {
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(NetworkError::Listen)?;
        let port = v4.local_addr().map_err(NetworkError::Listen)?.port();
        match TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
            Ok(v6) => return Ok((v4, v6, port)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && attempts > 1 => {
                attempts -= 1;
            }
            Err(error) => return Err(NetworkError::Listen(error)),
        }
    }
}

#[cfg(target_os = "macos")]
const BIND_ATTEMPTS: u32 = 8;

#[cfg(target_os = "macos")]
const HEX: [u8; 16] = *b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_host_means_no_proxy() {
        assert!(Network::prepare(&[]).unwrap().is_none());
    }

    #[test]
    fn the_url_points_at_the_loopback_port() {
        let network = Network::prepare(&["api.example.com".parse().unwrap()])
            .unwrap()
            .unwrap();
        assert!(network.url().starts_with("http://"));
        assert!(
            network
                .url()
                .ends_with(&format!("127.0.0.1:{}", network.port()))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn on_macos_the_url_carries_a_password_that_debug_hides() {
        let network = Network::prepare(&["api.example.com".parse().unwrap()])
            .unwrap()
            .unwrap();
        let (credentials, _) = network
            .url()
            .trim_start_matches("http://")
            .split_once('@')
            .unwrap();
        let (_, password) = credentials.split_once(':').unwrap();
        assert_eq!(password.len(), 64);
        assert!(!format!("{network:?}").contains(password));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_proxy_needs_the_sandboxs_listener() {
        let network = Network::prepare(&["api.example.com".parse().unwrap()])
            .unwrap()
            .unwrap();
        assert!(matches!(network.start(None), Err(NetworkError::NoListener)));
    }
}
