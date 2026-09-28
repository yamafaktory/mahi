use std::{
    fmt,
    io::{
        self,
        Read,
        Write,
    },
    net::{
        Shutdown,
        SocketAddr,
        TcpListener,
        TcpStream,
        ToSocketAddrs,
    },
    sync::{
        Arc,
        atomic::{
            AtomicU64,
            AtomicUsize,
            Ordering,
        },
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use base64::{
    Engine,
    engine::general_purpose::STANDARD,
};
use rustix::io::Errno;
use subtle::ConstantTimeEq;
use zeroize::{
    Zeroize,
    Zeroizing,
};

use crate::{
    Allowlist,
    HostName,
    address::is_public,
};

const PORT: u16 = 443;
const HEAD_LIMIT: usize = 8 * 1024;
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
const LIMITS: Limits = Limits {
    head_deadline: Duration::from_secs(10),
    idle_limit: Duration::from_secs(300),
    idle_check: Duration::from_secs(5),
    max_connections: 64,
};
const ERROR_PAUSE: Duration = Duration::from_millis(50);
/// The user name the agent presents with the proxy password.
pub const PROXY_USER: &str = "mahi";
const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n";

/// Opens the connection to an allowed host, deciding which addresses may be used.
pub trait Connector: Send + Sync {
    /// Connects to `host` on `port`.
    ///
    /// # Errors
    ///
    /// Returns an error if the name cannot be resolved, has no address the connector accepts,
    /// or cannot be connected to.
    fn connect(&self, host: &HostName, port: u16) -> io::Result<TcpStream>;
}

/// Resolves names with the system resolver and connects only to public addresses.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicConnector;

impl Connector for PublicConnector {
    fn connect(&self, host: &HostName, port: u16) -> io::Result<TcpStream> {
        let addresses: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs()?.collect();
        connect_public(&addresses, Instant::now() + CONNECT_DEADLINE)
    }
}

fn connect_public(addresses: &[SocketAddr], deadline: Instant) -> io::Result<TcpStream> {
    let mut last = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "the name has no public address",
    );
    for address in addresses.iter().filter(|address| is_public(address.ip())) {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Err(io::ErrorKind::TimedOut.into());
        };
        match TcpStream::connect_timeout(address, left) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// The password the agent must present, as `Proxy-Authorization: Basic` for the user `mahi`.
pub struct ProxyToken {
    expected: Zeroizing<String>,
}

impl ProxyToken {
    /// Creates the token that accepts `password`.
    #[must_use]
    pub fn new(password: &str) -> Self {
        let credentials = Zeroizing::new(format!("{PROXY_USER}:{password}"));
        let encoded = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
        let expected = Zeroizing::new(format!("Basic {}", encoded.as_str()));
        Self { expected }
    }

    fn accepts(&self, value: &[u8]) -> bool {
        self.expected.as_bytes().ct_eq(value).into()
    }
}

impl fmt::Debug for ProxyToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyToken(..)")
    }
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    head_deadline: Duration,
    idle_limit: Duration,
    idle_check: Duration,
    max_connections: usize,
}

/// What the proxy allows, how it connects, and the password it asks for, if any.
pub struct Proxy {
    allowlist: Allowlist,
    connector: Box<dyn Connector>,
    token: Option<ProxyToken>,
    limits: Limits,
    open: AtomicUsize,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("allowlist", &self.allowlist)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    /// Creates a proxy that lets clients reach the hosts on `allowlist` through `connector`,
    /// asking for `token` when one is given.
    #[must_use]
    pub fn new(
        allowlist: Allowlist,
        connector: Box<dyn Connector>,
        token: Option<ProxyToken>,
    ) -> Self {
        Self {
            allowlist,
            connector,
            token,
            limits: LIMITS,
            open: AtomicUsize::new(0),
        }
    }
}

/// Accepts clients on `listener`, each on its own thread, at most 64 at a time; a client over
/// that limit gets `503 Service Unavailable`. The listener is made blocking first.
///
/// Returns the error that stopped it: accepting failed for a reason other than a lack of
/// resources or a client that gave up.
pub fn serve(listener: &TcpListener, proxy: &Arc<Proxy>) -> io::Error {
    if let Err(error) = listener.set_nonblocking(false) {
        return error;
    }
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if is_transient(&error) => {
                thread::sleep(ERROR_PAUSE);
                continue;
            }
            Err(error) => return error,
        };
        let Some(slot) = Slot::take(proxy) else {
            refuse_busy(&mut stream);
            continue;
        };
        let proxy = Arc::clone(proxy);
        let spawned = thread::Builder::new().spawn(move || {
            let _slot = slot;
            handle(&proxy, stream);
        });
        if spawned.is_err() {
            thread::sleep(ERROR_PAUSE);
        }
    }
}

fn refuse_busy(stream: &mut TcpStream) {
    let _ = stream.set_write_timeout(Some(ERROR_PAUSE));
    let _ = stream.set_read_timeout(Some(ERROR_PAUSE));
    let _ = stream.write_all(BUSY);
    let _ = stream.shutdown(Shutdown::Write);
    let mut unread = [0_u8; 1024];
    for _ in 0..HEAD_LIMIT / unread.len() {
        if !matches!(stream.read(&mut unread), Ok(read) if read > 0) {
            break;
        }
    }
    unread.zeroize();
}

fn is_transient(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .map(Errno::from_raw_os_error)
        .is_some_and(|errno| {
            [
                Errno::CONNABORTED,
                Errno::CONNRESET,
                Errno::MFILE,
                Errno::NFILE,
                Errno::NOBUFS,
                Errno::NOMEM,
                Errno::AGAIN,
                Errno::PROTO,
            ]
            .contains(&errno)
        })
}

struct Slot(Arc<Proxy>);

impl Slot {
    fn take(proxy: &Arc<Proxy>) -> Option<Self> {
        proxy
            .open
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |open| {
                (open < proxy.limits.max_connections).then_some(open + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(proxy)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    BadRequest,
    AuthenticationRequired,
    Forbidden,
    BadGateway,
}

impl Refusal {
    fn response(self) -> &'static [u8] {
        match self {
            Self::BadRequest => b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
            Self::AuthenticationRequired => {
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"mahi\"\r\nConnection: close\r\n\r\n"
            }
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
            Self::BadGateway => b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
        }
    }
}

fn handle(proxy: &Proxy, mut client: TcpStream) {
    let (upstream, early) = match open_tunnel(proxy, &mut client) {
        Ok(opened) => opened,
        Err(refusal) => {
            let _ = client.write_all(refusal.response());
            return;
        }
    };
    let established = client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .and_then(|()| upstream.try_clone())
        .and_then(|mut writer| writer.write_all(&early));
    if established.is_ok() {
        relay(client, upstream, proxy.limits);
    }
}

fn open_tunnel(proxy: &Proxy, client: &mut TcpStream) -> Result<(TcpStream, Vec<u8>), Refusal> {
    let (head, early) = read_head(client, proxy.limits.head_deadline).ok_or(Refusal::BadRequest)?;
    let request = parse(&head).ok_or(Refusal::BadRequest)?;
    if let Some(token) = &proxy.token
        && !request
            .authorization
            .is_some_and(|value| token.accepts(value))
    {
        return Err(Refusal::AuthenticationRequired);
    }
    let host: HostName = request.host.parse().map_err(|_| Refusal::Forbidden)?;
    if request.port != PORT || !proxy.allowlist.allows(&host) {
        return Err(Refusal::Forbidden);
    }
    let upstream = proxy
        .connector
        .connect(&host, request.port)
        .map_err(|_| Refusal::BadGateway)?;
    Ok((upstream, early))
}

fn read_head(client: &mut TcpStream, limit: Duration) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let deadline = Instant::now() + limit;
    let mut received = Zeroizing::new(Vec::with_capacity(HEAD_LIMIT + 1024));
    let mut buffer = Zeroizing::new([0_u8; 1024]);
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        client.set_read_timeout(Some(left)).ok()?;
        let read = match client.read(buffer.as_mut_slice()) {
            Ok(0) | Err(_) => return None,
            Ok(read) => read,
        };
        let searched_from = received.len().saturating_sub(3);
        received.extend_from_slice(buffer.get(..read)?);
        if let Some(end) = received
            .get(searched_from..)?
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            let split = searched_from + end + 4;
            if split > HEAD_LIMIT {
                return None;
            }
            let early = received.split_off(split);
            client.set_read_timeout(None).ok()?;
            return Some((received, early));
        }
        if received.len() > HEAD_LIMIT {
            return None;
        }
    }
}

struct Request<'a> {
    host: &'a str,
    port: u16,
    authorization: Option<&'a [u8]>,
}

fn parse(head: &[u8]) -> Option<Request<'_>> {
    let mut lines = head
        .split(|&byte| byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let request_line = std::str::from_utf8(lines.next()?).ok()?;
    let mut parts = request_line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if method != "CONNECT" || parts.next().is_some() || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
    {
        return None;
    }
    let (host, port) = target.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let mut authorization = None;
    for line in lines {
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let (name, value) = line.split_at(colon);
        if name.eq_ignore_ascii_case(b"proxy-authorization") {
            if authorization.is_some() {
                return None;
            }
            authorization = Some(value.get(1..)?.trim_ascii());
        }
    }
    Some(Request {
        host,
        port,
        authorization,
    })
}

fn relay(client: TcpStream, upstream: TcpStream, limits: Limits) {
    let last = Arc::new(Activity::new());
    let (Ok(client_reader), Ok(upstream_writer)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let clock = Arc::clone(&last);
    let outbound =
        thread::Builder::new().spawn(move || pump(client_reader, upstream_writer, &clock, limits));
    pump(upstream, client, &last, limits);
    if let Ok(outbound) = outbound {
        let _ = outbound.join();
    }
}

struct Activity {
    start: Instant,
    last: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn elapsed(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last.store(self.elapsed(), Ordering::Relaxed);
    }

    fn idle(&self) -> Duration {
        Duration::from_millis(
            self.elapsed()
                .saturating_sub(self.last.load(Ordering::Relaxed)),
        )
    }
}

fn pump(mut from: TcpStream, mut to: TcpStream, last: &Activity, limits: Limits) {
    let _ = from.set_read_timeout(Some(limits.idle_check));
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        match from.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                last.touch();
                let Some(chunk) = buffer.get(..read) else {
                    break;
                };
                if to.write_all(chunk).is_err() {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if last.idle() > limits.idle_limit {
                    let _ = from.shutdown(Shutdown::Both);
                    let _ = to.shutdown(Shutdown::Both);
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct LocalConnector {
        upstream: SocketAddr,
        asked: Arc<Mutex<Vec<String>>>,
    }

    impl Connector for LocalConnector {
        fn connect(&self, host: &HostName, port: u16) -> io::Result<TcpStream> {
            self.asked.lock().unwrap().push(format!("{host}:{port}"));
            if host.as_str() == "down.example.com" {
                return Err(io::ErrorKind::ConnectionRefused.into());
            }
            TcpStream::connect(self.upstream)
        }
    }

    fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                thread::spawn(move || {
                    let mut reader = stream.try_clone().unwrap();
                    let _ = io::copy(&mut reader, &mut stream);
                    let _ = stream.shutdown(Shutdown::Write);
                });
            }
        });
        address
    }

    struct Running {
        address: SocketAddr,
        proxy: Arc<Proxy>,
        asked: Arc<Mutex<Vec<String>>>,
    }

    fn start(token: Option<ProxyToken>) -> Running {
        start_with(token, LIMITS)
    }

    fn start_with(token: Option<ProxyToken>, limits: Limits) -> Running {
        let allowlist = Allowlist::new(vec![
            "api.example.com".parse().unwrap(),
            "down.example.com".parse().unwrap(),
        ]);
        let asked = Arc::new(Mutex::new(Vec::new()));
        let connector = LocalConnector {
            upstream: echo_server(),
            asked: Arc::clone(&asked),
        };
        let mut proxy = Proxy::new(allowlist, Box::new(connector), token);
        proxy.limits = limits;
        let proxy = Arc::new(proxy);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let serving = Arc::clone(&proxy);
        thread::spawn(move || serve(&listener, &serving));
        Running {
            address,
            proxy,
            asked,
        }
    }

    fn request(running: &Running, head: &str, then: &[u8]) -> (String, TcpStream) {
        let mut client = TcpStream::connect(running.address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client.write_all(head.as_bytes()).unwrap();
        client.write_all(then).unwrap();
        let mut status = Vec::new();
        let mut byte = [0_u8; 1];
        while !status.ends_with(b"\r\n\r\n") {
            if client.read(&mut byte).unwrap() == 0 {
                break;
            }
            status.push(byte[0]);
        }
        (String::from_utf8(status).unwrap(), client)
    }

    fn status(running: &Running, head: &str) -> String {
        let (response, _) = request(running, head, b"");
        response.lines().next().unwrap_or_default().to_owned()
    }

    #[test]
    fn an_allowed_host_gets_a_tunnel_that_carries_early_bytes_both_ways() {
        let running = start(None);
        let (response, mut client) = request(
            &running,
            "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\nhello ",
            b"",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        client.write_all(b"world").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut echoed = String::new();
        client.read_to_string(&mut echoed).unwrap();
        assert_eq!(echoed, "hello world");
    }

    #[test]
    fn hosts_ports_and_addresses_off_the_list_are_forbidden() {
        let running = start(None);
        for target in [
            "other.example.com:443",
            "example.com:443",
            "api.example.com:80",
            "api.example.com:8443",
            "127.0.0.1:443",
            "[::1]:443",
            "localhost:443",
        ] {
            assert_eq!(
                status(&running, &format!("CONNECT {target} HTTP/1.1\r\n\r\n")),
                "HTTP/1.1 403 Forbidden",
                "{target}"
            );
        }
        assert!(running.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn anything_but_a_well_formed_connect_is_a_bad_request() {
        let running = start(None);
        for head in [
            "GET http://api.example.com/ HTTP/1.1\r\n\r\n",
            "CONNECT api.example.com HTTP/1.1\r\n\r\n",
            "CONNECT api.example.com:443\r\n\r\n",
            "CONNECT api.example.com:443 HTTP/2 extra\r\n\r\n",
            "CONNECT api.example.com:99999 HTTP/1.1\r\n\r\n",
            "\r\n\r\n",
        ] {
            assert_eq!(
                status(&running, head),
                "HTTP/1.1 400 Bad Request",
                "{head:?}"
            );
        }
        let huge = format!(
            "CONNECT api.example.com:443 HTTP/1.1\r\nX: {}\r\n\r\n",
            "a".repeat(HEAD_LIMIT)
        );
        assert_eq!(status(&running, &huge), "HTTP/1.1 400 Bad Request");
    }

    #[test]
    fn an_unreachable_host_is_a_bad_gateway() {
        let running = start(None);
        assert_eq!(
            status(&running, "CONNECT down.example.com:443 HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 502 Bad Gateway"
        );
    }

    #[test]
    fn a_token_is_required_when_the_proxy_has_one() {
        let running = start(Some(ProxyToken::new("s3cret")));
        let connect = "CONNECT api.example.com:443 HTTP/1.1\r\n";
        let basic = |credentials: &str| {
            format!(
                "{connect}Proxy-Authorization: Basic {}\r\n\r\n",
                STANDARD.encode(credentials)
            )
        };
        assert_eq!(
            status(&running, &format!("{connect}\r\n")),
            "HTTP/1.1 407 Proxy Authentication Required"
        );
        for wrong in ["mahi:wrong", "other:s3cret", "mahi:s3cre", "mahi:s3cret2"] {
            assert_eq!(
                status(&running, &basic(wrong)),
                "HTTP/1.1 407 Proxy Authentication Required",
                "{wrong}"
            );
        }
        let twice = format!(
            "{connect}Proxy-Authorization: Basic {0}\r\nproxy-authorization: Basic {0}\r\n\r\n",
            STANDARD.encode("mahi:s3cret")
        );
        assert_eq!(status(&running, &twice), "HTTP/1.1 400 Bad Request");
        assert_eq!(
            status(&running, &basic("mahi:s3cret")),
            "HTTP/1.1 200 Connection Established"
        );
        assert!(!format!("{:?}", running.proxy).contains("s3cret"));
    }

    #[test]
    fn connections_beyond_the_limit_get_no_slot() {
        let proxy = Arc::new(Proxy::new(
            Allowlist::default(),
            Box::new(PublicConnector),
            None,
        ));
        let slots: Vec<Slot> = (0..LIMITS.max_connections)
            .map(|_| Slot::take(&proxy).unwrap())
            .collect();
        assert!(Slot::take(&proxy).is_none());
        drop(slots);
        assert!(Slot::take(&proxy).is_some());
    }

    fn fast() -> Limits {
        Limits {
            head_deadline: Duration::from_millis(200),
            idle_limit: Duration::from_millis(300),
            idle_check: Duration::from_millis(50),
            max_connections: 1,
        }
    }

    #[test]
    fn a_client_that_never_finishes_its_request_is_refused_at_the_deadline() {
        let running = start_with(None, fast());
        let started = Instant::now();
        assert_eq!(
            status(&running, "CONNECT api.example.com:443 HTTP/1.1\r\n"),
            "HTTP/1.1 400 Bad Request"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn an_idle_tunnel_is_closed() {
        let running = start_with(None, fast());
        let (response, mut client) = request(
            &running,
            "CONNECT api.example.com:443 HTTP/1.1\r\n\r\n",
            b"",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let started = Instant::now();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_client_over_the_limit_is_told_the_proxy_is_busy() {
        let running = start_with(
            None,
            Limits {
                idle_limit: Duration::from_secs(60),
                ..fast()
            },
        );
        let (response, _held) = request(
            &running,
            "CONNECT api.example.com:443 HTTP/1.1\r\n\r\n",
            b"",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(
            status(&running, "CONNECT api.example.com:443 HTTP/1.1\r\n\r\n"),
            "HTTP/1.1 503 Service Unavailable"
        );
    }

    #[test]
    fn only_public_addresses_are_connected_to() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let error = connect_public(&[local], Instant::now() + CONNECT_DEADLINE).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[test]
    fn folded_or_misnamed_authorization_headers_do_not_count() {
        let running = start(Some(ProxyToken::new("s3cret")));
        let value = STANDARD.encode("mahi:s3cret");
        for head in [
            format!(
                "CONNECT api.example.com:443 HTTP/1.1\r\nProxy-Authorization:\r\n Basic {value}\r\n\r\n"
            ),
            format!(
                "CONNECT api.example.com:443 HTTP/1.1\r\nProxy-Authorization : Basic {value}\r\n\r\n"
            ),
            format!("CONNECT api.example.com:443 HTTP/1.1\r\nAuthorization: Basic {value}\r\n\r\n"),
            format!(
                "CONNECT api.example.com:443 HTTP/1.1\r\nProxy-Authorization: basic {value}\r\n\r\n"
            ),
        ] {
            assert_eq!(
                status(&running, &head),
                "HTTP/1.1 407 Proxy Authentication Required",
                "{head:?}"
            );
        }
        assert_eq!(
            status(
                &running,
                &format!(
                    "CONNECT api.example.com:443 HTTP/1.1\nProxy-Authorization: Basic {value}\n\r\n\r\n"
                )
            ),
            "HTTP/1.1 200 Connection Established"
        );
    }
}
