use std::{
    any::Any,
    fmt,
    io::{
        self,
        BufRead,
        BufReader,
        Cursor,
        Read,
    },
    sync::Arc,
    thread,
    time::Duration,
};

use gix::{
    protocol::transport::Protocol,
    sec::identity::Account,
};
use gix_error::{
    ExnMessageResult,
    ExnResult,
    Message,
    ResultExt,
};
use gix_features::io::pipe;
use gix_transport::client::{
    TransportWithoutIO,
    blocking_io::http::{
        self,
        GetResponse,
        Http,
        PostBodyDataKind,
        PostResponse,
    },
};
use thiserror::Error;
use ureq::{
    Agent,
    Body,
    SendBody,
    http::Response,
    tls::{
        Certificate,
        RootCerts,
        TlsConfig,
        TlsProvider,
    },
    unversioned::{
        resolver::DefaultResolver,
        transport::{
            Buffers,
            ConnectionDetails,
            Connector,
            DefaultConnector,
            NextTimeout,
            Transport,
        },
    },
};
use zeroize::Zeroizing;

use crate::{
    HttpsRemote,
    ProxySetting,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const STALL_TIMEOUT: Duration = Duration::from_secs(300);
const PIPE_WRITES: usize = 16;
const DEFAULT_USER: &str = "x-access-token";

/// Where the server certificates an HTTPS remote presents are checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Roots {
    /// The Web PKI's roots, as `webpki-roots` holds them.
    WebPki,
    /// Only these DER certificates, such as a test's own authority.
    Only(Vec<Vec<u8>>),
}

/// A token an HTTPS remote accepts, sent with Basic authentication. It never appears in
/// `Debug` output and is wiped when dropped.
#[derive(Clone)]
pub struct Token(Zeroizing<String>);

impl Token {
    /// Takes `secret`: a token, sent with the user the remote's URL names or else
    /// `x-access-token`, or `user:token`.
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token")
    }
}

/// How to reach HTTPS remotes: the proxy, the certificate roots, and the token.
#[derive(Debug, Clone)]
pub struct HttpsAccess {
    /// The proxy from `HTTPS_PROXY` and `NO_PROXY`, if any.
    pub proxy: Option<ProxySetting>,
    /// The roots server certificates are checked against.
    pub roots: Roots,
    /// The token for the remote's host, if one is stored.
    pub token: Option<Token>,
}

/// Why an HTTPS remote cannot be reached.
#[derive(Debug, Error)]
pub enum ConnectError {
    /// The proxy is not one this client can use.
    #[error("the proxy is not usable")]
    Proxy,
    /// The transport refused the credentials.
    #[error("cannot use the credentials")]
    Credentials(#[source] gix_transport::client::Error),
}

/// A git transport to an HTTPS remote, speaking the smart HTTP protocol.
pub type HttpsTransport = http::Transport<Client>;

/// Returns a transport to `remote` through `access`'s proxy, unless its host is let through
/// directly, checking the server against `access`'s roots and sending its token. Redirects are
/// not followed, so the token only ever goes to the remote's own host.
///
/// # Errors
///
/// Returns [`ConnectError::Proxy`] if the proxy URL cannot be used, or
/// [`ConnectError::Credentials`] if the token cannot be set.
pub fn connect(remote: &HttpsRemote, access: &HttpsAccess) -> Result<HttpsTransport, ConnectError> {
    let client = client(remote.host(), access)?;
    let mut transport = http::connect_http(client, remote.url().clone(), Protocol::V2, false);
    if let Some(token) = &access.token {
        let (username, password) = match token.0.split_once(':') {
            Some((user, password)) => (user.to_owned(), password.to_owned()),
            None => (
                remote.user().unwrap_or(DEFAULT_USER).to_owned(),
                token.0.as_str().to_owned(),
            ),
        };
        transport
            .set_identity(Account {
                username,
                password,
                oauth_refresh_token: None,
            })
            .map_err(ConnectError::Credentials)?;
    }
    Ok(transport)
}

/// Returns the HTTP client for requests to `host`: through `access`'s proxy unless the host is
/// let through directly, checking servers against `access`'s roots, following no redirect.
///
/// # Errors
///
/// Returns [`ConnectError::Proxy`] if the proxy URL cannot be used.
pub fn client(host: &str, access: &HttpsAccess) -> Result<Client, ConnectError> {
    let proxy = match access.proxy.as_ref().and_then(|proxy| proxy.for_host(host)) {
        Some(url) => Some(ureq::Proxy::new(url).map_err(|_| ConnectError::Proxy)?),
        None => None,
    };
    let roots = match &access.roots {
        Roots::WebPki => RootCerts::WebPki,
        Roots::Only(certificates) => {
            let owned: Vec<Certificate<'static>> = certificates
                .iter()
                .map(|der| Certificate::from_der(der).to_owned())
                .collect();
            RootCerts::new_with_certs(&owned)
        }
    };
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(roots)
        .unversioned_rustls_crypto_provider(Arc::new(mahi_tls::provider()))
        .build();
    let config = Agent::config_builder()
        .proxy(proxy)
        .tls_config(tls)
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_recv_response(Some(RESPONSE_TIMEOUT))
        .build();
    let connector = DefaultConnector::new().chain(StallBound);
    Ok(Client {
        agent: Agent::with_parts(config, connector, DefaultResolver::default()),
    })
}

/// Wraps every connection so no single wait to send or receive lasts longer than five
/// minutes: a server or proxy that stops making progress fails the transfer instead of
/// holding it forever.
#[derive(Debug)]
struct StallBound;

impl Connector<Box<dyn Transport>> for StallBound {
    type Out = Bounded;

    fn connect(
        &self,
        _details: &ConnectionDetails,
        chained: Option<Box<dyn Transport>>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        Ok(chained.map(Bounded))
    }
}

#[derive(Debug)]
struct Bounded(Box<dyn Transport>);

impl Transport for Bounded {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.0.buffers()
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.0.transmit_output(amount, capped(timeout))
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.0.await_input(capped(timeout))
    }

    fn is_open(&mut self) -> bool {
        self.0.is_open()
    }

    fn is_tls(&self) -> bool {
        self.0.is_tls()
    }
}

fn capped(timeout: NextTimeout) -> NextTimeout {
    let stall = STALL_TIMEOUT.into();
    if timeout.after > stall {
        NextTimeout {
            after: stall,
            reason: timeout.reason,
        }
    } else {
        timeout
    }
}

/// The HTTP client gix's smart HTTP transport sends its requests through.
pub struct Client {
    agent: Agent,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Client")
    }
}

type Headers = Box<dyn BufRead + Send + Unpin>;

impl Http for Client {
    type Headers = Headers;
    type ResponseBody = Headers;
    type PostBody = pipe::Writer;

    fn get(
        &mut self,
        url: &str,
        _base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> ExnMessageResult<GetResponse<Self::Headers, Self::ResponseBody>> {
        let mut request = self.agent.get(url);
        for header in headers {
            if let Some((name, value)) = header.as_ref().split_once(':') {
                request = request.header(name.trim(), value.trim());
            }
        }
        let response = request
            .call()
            .map_err(io::Error::other)
            .or_raise(|| Message::new("cannot reach the remote"))?;
        let (headers, body) = accepted(response).or_raise(|| Message::new("the remote refused"))?;
        Ok(GetResponse {
            headers: Box::new(Cursor::new(headers)),
            body: Box::new(BufReader::new(body)),
        })
    }

    fn post(
        &mut self,
        url: &str,
        _base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        _body: PostBodyDataKind,
    ) -> ExnMessageResult<PostResponse<Self::Headers, Self::ResponseBody, Self::PostBody>> {
        let mut request = self.agent.post(url);
        for header in headers {
            if let Some((name, value)) = header.as_ref().split_once(':') {
                request = request.header(name.trim(), value.trim());
            }
        }
        let (post_body, post_reader) = pipe::unidirectional(PIPE_WRITES);
        let (mut headers_writer, headers_reader) = pipe::unidirectional(1);
        let (mut body_writer, body_reader) = pipe::unidirectional(PIPE_WRITES);
        let worker = thread::Builder::new().name("mahi-http-post".to_owned());
        let spawned = worker.spawn(move || {
            let sent = request
                .send(SendBody::from_owned_reader(post_reader))
                .map_err(io::Error::other)
                .and_then(accepted);
            match sent {
                Ok((headers, body)) => {
                    let _ = io::Write::write_all(&mut headers_writer, &headers);
                    drop(headers_writer);
                    if let Err(error) = io::copy(&mut { body }, &mut body_writer) {
                        let _ = body_writer.channel.send(Err(error));
                    }
                }
                Err(error) => {
                    let kind = error.kind();
                    let _ = headers_writer
                        .channel
                        .send(Err(io::Error::new(kind, error.to_string())));
                    let _ = body_writer.channel.send(Err(error));
                }
            }
        });
        spawned.or_raise(|| Message::new("cannot start the request"))?;
        Ok(PostResponse {
            post_body,
            headers: Box::new(headers_reader),
            body: Box::new(body_reader),
        })
    }

    fn configure(&mut self, _config: &dyn Any) -> ExnResult {
        Ok(())
    }
}

/// Returns the header lines of a successful response, leaving out values that are not
/// visible ASCII, and its body; or an error for any other response:
/// a redirect, which is not followed, refused credentials, or another status.
fn accepted(response: Response<Body>) -> io::Result<(Vec<u8>, impl Read + Send + 'static)> {
    let status = response.status();
    if status.is_redirection() {
        return Err(io::Error::other(
            "the remote redirected elsewhere; set the remote's url to where it moved",
        ));
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the remote refused access (HTTP {}); store a token with mahi credential add",
                status.as_u16()
            ),
        ));
    }
    if !status.is_success() {
        return Err(io::Error::other(format!(
            "the remote answered HTTP {}",
            status.as_u16()
        )));
    }
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        headers.extend_from_slice(name.as_str().as_bytes());
        headers.extend_from_slice(b": ");
        headers.extend_from_slice(value.as_bytes());
        headers.push(b'\n');
    }
    Ok((headers, response.into_body().into_reader()))
}
