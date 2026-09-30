//! An HTTPS server for the tests, signed by a test authority with an Ed25519 key, answering
//! each request on its own connection.

use std::{
    fmt::Write as _,
    io::{
        BufRead,
        BufReader,
        Read,
        Write,
    },
    net::TcpListener,
    sync::{
        Arc,
        Mutex,
    },
    thread,
};

use ed25519_dalek::Signer as _;
use rustls::{
    ServerConfig,
    ServerConnection,
    SignatureAlgorithm,
    SignatureScheme,
    StreamOwned,
    pki_types::CertificateDer,
    server::{
        ClientHello,
        ResolvesServerCert,
    },
    sign::{
        CertifiedKey,
        Signer,
        SigningKey,
    },
};

pub(crate) const CA: &[u8] = include_bytes!("../data/ca.der");
const CERT: &[u8] = include_bytes!("../data/server.der");
const KEY: &[u8] = include_bytes!("../data/server-key.der");

#[derive(Debug)]
struct Ed25519(ed25519_dalek::SigningKey);

impl SigningKey for Ed25519 {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(Ed25519(self.0.clone())) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Signer for Ed25519 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[derive(Debug)]
struct Resolver(Arc<CertifiedKey>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub(crate) line: String,
    pub(crate) headers: Vec<String>,
    pub(crate) body: Vec<u8>,
}

impl Request {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|header| {
            let (key, value) = header.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

pub(crate) type Reply = (u16, Vec<(&'static str, String)>, Vec<u8>);
pub(crate) type Answer = Arc<dyn Fn(&Request) -> Reply + Send + Sync>;

pub(crate) struct Server {
    pub(crate) port: u16,
    pub(crate) requests: Arc<Mutex<Vec<Request>>>,
}

pub(crate) fn server(answer: Answer) -> Server {
    let secret: [u8; 32] = KEY[KEY.len() - 32..].try_into().unwrap();
    let key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(CERT.to_vec())],
        Arc::new(Ed25519(ed25519_dalek::SigningKey::from_bytes(&secret))),
    ));
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(mahi_tls::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(key))),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let config = Arc::clone(&config);
            let seen = Arc::clone(&seen);
            let answer = Arc::clone(&answer);
            thread::spawn(move || {
                let connection = ServerConnection::new(config).unwrap();
                let mut tls = StreamOwned::new(connection, stream);
                let Some(request) = read_request(&mut tls) else {
                    return;
                };
                let (status, headers, body) = answer(&request);
                seen.lock().unwrap().push(request);
                let mut response = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
                for (name, value) in headers {
                    let _ = write!(response, "{name}: {value}\r\n");
                }
                let _ = write!(response, "Content-Length: {}\r\n\r\n", body.len());
                let _ = tls.write_all(response.as_bytes());
                let _ = tls.write_all(&body);
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    Server { port, requests }
}

pub(crate) fn read_request(stream: &mut impl Read) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end().to_owned();
        if header.is_empty() {
            break;
        }
        headers.push(header);
    }
    let mut request = Request {
        line: line.trim_end().to_owned(),
        headers,
        body: Vec::new(),
    };
    if request.header("transfer-encoding") == Some("chunked") {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).ok()?;
            let size = usize::from_str_radix(size.trim(), 16).ok()?;
            let mut chunk = vec![0; size + 2];
            reader.read_exact(&mut chunk).ok()?;
            if size == 0 {
                break;
            }
            request.body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(length) = request.header("content-length") {
        let mut body = vec![0; length.parse().ok()?];
        reader.read_exact(&mut body).ok()?;
        request.body = body;
    }
    Some(request)
}
