use std::{
    io::{
        self,
        Read,
        Write,
    },
    os::unix::net::UnixStream,
    path::{
        Path,
        PathBuf,
    },
    time::{
        Duration,
        Instant,
    },
};

use rustix::{
    event::{
        PollFd,
        PollFlags,
        Timespec,
        poll,
    },
    io::Errno,
};
use ssh_key::{
    Algorithm,
    HashAlg,
    PublicKey,
    Signature,
    SshSig,
};
use thiserror::Error;

const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;
const MAX_RESPONSE_BYTES: u32 = 1024;
const TIMEOUT: Duration = Duration::from_secs(60);

/// A connection point to a running ssh-agent, which signs with keys it holds unlocked.
///
/// Only signing is used: mahi never asks the agent for anything else. A whole exchange must
/// finish within 60 seconds, long enough for the agent to ask the user to confirm or touch a
/// hardware key.
#[derive(Debug, Clone)]
pub struct SshAgent {
    socket: PathBuf,
    timeout: Duration,
}

/// An SSH key held by an agent, used to make SSHSIG signatures.
#[derive(Debug, Clone)]
pub struct AgentSigner {
    agent: SshAgent,
    key: PublicKey,
}

/// Talking to the agent failed.
#[derive(Debug, Error)]
pub enum AgentError {
    /// The agent socket cannot be reached.
    #[error("cannot reach ssh-agent at {}", .0.display())]
    Connect(PathBuf, #[source] io::Error),
    /// The agent refused, usually because it does not hold the key.
    #[error("ssh-agent refused to sign; is the key loaded (ssh-add)?")]
    Refused,
    /// The agent's answer is not a valid ed25519 signature response.
    #[error("ssh-agent sent a malformed response")]
    Malformed,
    /// The agent signed, but not with the requested key.
    #[error("ssh-agent signed with a different key")]
    WrongKey,
    /// The key is not ed25519, the only kind mahi signs with.
    #[error("{0} keys are not supported for signing; use an ed25519 key")]
    UnsupportedKey(String),
    /// Reading from or writing to the agent failed, or it did not answer in time.
    #[error("ssh-agent connection failed")]
    Io(#[from] io::Error),
    /// Building the signature failed.
    #[error("cannot build signature")]
    Signature(#[from] ssh_key::Error),
}

impl SshAgent {
    /// Uses the agent listening on `socket`, the value of `SSH_AUTH_SOCK`.
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
            timeout: TIMEOUT,
        }
    }

    /// Asks the agent to sign `data` with `key`, and returns the raw ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Refused`] if the agent does not sign, [`AgentError::Malformed`] if
    /// its answer is not an ed25519 signature, or another [`AgentError`] if the connection
    /// fails.
    pub fn sign(&self, key: &PublicKey, data: &[u8]) -> Result<Signature, AgentError> {
        let deadline = Instant::now() + self.timeout;
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|error| AgentError::Connect(self.socket.clone(), error))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let mut body = vec![SIGN_REQUEST];
        put_string(&mut body, &key.to_bytes()?)?;
        put_string(&mut body, data)?;
        body.extend_from_slice(&0u32.to_be_bytes());
        let len = u32::try_from(body.len()).map_err(|_| AgentError::Malformed)?;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(&body)?;
        stream.set_nonblocking(true)?;

        let response = read_frame(&mut stream, deadline)?;
        match response.split_first() {
            Some((&SIGN_RESPONSE, rest)) => {
                let (blob, rest) = take_string(rest).ok_or(AgentError::Malformed)?;
                if !rest.is_empty() {
                    return Err(AgentError::Malformed);
                }
                let signature = Signature::try_from(blob).map_err(|_| AgentError::Malformed)?;
                if signature.algorithm() != Algorithm::Ed25519 {
                    return Err(AgentError::Malformed);
                }
                Ok(signature)
            }
            Some((&FAILURE, [])) => Err(AgentError::Refused),
            _ => Err(AgentError::Malformed),
        }
    }
}

impl AgentSigner {
    /// Signs with `key` through `agent`.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::UnsupportedKey`] if `key` is not ed25519.
    pub fn new(agent: SshAgent, key: PublicKey) -> Result<Self, AgentError> {
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(AgentError::UnsupportedKey(key.algorithm().to_string()));
        }
        Ok(Self { agent, key })
    }

    /// Returns the key the agent signs with.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// Makes an SSHSIG signature over `message` in `namespace`, and checks it before returning.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] if the agent does not sign, or its signature does not verify.
    pub fn sign(
        &self,
        namespace: &str,
        hash: HashAlg,
        message: &[u8],
    ) -> Result<SshSig, AgentError> {
        let data = SshSig::signed_data(namespace, hash, message)?;
        let raw = self.agent.sign(&self.key, &data)?;
        let signature = SshSig::new(self.key.key_data().clone(), namespace, hash, raw)?;
        self.key
            .verify(namespace, message, &signature)
            .map_err(|_| AgentError::WrongKey)?;
        Ok(signature)
    }
}

fn put_string(buffer: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AgentError> {
    let len = u32::try_from(bytes.len()).map_err(|_| AgentError::Malformed)?;
    buffer.extend_from_slice(&len.to_be_bytes());
    buffer.extend_from_slice(bytes);
    Ok(())
}

fn take_string(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    (rest.len() >= len).then(|| rest.split_at(len))
}

fn read_frame(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, AgentError> {
    let mut len = [0; 4];
    read_exact_by(stream, &mut len, deadline)?;
    let len = u32::from_be_bytes(len);
    if len == 0 || len > MAX_RESPONSE_BYTES {
        return Err(AgentError::Malformed);
    }
    let mut frame = vec![0; usize::try_from(len).map_err(|_| AgentError::Malformed)?];
    read_exact_by(stream, &mut frame, deadline)?;
    Ok(frame)
}

fn read_exact_by(stream: &mut UnixStream, mut buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => buf = &mut buf[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_readable(stream, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn wait_readable(stream: &UnixStream, deadline: Instant) -> io::Result<()> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(io::ErrorKind::TimedOut)?;
    let timeout = Timespec::try_from(left).map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut fds = [PollFd::new(stream, PollFlags::IN)];
    match poll(&mut fds, Some(&timeout)) {
        Ok(0) => Err(io::ErrorKind::TimedOut.into()),
        Ok(_) | Err(Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::net::UnixListener,
        thread::{
            self,
            JoinHandle,
        },
    };

    use ssh_key::{
        PrivateKey,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    struct FakeAgent {
        _dir: TempDir,
        socket: PathBuf,
        handle: JoinHandle<Vec<u8>>,
    }

    fn fake_agent(answer: impl FnOnce(&[u8]) -> Vec<u8> + Send + 'static) -> FakeAgent {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let request = read_frame(&mut stream, deadline).unwrap();
            let response = answer(&request);
            let _ = stream.write_all(&response);
            request
        });
        FakeAgent {
            _dir: dir,
            socket,
            handle,
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut framed = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(body);
        framed
    }

    fn signing_agent(key: PrivateKey) -> impl FnOnce(&[u8]) -> Vec<u8> {
        move |request| {
            let (_, rest) = request.split_first().unwrap();
            let (_, rest) = take_string(rest).unwrap();
            let (data, _) = take_string(rest).unwrap();
            let signature: Signature = signature::Signer::try_sign(&key, data).unwrap();
            let mut body = vec![SIGN_RESPONSE];
            put_string(&mut body, &Vec::<u8>::try_from(signature).unwrap()).unwrap();
            frame(&body)
        }
    }

    #[test]
    fn an_agent_signature_becomes_a_verified_sshsig() {
        let key = ed25519();
        let agent = fake_agent(signing_agent(key.clone()));
        let signer =
            AgentSigner::new(SshAgent::new(&agent.socket), key.public_key().clone()).unwrap();
        let signature = signer.sign("mahi-meta", HashAlg::Sha512, b"body").unwrap();
        let request = agent.handle.join().unwrap();
        let (kind, rest) = request.split_first().unwrap();
        assert_eq!(*kind, SIGN_REQUEST);
        let (blob, rest) = take_string(rest).unwrap();
        assert_eq!(blob, key.public_key().to_bytes().unwrap());
        let (data, flags) = take_string(rest).unwrap();
        assert_eq!(
            data,
            SshSig::signed_data("mahi-meta", HashAlg::Sha512, b"body").unwrap()
        );
        assert_eq!(flags, [0; 4]);
        assert!(
            key.public_key()
                .verify("mahi-meta", b"body", &signature)
                .is_ok()
        );
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let key = ed25519();
        let agent = fake_agent(signing_agent(ed25519()));
        let signer =
            AgentSigner::new(SshAgent::new(&agent.socket), key.public_key().clone()).unwrap();
        let result = signer.sign("mahi-meta", HashAlg::Sha512, b"body");
        agent.handle.join().unwrap();
        assert!(matches!(result, Err(AgentError::WrongKey)));
    }

    #[test]
    fn a_refusal_is_reported() {
        let key = ed25519();
        let agent = fake_agent(|_| frame(&[FAILURE]));
        let result = SshAgent::new(&agent.socket).sign(key.public_key(), b"data");
        agent.handle.join().unwrap();
        assert!(matches!(result, Err(AgentError::Refused)));
    }

    #[test]
    fn malformed_and_oversized_answers_are_refused() {
        let answers: Vec<Vec<u8>> = vec![
            frame(&[SIGN_RESPONSE]),
            frame(&[SIGN_RESPONSE, 0, 0, 0, 9, 1, 2]),
            frame(&[99]),
            frame(&[FAILURE, 0]),
            frame(&[SIGN_RESPONSE, 0, 0, 0, 1, 7, 0]),
            frame(&signature_response(b"ssh-rsa", &[1; 64])),
            frame(&signature_response(b"ssh-ed25519", &[1; 10])),
            vec![0, 0, 0, 0],
            (MAX_RESPONSE_BYTES + 1).to_be_bytes().to_vec(),
        ];
        for answer in answers {
            let key = ed25519();
            let expected = answer.clone();
            let agent = fake_agent(move |_| answer);
            let result = SshAgent::new(&agent.socket).sign(key.public_key(), b"data");
            agent.handle.join().unwrap();
            assert!(matches!(result, Err(AgentError::Malformed)), "{expected:?}");
        }
    }

    fn signature_response(algorithm: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        put_string(&mut blob, algorithm).unwrap();
        put_string(&mut blob, signature).unwrap();
        let mut body = vec![SIGN_RESPONSE];
        put_string(&mut body, &blob).unwrap();
        body
    }

    #[test]
    fn a_frame_cut_short_is_an_io_error() {
        let key = ed25519();
        let agent = fake_agent(|_| vec![0, 0, 0, 50, SIGN_RESPONSE, 1, 2]);
        let result = SshAgent::new(&agent.socket).sign(key.public_key(), b"data");
        agent.handle.join().unwrap();
        assert!(
            matches!(result, Err(AgentError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn a_slow_agent_is_cut_off_at_the_deadline() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(&[0, 0, 0, 100]);
            for _ in 0..40 {
                thread::sleep(Duration::from_millis(50));
                if stream.write_all(&[0]).is_err() {
                    break;
                }
            }
        });
        let agent = SshAgent {
            socket,
            timeout: Duration::from_millis(300),
        };
        let started = Instant::now();
        let result = agent.sign(ed25519().public_key(), b"data");
        let elapsed = started.elapsed();
        handle.join().unwrap();
        assert!(matches!(result, Err(AgentError::Io(e)) if e.kind() == io::ErrorKind::TimedOut));
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    }

    #[test]
    fn only_ed25519_keys_can_sign() {
        let dir = TempDir::new().unwrap();
        let rsa = PublicKey::from_openssh(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDU88jp0gZG1pnbk45/jquMkXECFQjH4lB40SRDQBOd6sYfqqaLt1gdu0tK8jApiV/sbirg4lAgTEWOfYCkXegaBgE51266E3LYEwRcgp/KosX0sw0AACaLV5wQtlNUegIaNEmXGxCK4tKcdoYj+kNKnk9r33GLXcbL3yeIyGRGvw==",
        )
        .unwrap();
        let ed25519_key = *ed25519().public_key().key_data().ed25519().unwrap();
        let security_key = PublicKey::new(
            ssh_key::public::KeyData::SkEd25519(ssh_key::public::SkEd25519::new(
                ed25519_key,
                "ssh:",
            )),
            "",
        );
        for key in [rsa, security_key] {
            assert!(
                matches!(
                    AgentSigner::new(SshAgent::new(&dir.path().join("s")), key.clone()),
                    Err(AgentError::UnsupportedKey(_))
                ),
                "{}",
                key.algorithm()
            );
        }
    }

    #[test]
    fn a_missing_socket_is_a_connection_error() {
        let dir = TempDir::new().unwrap();
        let key = ed25519();
        assert!(matches!(
            SshAgent::new(&dir.path().join("none.sock")).sign(key.public_key(), b"data"),
            Err(AgentError::Connect(..))
        ));
    }
}
