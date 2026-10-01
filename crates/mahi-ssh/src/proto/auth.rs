use signature::Verifier;
use ssh_key::{
    PublicKey,
    Signature,
};
use thiserror::Error;

use super::{
    kex::HostKeyAlgorithm,
    message::{
        self,
        AuthMethod,
        Message,
    },
    transport::{
        Transport,
        TransportError,
    },
    wire::{
        Reader,
        WireError,
        put_bool,
        put_string,
    },
};

pub(crate) const MAX_KEYS: usize = 6;
const USERAUTH: &[u8] = b"ssh-userauth";
const CONNECTION: &[u8] = b"ssh-connection";

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum AuthError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("the server sent message {0} during login")]
    Unexpected(u8),
    #[error("the server accepted none of the keys")]
    NotAccepted,
    #[error("ssh-agent's signature does not verify with its key")]
    AgentSignature,
    #[error("the server does not accept public-key logins")]
    MethodNotOffered,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    Continue,
    Sign(Vec<u8>),
    Authenticated,
}

struct Candidate {
    key: PublicKey,
    blob: Vec<u8>,
    algorithm: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    ServiceAccept,
    Accepted,
    Signature,
    Result,
    Done,
}

pub(crate) struct Auth {
    user: String,
    candidates: Vec<Candidate>,
    current: usize,
    state: State,
    session_id: [u8; 32],
    scratch: Vec<u8>,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Auth")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

pub(crate) fn login_algorithm(key: &PublicKey) -> Option<&'static str> {
    HostKeyAlgorithm::ALL
        .into_iter()
        .map(HostKeyAlgorithm::name)
        .find(|name| *name == key.algorithm().as_str())
}

impl Auth {
    pub(crate) fn start(
        transport: &mut Transport,
        user: &str,
        keys: impl IntoIterator<Item = PublicKey>,
    ) -> Result<Self, AuthError> {
        let session_id = *transport.session_id().ok_or(TransportError::NotReady)?;
        let candidates = keys
            .into_iter()
            .filter_map(|key| {
                let algorithm = login_algorithm(&key)?;
                let blob = key.to_bytes().ok()?;
                Some(Candidate {
                    key,
                    blob,
                    algorithm,
                })
            })
            .take(MAX_KEYS)
            .collect();
        let mut auth = Self {
            user: user.to_owned(),
            candidates,
            current: 0,
            state: State::ServiceAccept,
            session_id,
            scratch: Vec::with_capacity(256),
        };
        auth.send(transport, Message::ServiceRequest(USERAUTH))?;
        Ok(auth)
    }

    pub(crate) fn key(&self) -> Option<&PublicKey> {
        self.candidates
            .get(self.current)
            .map(|candidate| &candidate.key)
    }

    pub(crate) fn handle(
        &mut self,
        transport: &mut Transport,
        payload: &[u8],
    ) -> Result<Progress, AuthError> {
        let message = Message::decode(payload)?;
        match (self.state, message) {
            (State::Done, _) => {}
            (_, Message::UserauthBanner { .. }) => return Ok(Progress::Continue),
            (State::ServiceAccept, Message::ServiceAccept(USERAUTH)) => {
                self.query(transport)?;
                return Ok(Progress::Continue);
            }
            (State::Accepted, Message::UserauthPkOk { algorithm, key }) => {
                let candidate = self
                    .candidates
                    .get(self.current)
                    .ok_or(AuthError::NotAccepted)?;
                if algorithm == candidate.algorithm.as_bytes() && key == candidate.blob {
                    self.state = State::Signature;
                    return Ok(Progress::Sign(self.signed_data()?));
                }
            }
            (State::Accepted | State::Result, Message::UserauthFailure { methods, .. }) => {
                if !methods.contains("publickey") {
                    self.state = State::Done;
                    return Err(AuthError::MethodNotOffered);
                }
                self.current += 1;
                self.query(transport)?;
                return Ok(Progress::Continue);
            }
            (State::Result, Message::UserauthSuccess) => {
                self.state = State::Done;
                transport.set_authenticated();
                return Ok(Progress::Authenticated);
            }
            _ => {}
        }
        Err(AuthError::Unexpected(
            payload.first().copied().unwrap_or_default(),
        ))
    }

    pub(crate) fn signed(
        &mut self,
        transport: &mut Transport,
        signature: &[u8],
    ) -> Result<Progress, AuthError> {
        if self.state != State::Signature {
            return Err(AuthError::Unexpected(message::USERAUTH_PK_OK));
        }
        let candidate = self
            .candidates
            .get(self.current)
            .ok_or(AuthError::NotAccepted)?;
        let data = self.signed_data()?;
        verify(candidate, &data, signature)?;
        let candidate = self
            .candidates
            .get(self.current)
            .ok_or(AuthError::NotAccepted)?;
        let request = Message::UserauthRequest {
            user: self.user.as_bytes(),
            service: CONNECTION,
            method: AuthMethod::PublicKey {
                algorithm: candidate.algorithm.as_bytes(),
                key: &candidate.blob,
                signature: Some(signature),
            },
        };
        self.scratch.clear();
        request.encode(&mut self.scratch)?;
        transport.send(&self.scratch)?;
        self.state = State::Result;
        Ok(Progress::Continue)
    }

    pub(crate) fn sign_refused(
        &mut self,
        transport: &mut Transport,
    ) -> Result<Progress, AuthError> {
        if self.state != State::Signature {
            return Err(AuthError::Unexpected(message::USERAUTH_PK_OK));
        }
        self.current += 1;
        self.query(transport)?;
        Ok(Progress::Continue)
    }

    fn query(&mut self, transport: &mut Transport) -> Result<(), AuthError> {
        let Some(candidate) = self.candidates.get(self.current) else {
            self.state = State::Done;
            return Err(AuthError::NotAccepted);
        };
        let request = Message::UserauthRequest {
            user: self.user.as_bytes(),
            service: CONNECTION,
            method: AuthMethod::PublicKey {
                algorithm: candidate.algorithm.as_bytes(),
                key: &candidate.blob,
                signature: None,
            },
        };
        self.scratch.clear();
        request.encode(&mut self.scratch)?;
        transport.send(&self.scratch)?;
        self.state = State::Accepted;
        Ok(())
    }

    fn send(&mut self, transport: &mut Transport, message: Message<'_>) -> Result<(), AuthError> {
        self.scratch.clear();
        message.encode(&mut self.scratch)?;
        transport.send(&self.scratch)?;
        Ok(())
    }

    fn signed_data(&self) -> Result<Vec<u8>, AuthError> {
        let candidate = self
            .candidates
            .get(self.current)
            .ok_or(AuthError::NotAccepted)?;
        let mut data = Vec::with_capacity(96 + self.user.len() + candidate.blob.len());
        put_string(&mut data, &self.session_id)?;
        data.push(message::USERAUTH_REQUEST);
        put_string(&mut data, self.user.as_bytes())?;
        put_string(&mut data, CONNECTION)?;
        put_string(&mut data, b"publickey")?;
        put_bool(&mut data, true);
        put_string(&mut data, candidate.algorithm.as_bytes())?;
        put_string(&mut data, &candidate.blob)?;
        Ok(data)
    }
}

fn verify(candidate: &Candidate, data: &[u8], blob: &[u8]) -> Result<(), AuthError> {
    let mut reader = Reader::new(blob);
    let algorithm = reader.string().map_err(|_| AuthError::AgentSignature)?;
    let bytes = reader.string().map_err(|_| AuthError::AgentSignature)?;
    reader.finish().map_err(|_| AuthError::AgentSignature)?;
    if algorithm != candidate.algorithm.as_bytes() {
        return Err(AuthError::AgentSignature);
    }
    let signature = Signature::new(candidate.key.algorithm(), bytes.to_vec())
        .map_err(|_| AuthError::AgentSignature)?;
    candidate
        .key
        .key_data()
        .verify(data, &signature)
        .map_err(|_| AuthError::AgentSignature)
}

#[cfg(test)]
mod tests {
    use ssh_key::{
        Algorithm,
        EcdsaCurve,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;
    use crate::proto::{
        test_server::{
            TestServer,
            connected,
            pump,
        },
        transport::Poll,
    };

    fn key(algorithm: Algorithm) -> PrivateKey {
        PrivateKey::random(&mut OsRng, algorithm).unwrap()
    }

    fn p256() -> Algorithm {
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }
    }

    fn sign(key: &PrivateKey, data: &[u8]) -> Vec<u8> {
        let signature: Signature = signature::Signer::try_sign(key.key_data(), data).unwrap();
        Vec::try_from(signature).unwrap()
    }

    fn expected_signed_data(session_id: &[u8], user: &str, key: &PublicKey) -> Vec<u8> {
        let blob = key.to_bytes().unwrap();
        let algorithm = key.algorithm();
        let mut data = Vec::new();
        for (field, string) in [
            (session_id, true),
            (&[message::USERAUTH_REQUEST][..], false),
            (user.as_bytes(), true),
            (b"ssh-connection", true),
            (b"publickey", true),
            (&[1][..], false),
            (algorithm.as_str().as_bytes(), true),
            (&blob, true),
        ] {
            if string {
                data.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            }
            data.extend_from_slice(field);
        }
        data
    }

    struct Server {
        accepted: Option<PublicKey>,
        session_id: [u8; 32],
        verified: bool,
    }

    impl Server {
        fn answer(&mut self, server: &mut TestServer) {
            for payload in std::mem::take(&mut server.received) {
                match Message::decode(&payload).unwrap() {
                    Message::ServiceRequest(b"ssh-userauth") => {
                        server.send_message(Message::UserauthBanner { message: b"hello" });
                        server.send_message(Message::ServiceAccept(b"ssh-userauth"));
                    }
                    Message::UserauthRequest {
                        user,
                        service: b"ssh-connection",
                        method:
                            AuthMethod::PublicKey {
                                algorithm,
                                key,
                                signature,
                            },
                    } => {
                        let presented = PublicKey::from_bytes(key).unwrap();
                        let accepted = self
                            .accepted
                            .as_ref()
                            .is_some_and(|accepted| accepted.key_data() == presented.key_data());
                        match (accepted, signature) {
                            (false, _) => server.send_message(failure()),
                            (true, None) => {
                                server.send_message(Message::UserauthPkOk { algorithm, key });
                            }
                            (true, Some(signature)) => {
                                let data = expected_signed_data(
                                    &self.session_id,
                                    std::str::from_utf8(user).unwrap(),
                                    &presented,
                                );
                                let signature = Signature::try_from(signature).unwrap();
                                presented.key_data().verify(&data, &signature).unwrap();
                                self.verified = true;
                                server.send_message(Message::UserauthSuccess);
                            }
                        }
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }

    fn failure() -> Message<'static> {
        Message::UserauthFailure {
            methods: crate::proto::wire::NameList::parse(b"publickey").unwrap(),
            partial: false,
        }
    }

    fn step(
        transport: &mut Transport,
        server: &mut TestServer,
        script: &mut Server,
        auth: &mut Auth,
    ) -> Result<Progress, AuthError> {
        loop {
            script.answer(server);
            match pump(transport, server)? {
                Poll::Message => {
                    let payload = transport.message().to_vec();
                    match auth.handle(transport, &payload)? {
                        Progress::Continue => {}
                        progress => return Ok(progress),
                    }
                }
                Poll::Pending if server.received.is_empty() => return Ok(Progress::Continue),
                _ => {}
            }
        }
    }

    fn setup(accepted: Option<&PrivateKey>) -> (Transport, TestServer, Server) {
        let (transport, server) = connected(HostKeyAlgorithm::Ed25519);
        let script = Server {
            accepted: accepted.map(|key| key.public_key().clone()),
            session_id: *transport.session_id().unwrap(),
            verified: false,
        };
        (transport, server, script)
    }

    #[test]
    fn the_agent_signs_only_for_the_key_the_server_accepts() {
        let refused = key(Algorithm::Ed25519);
        let accepted = key(p256());
        let (mut transport, mut server, mut script) = setup(Some(&accepted));
        assert!(!transport.is_authenticated());
        let mut auth = Auth::start(
            &mut transport,
            "git",
            [refused.public_key().clone(), accepted.public_key().clone()],
        )
        .unwrap();
        let Progress::Sign(data) =
            step(&mut transport, &mut server, &mut script, &mut auth).unwrap()
        else {
            panic!("no signature asked");
        };
        assert_eq!(
            auth.key().unwrap().key_data(),
            accepted.public_key().key_data()
        );
        assert_eq!(
            data,
            expected_signed_data(
                transport.session_id().unwrap(),
                "git",
                accepted.public_key()
            )
        );
        assert_eq!(
            auth.signed(&mut transport, &sign(&accepted, &data)),
            Ok(Progress::Continue)
        );
        assert_eq!(
            step(&mut transport, &mut server, &mut script, &mut auth),
            Ok(Progress::Authenticated)
        );
        assert!(script.verified);
        assert!(transport.is_authenticated());
        let mut banner = Vec::new();
        Message::UserauthBanner { message: b"late" }
            .encode(&mut banner)
            .unwrap();
        assert_eq!(
            auth.handle(&mut transport, &banner),
            Err(AuthError::Unexpected(message::USERAUTH_BANNER))
        );
        assert_eq!(format!("{auth:?}"), "Auth { state: Done, .. }");
    }

    #[test]
    fn no_accepted_key_ends_the_login() {
        let (mut transport, mut server, mut script) = setup(None);
        let mut auth = Auth::start(
            &mut transport,
            "git",
            [key(Algorithm::Ed25519).public_key().clone()],
        )
        .unwrap();
        assert_eq!(
            step(&mut transport, &mut server, &mut script, &mut auth),
            Err(AuthError::NotAccepted)
        );
        let (mut transport, mut server, mut script) = setup(None);
        let mut auth = Auth::start(&mut transport, "git", []).unwrap();
        assert_eq!(
            step(&mut transport, &mut server, &mut script, &mut auth),
            Err(AuthError::NotAccepted)
        );
    }

    #[test]
    fn a_refused_signature_moves_to_the_next_key() {
        let first = key(Algorithm::Ed25519);
        let second = key(Algorithm::Ed25519);
        let (mut transport, mut server, mut script) = setup(Some(&first));
        let mut auth = Auth::start(
            &mut transport,
            "git",
            [first.public_key().clone(), second.public_key().clone()],
        )
        .unwrap();
        assert!(matches!(
            step(&mut transport, &mut server, &mut script, &mut auth),
            Ok(Progress::Sign(_))
        ));
        script.accepted = Some(second.public_key().clone());
        assert_eq!(auth.sign_refused(&mut transport), Ok(Progress::Continue));
        assert_eq!(
            auth.key().unwrap().key_data(),
            second.public_key().key_data()
        );
        let Progress::Sign(data) =
            step(&mut transport, &mut server, &mut script, &mut auth).unwrap()
        else {
            panic!("no signature asked");
        };
        assert_eq!(
            auth.key().unwrap().key_data(),
            second.public_key().key_data()
        );
        auth.signed(&mut transport, &sign(&second, &data)).unwrap();
        assert_eq!(
            step(&mut transport, &mut server, &mut script, &mut auth),
            Ok(Progress::Authenticated)
        );
    }

    #[test]
    fn a_signature_that_does_not_verify_is_never_sent() {
        let accepted = key(Algorithm::Ed25519);
        let other = key(Algorithm::Ed25519);
        let ecdsa = key(p256());
        let (mut transport, mut server, mut script) = setup(Some(&accepted));
        let mut auth = Auth::start(&mut transport, "git", [accepted.public_key().clone()]).unwrap();
        let Progress::Sign(data) =
            step(&mut transport, &mut server, &mut script, &mut auth).unwrap()
        else {
            panic!("no signature asked");
        };
        let sent = transport.output().len();
        for bad in [
            sign(&other, &data),
            sign(&accepted, b"other data"),
            sign(&ecdsa, &data),
            [sign(&accepted, &data), vec![0]].concat(),
            Vec::new(),
        ] {
            assert_eq!(
                auth.signed(&mut transport, &bad),
                Err(AuthError::AgentSignature)
            );
            assert_eq!(transport.output().len(), sent);
        }
        assert_eq!(
            auth.signed(&mut transport, &sign(&accepted, &data)),
            Ok(Progress::Continue)
        );
    }

    #[test]
    fn a_pk_ok_for_another_key_or_messages_out_of_place_are_refused() {
        let accepted = key(Algorithm::Ed25519);
        let (mut transport, _server, _script) = setup(Some(&accepted));
        let mut auth = Auth::start(&mut transport, "git", [accepted.public_key().clone()]).unwrap();
        assert_eq!(
            auth.handle(&mut transport, &[message::USERAUTH_SUCCESS]),
            Err(AuthError::Unexpected(message::USERAUTH_SUCCESS))
        );
        let mut accept = Vec::new();
        Message::ServiceAccept(b"ssh-userauth")
            .encode(&mut accept)
            .unwrap();
        auth.handle(&mut transport, &accept).unwrap();
        let other = key(Algorithm::Ed25519).public_key().to_bytes().unwrap();
        let mut pk_ok = Vec::new();
        Message::UserauthPkOk {
            algorithm: b"ssh-ed25519",
            key: &other,
        }
        .encode(&mut pk_ok)
        .unwrap();
        assert_eq!(
            auth.handle(&mut transport, &pk_ok),
            Err(AuthError::Unexpected(message::USERAUTH_PK_OK))
        );
        assert_eq!(
            auth.handle(&mut transport, &[message::USERAUTH_SUCCESS]),
            Err(AuthError::Unexpected(message::USERAUTH_SUCCESS))
        );
        assert_eq!(
            auth.handle(
                &mut transport,
                &[message::CHANNEL_DATA, 0, 0, 0, 0, 0, 0, 0, 0]
            ),
            Err(AuthError::Unexpected(message::CHANNEL_DATA))
        );
    }

    fn encoded(message: Message<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        message.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn a_pk_ok_with_another_algorithm_or_replies_while_signing_are_refused() {
        let accepted = key(Algorithm::Ed25519);
        let blob = accepted.public_key().to_bytes().unwrap();
        let (mut transport, _server, _script) = setup(Some(&accepted));
        let mut auth = Auth::start(&mut transport, "git", [accepted.public_key().clone()]).unwrap();
        auth.handle(
            &mut transport,
            &encoded(Message::ServiceAccept(b"ssh-userauth")),
        )
        .unwrap();
        let wrong_algorithm = encoded(Message::UserauthPkOk {
            algorithm: b"ecdsa-sha2-nistp256",
            key: &blob,
        });
        assert_eq!(
            auth.handle(&mut transport, &wrong_algorithm),
            Err(AuthError::Unexpected(message::USERAUTH_PK_OK))
        );
        let right = encoded(Message::UserauthPkOk {
            algorithm: b"ssh-ed25519",
            key: &blob,
        });
        let (mut transport, _server, _script) = setup(Some(&accepted));
        let mut auth = Auth::start(&mut transport, "git", [accepted.public_key().clone()]).unwrap();
        auth.handle(
            &mut transport,
            &encoded(Message::ServiceAccept(b"ssh-userauth")),
        )
        .unwrap();
        assert!(matches!(
            auth.handle(&mut transport, &right),
            Ok(Progress::Sign(_))
        ));
        for reply in [
            encoded(failure()),
            vec![message::USERAUTH_SUCCESS],
            right.clone(),
        ] {
            assert_eq!(
                auth.handle(&mut transport, &reply),
                Err(AuthError::Unexpected(reply[0]))
            );
        }
        auth.signed(
            &mut transport,
            &sign(&accepted, &auth.signed_data().unwrap()),
        )
        .unwrap();
        assert_eq!(
            auth.handle(&mut transport, &right),
            Err(AuthError::Unexpected(message::USERAUTH_PK_OK))
        );
    }

    #[test]
    fn a_partial_success_moves_on_and_a_server_without_publickey_stops_the_login() {
        let first = key(Algorithm::Ed25519);
        let second = key(Algorithm::Ed25519);
        let (mut transport, _server, _script) = setup(None);
        let mut auth = Auth::start(
            &mut transport,
            "git",
            [first.public_key().clone(), second.public_key().clone()],
        )
        .unwrap();
        auth.handle(
            &mut transport,
            &encoded(Message::ServiceAccept(b"ssh-userauth")),
        )
        .unwrap();
        let partial = encoded(Message::UserauthFailure {
            methods: crate::proto::wire::NameList::parse(b"publickey,password").unwrap(),
            partial: true,
        });
        assert_eq!(
            auth.handle(&mut transport, &partial),
            Ok(Progress::Continue)
        );
        assert_eq!(
            auth.key().unwrap().key_data(),
            second.public_key().key_data()
        );
        let no_publickey = encoded(Message::UserauthFailure {
            methods: crate::proto::wire::NameList::parse(b"password,keyboard-interactive").unwrap(),
            partial: false,
        });
        assert_eq!(
            auth.handle(&mut transport, &no_publickey),
            Err(AuthError::MethodNotOffered)
        );
    }

    #[test]
    fn at_most_six_supported_keys_are_tried_and_rsa_is_skipped() {
        let rsa = PublicKey::from_openssh(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCon5LKy0wKilz4XciwFziIQp1K5se6f/fSH7d9re1rFspyRZiiUwgo51S35FCUUwaDULJEiBTb6VDNULuiPeYtAIBmRWyMvvQTchT2UNTSVYj5vOkuMpu/eBtkuzI6EtnVbqwhXeEAjIHn+dHpJNGB6o3d2uHolL+L48qCD4YQhQ==",
        )
        .unwrap();
        assert_eq!(login_algorithm(&rsa), None);
        let keys: Vec<PrivateKey> = (0..8).map(|_| key(Algorithm::Ed25519)).collect();
        let (mut transport, mut server, mut script) = setup(Some(&keys[6]));
        let mut auth = Auth::start(
            &mut transport,
            "git",
            std::iter::once(rsa).chain(keys.iter().map(|key| key.public_key().clone())),
        )
        .unwrap();
        assert_eq!(auth.candidates.len(), MAX_KEYS);
        assert_eq!(
            step(&mut transport, &mut server, &mut script, &mut auth),
            Err(AuthError::NotAccepted)
        );
    }
}
