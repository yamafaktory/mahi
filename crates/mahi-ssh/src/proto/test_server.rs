use ml_kem::ml_kem_768;
use sha2::{
    Digest,
    Sha256,
};
use ssh_key::PrivateKey;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use super::{
    cipher::{
        Opener,
        Sealer,
    },
    kex::{
        ExchangeInputs,
        HostKeyAlgorithm,
        KexMethod,
        KeyUse,
        SharedSecret,
        derive_key,
        exchange_hash,
        negotiate,
    },
    message::{
        self,
        KexInit,
        Message,
    },
    packet::Inbound,
    wire::NameList,
};

pub(crate) const SERVER_ID: &[u8] = b"SSH-2.0-TestServer_1.0";
const MLKEM_PUBLIC_BYTES: usize = 1184;

#[derive(Clone, Debug, Default)]
pub(crate) enum Tamper {
    #[default]
    None,
    Signature,
    HostKey(Box<PrivateKey>),
    ServerPublic(Vec<u8>),
}

pub(crate) struct TestServer {
    pub(crate) key: PrivateKey,
    pub(crate) output: Vec<u8>,
    pub(crate) kex: String,
    pub(crate) host_keys: String,
    pub(crate) ciphers: String,
    pub(crate) auto_reply: bool,
    pub(crate) tamper: Tamper,
    pub(crate) before_newkeys: Option<Vec<u8>>,
    pub(crate) received: Vec<Vec<u8>>,
    pub(crate) kexinits: usize,
    inbound: Inbound,
    opener: Opener,
    sealer: Sealer,
    receive_sequence: u32,
    send_sequence: u32,
    client_id: Option<Vec<u8>>,
    client_kexinit: Option<Vec<u8>>,
    server_kexinit: Option<Vec<u8>>,
    client_public: Option<Vec<u8>>,
    pending_opener: Option<Opener>,
    session_id: Option<[u8; 32]>,
    first: bool,
}

pub(crate) fn host_key(algorithm: HostKeyAlgorithm) -> PrivateKey {
    let algorithm = match algorithm {
        HostKeyAlgorithm::Ed25519 => ssh_key::Algorithm::Ed25519,
        HostKeyAlgorithm::EcdsaP256 => ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
        HostKeyAlgorithm::EcdsaP384 => ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP384,
        },
    };
    PrivateKey::random(&mut ssh_key::rand_core::OsRng, algorithm).unwrap()
}

impl TestServer {
    pub(crate) fn new(key: PrivateKey) -> Self {
        let mut output = SERVER_ID.to_vec();
        output.extend_from_slice(b"\r\n");
        Self {
            host_keys: key.algorithm().as_str().to_owned(),
            key,
            output,
            kex: "mlkem768x25519-sha256,curve25519-sha256,kex-strict-s-v00@openssh.com".to_owned(),
            ciphers: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
                .to_owned(),
            auto_reply: true,
            tamper: Tamper::None,
            before_newkeys: None,
            received: Vec::new(),
            kexinits: 0,
            inbound: Inbound::default(),
            opener: Opener::clear(),
            sealer: Sealer::clear(),
            receive_sequence: 0,
            send_sequence: 0,
            client_id: None,
            client_kexinit: None,
            server_kexinit: None,
            client_public: None,
            pending_opener: None,
            session_id: None,
            first: true,
        }
    }

    pub(crate) fn send(&mut self, payload: &[u8]) {
        self.sealer
            .seal(self.send_sequence, payload, &mut self.output)
            .unwrap();
        self.send_sequence = self.send_sequence.wrapping_add(1);
    }

    pub(crate) fn send_message(&mut self, message: Message<'_>) {
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();
        self.send(&payload);
    }

    pub(crate) fn send_kexinit(&mut self) {
        let list = |text: &'static [u8]| NameList::parse(text).unwrap();
        let init = KexInit {
            cookie: [5; 16],
            kex: NameList::parse(self.kex.as_bytes()).unwrap(),
            host_key: NameList::parse(self.host_keys.as_bytes()).unwrap(),
            cipher_c2s: NameList::parse(self.ciphers.as_bytes()).unwrap(),
            cipher_s2c: NameList::parse(self.ciphers.as_bytes()).unwrap(),
            mac_c2s: list(b"hmac-sha2-256-etm@openssh.com"),
            mac_s2c: list(b"hmac-sha2-256-etm@openssh.com"),
            compression_c2s: list(b"none,zlib@openssh.com"),
            compression_s2c: list(b"none,zlib@openssh.com"),
            language_c2s: list(b""),
            language_s2c: list(b""),
            first_kex_follows: false,
        };
        let mut payload = Vec::new();
        Message::KexInit(init).encode(&mut payload).unwrap();
        self.send(&payload);
        self.server_kexinit = Some(payload);
    }

    pub(crate) fn session_id(&self) -> Option<&[u8; 32]> {
        self.session_id.as_ref()
    }

    pub(crate) fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }

    pub(crate) fn receive(&mut self, bytes: &[u8]) {
        self.inbound.push(bytes).unwrap();
        if self.client_id.is_none() {
            let buffered = self.inbound.buffered();
            let Some(end) = buffered.iter().position(|&byte| byte == b'\n') else {
                return;
            };
            self.client_id = Some(buffered[..end - 1].to_vec());
            self.inbound.consume(end + 1);
        }
        while let Some(payload) = self
            .inbound
            .next(&mut self.opener, self.receive_sequence)
            .unwrap()
        {
            let payload = payload.to_vec();
            self.receive_sequence = self.receive_sequence.wrapping_add(1);
            match payload[0] {
                message::KEXINIT => {
                    self.kexinits += 1;
                    self.client_kexinit = Some(payload);
                    if self.server_kexinit.is_none() {
                        self.send_kexinit();
                    }
                }
                message::KEX_ECDH_INIT => {
                    let Message::KexEcdhInit { client_public } = Message::decode(&payload).unwrap()
                    else {
                        unreachable!()
                    };
                    self.client_public = Some(client_public.to_vec());
                    if self.auto_reply {
                        self.reply();
                    }
                }
                message::NEWKEYS => {
                    self.opener = self.pending_opener.take().unwrap();
                    self.receive_sequence = 0;
                    self.client_kexinit = None;
                    self.server_kexinit = None;
                    self.first = false;
                }
                _ => self.received.push(payload),
            }
        }
    }

    pub(crate) fn reply(&mut self) {
        let client_kexinit = self.client_kexinit.clone().unwrap();
        let server_kexinit = self.server_kexinit.clone().unwrap();
        let Message::KexInit(client) = Message::decode(&client_kexinit).unwrap() else {
            unreachable!()
        };
        let Message::KexInit(server) = Message::decode(&server_kexinit).unwrap() else {
            unreachable!()
        };
        let algorithms = negotiate(&client, &server, false).unwrap();
        let client_public = self.client_public.clone().unwrap();
        let x25519 = StaticSecret::from([0x42; 32]);
        let x25519_public = *x25519_dalek::PublicKey::from(&x25519).as_bytes();
        let (server_public, secret) = match algorithms.kex {
            KexMethod::Curve25519 => {
                let theirs: [u8; 32] = client_public.as_slice().try_into().unwrap();
                let shared = x25519.diffie_hellman(&theirs.into());
                (
                    x25519_public.to_vec(),
                    SharedSecret::Mpint(Zeroizing::new(shared.to_bytes())),
                )
            }
            KexMethod::MlKem768X25519 => {
                let (encapsulation, classical) = client_public.split_at(MLKEM_PUBLIC_BYTES);
                let key =
                    ml_kem_768::EncapsulationKey::new(encapsulation.try_into().unwrap()).unwrap();
                let (ciphertext, quantum) = key.encapsulate_deterministic(&[0x24; 32].into());
                let theirs: [u8; 32] = classical.try_into().unwrap();
                let shared = x25519.diffie_hellman(&theirs.into());
                let mut hasher = Sha256::new();
                hasher.update(quantum.as_slice());
                hasher.update(shared.as_bytes());
                let mut server_public = ciphertext.to_vec();
                server_public.extend_from_slice(&x25519_public);
                (
                    server_public,
                    SharedSecret::String(Zeroizing::new(hasher.finalize().into())),
                )
            }
        };
        let signing_key = match &self.tamper {
            Tamper::HostKey(other) => (**other).clone(),
            _ => self.key.clone(),
        };
        let host_key = signing_key.public_key().to_bytes().unwrap();
        let hash = exchange_hash(
            &ExchangeInputs {
                client_id: self.client_id.as_deref().unwrap(),
                server_id: SERVER_ID,
                client_kexinit: &client_kexinit,
                server_kexinit: &server_kexinit,
                host_key: &host_key,
                client_public: &client_public,
                server_public: &server_public,
            },
            &secret,
        )
        .unwrap();
        let mut signed_hash = hash;
        if matches!(self.tamper, Tamper::Signature) {
            signed_hash[0] ^= 1;
        }
        let signature: ssh_key::Signature =
            signature::Signer::try_sign(signing_key.key_data(), &signed_hash).unwrap();
        let signature = Vec::try_from(signature).unwrap();
        let server_public = match &self.tamper {
            Tamper::ServerPublic(replacement) => replacement.clone(),
            _ => server_public,
        };
        self.send_message(Message::KexEcdhReply {
            host_key: &host_key,
            server_public: &server_public,
            signature: &signature,
        });
        let session_id = *self.session_id.get_or_insert(hash);
        let derive =
            |key_use, length| derive_key(&secret, &hash, &session_id, key_use, length).unwrap();
        let (send, receive) = (algorithms.cipher_s2c, algorithms.cipher_c2s);
        let sealer = Sealer::new(
            send,
            &derive(KeyUse::KeyServerToClient, send.key_len()),
            &derive(KeyUse::IvServerToClient, send.iv_len()),
        )
        .unwrap();
        self.pending_opener = Some(
            Opener::new(
                receive,
                &derive(KeyUse::KeyClientToServer, receive.key_len()),
                &derive(KeyUse::IvClientToServer, receive.iv_len()),
            )
            .unwrap(),
        );
        if let Some(payload) = self.before_newkeys.take() {
            self.send(&payload);
        }
        self.send(&[message::NEWKEYS]);
        self.sealer = sealer;
        self.send_sequence = 0;
    }
}

pub(crate) fn pump(
    client: &mut super::transport::Transport,
    server: &mut TestServer,
) -> Result<super::transport::Poll, super::transport::TransportError> {
    use super::transport::Poll;
    for _ in 0..1024 {
        let from_client = client.output().to_vec();
        client.advance_output(from_client.len());
        server.receive(&from_client);
        let mut from_server = server.take_output();
        let fed = from_server.len().min(client.room());
        client.receive(&from_server[..fed])?;
        server.output = from_server.split_off(fed);
        let poll = client.poll()?;
        if poll != Poll::Pending || (from_client.is_empty() && fed == 0) {
            return Ok(poll);
        }
    }
    Ok(Poll::Pending)
}

pub(crate) fn connected(algorithm: HostKeyAlgorithm) -> (super::transport::Transport, TestServer) {
    let mut server = TestServer::new(host_key(algorithm));
    let mut client = super::transport::Transport::new(&[algorithm]).unwrap();
    assert_eq!(
        pump(&mut client, &mut server),
        Ok(super::transport::Poll::HostKey)
    );
    client.accept_host_key().unwrap();
    assert_eq!(
        pump(&mut client, &mut server),
        Ok(super::transport::Poll::Pending)
    );
    (client, server)
}
