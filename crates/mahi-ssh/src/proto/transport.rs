use std::ops::Range;

use ssh_key::PublicKey;
use thiserror::Error;

use super::{
    cipher::{
        Opener,
        PacketError,
        Sealer,
    },
    kex::{
        Algorithms,
        CLIENT_CIPHERS,
        CLIENT_COMPRESSION,
        CLIENT_ID,
        CLIENT_KEX,
        CLIENT_MACS,
        ExchangeInputs,
        HostKeyAlgorithm,
        Identification,
        KexError,
        KeyShare,
        KeyUse,
        Line,
        SharedSecret,
        derive_key,
        exchange_hash,
        negotiate,
        verify_host_key,
    },
    message::{
        self,
        KexInit,
        Message,
    },
    packet::Inbound,
    wire::{
        NameList,
        WireError,
    },
};

const REKEY_BYTES: u64 = 1 << 30;
const REKEY_PACKETS: u64 = 1 << 28;
const MAX_DESCRIPTION: usize = 256;
const COMPACT_OUTPUT: usize = 64 << 10;
const MAX_PENDING_OUTPUT: usize = 1 << 20;
const MAX_HELD: usize = 256 << 10;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum TransportError {
    #[error(transparent)]
    Kex(#[from] KexError),
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("the server sent message {0} where it is not allowed")]
    Unexpected(u8),
    #[error("the server closed the connection: {description}")]
    Disconnected { reason: u32, description: String },
    #[error("the server presented another host key when rekeying")]
    HostKeyChanged,
    #[error("a packet sequence number would wrap before a rekey")]
    SequenceWrap,
    #[error("the server said it does not implement message number {0}")]
    Unimplemented(u32),
    #[error("a message was sent before the key exchange finished")]
    NotReady,
    #[error("more than 256 KiB was sent during a rekey")]
    HeldOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Poll {
    Pending,
    HostKey,
    Message,
}

#[derive(Debug)]
enum Awaiting {
    ServerKexInit,
    Reply {
        algorithms: Algorithms,
        share: KeyShare,
    },
    Acceptance {
        keys: Box<NewKeys>,
    },
    ServerNewKeys {
        opener: Box<Opener>,
    },
}

struct NewKeys {
    sealer: Sealer,
    opener: Opener,
}

impl std::fmt::Debug for NewKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NewKeys")
    }
}

#[derive(Debug)]
struct Exchange {
    client_kexinit: Vec<u8>,
    server_kexinit: Option<Vec<u8>>,
    step: Awaiting,
}

pub(crate) struct Transport {
    inbound: Inbound,
    output: Vec<u8>,
    output_start: usize,
    opener: Opener,
    sealer: Sealer,
    receive_sequence: u32,
    send_sequence: u32,
    identification: Option<Identification>,
    server_id: Vec<u8>,
    host_key_algorithms: String,
    exchange: Option<Exchange>,
    first: bool,
    session_id: Option<[u8; 32]>,
    host_key: Option<PublicKey>,
    received_since_kex: (u64, u64),
    sent_since_kex: (u64, u64),
    rekey_after: (u64, u64),
    authenticated: bool,
    held: Vec<u8>,
    current: Option<Range<usize>>,
    scratch: Vec<u8>,
    failed: Option<TransportError>,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Transport").finish_non_exhaustive()
    }
}

impl Transport {
    pub(crate) fn new(host_keys: &[HostKeyAlgorithm]) -> Result<Self, TransportError> {
        let mut host_key_algorithms = String::new();
        for algorithm in host_keys {
            if !host_key_algorithms.is_empty() {
                host_key_algorithms.push(',');
            }
            host_key_algorithms.push_str(algorithm.name());
        }
        let mut transport = Self {
            inbound: Inbound::default(),
            output: Vec::with_capacity(4096),
            output_start: 0,
            opener: Opener::clear(),
            sealer: Sealer::clear(),
            receive_sequence: 0,
            send_sequence: 0,
            identification: Some(Identification::default()),
            server_id: Vec::new(),
            host_key_algorithms,
            exchange: None,
            first: true,
            session_id: None,
            host_key: None,
            received_since_kex: (0, 0),
            sent_since_kex: (0, 0),
            rekey_after: (REKEY_BYTES, REKEY_PACKETS),
            authenticated: false,
            held: Vec::new(),
            current: None,
            scratch: Vec::new(),
            failed: None,
        };
        transport.output.extend_from_slice(CLIENT_ID);
        transport.output.extend_from_slice(b"\r\n");
        transport.send_kexinit()?;
        Ok(transport)
    }

    #[cfg(any(fuzzing, feature = "fuzzing"))]
    pub(crate) fn established() -> Result<Self, TransportError> {
        let mut transport = Self::new(&[HostKeyAlgorithm::Ed25519])?;
        transport.identification = None;
        transport.exchange = None;
        transport.session_id = Some([0; 32]);
        transport.first = false;
        transport.authenticated = true;
        transport.output.clear();
        Ok(transport)
    }

    pub(crate) fn receive(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.current = None;
        let result = self.healthy().and_then(|()| Ok(self.inbound.push(bytes)?));
        self.record(result)
    }

    fn healthy(&self) -> Result<(), TransportError> {
        self.failed.clone().map_or(Ok(()), Err)
    }

    fn record<T>(&mut self, result: Result<T, TransportError>) -> Result<T, TransportError> {
        if let Err(error) = &result
            && *error != TransportError::NotReady
        {
            self.failed.get_or_insert_with(|| error.clone());
            self.current = None;
        }
        result
    }

    pub(crate) fn room(&self) -> usize {
        self.inbound.room()
    }

    pub(crate) fn output(&self) -> &[u8] {
        self.output.get(self.output_start..).unwrap_or_default()
    }

    pub(crate) fn advance_output(&mut self, count: usize) {
        self.output_start = self
            .output_start
            .saturating_add(count)
            .min(self.output.len());
        if self.output_start == self.output.len() {
            self.output.clear();
            self.output_start = 0;
        } else if self.output_start > COMPACT_OUTPUT {
            self.output.drain(..self.output_start);
            self.output_start = 0;
        }
    }

    pub(crate) fn ready(&self) -> bool {
        self.exchange.is_none() && self.session_id.is_some()
    }

    pub(crate) fn host_key(&self) -> Option<&PublicKey> {
        self.host_key.as_ref()
    }

    pub(crate) fn session_id(&self) -> Option<&[u8; 32]> {
        self.session_id.as_ref()
    }

    pub(crate) fn message(&self) -> &[u8] {
        self.current
            .clone()
            .map(|range| self.inbound.payload(range))
            .unwrap_or_default()
    }

    pub(crate) fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let result = self.healthy().and_then(|()| self.send_ready(payload));
        self.record(result)
    }

    fn send_ready(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        if self.session_id.is_none() || self.first {
            return Err(TransportError::NotReady);
        }
        if self.exchange.is_some() {
            if self.held.len() + 4 + payload.len() > MAX_HELD {
                return Err(TransportError::HeldOverflow);
            }
            let length = u32::try_from(payload.len()).map_err(|_| WireError::TooLong)?;
            self.held.extend_from_slice(&length.to_be_bytes());
            self.held.extend_from_slice(payload);
            return Ok(());
        }
        self.seal(payload)?;
        if self.due(self.sent_since_kex) {
            self.rekey()?;
        }
        Ok(())
    }

    pub(crate) fn start_rekey(&mut self) -> Result<(), TransportError> {
        self.healthy()?;
        let result = self.rekey();
        self.record(result)
    }

    pub(crate) fn set_authenticated(&mut self) {
        self.authenticated = true;
    }

    #[cfg(test)]
    pub(crate) fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    #[cfg(test)]
    pub(crate) fn set_rekey_after(&mut self, bytes: u64, packets: u64) {
        self.rekey_after = (bytes, packets);
    }

    fn rekey(&mut self) -> Result<(), TransportError> {
        if self.authenticated && self.exchange.is_none() && self.session_id.is_some() {
            self.send_kexinit()?;
        }
        Ok(())
    }

    pub(crate) fn accept_host_key(&mut self) -> Result<(), TransportError> {
        self.healthy()?;
        let result = self.accept();
        self.record(result)
    }

    fn accept(&mut self) -> Result<(), TransportError> {
        let Some(exchange) = self.exchange.as_mut() else {
            return Err(TransportError::NotReady);
        };
        let Awaiting::Acceptance { .. } = exchange.step else {
            return Err(TransportError::NotReady);
        };
        let Awaiting::Acceptance { keys } =
            std::mem::replace(&mut exchange.step, Awaiting::ServerKexInit)
        else {
            return Err(TransportError::NotReady);
        };
        self.send_newkeys(*keys)
    }

    pub(crate) fn poll(&mut self) -> Result<Poll, TransportError> {
        self.current = None;
        self.healthy()?;
        let result = self.advance();
        self.record(result)
    }

    fn advance(&mut self) -> Result<Poll, TransportError> {
        if let Some(identification) = self.identification.as_mut() {
            loop {
                let Some(line) = identification.read(self.inbound.buffered())? else {
                    return Ok(Poll::Pending);
                };
                match line {
                    Line::Other { consumed } => self.inbound.consume(consumed),
                    Line::Version { consumed, id } => {
                        self.server_id =
                            self.inbound.buffered().get(id).unwrap_or_default().to_vec();
                        self.inbound.consume(consumed);
                        self.identification = None;
                        break;
                    }
                }
            }
        }
        loop {
            if self.output().len() >= MAX_PENDING_OUTPUT {
                return Ok(Poll::Pending);
            }
            if matches!(
                self.exchange,
                Some(Exchange {
                    step: Awaiting::Acceptance { .. },
                    ..
                })
            ) {
                return Ok(Poll::HostKey);
            }
            let Some(range) = self
                .inbound
                .next_range(&mut self.opener, self.receive_sequence)?
            else {
                return Ok(Poll::Pending);
            };
            let sequence = self.receive_sequence;
            self.advance_receive(range.len())?;
            if let Some(poll) = self.dispatch(range, sequence)? {
                return Ok(poll);
            }
        }
    }

    fn due(&self, (bytes, packets): (u64, u64)) -> bool {
        bytes >= self.rekey_after.0 || packets >= self.rekey_after.1
    }

    fn advance_receive(&mut self, length: usize) -> Result<(), TransportError> {
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(TransportError::SequenceWrap)?;
        self.received_since_kex.0 += length as u64;
        self.received_since_kex.1 += 1;
        if self.due(self.received_since_kex) {
            self.rekey()?;
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        range: Range<usize>,
        sequence: u32,
    ) -> Result<Option<Poll>, TransportError> {
        let payload = self.inbound.payload(range.clone());
        let number = *payload.first().ok_or(WireError::Empty)?;
        let in_first_exchange =
            self.session_id.is_none() || (self.first && self.exchange.is_some());
        if in_first_exchange
            && !matches!(
                number,
                message::KEXINIT | message::NEWKEYS | 30..=49 | message::DISCONNECT
            )
        {
            return Err(TransportError::Unexpected(number));
        }
        match number {
            message::DISCONNECT => {
                let Message::Disconnect {
                    reason,
                    description,
                } = Message::decode(payload)?
                else {
                    return Err(TransportError::Unexpected(number));
                };
                Err(TransportError::Disconnected {
                    reason,
                    description: printable(description),
                })
            }
            message::IGNORE | message::DEBUG => {
                Message::decode(payload)?;
                Ok(None)
            }
            message::UNIMPLEMENTED => {
                let Message::Unimplemented { sequence } = Message::decode(payload)? else {
                    return Err(TransportError::Unexpected(number));
                };
                Err(TransportError::Unimplemented(sequence))
            }
            message::KEXINIT => {
                let payload = payload.to_vec();
                self.on_kexinit(payload)?;
                Ok(None)
            }
            message::KEX_ECDH_REPLY => {
                let payload = payload.to_vec();
                self.on_reply(&payload)?;
                Ok(None)
            }
            message::NEWKEYS => {
                Message::decode(payload)?;
                self.on_newkeys()?;
                Ok(None)
            }
            message::KEX_ECDH_INIT | 22..=29 | 32..=49 => Err(TransportError::Unexpected(number)),
            message::SERVICE_REQUEST
            | message::SERVICE_ACCEPT
            | message::USERAUTH_REQUEST..=127 => {
                if self
                    .exchange
                    .as_ref()
                    .is_some_and(|exchange| exchange.server_kexinit.is_some())
                {
                    return Err(TransportError::Unexpected(number));
                }
                self.current = Some(range);
                Ok(Some(Poll::Message))
            }
            _ => {
                self.scratch.clear();
                Message::Unimplemented { sequence }.encode(&mut self.scratch)?;
                let reply = std::mem::take(&mut self.scratch);
                let sealed = self.seal(&reply);
                self.scratch = reply;
                sealed?;
                Ok(None)
            }
        }
    }

    fn send_kexinit(&mut self) -> Result<(), TransportError> {
        let mut cookie = [0; 16];
        getrandom::fill(&mut cookie).map_err(|_| KexError::Random)?;
        let host_key = NameList::parse(self.host_key_algorithms.as_bytes())?;
        let fixed = |list: &'static str| NameList::parse(list.as_bytes());
        let init = KexInit {
            cookie,
            kex: fixed(CLIENT_KEX)?,
            host_key,
            cipher_c2s: fixed(CLIENT_CIPHERS)?,
            cipher_s2c: fixed(CLIENT_CIPHERS)?,
            mac_c2s: fixed(CLIENT_MACS)?,
            mac_s2c: fixed(CLIENT_MACS)?,
            compression_c2s: fixed(CLIENT_COMPRESSION)?,
            compression_s2c: fixed(CLIENT_COMPRESSION)?,
            language_c2s: fixed("")?,
            language_s2c: fixed("")?,
            first_kex_follows: false,
        };
        let mut payload = Vec::with_capacity(512);
        Message::KexInit(init).encode(&mut payload)?;
        self.seal(&payload)?;
        self.exchange = Some(Exchange {
            client_kexinit: payload,
            server_kexinit: None,
            step: Awaiting::ServerKexInit,
        });
        Ok(())
    }

    fn on_kexinit(&mut self, payload: Vec<u8>) -> Result<(), TransportError> {
        if self.exchange.is_none() {
            self.send_kexinit()?;
        }
        let exchange = self
            .exchange
            .as_mut()
            .ok_or(TransportError::Unexpected(message::KEXINIT))?;
        if exchange.server_kexinit.is_some() {
            return Err(TransportError::Unexpected(message::KEXINIT));
        }
        let Message::KexInit(server) = Message::decode(&payload)? else {
            return Err(TransportError::Unexpected(message::KEXINIT));
        };
        let Message::KexInit(client) = Message::decode(&exchange.client_kexinit)? else {
            return Err(TransportError::Unexpected(message::KEXINIT));
        };
        let algorithms = negotiate(&client, &server, self.first)?;
        let share = KeyShare::generate(algorithms.kex)?;
        exchange.server_kexinit = Some(payload);
        self.scratch.clear();
        Message::KexEcdhInit {
            client_public: share.public(),
        }
        .encode(&mut self.scratch)?;
        exchange.step = Awaiting::Reply { algorithms, share };
        let init = std::mem::take(&mut self.scratch);
        let sealed = self.seal(&init);
        self.scratch = init;
        sealed
    }

    fn on_reply(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let Message::KexEcdhReply {
            host_key,
            server_public,
            signature,
        } = Message::decode(payload)?
        else {
            return Err(TransportError::Unexpected(message::KEX_ECDH_REPLY));
        };
        let Some(exchange) = self.exchange.as_mut() else {
            return Err(TransportError::Unexpected(message::KEX_ECDH_REPLY));
        };
        let Awaiting::Reply { algorithms, share } =
            std::mem::replace(&mut exchange.step, Awaiting::ServerKexInit)
        else {
            return Err(TransportError::Unexpected(message::KEX_ECDH_REPLY));
        };
        let secret = share.agree(server_public)?;
        let hash = exchange_hash(
            &ExchangeInputs {
                client_id: CLIENT_ID,
                server_id: &self.server_id,
                client_kexinit: &exchange.client_kexinit,
                server_kexinit: exchange.server_kexinit.as_deref().unwrap_or_default(),
                host_key,
                client_public: share.public(),
                server_public,
            },
            &secret,
        )?;
        drop(share);
        let key = verify_host_key(algorithms.host_key, host_key, signature, &hash)?;
        let session_id = *self.session_id.get_or_insert(hash);
        let keys = new_keys(algorithms, &secret, &hash, &session_id)?;
        match &self.host_key {
            None => {
                self.host_key = Some(key);
                algorithms
                    .host_key
                    .name()
                    .clone_into(&mut self.host_key_algorithms);
                exchange.step = Awaiting::Acceptance {
                    keys: Box::new(keys),
                };
                Ok(())
            }
            Some(first) if first.key_data() == key.key_data() => self.send_newkeys(keys),
            Some(_) => Err(TransportError::HostKeyChanged),
        }
    }

    fn on_newkeys(&mut self) -> Result<(), TransportError> {
        let Some(exchange) = self.exchange.take() else {
            return Err(TransportError::Unexpected(message::NEWKEYS));
        };
        let Awaiting::ServerNewKeys { opener } = exchange.step else {
            return Err(TransportError::Unexpected(message::NEWKEYS));
        };
        self.opener = *opener;
        self.receive_sequence = 0;
        self.received_since_kex = (0, 0);
        self.first = false;
        let mut held = std::mem::take(&mut self.held);
        let mut rest = held.as_slice();
        while let Some((length, after)) = rest.split_first_chunk::<4>() {
            let (payload, after) = after
                .split_at_checked(u32::from_be_bytes(*length) as usize)
                .ok_or(TransportError::NotReady)?;
            self.seal(payload)?;
            rest = after;
        }
        held.clear();
        self.held = held;
        Ok(())
    }

    fn send_newkeys(&mut self, keys: NewKeys) -> Result<(), TransportError> {
        self.seal(&[message::NEWKEYS])?;
        self.sealer = keys.sealer;
        self.send_sequence = 0;
        self.sent_since_kex = (0, 0);
        if let Some(exchange) = self.exchange.as_mut() {
            exchange.step = Awaiting::ServerNewKeys {
                opener: Box::new(keys.opener),
            };
        }
        Ok(())
    }

    fn seal(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        self.sealer
            .seal(self.send_sequence, payload, &mut self.output)?;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(TransportError::SequenceWrap)?;
        self.sent_since_kex.0 += payload.len() as u64;
        self.sent_since_kex.1 += 1;
        Ok(())
    }
}

fn new_keys(
    algorithms: Algorithms,
    secret: &SharedSecret,
    hash: &[u8; 32],
    session_id: &[u8; 32],
) -> Result<NewKeys, TransportError> {
    let derive = |key_use, length| derive_key(secret, hash, session_id, key_use, length);
    let (send, receive) = (algorithms.cipher_c2s, algorithms.cipher_s2c);
    Ok(NewKeys {
        sealer: Sealer::new(
            send,
            &derive(KeyUse::KeyClientToServer, send.key_len())?,
            &derive(KeyUse::IvClientToServer, send.iv_len())?,
        )?,
        opener: Opener::new(
            receive,
            &derive(KeyUse::KeyServerToClient, receive.key_len())?,
            &derive(KeyUse::IvServerToClient, receive.iv_len())?,
        )?,
    })
}

pub(crate) fn printable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes.get(..MAX_DESCRIPTION).unwrap_or(bytes))
        .chars()
        .map(|c| {
            if c.is_control() || mahi_core::is_invisible(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        cipher::CipherName,
        test_server::{
            SERVER_ID,
            Tamper,
            TestServer,
            host_key,
        },
    };

    fn client(algorithm: HostKeyAlgorithm) -> Transport {
        Transport::new(&[algorithm]).unwrap()
    }

    fn pump(client: &mut Transport, server: &mut TestServer) -> Result<Poll, TransportError> {
        for _ in 0..16 {
            let from_client = client.output().to_vec();
            client.advance_output(from_client.len());
            server.receive(&from_client);
            let from_server = server.take_output();
            client.receive(&from_server)?;
            let poll = client.poll()?;
            if poll != Poll::Pending || (from_client.is_empty() && from_server.is_empty()) {
                return Ok(poll);
            }
        }
        Ok(Poll::Pending)
    }

    fn connected(algorithm: HostKeyAlgorithm, kex: &str, cipher: &str) -> (Transport, TestServer) {
        let mut server = TestServer::new(host_key(algorithm));
        server.kex = format!("{kex},kex-strict-s-v00@openssh.com");
        server.ciphers = cipher.to_owned();
        let mut client = client(algorithm);
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::HostKey));
        assert!(client.output().is_empty());
        assert_eq!(client.poll(), Ok(Poll::HostKey));
        assert!(client.output().is_empty());
        assert_eq!(
            client.host_key().unwrap().key_data(),
            server.key.public_key().key_data()
        );
        assert!(!client.ready());
        assert_eq!(client.send(b"\x05"), Err(TransportError::NotReady));
        client.accept_host_key().unwrap();
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        assert!(client.ready());
        (client, server)
    }

    fn round_trip(client: &mut Transport, server: &mut TestServer) {
        let mut request = Vec::new();
        Message::ServiceRequest(b"ssh-userauth")
            .encode(&mut request)
            .unwrap();
        client.send(&request).unwrap();
        server.send_message(Message::ServiceAccept(b"ssh-userauth"));
        assert_eq!(pump(client, server), Ok(Poll::Message));
        assert_eq!(
            Message::decode(client.message()),
            Ok(Message::ServiceAccept(b"ssh-userauth"))
        );
        assert_eq!(server.received.pop(), Some(request));
    }

    #[test]
    fn a_disconnect_description_is_shown_without_control_or_invisible_characters() {
        assert_eq!(
            printable("bye\x1b[2J now\u{2028}x\u{e0041}y\u{202e}z".as_bytes()),
            "bye?[2J now?x?y?z"
        );
    }

    #[test]
    fn every_kex_host_key_and_cipher_connects_and_carries_messages() {
        for kex in [
            "mlkem768x25519-sha256",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
        ] {
            for algorithm in HostKeyAlgorithm::ALL {
                for cipher in CipherName::ALL {
                    let (mut client, mut server) = connected(algorithm, kex, cipher.name());
                    round_trip(&mut client, &mut server);
                    round_trip(&mut client, &mut server);
                }
            }
        }
    }

    #[test]
    fn the_session_id_is_the_first_exchange_hash_and_survives_rekeys() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes128-gcm@openssh.com",
        );
        let first = *client.session_id().unwrap();
        client.set_authenticated();
        client.start_rekey().unwrap();
        assert!(!client.ready());
        let mut held = Vec::new();
        Message::ServiceRequest(b"held").encode(&mut held).unwrap();
        client.send(&held).unwrap();
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        assert_eq!(server.received, [held]);
        server.received.clear();
        assert!(client.ready());
        assert_eq!(client.session_id(), Some(&first));
        round_trip(&mut client, &mut server);
    }

    #[test]
    fn client_and_server_agree_on_the_session_id() {
        let (client, server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes128-gcm@openssh.com",
        );
        assert_eq!(client.session_id(), server.session_id());
    }

    #[test]
    fn a_rekey_starts_after_the_packet_limit_in_either_direction_and_not_before() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "chacha20-poly1305@openssh.com",
        );
        client.set_authenticated();
        client.rekey_after = (u64::MAX, 3);
        client.send(b"\x02\0\0\0\0").unwrap();
        client.send(b"\x02\0\0\0\0").unwrap();
        assert!(client.ready());
        client.send(b"\x02\0\0\0\0").unwrap();
        assert!(!client.ready());
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        assert!(client.ready());
        for _ in 0..2 {
            server.send_message(Message::Ignore(b""));
        }
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        assert!(client.ready());
        server.send_message(Message::Ignore(b""));
        let from_server = server.take_output();
        client.receive(&from_server).unwrap();
        assert_eq!(client.poll(), Ok(Poll::Pending));
        assert!(!client.ready());
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        assert!(client.ready());
        round_trip(&mut client, &mut server);
    }

    #[test]
    fn a_rekey_starts_after_the_byte_limit() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        client.set_authenticated();
        client.rekey_after = (100, u64::MAX);
        client.send(&[2; 99]).unwrap();
        assert!(client.ready());
        client.send(&[2; 2]).unwrap();
        assert!(!client.ready());
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        round_trip(&mut client, &mut server);
    }

    #[test]
    fn a_rekey_starts_after_the_byte_limit_on_receive() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        client.set_authenticated();
        client.rekey_after = (100, u64::MAX);
        server.send_message(Message::Ignore(&[0; 50]));
        let from_server = server.take_output();
        client.receive(&from_server).unwrap();
        assert_eq!(client.poll(), Ok(Poll::Pending));
        assert!(client.ready());
        server.send_message(Message::Ignore(&[0; 50]));
        let from_server = server.take_output();
        client.receive(&from_server).unwrap();
        assert_eq!(client.poll(), Ok(Poll::Pending));
        assert!(!client.ready());
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        round_trip(&mut client, &mut server);
    }

    #[test]
    fn the_client_starts_no_rekey_before_login_as_openssh_refuses_one() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        client.rekey_after = (u64::MAX, 1);
        client.start_rekey().unwrap();
        client.send(b"\x02\0\0\0\0").unwrap();
        assert!(client.ready());
        server.send_kexinit();
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        assert!(client.ready());
        round_trip(&mut client, &mut server);
    }

    #[test]
    fn rekeys_offer_only_the_host_key_type_of_the_first_exchange() {
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::EcdsaP256));
        let mut client = Transport::new(&HostKeyAlgorithm::ALL).unwrap();
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::HostKey));
        assert_eq!(client.host_key_algorithms, "ecdsa-sha2-nistp256");
    }

    #[test]
    fn nothing_more_is_read_while_a_megabyte_waits_to_be_written() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        let payload = vec![2; 30_000];
        while client.output().len() < MAX_PENDING_OUTPUT {
            client.send(&payload).unwrap();
        }
        server.send_message(Message::ServiceAccept(b"ssh-userauth"));
        let from_server = server.take_output();
        client.receive(&from_server).unwrap();
        assert_eq!(client.poll(), Ok(Poll::Pending));
        let pending = client.output().len();
        client.advance_output(pending);
        assert_eq!(client.poll(), Ok(Poll::Message));
    }

    #[test]
    fn the_default_rekey_limits_are_a_gibibyte_and_two_to_the_28_packets() {
        let client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(client.rekey_after, (1 << 30, 1 << 28));
    }

    #[test]
    fn a_rekey_cannot_start_during_the_first_exchange() {
        let mut client = client(HostKeyAlgorithm::Ed25519);
        let sent = client.output().len();
        client.start_rekey().unwrap();
        assert_eq!(client.output().len(), sent);
    }

    #[test]
    fn output_is_kept_until_written_and_compacted_after() {
        let (mut client, _server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        assert!(client.output().is_empty());
        client.send(&[2; 40]).unwrap();
        let first = client.output().to_vec();
        client.advance_output(10);
        assert_eq!(client.output(), &first[10..]);
        assert_eq!(client.output_start, 10);
        client.send(&[2; 40]).unwrap();
        assert_eq!(client.output().len(), 2 * first.len() - 10);
        client.advance_output(first.len() - 10);
        assert_eq!(client.output().len(), first.len());
        client.advance_output(usize::MAX);
        assert!(client.output().is_empty());
        assert_eq!(client.output.len(), 0);
        for _ in 0..3 {
            client.send(&vec![2; 30_000]).unwrap();
        }
        client.advance_output(70_000);
        assert!(client.output_start <= COMPACT_OUTPUT);
        assert_eq!(
            client.output().len(),
            client.output.len() - client.output_start
        );
    }

    #[test]
    fn keys_never_appear_in_debug_output() {
        let (client, _server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        assert_eq!(format!("{client:?}"), "Transport { .. }");
        let keys = NewKeys {
            sealer: Sealer::clear(),
            opener: Opener::clear(),
        };
        assert_eq!(format!("{keys:?}"), "NewKeys");
    }

    #[test]
    fn at_most_256_kib_is_held_during_a_rekey() {
        let (mut client, _server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes128-gcm@openssh.com",
        );
        client.set_authenticated();
        client.start_rekey().unwrap();
        let exact = vec![2; (64 << 10) - 4];
        for _ in 0..4 {
            client.send(&exact).unwrap();
        }
        assert_eq!(client.held.len(), MAX_HELD);
        assert_eq!(client.send(b""), Err(TransportError::HeldOverflow));
        assert_eq!(client.poll(), Err(TransportError::HeldOverflow));
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes128-gcm@openssh.com",
        );
        client.set_authenticated();
        client.start_rekey().unwrap();
        let payload = vec![2; 64 << 10];
        for _ in 0..3 {
            client.send(&payload).unwrap();
        }
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        assert_eq!(server.received.len(), 3);
        assert!(client.held.is_empty());
        client.send(&payload).unwrap();
    }

    #[test]
    fn the_server_may_start_a_rekey_at_any_time() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::EcdsaP256,
            "mlkem768x25519-sha256",
            "chacha20-poly1305@openssh.com",
        );
        round_trip(&mut client, &mut server);
        server.send_kexinit();
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        assert!(client.ready());
        round_trip(&mut client, &mut server);
        server.send_kexinit();
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        round_trip(&mut client, &mut server);
    }

    #[test]
    fn a_host_key_that_changes_on_rekey_ends_the_connection() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "chacha20-poly1305@openssh.com",
        );
        server.tamper = Tamper::HostKey(Box::new(host_key(HostKeyAlgorithm::Ed25519)));
        server.send_kexinit();
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::HostKeyChanged)
        );
    }

    #[test]
    fn a_wrong_signature_or_server_value_is_refused() {
        for (tamper, expected) in [
            (Tamper::Signature, TransportError::Kex(KexError::Signature)),
            (
                Tamper::ServerPublic(vec![0; 32]),
                TransportError::Kex(KexError::ServerPublic),
            ),
            (
                Tamper::HostKey(Box::new(host_key(HostKeyAlgorithm::EcdsaP256))),
                TransportError::Kex(KexError::HostKeyType),
            ),
        ] {
            let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
            server.tamper = tamper;
            let mut client = client(HostKeyAlgorithm::Ed25519);
            assert_eq!(pump(&mut client, &mut server), Err(expected));
        }
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        server.kex = "curve25519-sha256,kex-strict-s-v00@openssh.com".to_owned();
        server.tamper = Tamper::ServerPublic(vec![0; 32]);
        let mut client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Kex(KexError::WeakSharedSecret))
        );
    }

    #[test]
    fn after_an_error_every_call_fails_the_same_way() {
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        server.tamper = Tamper::Signature;
        let mut client = client(HostKeyAlgorithm::Ed25519);
        let error = TransportError::Kex(KexError::Signature);
        assert_eq!(pump(&mut client, &mut server), Err(error.clone()));
        assert_eq!(client.poll(), Err(error.clone()));
        assert_eq!(client.receive(b"x"), Err(error.clone()));
        assert_eq!(client.send(b"\x05"), Err(error.clone()));
        assert_eq!(client.accept_host_key(), Err(error.clone()));
        assert_eq!(client.start_rekey(), Err(error));
        assert!(client.message().is_empty());
    }

    #[test]
    fn a_server_without_strict_kex_is_refused() {
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        server.kex = "curve25519-sha256".to_owned();
        let mut client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Kex(KexError::NoStrictKex))
        );
    }

    #[test]
    fn nothing_but_the_kexinit_may_come_first_or_interrupt_the_first_exchange() {
        for (early, number) in [
            (Message::Ignore(b"terrapin"), message::IGNORE),
            (Message::Debug { message: b"hi" }, message::DEBUG),
            (
                Message::ServiceAccept(b"ssh-userauth"),
                message::SERVICE_ACCEPT,
            ),
            (Message::Unknown(200), 200),
            (Message::NewKeys, message::NEWKEYS),
        ] {
            let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
            server.send_message(early);
            let mut client = client(HostKeyAlgorithm::Ed25519);
            assert_eq!(
                pump(&mut client, &mut server),
                Err(TransportError::Unexpected(number)),
                "{number}"
            );
        }
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        server.auto_reply = false;
        let mut client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        server.send_message(Message::Ignore(b"x"));
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Unexpected(message::IGNORE))
        );
    }

    #[test]
    fn nothing_may_come_between_the_reply_and_newkeys_in_the_first_exchange() {
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        server.before_newkeys = Some(vec![message::IGNORE, 0, 0, 0, 0]);
        let mut client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::HostKey));
        client.accept_host_key().unwrap();
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Unexpected(message::IGNORE))
        );
    }

    #[test]
    fn a_reply_as_the_first_packet_is_refused_and_a_disconnect_is_reported() {
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        server.send_message(Message::KexEcdhReply {
            host_key: b"",
            server_public: b"",
            signature: b"",
        });
        let mut first = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(
            pump(&mut first, &mut server),
            Err(TransportError::Unexpected(message::KEX_ECDH_REPLY))
        );
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        server.send_message(Message::Disconnect {
            reason: 2,
            description: b"too many",
        });
        let mut client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Disconnected {
                reason: 2,
                description: "too many".to_owned()
            })
        );
    }

    #[test]
    fn newkeys_before_the_reply_is_refused() {
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        server.auto_reply = false;
        let mut client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        server.send(&[message::NEWKEYS]);
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Unexpected(message::NEWKEYS))
        );
    }

    #[test]
    fn a_second_reply_or_kexinit_is_refused() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        server.send_message(Message::KexEcdhReply {
            host_key: b"",
            server_public: b"",
            signature: b"",
        });
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Unexpected(message::KEX_ECDH_REPLY))
        );
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        server.auto_reply = false;
        server.send_kexinit();
        server.send_kexinit();
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Unexpected(message::KEXINIT))
        );
    }

    #[test]
    fn connection_messages_during_the_servers_rekey_are_refused() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes256-gcm@openssh.com",
        );
        server.auto_reply = false;
        server.send_kexinit();
        server.send_message(Message::ChannelEof { recipient: 0 });
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Unexpected(message::CHANNEL_EOF))
        );
    }

    #[test]
    fn unknown_messages_get_unimplemented_with_their_sequence_number() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "chacha20-poly1305@openssh.com",
        );
        server.send(&[message::IGNORE, 0, 0, 0, 0]);
        server.send(&[200, 1, 2, 3]);
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        let mut expected = Vec::new();
        Message::Unimplemented { sequence: 1 }
            .encode(&mut expected)
            .unwrap();
        assert_eq!(server.received, [expected]);
    }

    #[test]
    fn an_unimplemented_from_the_server_ends_the_connection() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes128-gcm@openssh.com",
        );
        server.send_message(Message::Unimplemented { sequence: 9 });
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Unimplemented(9))
        );
    }

    #[test]
    fn key_exchange_messages_outside_an_exchange_end_the_connection() {
        for number in [message::KEX_ECDH_INIT, 22, 29, 32, 49] {
            let (mut client, mut server) = connected(
                HostKeyAlgorithm::Ed25519,
                "curve25519-sha256",
                "aes128-gcm@openssh.com",
            );
            server.send(&[number]);
            assert_eq!(
                pump(&mut client, &mut server),
                Err(TransportError::Unexpected(number)),
                "{number}"
            );
        }
    }

    #[test]
    fn a_disconnect_is_reported_without_control_characters() {
        let (mut client, mut server) = connected(
            HostKeyAlgorithm::Ed25519,
            "curve25519-sha256",
            "aes128-gcm@openssh.com",
        );
        server.send_message(Message::Disconnect {
            reason: 11,
            description: "bye\x1b[2J \u{202e}now".as_bytes(),
        });
        assert_eq!(
            pump(&mut client, &mut server),
            Err(TransportError::Disconnected {
                reason: 11,
                description: "bye?[2J ?now".to_owned()
            })
        );
    }

    #[test]
    fn the_server_identification_is_read_after_other_lines() {
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        let mut output = b"Welcome\r\nto the server\r\n".to_vec();
        output.extend_from_slice(&server.take_output());
        server.output = output;
        let mut client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::HostKey));
        assert_eq!(client.server_id, SERVER_ID);
    }

    #[test]
    fn a_frame_from_the_old_keys_after_newkeys_fails_authentication() {
        let mut server = TestServer::new(host_key(HostKeyAlgorithm::Ed25519));
        let mut client = client(HostKeyAlgorithm::Ed25519);
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::HostKey));
        client.accept_host_key().unwrap();
        assert_eq!(pump(&mut client, &mut server), Ok(Poll::Pending));
        let mut stale = Vec::new();
        Sealer::clear()
            .seal(0, b"\x02\0\0\0\0", &mut stale)
            .unwrap();
        assert!(matches!(
            client.receive(&stale).and_then(|()| client.poll()),
            Err(TransportError::Packet(_))
        ));
    }
}
