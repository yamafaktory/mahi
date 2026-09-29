use std::{
    collections::{
        HashMap,
        HashSet,
        VecDeque,
    },
    fmt,
};

use chacha20poly1305::{
    KeyInit,
    XChaCha20Poly1305,
    XNonce,
    aead::{
        Aead,
        Payload,
    },
};
use ed25519_dalek::{
    Signature,
    Signer,
    SigningKey,
    VerifyingKey,
};
use mahi_core::{
    AgentSlot,
    ParticipantName,
    ThreadId,
};
use mahi_crypto::ThreadKey;
use mahi_thread::NodeId;
use serde::{
    Deserialize,
    Serialize,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// The largest frame the live layer sends or accepts, in bytes.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// The most bytes of terminal data one frame carries.
pub const MAX_CHUNK_BYTES: usize = 60 * 1024;
/// The most frames one screen is split into.
pub const MAX_SCREEN_PARTS: u16 = 64;
/// The most rows a screen or a resize may have, so a viewer never allocates a huge screen.
pub const MAX_ROWS: u16 = 1000;
/// The most columns a screen or a resize may have.
pub const MAX_COLUMNS: u16 = 1000;

const SIGNED_LABEL: &[u8] = b"mahi-live-v1";
const TOPIC_INFO: &[u8] = b"mahi-live-topic-v1";
const SEAL_INFO: &[u8] = b"mahi-live-seal-v1";
const NONCE_BYTES: usize = 24;
const EPOCH_BYTES: usize = 16;
const CHALLENGE_BYTES: usize = 16;
const REMEMBERED_CHALLENGES: usize = 256;

/// The keys of a thread's live stream, derived from its thread key: the gossip topic, which
/// only participants can find, and the key frames are sealed with.
pub struct LiveKeys {
    thread: ThreadId,
    topic: [u8; 32],
    seal: Zeroizing<[u8; 32]>,
}

/// What a frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// The agent's terminal output, as it wrote it.
    Output {
        /// The agent whose output it is.
        slot: AgentSlot,
        /// At most [`MAX_CHUNK_BYTES`] of output.
        bytes: Vec<u8>,
    },
    /// The agent's terminal changed size.
    Resize {
        /// The agent whose terminal it is.
        slot: AgentSlot,
        /// Its height in rows.
        rows: u16,
        /// Its width in columns.
        columns: u16,
    },
    /// A viewer asks for the screens of the thread's agents.
    ScreenRequest {
        /// A random value the answer must carry.
        challenge: [u8; CHALLENGE_BYTES],
    },
    /// Part of an agent's screen, as the escape sequences that redraw it.
    Screen {
        /// The agent whose screen it is.
        slot: AgentSlot,
        /// The screen's height in rows.
        rows: u16,
        /// The screen's width in columns.
        columns: u16,
        /// The challenge of the request this answers.
        challenge: [u8; CHALLENGE_BYTES],
        /// Which part this is, from 0.
        part: u16,
        /// How many parts the screen has, at most [`MAX_SCREEN_PARTS`].
        parts: u16,
        /// At most [`MAX_CHUNK_BYTES`] of the screen.
        bytes: Vec<u8>,
    },
}

/// A frame a receiver accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// The node that sent it.
    pub sender: NodeId,
    /// The participant that node belongs to.
    pub participant: ParticipantName,
    /// What it carries.
    pub body: Body,
}

/// A frame that was not sent or not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FrameError {
    /// The thread key could not give the live keys, which never happens with a key age made.
    #[error("cannot derive the live keys")]
    Keys,
    /// The random source failed.
    #[error("random source unavailable")]
    Random,
    /// The frame is larger than [`MAX_FRAME_BYTES`], or a body larger than its limits.
    #[error("the frame is too large")]
    TooLarge,
    /// The frame is not in the expected format.
    #[error("the frame is malformed")]
    Malformed,
    /// The sender is not a participant's node.
    #[error("the sender is not a participant")]
    NotParticipant,
    /// The signature does not check.
    #[error("the frame's signature does not check")]
    BadSignature,
    /// The frame cannot be opened with the thread's live key.
    #[error("the frame cannot be opened")]
    Unreadable,
    /// The frame draws for an agent of another participant.
    #[error("the frame draws for another participant's agent")]
    NotTheirSlot,
    /// The frame was already accepted, or is older than one that was.
    #[error("the frame was already received")]
    Replayed,
    /// The frame comes from a run of its sender this receiver has not anchored with a screen.
    #[error("the frame comes from a run this viewer has not seen start")]
    Unanchored,
}

#[derive(Serialize, Deserialize)]
struct WireFrame<'a> {
    sender: [u8; 32],
    #[serde(with = "signature_bytes")]
    signature: [u8; 64],
    nonce: [u8; NONCE_BYTES],
    ciphertext: &'a [u8],
}

#[derive(Serialize, Deserialize)]
struct WirePlain<'a> {
    epoch: [u8; EPOCH_BYTES],
    sequence: u64,
    #[serde(borrow)]
    body: WireBody<'a>,
}

#[derive(Serialize, Deserialize)]
enum WireBody<'a> {
    Output {
        slot: &'a str,
        bytes: &'a [u8],
    },
    Resize {
        slot: &'a str,
        rows: u16,
        columns: u16,
    },
    ScreenRequest {
        challenge: [u8; CHALLENGE_BYTES],
    },
    Screen {
        slot: &'a str,
        rows: u16,
        columns: u16,
        challenge: [u8; CHALLENGE_BYTES],
        part: u16,
        parts: u16,
        bytes: &'a [u8],
    },
}

mod signature_bytes {
    use serde::{
        Deserialize,
        Deserializer,
        Serializer,
        de::Error,
    };

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; 64],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 64], D::Error> {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        <[u8; 64]>::try_from(bytes).map_err(|_| D::Error::custom("a signature is 64 bytes"))
    }
}

impl fmt::Debug for LiveKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveKeys")
            .field("thread", &self.thread)
            .finish_non_exhaustive()
    }
}

impl LiveKeys {
    /// Derives the live keys of `thread` from its thread key.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Keys`] if the thread key cannot give them.
    pub fn derive(thread_key: &ThreadKey, thread: ThreadId) -> Result<Self, FrameError> {
        let salt = thread.as_bytes();
        let topic = thread_key
            .derive(salt, TOPIC_INFO)
            .map_err(|_| FrameError::Keys)?;
        let seal = thread_key
            .derive(salt, SEAL_INFO)
            .map_err(|_| FrameError::Keys)?;
        Ok(Self {
            thread,
            topic: *topic,
            seal,
        })
    }

    /// Returns the gossip topic of the thread's live stream.
    #[must_use]
    pub fn topic(&self) -> [u8; 32] {
        self.topic
    }

    fn signed_message(
        &self,
        sender: &[u8; 32],
        nonce: &[u8; NONCE_BYTES],
        ciphertext: &[u8],
    ) -> Vec<u8> {
        [
            SIGNED_LABEL,
            self.thread.as_bytes(),
            &self.topic,
            sender,
            nonce,
            ciphertext,
        ]
        .concat()
    }

    fn associated_data(&self, sender: &[u8; 32]) -> Vec<u8> {
        [self.thread.as_bytes().as_slice(), sender].concat()
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.seal).into())
    }
}

/// Seals and signs the frames one node sends in one run of mahi.
pub struct FrameSender {
    keys: LiveKeys,
    signing: SigningKey,
    node: NodeId,
    epoch: [u8; EPOCH_BYTES],
    sequence: u64,
}

impl fmt::Debug for FrameSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameSender")
            .field("node", &self.node)
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl FrameSender {
    /// Starts a new run of frames from the node whose secret key is `node_secret`.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Random`] if the random source fails, or [`FrameError::Keys`] if
    /// the node key is unusable.
    pub fn new(keys: LiveKeys, node_secret: &[u8; 32]) -> Result<Self, FrameError> {
        let signing = SigningKey::from_bytes(node_secret);
        let node =
            NodeId::from_bytes(signing.verifying_key().to_bytes()).map_err(|_| FrameError::Keys)?;
        let mut epoch = [0_u8; EPOCH_BYTES];
        getrandom::fill(&mut epoch).map_err(|_| FrameError::Random)?;
        Ok(Self {
            keys,
            signing,
            node,
            epoch,
            sequence: 0,
        })
    }

    /// Returns the gossip topic the frames go to.
    #[must_use]
    pub fn topic(&self) -> [u8; 32] {
        self.keys.topic()
    }

    /// Seals and signs `body` as the next frame.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::TooLarge`] if the body or the frame is over its limits, or
    /// [`FrameError::Random`] if no nonce can be drawn.
    pub fn seal(&mut self, body: &Body) -> Result<Vec<u8>, FrameError> {
        let slot;
        let wire = match body {
            Body::Output { slot: owner, bytes } => {
                check_chunk(bytes)?;
                slot = owner.to_string();
                WireBody::Output { slot: &slot, bytes }
            }
            Body::Resize {
                slot: owner,
                rows,
                columns,
            } => {
                slot = owner.to_string();
                check_size(*rows, *columns)?;
                WireBody::Resize {
                    slot: &slot,
                    rows: *rows,
                    columns: *columns,
                }
            }
            Body::ScreenRequest { challenge } => WireBody::ScreenRequest {
                challenge: *challenge,
            },
            Body::Screen {
                slot: owner,
                rows,
                columns,
                challenge,
                part,
                parts,
                bytes,
            } => {
                check_chunk(bytes)?;
                check_parts(*part, *parts)?;
                check_size(*rows, *columns)?;
                slot = owner.to_string();
                WireBody::Screen {
                    slot: &slot,
                    rows: *rows,
                    columns: *columns,
                    challenge: *challenge,
                    part: *part,
                    parts: *parts,
                    bytes,
                }
            }
        };
        self.seal_wire(wire)
    }

    fn seal_wire(&mut self, wire: WireBody<'_>) -> Result<Vec<u8>, FrameError> {
        self.sequence = self.sequence.checked_add(1).ok_or(FrameError::TooLarge)?;
        let plain = Zeroizing::new(
            postcard::to_allocvec(&WirePlain {
                epoch: self.epoch,
                sequence: self.sequence,
                body: wire,
            })
            .map_err(|_| FrameError::TooLarge)?,
        );
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| FrameError::Random)?;
        let sender = *self.node.as_bytes();
        let ciphertext = self
            .keys
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &self.keys.associated_data(&sender),
                },
            )
            .map_err(|_| FrameError::TooLarge)?;
        let signature = self
            .signing
            .sign(&self.keys.signed_message(&sender, &nonce, &ciphertext))
            .to_bytes();
        let frame = postcard::to_allocvec(&WireFrame {
            sender,
            signature,
            nonce,
            ciphertext: &ciphertext,
        })
        .map_err(|_| FrameError::TooLarge)?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        Ok(frame)
    }
}

#[derive(Debug, Clone, Copy)]
struct SenderState {
    epoch: [u8; EPOCH_BYTES],
    sequence: u64,
    anchored_with: [u8; CHALLENGE_BYTES],
}

/// Checks and opens the frames one viewer or host receives, and keeps what replay protection
/// needs.
pub struct FrameReceiver {
    keys: LiveKeys,
    participants: HashMap<NodeId, ParticipantName>,
    senders: HashMap<NodeId, SenderState>,
    challenge: Option<[u8; CHALLENGE_BYTES]>,
    requests: VecDeque<[u8; CHALLENGE_BYTES]>,
    seen_requests: HashSet<[u8; CHALLENGE_BYTES]>,
}

impl fmt::Debug for FrameReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameReceiver")
            .field("participants", &self.participants)
            .finish_non_exhaustive()
    }
}

impl FrameReceiver {
    /// Starts receiving frames from the nodes of `participants`.
    pub fn new(
        keys: LiveKeys,
        participants: impl IntoIterator<Item = (NodeId, ParticipantName)>,
    ) -> Self {
        Self {
            keys,
            participants: participants.into_iter().collect(),
            senders: HashMap::new(),
            challenge: None,
            requests: VecDeque::with_capacity(REMEMBERED_CHALLENGES),
            seen_requests: HashSet::with_capacity(REMEMBERED_CHALLENGES),
        }
    }

    /// Replaces the participants, as a newer `meta` lists them; nodes no longer listed are
    /// forgotten.
    pub fn set_participants(
        &mut self,
        participants: impl IntoIterator<Item = (NodeId, ParticipantName)>,
    ) {
        self.participants = participants.into_iter().collect();
        let participants = &self.participants;
        self.senders
            .retain(|node, _| participants.contains_key(node));
    }

    /// Returns a request for the agents' screens, with a new challenge that anchors the runs
    /// of the senders that answer it.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Random`] if the random source fails.
    pub fn request_screen(&mut self) -> Result<Body, FrameError> {
        let mut challenge = [0_u8; CHALLENGE_BYTES];
        getrandom::fill(&mut challenge).map_err(|_| FrameError::Random)?;
        self.challenge = Some(challenge);
        Ok(Body::ScreenRequest { challenge })
    }

    /// Checks and opens `frame`.
    ///
    /// # Errors
    ///
    /// Returns the [`FrameError`] that says why the frame was dropped.
    pub fn open(&mut self, frame: &[u8]) -> Result<Received, FrameError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        let wire: WireFrame<'_> = decode_exact(frame)?;
        let sender = NodeId::from_bytes(wire.sender).map_err(|_| FrameError::NotParticipant)?;
        let participant = self
            .participants
            .get(&sender)
            .cloned()
            .ok_or(FrameError::NotParticipant)?;
        let verifying =
            VerifyingKey::from_bytes(&wire.sender).map_err(|_| FrameError::BadSignature)?;
        verifying
            .verify_strict(
                &self
                    .keys
                    .signed_message(&wire.sender, &wire.nonce, wire.ciphertext),
                &Signature::from_bytes(&wire.signature),
            )
            .map_err(|_| FrameError::BadSignature)?;
        let plain = Zeroizing::new(
            self.keys
                .cipher()
                .decrypt(
                    XNonce::from_slice(&wire.nonce),
                    Payload {
                        msg: wire.ciphertext,
                        aad: &self.keys.associated_data(&wire.sender),
                    },
                )
                .map_err(|_| FrameError::Unreadable)?,
        );
        let plain: WirePlain<'_> = decode_exact(&plain)?;
        let body = parse_body(&plain.body)?;
        if drawn_slot(&body).is_some_and(|slot| slot.participant() != &participant) {
            return Err(FrameError::NotTheirSlot);
        }
        self.check_order(sender, &plain, &body)?;
        Ok(Received {
            sender,
            participant,
            body,
        })
    }

    fn check_order(
        &mut self,
        sender: NodeId,
        plain: &WirePlain<'_>,
        body: &Body,
    ) -> Result<(), FrameError> {
        if let Body::ScreenRequest { challenge } = body {
            return self.remember_request(*challenge);
        }
        let state = self.senders.get(&sender).copied();
        if let Some(state) = state.filter(|state| state.epoch == plain.epoch) {
            if plain.sequence <= state.sequence {
                return Err(FrameError::Replayed);
            }
            if let Some(current) = self.senders.get_mut(&sender) {
                current.sequence = plain.sequence;
            }
            return Ok(());
        }
        match body {
            Body::Screen {
                challenge, part: 0, ..
            } if Some(*challenge) == self.challenge
                && state.is_none_or(|state| state.anchored_with != *challenge) =>
            {
                self.senders.insert(
                    sender,
                    SenderState {
                        epoch: plain.epoch,
                        sequence: plain.sequence,
                        anchored_with: *challenge,
                    },
                );
                Ok(())
            }
            _ => Err(FrameError::Unanchored),
        }
    }

    fn remember_request(&mut self, challenge: [u8; CHALLENGE_BYTES]) -> Result<(), FrameError> {
        if !self.seen_requests.insert(challenge) {
            return Err(FrameError::Replayed);
        }
        if self.requests.len() == REMEMBERED_CHALLENGES
            && let Some(oldest) = self.requests.pop_front()
        {
            self.seen_requests.remove(&oldest);
        }
        self.requests.push_back(challenge);
        Ok(())
    }
}

fn check_size(rows: u16, columns: u16) -> Result<(), FrameError> {
    if rows == 0 || columns == 0 || rows > MAX_ROWS || columns > MAX_COLUMNS {
        return Err(FrameError::Malformed);
    }
    Ok(())
}

fn check_chunk(bytes: &[u8]) -> Result<(), FrameError> {
    if bytes.len() > MAX_CHUNK_BYTES {
        return Err(FrameError::TooLarge);
    }
    Ok(())
}

fn check_parts(part: u16, parts: u16) -> Result<(), FrameError> {
    if parts == 0 || parts > MAX_SCREEN_PARTS || part >= parts {
        return Err(FrameError::Malformed);
    }
    Ok(())
}

fn drawn_slot(body: &Body) -> Option<&AgentSlot> {
    match body {
        Body::Output { slot, .. } | Body::Resize { slot, .. } | Body::Screen { slot, .. } => {
            Some(slot)
        }
        Body::ScreenRequest { .. } => None,
    }
}

fn parse_body(wire: &WireBody<'_>) -> Result<Body, FrameError> {
    let slot = |text: &str| text.parse::<AgentSlot>().map_err(|_| FrameError::Malformed);
    Ok(match *wire {
        WireBody::Output { slot: owner, bytes } => {
            check_chunk(bytes)?;
            Body::Output {
                slot: slot(owner)?,
                bytes: bytes.to_vec(),
            }
        }
        WireBody::Resize {
            slot: owner,
            rows,
            columns,
        } => Body::Resize {
            slot: {
                check_size(rows, columns)?;
                slot(owner)?
            },
            rows,
            columns,
        },
        WireBody::ScreenRequest { challenge } => Body::ScreenRequest { challenge },
        WireBody::Screen {
            slot: owner,
            rows,
            columns,
            challenge,
            part,
            parts,
            bytes,
        } => {
            check_chunk(bytes)?;
            check_parts(part, parts)?;
            check_size(rows, columns)?;
            Body::Screen {
                slot: slot(owner)?,
                rows,
                columns,
                challenge,
                part,
                parts,
                bytes: bytes.to_vec(),
            }
        }
    })
}

fn decode_exact<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, FrameError> {
    let (value, rest) = postcard::take_from_bytes(bytes).map_err(|_| FrameError::Malformed)?;
    if !rest.is_empty() {
        return Err(FrameError::Malformed);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use mahi_core::AgentName;

    use super::*;

    struct Thread {
        key: ThreadKey,
        id: ThreadId,
    }

    impl Thread {
        fn new() -> Self {
            Self {
                key: ThreadKey::generate(),
                id: ThreadId::random().unwrap(),
            }
        }

        fn keys(&self) -> LiveKeys {
            LiveKeys::derive(&self.key, self.id).unwrap()
        }

        fn sender(&self, secret: u8) -> FrameSender {
            FrameSender::new(self.keys(), &[secret; 32]).unwrap()
        }

        fn receiver(&self) -> FrameReceiver {
            FrameReceiver::new(
                self.keys(),
                [(1, "alice"), (2, "bob"), (3, "mallory")]
                    .map(|(secret, name)| (node(secret), ParticipantName::new(name).unwrap())),
            )
        }
    }

    fn node(secret: u8) -> NodeId {
        NodeId::from_bytes(
            SigningKey::from_bytes(&[secret; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
    }

    fn slot(participant: &str) -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new(participant).unwrap(),
            AgentName::new("claude").unwrap(),
        )
    }

    fn output(participant: &str, text: &str) -> Body {
        Body::Output {
            slot: slot(participant),
            bytes: text.as_bytes().to_vec(),
        }
    }

    fn screen(participant: &str, request: &Body) -> Body {
        let Body::ScreenRequest { challenge } = request else {
            panic!("not a request");
        };
        Body::Screen {
            slot: slot(participant),
            rows: 24,
            columns: 80,
            challenge: *challenge,
            part: 0,
            parts: 1,
            bytes: b"screen".to_vec(),
        }
    }

    #[test]
    fn a_viewer_starts_from_the_answered_screen_then_follows_in_order() {
        let thread = Thread::new();
        let mut host = thread.sender(1);
        let mut viewer = thread.receiver();
        let early = host.seal(&output("alice", "before")).unwrap();
        assert_eq!(viewer.open(&early), Err(FrameError::Unanchored));

        let request = viewer.request_screen().unwrap();
        let answer = host.seal(&screen("alice", &request)).unwrap();
        let received = viewer.open(&answer).unwrap();
        assert_eq!(received.sender, node(1));
        assert_eq!(received.participant.as_str(), "alice");
        assert_eq!(received.body, screen("alice", &request));

        let first = host.seal(&output("alice", "one")).unwrap();
        let second = host.seal(&output("alice", "two")).unwrap();
        assert_eq!(viewer.open(&first).unwrap().body, output("alice", "one"));
        assert_eq!(viewer.open(&second).unwrap().body, output("alice", "two"));
        for replay in [&first, &second, &answer, &early] {
            assert_eq!(viewer.open(replay), Err(FrameError::Replayed));
        }
    }

    #[test]
    fn a_restarted_sender_is_followed_only_after_a_new_screen() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let mut old = thread.sender(1);
        let request = viewer.request_screen().unwrap();
        let old_screen = old.seal(&screen("alice", &request)).unwrap();
        viewer.open(&old_screen).unwrap();

        let mut restarted = thread.sender(1);
        let fresh = restarted.seal(&output("alice", "new run")).unwrap();
        assert_eq!(viewer.open(&fresh), Err(FrameError::Unanchored));
        let request = viewer.request_screen().unwrap();
        assert_eq!(viewer.open(&old_screen), Err(FrameError::Replayed));
        viewer
            .open(&restarted.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let next = restarted.seal(&output("alice", "followed")).unwrap();
        assert_eq!(
            viewer.open(&next).unwrap().body,
            output("alice", "followed")
        );
        let from_old_run = old.seal(&output("alice", "old")).unwrap();
        assert_eq!(viewer.open(&from_old_run), Err(FrameError::Unanchored));
        assert_eq!(viewer.open(&old_screen), Err(FrameError::Unanchored));
    }

    #[test]
    fn strangers_removed_participants_and_foreign_slots_are_refused() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let request = viewer.request_screen().unwrap();
        let mut stranger = thread.sender(4);
        assert_eq!(
            viewer.open(&stranger.seal(&screen("alice", &request)).unwrap()),
            Err(FrameError::NotParticipant)
        );
        let mut mallory = thread.sender(3);
        assert_eq!(
            viewer.open(&mallory.seal(&screen("alice", &request)).unwrap()),
            Err(FrameError::NotTheirSlot)
        );
        viewer
            .open(&mallory.seal(&screen("mallory", &request)).unwrap())
            .unwrap();
        viewer.set_participants([(node(1), ParticipantName::new("alice").unwrap())]);
        assert_eq!(
            viewer.open(&mallory.seal(&output("mallory", "x")).unwrap()),
            Err(FrameError::NotParticipant)
        );
    }

    #[test]
    fn a_frame_cannot_be_changed_resigned_or_moved_to_another_thread() {
        let thread = Thread::new();
        let mut host = thread.sender(1);
        let mut viewer = thread.receiver();
        let request = viewer.request_screen().unwrap();
        let frame = host.seal(&screen("alice", &request)).unwrap();

        let mut changed = frame.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert_eq!(viewer.open(&changed), Err(FrameError::BadSignature));

        let wire: WireFrame<'_> = decode_exact(&frame).unwrap();
        let mallory = SigningKey::from_bytes(&[3; 32]);
        let mallory_node = mallory.verifying_key().to_bytes();
        let keys = thread.keys();
        let resigned = postcard::to_allocvec(&WireFrame {
            sender: mallory_node,
            signature: mallory
                .sign(&keys.signed_message(&mallory_node, &wire.nonce, wire.ciphertext))
                .to_bytes(),
            nonce: wire.nonce,
            ciphertext: wire.ciphertext,
        })
        .unwrap();
        assert_eq!(viewer.open(&resigned), Err(FrameError::Unreadable));

        let other = Thread {
            key: ThreadKey::generate(),
            id: thread.id,
        };
        let mut elsewhere = other.receiver();
        assert_eq!(elsewhere.open(&frame), Err(FrameError::BadSignature));
        assert_ne!(other.keys().topic(), thread.keys().topic());
    }

    #[test]
    fn oversized_and_malformed_frames_are_refused() {
        let thread = Thread::new();
        let mut host = thread.sender(1);
        let mut viewer = thread.receiver();
        let big = Body::Output {
            slot: slot("alice"),
            bytes: vec![0; MAX_CHUNK_BYTES + 1],
        };
        assert_eq!(host.seal(&big), Err(FrameError::TooLarge));
        let full = Body::Output {
            slot: slot("alice"),
            bytes: vec![0; MAX_CHUNK_BYTES],
        };
        assert!(host.seal(&full).unwrap().len() <= MAX_FRAME_BYTES);
        for (part, parts) in [(0, 0), (1, 1), (0, MAX_SCREEN_PARTS + 1)] {
            let bad = Body::Screen {
                slot: slot("alice"),
                rows: 24,
                columns: 80,
                challenge: [0; 16],
                part,
                parts,
                bytes: Vec::new(),
            };
            assert_eq!(host.seal(&bad), Err(FrameError::Malformed));
        }
        let flat = Body::Screen {
            slot: slot("alice"),
            rows: 0,
            columns: 80,
            challenge: [0; 16],
            part: 0,
            parts: 1,
            bytes: Vec::new(),
        };
        assert_eq!(host.seal(&flat), Err(FrameError::Malformed));
        let huge = Body::Resize {
            slot: slot("alice"),
            rows: MAX_ROWS + 1,
            columns: 80,
        };
        assert_eq!(host.seal(&huge), Err(FrameError::Malformed));
        let flat_screen = host
            .seal_wire(WireBody::Screen {
                slot: "alice.claude",
                rows: 24,
                columns: MAX_COLUMNS + 1,
                challenge: [0; 16],
                part: 0,
                parts: 1,
                bytes: b"",
            })
            .unwrap();
        assert_eq!(viewer.open(&flat_screen), Err(FrameError::Malformed));
        assert_eq!(
            viewer.open(&vec![0; MAX_FRAME_BYTES + 1]),
            Err(FrameError::TooLarge)
        );
        assert_eq!(viewer.open(b"not a frame"), Err(FrameError::Malformed));
        let mut trailing = host.seal(&output("alice", "x")).unwrap();
        trailing.push(0);
        assert_eq!(viewer.open(&trailing), Err(FrameError::Malformed));
    }

    #[test]
    fn a_challenge_anchors_a_sender_once_so_an_old_run_cannot_come_back() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let request = viewer.request_screen().unwrap();
        let mut first_run = thread.sender(1);
        let first_screen = first_run.seal(&screen("alice", &request)).unwrap();
        viewer.open(&first_screen).unwrap();
        let first_output = first_run.seal(&output("alice", "old")).unwrap();

        let mut second_run = thread.sender(1);
        let second_screen = second_run.seal(&screen("alice", &request)).unwrap();
        assert_eq!(viewer.open(&second_screen), Err(FrameError::Unanchored));

        let request = viewer.request_screen().unwrap();
        viewer
            .open(&second_run.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        assert_eq!(viewer.open(&first_screen), Err(FrameError::Unanchored));
        assert_eq!(viewer.open(&first_output), Err(FrameError::Unanchored));
        let again = first_run.seal(&screen("alice", &request)).unwrap();
        assert_eq!(viewer.open(&again), Err(FrameError::Unanchored));
    }

    #[test]
    fn only_the_first_part_of_a_screen_anchors() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let Body::ScreenRequest { challenge } = viewer.request_screen().unwrap() else {
            panic!("not a request");
        };
        let mut host = thread.sender(1);
        let second_part = Body::Screen {
            slot: slot("alice"),
            rows: 24,
            columns: 80,
            challenge,
            part: 1,
            parts: 2,
            bytes: b"end".to_vec(),
        };
        assert_eq!(
            viewer.open(&host.seal(&second_part).unwrap()),
            Err(FrameError::Unanchored)
        );
    }

    #[test]
    fn a_replayed_screen_request_is_dropped() {
        let thread = Thread::new();
        let mut bob = thread.sender(2);
        let mut host = thread.receiver();
        let frame = bob
            .seal(&Body::ScreenRequest { challenge: [6; 16] })
            .unwrap();
        host.open(&frame).unwrap();
        assert_eq!(host.open(&frame), Err(FrameError::Replayed));
        let same_challenge = bob
            .seal(&Body::ScreenRequest { challenge: [6; 16] })
            .unwrap();
        assert_eq!(host.open(&same_challenge), Err(FrameError::Replayed));
    }

    #[test]
    fn output_and_resizes_for_another_participants_agent_are_refused() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let mut mallory = thread.sender(3);
        let resize = Body::Resize {
            slot: slot("alice"),
            rows: 24,
            columns: 80,
        };
        for body in [output("alice", "x"), resize] {
            assert_eq!(
                viewer.open(&mallory.seal(&body).unwrap()),
                Err(FrameError::NotTheirSlot)
            );
        }
        let empty = Body::Resize {
            slot: slot("mallory"),
            rows: 0,
            columns: 80,
        };
        assert_eq!(mallory.seal(&empty), Err(FrameError::Malformed));
        let bad_slot = mallory
            .seal_wire(WireBody::Output {
                slot: "Not A Slot",
                bytes: b"x",
            })
            .unwrap();
        assert_eq!(viewer.open(&bad_slot), Err(FrameError::Malformed));
        let zero_rows = mallory
            .seal_wire(WireBody::Resize {
                slot: "mallory.claude",
                rows: 0,
                columns: 80,
            })
            .unwrap();
        assert_eq!(viewer.open(&zero_rows), Err(FrameError::Malformed));
        assert!(!format!("{mallory:?}").contains(&format!("{:?}", [3_u8; 32])));
    }

    #[test]
    fn a_screen_request_from_an_unanchored_run_is_heard_but_anchors_nothing() {
        let thread = Thread::new();
        let mut bob = thread.sender(2);
        let mut host = thread.receiver();
        let request = Body::ScreenRequest { challenge: [5; 16] };
        let frame = bob.seal(&request).unwrap();
        assert_eq!(host.open(&frame).unwrap().body, request);
        assert_eq!(
            host.open(&bob.seal(&output("bob", "x")).unwrap()),
            Err(FrameError::Unanchored)
        );
        assert!(!format!("{:?}", thread.keys()).contains("seal"));
    }
}
