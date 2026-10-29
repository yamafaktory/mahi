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
    is_invisible,
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
/// The fewest rows a screen or a resize may have, so a line that wraps can scroll.
pub const MIN_ROWS: u16 = 2;
/// The fewest columns a screen or a resize may have, so a wide character fits in a row.
pub const MIN_COLUMNS: u16 = 2;

const SIGNED_LABEL: &[u8] = b"mahi-live-v2";
const TOPIC_INFO: &[u8] = b"mahi-live-topic-v2";
const SEAL_INFO: &[u8] = b"mahi-live-seal-v2";
const NONCE_BYTES: usize = 24;
const EPOCH_BYTES: usize = 16;
const CHALLENGE_BYTES: usize = 16;
const REMEMBERED_CHALLENGES: usize = 256;
/// How many runs of a sender a receiver remembers, refusing lists of claims no newer than
/// the newest seen from the same run.
const REMEMBERED_RUNS: usize = 8;
/// The most claims one frame carries.
pub const MAX_FRAME_CLAIMS: usize = 64;
/// The longest a claimed path or task may be, in bytes.
pub const MAX_CLAIM_BYTES: usize = 256;
/// The longest a claim's note may be, in bytes.
pub const MAX_CLAIM_NOTE_BYTES: usize = 200;
/// The size of a commit's id.
pub const COMMIT_BYTES: usize = 20;
/// The most turn-end snapshots one claims frame names.
pub const MAX_FRAME_TURN_ENDS: usize = 64;
/// The most agents' states one claims frame tells.
pub const MAX_FRAME_STATES: usize = 64;

/// The keys of a thread's live stream, derived from its thread key: the gossip topic, which
/// only participants can find, and the key frames are sealed with.
#[derive(Clone)]
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
    /// The agent's host is still there, sent when it has had nothing else to send for a while.
    Heartbeat {
        /// The agent whose host it is.
        slot: AgentSlot,
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
    /// A host's whole list of the claims its agents hold, at most [`MAX_FRAME_CLAIMS`], with
    /// the latest turn-end snapshot of each of its agents, at most [`MAX_FRAME_TURN_ENDS`],
    /// and the state of each, at most [`MAX_FRAME_STATES`], which a receiver keeps only from
    /// a run it anchored, when the frame is newer than the last states it took from that run,
    /// as the whole list of the states that run tells.
    Claims {
        /// The claims, each of an agent of the sender.
        claims: Vec<ClaimEntry>,
        /// The latest turn-end snapshots, each of an agent of the sender, one per agent.
        turn_ends: Vec<TurnEnd>,
        /// The states, each of an agent of the sender, one per agent.
        states: Vec<StateEntry>,
    },
    /// The agent's turn ended, and this is its turn-end snapshot.
    TurnEnded(TurnEnd),
    /// The agent's state changed, and this is the new one.
    State(StateEntry),
}

/// What an agent does, as its host tells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    /// A turn is open.
    Working,
    /// Its turn ended: it waits for its next prompt.
    Done,
    /// It waits on a question of its own for its user.
    Asks,
}

impl TurnState {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Working => 0,
            Self::Done => 1,
            Self::Asks => 2,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Working),
            1 => Some(Self::Done),
            2 => Some(Self::Asks),
            _ => None,
        }
    }
}

/// The state of an agent, as its host tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateEntry {
    /// The agent.
    pub slot: AgentSlot,
    /// What it does.
    pub state: TurnState,
}

/// The latest turn-end snapshot of an agent, as its host names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnEnd {
    /// The agent.
    pub slot: AgentSlot,
    /// The snapshot's commit.
    pub commit: [u8; COMMIT_BYTES],
}

/// An advisory claim on a path or a task, as a host sends it: the agent that holds it, what
/// it claims (1 to [`MAX_CLAIM_BYTES`] bytes), an optional note (at most
/// [`MAX_CLAIM_NOTE_BYTES`]), neither with control or invisible characters, and how long ago it
/// was taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEntry {
    /// The agent that holds the claim.
    pub slot: AgentSlot,
    /// What it claims.
    pub what: String,
    /// What it does with it.
    pub note: Option<String>,
    /// How long ago the claim was taken, in seconds.
    pub age_secs: u32,
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
    /// Whether it is a claims frame whose states are the whole list its sender's anchored
    /// run tells: from that run, and newer than the last states taken from it.
    pub told_states: bool,
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
    Heartbeat {
        slot: &'a str,
    },
    Claims {
        #[serde(borrow)]
        claims: Vec<WireClaim<'a>>,
        #[serde(borrow)]
        turn_ends: Vec<WireTurnEnd<'a>>,
        #[serde(borrow)]
        states: Vec<WireState<'a>>,
    },
    TurnEnded(#[serde(borrow)] WireTurnEnd<'a>),
    State(#[serde(borrow)] WireState<'a>),
}

#[derive(Serialize, Deserialize)]
struct WireState<'a> {
    slot: &'a str,
    state: u8,
}

#[derive(Serialize, Deserialize)]
struct WireTurnEnd<'a> {
    slot: &'a str,
    commit: [u8; COMMIT_BYTES],
}

#[derive(Serialize, Deserialize)]
struct WireClaim<'a> {
    slot: &'a str,
    what: &'a str,
    note: Option<&'a str>,
    age_secs: u32,
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

    /// Returns the thread whose stream these keys are for.
    #[must_use]
    pub fn thread(&self) -> ThreadId {
        self.thread
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
            Body::Heartbeat { slot: owner } => {
                slot = owner.to_string();
                WireBody::Heartbeat { slot: &slot }
            }
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
            Body::Claims {
                claims,
                turn_ends,
                states,
            } => return self.seal_claims(claims, turn_ends, states),
            Body::TurnEnded(ended) => {
                slot = ended.slot.to_string();
                WireBody::TurnEnded(WireTurnEnd {
                    slot: &slot,
                    commit: ended.commit,
                })
            }
            Body::State(told) => {
                slot = told.slot.to_string();
                WireBody::State(WireState {
                    slot: &slot,
                    state: told.state.code(),
                })
            }
        };
        self.seal_wire(wire)
    }

    fn seal_claims(
        &mut self,
        claims: &[ClaimEntry],
        turn_ends: &[TurnEnd],
        states: &[StateEntry],
    ) -> Result<Vec<u8>, FrameError> {
        check_claims(
            claims.len(),
            claims
                .iter()
                .map(|claim| (claim.what.as_str(), claim.note.as_deref())),
        )?;
        check_once_each(
            turn_ends.iter().map(|ended| &ended.slot),
            MAX_FRAME_TURN_ENDS,
        )?;
        check_once_each(states.iter().map(|told| &told.slot), MAX_FRAME_STATES)?;
        let slots: Vec<String> = claims
            .iter()
            .map(|claim| &claim.slot)
            .chain(turn_ends.iter().map(|ended| &ended.slot))
            .chain(states.iter().map(|told| &told.slot))
            .map(ToString::to_string)
            .collect();
        let (claim_slots, rest) = slots.split_at(claims.len());
        let (ended_slots, state_slots) = rest.split_at(turn_ends.len());
        self.seal_wire(WireBody::Claims {
            claims: claims
                .iter()
                .zip(claim_slots)
                .map(|(claim, slot)| WireClaim {
                    slot,
                    what: &claim.what,
                    note: claim.note.as_deref(),
                    age_secs: claim.age_secs,
                })
                .collect(),
            turn_ends: turn_ends
                .iter()
                .zip(ended_slots)
                .map(|(ended, slot)| WireTurnEnd {
                    slot,
                    commit: ended.commit,
                })
                .collect(),
            states: states
                .iter()
                .zip(state_slots)
                .map(|(told, slot)| WireState {
                    slot,
                    state: told.state.code(),
                })
                .collect(),
        })
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
    told_through: u64,
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
    claims: HashMap<NodeId, ClaimsSeen>,
}

/// The newest list of claims seen from each of a sender's latest runs, by its run's epoch.
#[derive(Debug, Default)]
struct ClaimsSeen {
    runs: VecDeque<([u8; EPOCH_BYTES], u64)>,
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
            claims: HashMap::new(),
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
        self.claims
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
        let mut body = parse_body(&plain.body)?;
        if drawn_slot(&body).is_some_and(|slot| slot.participant() != &participant) {
            return Err(FrameError::NotTheirSlot);
        }
        if let Body::Claims {
            claims,
            turn_ends,
            states,
        } = &body
            && claims
                .iter()
                .map(|claim| &claim.slot)
                .chain(turn_ends.iter().map(|ended| &ended.slot))
                .chain(states.iter().map(|told| &told.slot))
                .any(|slot| slot.participant() != &participant)
        {
            return Err(FrameError::NotTheirSlot);
        }
        let after_told = self.after_told(sender, &plain);
        let told_states = match &mut body {
            Body::Claims { states, .. } if after_told != Some(true) => {
                states.clear();
                false
            }
            Body::Claims { .. } | Body::State(_) => {
                if after_told == Some(false) {
                    return Err(FrameError::Replayed);
                }
                true
            }
            Body::Output { .. }
            | Body::Resize { .. }
            | Body::Heartbeat { .. }
            | Body::ScreenRequest { .. }
            | Body::Screen { .. }
            | Body::TurnEnded(_) => false,
        };
        self.check_order(sender, &plain, &body)?;
        if told_states && let Some(state) = self.senders.get_mut(&sender) {
            state.told_through = plain.sequence;
        }
        Ok(Received {
            sender,
            participant,
            told_states: told_states && matches!(body, Body::Claims { .. }),
            body,
        })
    }

    /// Says whether `plain` comes after the last states this receiver took from the run of
    /// `sender` it anchored, or `None` when `plain` is not from that run. A state frame and
    /// a claims frame's states are taken only after them, since claims are not anchored and
    /// each may arrive after a newer state; other frames tell no state, so they do not order
    /// states.
    fn after_told(&self, sender: NodeId, plain: &WirePlain<'_>) -> Option<bool> {
        self.senders
            .get(&sender)
            .filter(|state| state.epoch == plain.epoch)
            .map(|state| plain.sequence > state.told_through)
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
        if let Body::Claims { .. } = body {
            return self.remember_claims(sender, plain);
        }
        let state = self.senders.get(&sender).copied();
        if let Some(state) = state.filter(|state| state.epoch == plain.epoch) {
            if let Body::State(_) = body {
                return Ok(());
            }
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
                        told_through: plain.sequence,
                    },
                );
                Ok(())
            }
            _ => Err(FrameError::Unanchored),
        }
    }

    /// Takes a list of claims only when it is newer than every list seen from the same run of
    /// its sender, remembering its latest runs; hosts do not anchor each other, so claims are
    /// ordered on their own, and runs cannot be ordered among themselves.
    fn remember_claims(&mut self, sender: NodeId, plain: &WirePlain<'_>) -> Result<(), FrameError> {
        let seen = self.claims.entry(sender).or_default();
        if let Some((_, sequence)) = seen
            .runs
            .iter_mut()
            .find(|(epoch, _)| *epoch == plain.epoch)
        {
            if plain.sequence <= *sequence {
                return Err(FrameError::Replayed);
            }
            *sequence = plain.sequence;
            return Ok(());
        }
        if seen.runs.len() == REMEMBERED_RUNS {
            seen.runs.pop_front();
        }
        seen.runs.push_back((plain.epoch, plain.sequence));
        Ok(())
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
    if rows < MIN_ROWS || columns < MIN_COLUMNS || rows > MAX_ROWS || columns > MAX_COLUMNS {
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

fn check_claims<'a>(
    count: usize,
    claims: impl Iterator<Item = (&'a str, Option<&'a str>)>,
) -> Result<(), FrameError> {
    if count > MAX_FRAME_CLAIMS {
        return Err(FrameError::TooLarge);
    }
    for (what, note) in claims {
        if !claim_fits(what, note) {
            return Err(FrameError::Malformed);
        }
    }
    Ok(())
}

/// Says whether `what` and `note` may make a claim: plain text of 1 to [`MAX_CLAIM_BYTES`]
/// bytes and at most [`MAX_CLAIM_NOTE_BYTES`], without control or invisible characters.
pub(crate) fn claim_fits(what: &str, note: Option<&str>) -> bool {
    let plain = |text: &str, most: usize| {
        !text.is_empty()
            && text.len() <= most
            && !text
                .chars()
                .any(|character| character.is_control() || is_invisible(character))
    };
    plain(what, MAX_CLAIM_BYTES)
        && what.trim() == what
        && note.is_none_or(|note| plain(note, MAX_CLAIM_NOTE_BYTES))
}

fn check_once_each<'a>(
    slots: impl ExactSizeIterator<Item = &'a AgentSlot>,
    most: usize,
) -> Result<(), FrameError> {
    if slots.len() > most {
        return Err(FrameError::TooLarge);
    }
    let mut seen = Vec::with_capacity(slots.len());
    for slot in slots {
        if seen.contains(&slot) {
            return Err(FrameError::Malformed);
        }
        seen.push(slot);
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
        Body::Output { slot, .. }
        | Body::Resize { slot, .. }
        | Body::Screen { slot, .. }
        | Body::Heartbeat { slot }
        | Body::TurnEnded(TurnEnd { slot, .. })
        | Body::State(StateEntry { slot, .. }) => Some(slot),
        Body::ScreenRequest { .. } | Body::Claims { .. } => None,
    }
}

/// Decodes `data` as a frame's plaintext and parses its body, for the fuzz targets.
#[cfg(any(fuzzing, feature = "fuzzing"))]
pub(crate) fn fuzz_plaintext(data: &[u8]) {
    if let Ok(plain) = decode_exact::<WirePlain<'_>>(data) {
        let _ = parse_body(&plain.body);
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
        WireBody::Heartbeat { slot: owner } => Body::Heartbeat { slot: slot(owner)? },
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
        WireBody::Claims {
            ref claims,
            ref turn_ends,
            ref states,
        } => parse_claims(claims, turn_ends, states)?,
        WireBody::TurnEnded(WireTurnEnd {
            slot: owner,
            commit,
        }) => Body::TurnEnded(TurnEnd {
            slot: slot(owner)?,
            commit,
        }),
        WireBody::State(ref told) => Body::State(parse_state(told)?),
    })
}

fn parse_state(told: &WireState<'_>) -> Result<StateEntry, FrameError> {
    Ok(StateEntry {
        slot: told.slot.parse().map_err(|_| FrameError::Malformed)?,
        state: TurnState::from_code(told.state).ok_or(FrameError::Malformed)?,
    })
}

fn parse_claims(
    claims: &[WireClaim<'_>],
    turn_ends: &[WireTurnEnd<'_>],
    states: &[WireState<'_>],
) -> Result<Body, FrameError> {
    let slot = |text: &str| text.parse::<AgentSlot>().map_err(|_| FrameError::Malformed);
    check_claims(
        claims.len(),
        claims.iter().map(|claim| (claim.what, claim.note)),
    )?;
    if turn_ends.len() > MAX_FRAME_TURN_ENDS || states.len() > MAX_FRAME_STATES {
        return Err(FrameError::TooLarge);
    }
    let turn_ends = turn_ends
        .iter()
        .map(|ended| {
            Ok(TurnEnd {
                slot: slot(ended.slot)?,
                commit: ended.commit,
            })
        })
        .collect::<Result<Vec<_>, FrameError>>()?;
    check_once_each(
        turn_ends.iter().map(|ended| &ended.slot),
        MAX_FRAME_TURN_ENDS,
    )?;
    let states = states
        .iter()
        .map(parse_state)
        .collect::<Result<Vec<_>, FrameError>>()?;
    check_once_each(states.iter().map(|told| &told.slot), MAX_FRAME_STATES)?;
    Ok(Body::Claims {
        claims: claims
            .iter()
            .map(|claim| {
                Ok(ClaimEntry {
                    slot: slot(claim.slot)?,
                    what: claim.what.to_owned(),
                    note: claim.note.map(str::to_owned),
                    age_secs: claim.age_secs,
                })
            })
            .collect::<Result<_, FrameError>>()?,
        turn_ends,
        states,
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
        let one_column = mallory
            .seal_wire(WireBody::Resize {
                slot: "mallory.claude",
                rows: 24,
                columns: 1,
            })
            .unwrap();
        assert_eq!(viewer.open(&one_column), Err(FrameError::Malformed));
        let one_row = mallory
            .seal_wire(WireBody::Resize {
                slot: "mallory.claude",
                rows: 1,
                columns: 80,
            })
            .unwrap();
        assert_eq!(viewer.open(&one_row), Err(FrameError::Malformed));
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

    #[test]
    fn a_heartbeat_follows_the_senders_run_and_only_its_owner_sends_it() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let mut host = thread.sender(1);
        let beat = Body::Heartbeat {
            slot: slot("alice"),
        };
        assert_eq!(
            viewer.open(&host.seal(&beat).unwrap()),
            Err(FrameError::Unanchored)
        );
        let request = viewer.request_screen().unwrap();
        viewer
            .open(&host.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let frame = host.seal(&beat).unwrap();
        assert_eq!(viewer.open(&frame).unwrap().body, beat);
        assert_eq!(viewer.open(&frame), Err(FrameError::Replayed));
        let mut mallory = thread.sender(3);
        assert_eq!(
            viewer.open(&mallory.seal(&beat).unwrap()),
            Err(FrameError::NotTheirSlot)
        );
    }

    fn turn_end(participant: &str, byte: u8) -> TurnEnd {
        TurnEnd {
            slot: slot(participant),
            commit: [byte; COMMIT_BYTES],
        }
    }

    #[test]
    fn a_turn_end_follows_the_senders_run_and_only_its_owner_announces_it() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let mut host = thread.sender(1);
        let ended = Body::TurnEnded(turn_end("alice", 7));
        assert_eq!(
            viewer.open(&host.seal(&ended).unwrap()),
            Err(FrameError::Unanchored)
        );
        let request = viewer.request_screen().unwrap();
        viewer
            .open(&host.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let frame = host.seal(&ended).unwrap();
        assert_eq!(viewer.open(&frame).unwrap().body, ended);
        assert_eq!(viewer.open(&frame), Err(FrameError::Replayed));
        let mut mallory = thread.sender(3);
        assert_eq!(
            viewer.open(&mallory.seal(&ended).unwrap()),
            Err(FrameError::NotTheirSlot)
        );
    }

    fn state_entry(participant: &str, state: TurnState) -> StateEntry {
        StateEntry {
            slot: slot(participant),
            state,
        }
    }

    #[test]
    fn a_state_follows_the_senders_run_and_only_its_owner_tells_it() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let mut host = thread.sender(1);
        let working = Body::State(state_entry("alice", TurnState::Working));
        assert_eq!(
            viewer.open(&host.seal(&working).unwrap()),
            Err(FrameError::Unanchored)
        );
        let request = viewer.request_screen().unwrap();
        viewer
            .open(&host.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let frame = host.seal(&working).unwrap();
        assert_eq!(viewer.open(&frame).unwrap().body, working);
        assert_eq!(viewer.open(&frame), Err(FrameError::Replayed));
        let asks = Body::State(state_entry("alice", TurnState::Asks));
        assert_eq!(viewer.open(&host.seal(&asks).unwrap()).unwrap().body, asks);
        let mut mallory = thread.sender(3);
        assert_eq!(
            viewer.open(&mallory.seal(&working).unwrap()),
            Err(FrameError::NotTheirSlot)
        );
    }

    #[test]
    fn a_state_of_an_unknown_code_is_refused() {
        let thread = Thread::new();
        let mut receiver = thread.receiver();
        let mut alice = thread.sender(1);
        let unknown = alice
            .seal_wire(WireBody::State(WireState {
                slot: "alice.claude",
                state: 3,
            }))
            .unwrap();
        assert_eq!(receiver.open(&unknown), Err(FrameError::Malformed));
        for state in [TurnState::Working, TurnState::Done, TurnState::Asks] {
            assert_eq!(TurnState::from_code(state.code()), Some(state));
        }
    }

    #[test]
    fn claims_tell_states_only_from_the_anchored_run_and_after_its_last_states() {
        let thread = Thread::new();
        let mut receiver = thread.receiver();
        let mut alice = thread.sender(1);
        let claims = |state: TurnState| Body::Claims {
            claims: vec![claim("alice", "src/parser.rs")],
            turn_ends: vec![turn_end("alice", 1)],
            states: vec![state_entry("alice", state)],
        };
        let states_of = |received: Received| match received.body {
            Body::Claims {
                claims,
                turn_ends,
                states,
            } => {
                assert_eq!(claims.len(), 1);
                assert_eq!(turn_ends.len(), 1);
                states
            }
            body => panic!("not claims: {body:?}"),
        };
        let unanchored = alice.seal(&claims(TurnState::Asks)).unwrap();
        assert!(states_of(receiver.open(&unanchored).unwrap()).is_empty());

        let request = receiver.request_screen().unwrap();
        receiver
            .open(&alice.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let older = alice.seal(&claims(TurnState::Working)).unwrap();
        let state_frame = alice
            .seal(&Body::State(state_entry("alice", TurnState::Done)))
            .unwrap();
        receiver.open(&state_frame).unwrap();
        assert!(states_of(receiver.open(&older).unwrap()).is_empty());
        let newer = alice.seal(&claims(TurnState::Done)).unwrap();
        assert_eq!(
            states_of(receiver.open(&newer).unwrap()),
            [state_entry("alice", TurnState::Done)]
        );

        let late_state = alice
            .seal(&Body::State(state_entry("alice", TurnState::Working)))
            .unwrap();
        let newest = alice.seal(&claims(TurnState::Asks)).unwrap();
        assert_eq!(
            states_of(receiver.open(&newest).unwrap()),
            [state_entry("alice", TurnState::Asks)]
        );
        assert_eq!(receiver.open(&late_state), Err(FrameError::Replayed));

        let mut restarted = thread.sender(1);
        let other_run = restarted.seal(&claims(TurnState::Asks)).unwrap();
        assert!(states_of(receiver.open(&other_run).unwrap()).is_empty());
    }

    #[test]
    fn a_state_sent_before_the_screen_that_anchors_its_run_is_not_taken() {
        let thread = Thread::new();
        let mut receiver = thread.receiver();
        let mut alice = thread.sender(1);
        let request = receiver.request_screen().unwrap();
        let state = alice
            .seal(&Body::State(state_entry("alice", TurnState::Asks)))
            .unwrap();
        let claims = alice
            .seal(&Body::Claims {
                claims: Vec::new(),
                turn_ends: Vec::new(),
                states: vec![state_entry("alice", TurnState::Asks)],
            })
            .unwrap();
        receiver
            .open(&alice.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        assert_eq!(receiver.open(&state), Err(FrameError::Replayed));
        let late = receiver.open(&claims).unwrap();
        assert!(!late.told_states);
        assert!(matches!(late.body, Body::Claims { states, .. } if states.is_empty()));
    }

    #[test]
    fn a_state_frame_overtaken_by_newer_output_is_still_taken_once() {
        let thread = Thread::new();
        let mut receiver = thread.receiver();
        let mut alice = thread.sender(1);
        let request = receiver.request_screen().unwrap();
        receiver
            .open(&alice.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let asks = Body::State(state_entry("alice", TurnState::Asks));
        let state = alice.seal(&asks).unwrap();
        receiver
            .open(&alice.seal(&output("alice", "more")).unwrap())
            .unwrap();
        assert_eq!(receiver.open(&state).unwrap().body, asks);
        assert_eq!(receiver.open(&state), Err(FrameError::Replayed));
        let mut stranger = thread.sender(1);
        assert_eq!(
            receiver.open(&stranger.seal(&asks).unwrap()),
            Err(FrameError::Unanchored)
        );
    }

    #[test]
    fn a_claims_frame_tells_its_whole_list_of_states_only_from_the_anchored_run() {
        let thread = Thread::new();
        let mut receiver = thread.receiver();
        let mut alice = thread.sender(1);
        let none = Body::Claims {
            claims: Vec::new(),
            turn_ends: Vec::new(),
            states: Vec::new(),
        };
        assert!(
            !receiver
                .open(&alice.seal(&none).unwrap())
                .unwrap()
                .told_states
        );
        let request = receiver.request_screen().unwrap();
        receiver
            .open(&alice.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let told = receiver.open(&alice.seal(&none).unwrap()).unwrap();
        assert!(told.told_states);
        let output = receiver
            .open(&alice.seal(&output("alice", "x")).unwrap())
            .unwrap();
        assert!(!output.told_states);
    }

    #[test]
    fn a_claims_frame_overtaken_by_newer_output_still_tells_its_states() {
        let thread = Thread::new();
        let mut receiver = thread.receiver();
        let mut alice = thread.sender(1);
        let request = receiver.request_screen().unwrap();
        receiver
            .open(&alice.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let claims = alice
            .seal(&Body::Claims {
                claims: Vec::new(),
                turn_ends: Vec::new(),
                states: vec![state_entry("alice", TurnState::Working)],
            })
            .unwrap();
        receiver
            .open(&alice.seal(&output("alice", "more")).unwrap())
            .unwrap();
        let Body::Claims { states, .. } = receiver.open(&claims).unwrap().body else {
            panic!("not claims");
        };
        assert_eq!(states, [state_entry("alice", TurnState::Working)]);
    }

    #[test]
    fn claims_carry_only_the_senders_states_one_per_agent_and_a_bounded_number() {
        let thread = Thread::new();
        let mut alice = thread.sender(1);
        let mut receiver = thread.receiver();
        let request = receiver.request_screen().unwrap();
        receiver
            .open(&alice.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let listed = Body::Claims {
            claims: Vec::new(),
            turn_ends: Vec::new(),
            states: vec![state_entry("alice", TurnState::Done)],
        };
        assert_eq!(
            receiver.open(&alice.seal(&listed).unwrap()).unwrap().body,
            listed
        );
        let mut mallory = thread.sender(3);
        let forged = mallory
            .seal(&Body::Claims {
                claims: Vec::new(),
                turn_ends: Vec::new(),
                states: vec![
                    state_entry("mallory", TurnState::Done),
                    state_entry("alice", TurnState::Asks),
                ],
            })
            .unwrap();
        assert_eq!(receiver.open(&forged), Err(FrameError::NotTheirSlot));
        let twice = Body::Claims {
            claims: Vec::new(),
            turn_ends: Vec::new(),
            states: vec![
                state_entry("alice", TurnState::Working),
                state_entry("alice", TurnState::Done),
            ],
        };
        assert_eq!(alice.seal(&twice), Err(FrameError::Malformed));
        let wire_twice = alice
            .seal_wire(WireBody::Claims {
                claims: Vec::new(),
                turn_ends: Vec::new(),
                states: vec![
                    WireState {
                        slot: "alice.claude",
                        state: 0,
                    },
                    WireState {
                        slot: "alice.claude",
                        state: 1,
                    },
                ],
            })
            .unwrap();
        assert_eq!(receiver.open(&wire_twice), Err(FrameError::Malformed));
        let names: Vec<String> = (0..=MAX_FRAME_STATES)
            .map(|index| format!("alice.agent{index}"))
            .collect();
        let too_many = alice
            .seal_wire(WireBody::Claims {
                claims: Vec::new(),
                turn_ends: Vec::new(),
                states: names
                    .iter()
                    .map(|name| WireState {
                        slot: name,
                        state: 0,
                    })
                    .collect(),
            })
            .unwrap();
        assert_eq!(receiver.open(&too_many), Err(FrameError::TooLarge));
        let sealed_too_many = Body::Claims {
            claims: Vec::new(),
            turn_ends: Vec::new(),
            states: names
                .iter()
                .map(|name| StateEntry {
                    slot: name.parse().unwrap(),
                    state: TurnState::Done,
                })
                .collect(),
        };
        assert_eq!(alice.seal(&sealed_too_many), Err(FrameError::TooLarge));
    }

    #[test]
    fn claims_carry_only_the_senders_turn_ends_one_per_agent_and_a_bounded_number() {
        let thread = Thread::new();
        let mut alice = thread.sender(1);
        let mut receiver = thread.receiver();
        let listed = Body::Claims {
            states: Vec::new(),
            claims: Vec::new(),
            turn_ends: vec![turn_end("alice", 1)],
        };
        assert_eq!(
            receiver.open(&alice.seal(&listed).unwrap()).unwrap().body,
            listed
        );
        let mut mallory = thread.sender(3);
        let forged = mallory
            .seal(&Body::Claims {
                states: Vec::new(),
                claims: Vec::new(),
                turn_ends: vec![turn_end("mallory", 1), turn_end("alice", 2)],
            })
            .unwrap();
        assert_eq!(receiver.open(&forged), Err(FrameError::NotTheirSlot));
        let twice = Body::Claims {
            states: Vec::new(),
            claims: Vec::new(),
            turn_ends: vec![turn_end("alice", 1), turn_end("alice", 2)],
        };
        assert_eq!(alice.seal(&twice), Err(FrameError::Malformed));
        let wire_twice = alice
            .seal_wire(WireBody::Claims {
                states: Vec::new(),
                claims: Vec::new(),
                turn_ends: vec![
                    WireTurnEnd {
                        slot: "alice.claude",
                        commit: [1; COMMIT_BYTES],
                    },
                    WireTurnEnd {
                        slot: "alice.claude",
                        commit: [2; COMMIT_BYTES],
                    },
                ],
            })
            .unwrap();
        assert_eq!(receiver.open(&wire_twice), Err(FrameError::Malformed));
        let names: Vec<String> = (0..=MAX_FRAME_TURN_ENDS)
            .map(|index| format!("alice.agent{index}"))
            .collect();
        let too_many = alice
            .seal_wire(WireBody::Claims {
                states: Vec::new(),
                claims: Vec::new(),
                turn_ends: names
                    .iter()
                    .map(|name| WireTurnEnd {
                        slot: name,
                        commit: [1; COMMIT_BYTES],
                    })
                    .collect(),
            })
            .unwrap();
        assert_eq!(receiver.open(&too_many), Err(FrameError::TooLarge));
    }

    fn claim(participant: &str, what: &str) -> ClaimEntry {
        ClaimEntry {
            slot: slot(participant),
            what: what.to_owned(),
            note: Some("adding tests".to_owned()),
            age_secs: 60,
        }
    }

    #[test]
    fn a_hosts_claims_reach_others_without_a_screen_and_newer_lists_only() {
        let thread = Thread::new();
        let mut alice = thread.sender(1);
        let mut receiver = thread.receiver();
        let first = Body::Claims {
            states: Vec::new(),
            turn_ends: Vec::new(),
            claims: vec![claim("alice", "src/parser.rs")],
        };
        let older = alice.seal(&first).unwrap();
        let newer = alice
            .seal(&Body::Claims {
                states: Vec::new(),
                claims: Vec::new(),
                turn_ends: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            receiver.open(&newer).unwrap().body,
            Body::Claims {
                states: Vec::new(),
                claims: Vec::new(),
                turn_ends: Vec::new(),
            }
        );
        assert!(matches!(receiver.open(&older), Err(FrameError::Replayed)));
        assert!(matches!(receiver.open(&newer), Err(FrameError::Replayed)));
        let mut restarted = thread.sender(1);
        let again = restarted.seal(&first).unwrap();
        assert_eq!(receiver.open(&again).unwrap().body, first);
        let later = restarted
            .seal(&Body::Claims {
                states: Vec::new(),
                claims: Vec::new(),
                turn_ends: Vec::new(),
            })
            .unwrap();
        assert!(matches!(receiver.open(&older), Err(FrameError::Replayed)));
        assert!(receiver.open(&later).is_ok());
        assert!(matches!(receiver.open(&older), Err(FrameError::Replayed)));
    }

    #[test]
    fn claims_on_anothers_agents_too_many_or_odd_ones_are_refused() {
        let thread = Thread::new();
        let mut mallory = thread.sender(3);
        let mut receiver = thread.receiver();
        let forged = mallory
            .seal(&Body::Claims {
                states: Vec::new(),
                turn_ends: Vec::new(),
                claims: vec![claim("mallory", "a"), claim("alice", "b")],
            })
            .unwrap();
        assert!(matches!(
            receiver.open(&forged),
            Err(FrameError::NotTheirSlot)
        ));
        let many = Body::Claims {
            states: Vec::new(),
            turn_ends: Vec::new(),
            claims: (0..=MAX_FRAME_CLAIMS)
                .map(|index| claim("mallory", &index.to_string()))
                .collect(),
        };
        assert!(matches!(mallory.seal(&many), Err(FrameError::TooLarge)));
        for what in [
            "",
            " padded",
            "line\nbreak",
            "\u{202e}flip",
            &"x".repeat(MAX_CLAIM_BYTES + 1),
        ] {
            let odd = Body::Claims {
                states: Vec::new(),
                turn_ends: Vec::new(),
                claims: vec![claim("mallory", what)],
            };
            assert!(
                matches!(mallory.seal(&odd), Err(FrameError::Malformed)),
                "{what:?}"
            );
            let wire = mallory
                .seal_wire(WireBody::Claims {
                    states: Vec::new(),
                    turn_ends: Vec::new(),
                    claims: vec![WireClaim {
                        slot: "mallory.claude",
                        what,
                        note: None,
                        age_secs: 0,
                    }],
                })
                .unwrap();
            assert!(
                matches!(receiver.open(&wire), Err(FrameError::Malformed)),
                "{what:?}"
            );
        }
    }

    #[test]
    fn a_late_list_from_an_unseen_run_does_not_block_the_current_run() {
        let thread = Thread::new();
        let mut receiver = thread.receiver();
        let mut earlier = thread.sender(1);
        let late = earlier
            .seal(&Body::Claims {
                states: Vec::new(),
                claims: Vec::new(),
                turn_ends: Vec::new(),
            })
            .unwrap();
        let mut current = thread.sender(1);
        let first = current
            .seal(&Body::Claims {
                states: Vec::new(),
                claims: Vec::new(),
                turn_ends: Vec::new(),
            })
            .unwrap();
        let next = current
            .seal(&Body::Claims {
                states: Vec::new(),
                turn_ends: Vec::new(),
                claims: vec![claim("alice", "docs")],
            })
            .unwrap();
        assert!(receiver.open(&first).is_ok());
        assert!(receiver.open(&late).is_ok());
        assert!(receiver.open(&next).is_ok());
        assert!(matches!(receiver.open(&late), Err(FrameError::Replayed)));
    }
}
