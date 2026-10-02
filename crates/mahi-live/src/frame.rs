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

const SIGNED_LABEL: &[u8] = b"mahi-live-v1";
const TOPIC_INFO: &[u8] = b"mahi-live-topic-v1";
const SEAL_INFO: &[u8] = b"mahi-live-seal-v1";
const NONCE_BYTES: usize = 24;
const EPOCH_BYTES: usize = 16;
const CHALLENGE_BYTES: usize = 16;
const REMEMBERED_CHALLENGES: usize = 256;
/// The largest prompt a teammate can send an agent, in bytes.
pub const MAX_PROMPT_BYTES: usize = 8 * 1024;
/// The size of a prompt's id.
pub const PROMPT_ID_BYTES: usize = 16;
/// The size of the id of one run of a sender.
pub const RUN_BYTES: usize = EPOCH_BYTES;
/// The most prompts a host takes from one node in one of its runs.
pub const MAX_PROMPTS_PER_RUN: usize = 1024;
/// How many runs of a sender a receiver remembers, refusing lists of claims no newer than
/// the newest seen from the same run.
const REMEMBERED_RUNS: usize = 8;
/// The most claims one frame carries.
pub const MAX_FRAME_CLAIMS: usize = 64;
/// The longest a claimed path or task may be, in bytes.
pub const MAX_CLAIM_BYTES: usize = 256;
/// The longest a claim's note may be, in bytes.
pub const MAX_CLAIM_NOTE_BYTES: usize = 200;

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
    /// A participant asks the agent `slot` to take a prompt.
    Prompt {
        /// The agent the prompt is for.
        slot: AgentSlot,
        /// The run of the agent's host the prompt is for, so no later run takes it.
        run: [u8; RUN_BYTES],
        /// A random id the answers carry.
        id: [u8; PROMPT_ID_BYTES],
        /// The prompt's text.
        text: PromptText,
    },
    /// The host of the agent `slot` says what became of a prompt.
    PromptAnswer {
        /// The agent the prompt was for.
        slot: AgentSlot,
        /// The prompt's id.
        id: [u8; PROMPT_ID_BYTES],
        /// What became of it.
        outcome: PromptOutcome,
    },
    /// A host's whole list of the claims its agents hold, at most [`MAX_FRAME_CLAIMS`].
    Claims {
        /// The claims, each of an agent of the sender.
        claims: Vec<ClaimEntry>,
    },
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

/// The text of a prompt a teammate sends an agent: not empty, and at most
/// [`MAX_PROMPT_BYTES`].
#[derive(Clone, PartialEq, Eq)]
pub struct PromptText(String);

impl PromptText {
    /// Checks `text` as a prompt's text.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::Malformed`] if `text` is empty, or [`FrameError::TooLarge`] if it
    /// is longer than [`MAX_PROMPT_BYTES`].
    pub fn new(text: String) -> Result<Self, FrameError> {
        check_prompt(&text)?;
        Ok(Self(text))
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PromptText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptText")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// What became of a prompt a teammate sent an agent, as its host tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptOutcome {
    /// The prompt waits for the host user.
    Queued,
    /// The host user accepted it.
    Accepted,
    /// The host user rejected it.
    Rejected,
    /// The host let it go without the host user accepting or rejecting it.
    Dropped,
}

impl PromptOutcome {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::Accepted => 1,
            Self::Rejected => 2,
            Self::Dropped => 3,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Queued),
            1 => Some(Self::Accepted),
            2 => Some(Self::Rejected),
            3 => Some(Self::Dropped),
            _ => None,
        }
    }
}

/// Draws a new prompt id.
///
/// # Errors
///
/// Returns [`FrameError::Random`] if the random source fails.
pub fn prompt_id() -> Result<[u8; PROMPT_ID_BYTES], FrameError> {
    let mut id = [0_u8; PROMPT_ID_BYTES];
    getrandom::fill(&mut id).map_err(|_| FrameError::Random)?;
    Ok(id)
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
    /// The prompt is for another run, or this receiver takes no prompts.
    #[error("the prompt is not for this run")]
    OtherRun,
    /// The sender sent more than [`MAX_PROMPTS_PER_RUN`] prompts in this run.
    #[error("the sender sent too many prompts")]
    TooManyPrompts,
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
    Prompt {
        slot: &'a str,
        run: [u8; RUN_BYTES],
        id: [u8; PROMPT_ID_BYTES],
        text: &'a str,
    },
    PromptAnswer {
        slot: &'a str,
        id: [u8; PROMPT_ID_BYTES],
        outcome: u8,
    },
    Claims {
        #[serde(borrow)]
        claims: Vec<WireClaim<'a>>,
    },
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

    /// Returns the id of this run, which prompts for it carry.
    #[must_use]
    pub fn run(&self) -> [u8; RUN_BYTES] {
        self.epoch
    }

    /// Seals and signs `body` as the next frame.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::TooLarge`] if the body or the frame is over its limits, or
    /// [`FrameError::Random`] if no nonce can be drawn.
    pub fn seal(&mut self, body: &Body) -> Result<Vec<u8>, FrameError> {
        let slot;
        let slots: Vec<String>;
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
            Body::Prompt {
                slot: owner,
                run,
                id,
                text,
            } => {
                slot = owner.to_string();
                WireBody::Prompt {
                    slot: &slot,
                    run: *run,
                    id: *id,
                    text: text.as_str(),
                }
            }
            Body::PromptAnswer {
                slot: owner,
                id,
                outcome,
            } => {
                slot = owner.to_string();
                WireBody::PromptAnswer {
                    slot: &slot,
                    id: *id,
                    outcome: outcome.code(),
                }
            }
            Body::Claims { claims } => {
                check_claims(
                    claims.len(),
                    claims
                        .iter()
                        .map(|claim| (claim.what.as_str(), claim.note.as_deref())),
                )?;
                slots = claims.iter().map(|claim| claim.slot.to_string()).collect();
                WireBody::Claims {
                    claims: claims
                        .iter()
                        .zip(&slots)
                        .map(|(claim, slot)| WireClaim {
                            slot,
                            what: &claim.what,
                            note: claim.note.as_deref(),
                            age_secs: claim.age_secs,
                        })
                        .collect(),
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
    own_run: Option<OwnRun>,
    prompts: HashMap<NodeId, HashSet<[u8; PROMPT_ID_BYTES]>>,
    claims: HashMap<NodeId, ClaimsSeen>,
}

/// The newest list of claims seen from each of a sender's latest runs, by its run's epoch.
#[derive(Debug, Default)]
struct ClaimsSeen {
    runs: VecDeque<([u8; EPOCH_BYTES], u64)>,
}

#[derive(Debug)]
struct OwnRun {
    run: [u8; RUN_BYTES],
    owner: ParticipantName,
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
            own_run: None,
            prompts: HashMap::new(),
            claims: HashMap::new(),
        }
    }

    /// Takes the prompts for the agents of `owner` in the run of `sender`, the host's own; a
    /// receiver takes no prompts until it is told its run.
    pub fn take_prompts_for(&mut self, sender: &FrameSender, owner: ParticipantName) {
        let run = sender.run();
        if self.own_run.as_ref().is_none_or(|own| own.run != run) {
            self.prompts.clear();
        }
        self.own_run = Some(OwnRun { run, owner });
    }

    /// Returns the run of `sender` this receiver follows, which a prompt for its agents
    /// carries, or `None` before a screen of it anchored one.
    #[must_use]
    pub fn run_of(&self, sender: &NodeId) -> Option<[u8; RUN_BYTES]> {
        self.senders.get(sender).map(|state| state.epoch)
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
        let body = parse_body(&plain.body)?;
        if drawn_slot(&body).is_some_and(|slot| slot.participant() != &participant) {
            return Err(FrameError::NotTheirSlot);
        }
        if let Body::Claims { claims } = &body
            && claims
                .iter()
                .any(|claim| claim.slot.participant() != &participant)
        {
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
        if let Body::Prompt { slot, run, id, .. } = body {
            return self.remember_prompt(sender, slot, *run, *id);
        }
        if let Body::Claims { .. } = body {
            return self.remember_claims(sender, plain);
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

    fn remember_prompt(
        &mut self,
        sender: NodeId,
        slot: &AgentSlot,
        run: [u8; RUN_BYTES],
        id: [u8; PROMPT_ID_BYTES],
    ) -> Result<(), FrameError> {
        let Some(own) = self.own_run.as_ref().filter(|own| own.run == run) else {
            return Err(FrameError::OtherRun);
        };
        if slot.participant() != &own.owner {
            return Err(FrameError::NotTheirSlot);
        }
        let seen = self.prompts.entry(sender).or_default();
        if seen.contains(&id) {
            return Err(FrameError::Replayed);
        }
        if seen.len() >= MAX_PROMPTS_PER_RUN {
            return Err(FrameError::TooManyPrompts);
        }
        seen.insert(id);
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

fn check_prompt(text: &str) -> Result<(), FrameError> {
    if text.is_empty() {
        return Err(FrameError::Malformed);
    }
    if text.len() > MAX_PROMPT_BYTES {
        return Err(FrameError::TooLarge);
    }
    Ok(())
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
        | Body::PromptAnswer { slot, .. } => Some(slot),
        Body::ScreenRequest { .. } | Body::Prompt { .. } | Body::Claims { .. } => None,
    }
}

/// Decodes `data` as a frame's plaintext and parses its body, for the fuzz targets.
#[cfg(fuzzing)]
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
        WireBody::Prompt {
            slot: owner,
            run,
            id,
            text,
        } => {
            check_prompt(text)?;
            Body::Prompt {
                slot: slot(owner)?,
                run,
                id,
                text: PromptText(text.to_owned()),
            }
        }
        WireBody::PromptAnswer {
            slot: owner,
            id,
            outcome,
        } => Body::PromptAnswer {
            slot: slot(owner)?,
            id,
            outcome: PromptOutcome::from_code(outcome).ok_or(FrameError::Malformed)?,
        },
        WireBody::Claims { ref claims } => {
            check_claims(
                claims.len(),
                claims.iter().map(|claim| (claim.what, claim.note)),
            )?;
            Body::Claims {
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

    fn prompt(run: [u8; RUN_BYTES], id: [u8; PROMPT_ID_BYTES], text: &str) -> Body {
        Body::Prompt {
            slot: slot("alice"),
            run,
            id,
            text: PromptText::new(text.to_owned()).unwrap(),
        }
    }

    fn hosting(thread: &Thread) -> (FrameSender, FrameReceiver) {
        let alice = thread.sender(1);
        let mut host = thread.receiver();
        host.take_prompts_for(&alice, ParticipantName::new("alice").unwrap());
        (alice, host)
    }

    #[test]
    fn a_participants_prompt_reaches_the_host_once() {
        let thread = Thread::new();
        let (alice, mut host) = hosting(&thread);
        let mut bob = thread.sender(2);
        let id = prompt_id().unwrap();
        let body = prompt(alice.run(), id, "fix the parser test");
        let frame = bob.seal(&body).unwrap();
        let received = host.open(&frame).unwrap();
        assert_eq!(received.participant.as_str(), "bob");
        assert_eq!(received.body, body);
        assert_eq!(host.open(&frame), Err(FrameError::Replayed));
        let again = bob.seal(&prompt(alice.run(), id, "same id")).unwrap();
        assert_eq!(host.open(&again), Err(FrameError::Replayed));
        let mut carol = thread.sender(3);
        let same_id_elsewhere = carol.seal(&prompt(alice.run(), id, "mine")).unwrap();
        assert!(host.open(&same_id_elsewhere).is_ok());
        let mut stranger = thread.sender(9);
        let from_stranger = stranger
            .seal(&prompt(alice.run(), prompt_id().unwrap(), "hi"))
            .unwrap();
        assert_eq!(host.open(&from_stranger), Err(FrameError::NotParticipant));
        let for_bob = Body::Prompt {
            slot: slot("bob"),
            run: alice.run(),
            id: prompt_id().unwrap(),
            text: PromptText::new("hi".to_owned()).unwrap(),
        };
        let misdirected = carol.seal(&for_bob).unwrap();
        assert_eq!(host.open(&misdirected), Err(FrameError::NotTheirSlot));
    }

    #[test]
    fn a_participant_removed_and_listed_again_cannot_replay_a_prompt() {
        let thread = Thread::new();
        let (alice, mut host) = hosting(&thread);
        let mut bob = thread.sender(2);
        let frame = bob
            .seal(&prompt(alice.run(), prompt_id().unwrap(), "hi"))
            .unwrap();
        host.open(&frame).unwrap();
        let alice_only = [(node(1), ParticipantName::new("alice").unwrap())];
        host.set_participants(alice_only.clone());
        assert_eq!(host.open(&frame), Err(FrameError::NotParticipant));
        host.set_participants(
            alice_only
                .into_iter()
                .chain([(node(2), ParticipantName::new("bob").unwrap())]),
        );
        assert_eq!(host.open(&frame), Err(FrameError::Replayed));
    }

    #[test]
    fn a_prompt_is_taken_only_by_the_run_it_names() {
        let thread = Thread::new();
        let (alice, mut host) = hosting(&thread);
        let mut bob = thread.sender(2);
        let frame = bob
            .seal(&prompt(alice.run(), prompt_id().unwrap(), "hi"))
            .unwrap();
        let mut viewer = thread.receiver();
        assert_eq!(viewer.open(&frame), Err(FrameError::OtherRun));

        let restarted = thread.sender(1);
        host.take_prompts_for(&restarted, ParticipantName::new("alice").unwrap());
        assert_eq!(host.open(&frame), Err(FrameError::OtherRun));
        let fresh = bob
            .seal(&prompt(restarted.run(), prompt_id().unwrap(), "hi"))
            .unwrap();
        assert!(host.open(&fresh).is_ok());
    }

    #[test]
    fn a_viewer_learns_the_run_its_prompts_name_from_the_hosts_screen() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let mut alice = thread.sender(1);
        assert_eq!(viewer.run_of(&node(1)), None);
        let request = viewer.request_screen().unwrap();
        viewer
            .open(&alice.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        assert_eq!(viewer.run_of(&node(1)), Some(alice.run()));
    }

    #[test]
    fn a_host_remembers_every_prompt_of_a_run_up_to_its_limit() {
        let thread = Thread::new();
        let (alice, mut host) = hosting(&thread);
        let mut bob = thread.sender(2);
        let first = bob
            .seal(&prompt(alice.run(), prompt_id().unwrap(), "first"))
            .unwrap();
        host.open(&first).unwrap();
        for _ in 1..MAX_PROMPTS_PER_RUN {
            let next = bob
                .seal(&prompt(alice.run(), prompt_id().unwrap(), "next"))
                .unwrap();
            host.open(&next).unwrap();
        }
        assert_eq!(host.open(&first), Err(FrameError::Replayed));
        let over = bob
            .seal(&prompt(alice.run(), prompt_id().unwrap(), "over"))
            .unwrap();
        assert_eq!(host.open(&over), Err(FrameError::TooManyPrompts));
        let mut carol = thread.sender(3);
        let other_sender = carol
            .seal(&prompt(alice.run(), prompt_id().unwrap(), "mine"))
            .unwrap();
        assert!(host.open(&other_sender).is_ok());
    }

    #[test]
    fn prompt_text_is_bounded_and_kept_out_of_debug_output() {
        assert_eq!(PromptText::new(String::new()), Err(FrameError::Malformed));
        assert!(PromptText::new("x".repeat(MAX_PROMPT_BYTES)).is_ok());
        assert_eq!(
            PromptText::new("x".repeat(MAX_PROMPT_BYTES + 1)),
            Err(FrameError::TooLarge)
        );
        let text = PromptText::new("the secret plan".to_owned()).unwrap();
        assert_eq!(text.as_str(), "the secret plan");
        let body = prompt([0; RUN_BYTES], [0; PROMPT_ID_BYTES], "the secret plan");
        assert!(!format!("{body:?}").contains("secret"));
    }

    #[test]
    fn empty_oversized_or_non_utf8_prompt_text_is_refused() {
        let thread = Thread::new();
        let (alice, mut host) = hosting(&thread);
        let mut bob = thread.sender(2);
        let over = "x".repeat(MAX_PROMPT_BYTES + 1);
        for (text, error) in [
            ("", FrameError::Malformed),
            (over.as_str(), FrameError::TooLarge),
        ] {
            let frame = bob
                .seal_wire(WireBody::Prompt {
                    slot: "alice.claude",
                    run: alice.run(),
                    id: prompt_id().unwrap(),
                    text,
                })
                .unwrap();
            assert_eq!(host.open(&frame), Err(error));
        }
        let mut plain = postcard::to_allocvec(&WirePlain {
            epoch: [0; EPOCH_BYTES],
            sequence: 1,
            body: WireBody::Prompt {
                slot: "alice.claude",
                run: alice.run(),
                id: [0; PROMPT_ID_BYTES],
                text: "ab",
            },
        })
        .unwrap();
        let last = plain.len() - 1;
        plain[last] = 0xff;
        assert!(matches!(
            decode_exact::<WirePlain<'_>>(&plain),
            Err(FrameError::Malformed)
        ));
    }

    #[test]
    fn only_the_agents_owner_answers_its_prompts() {
        let thread = Thread::new();
        let mut viewer = thread.receiver();
        let mut alice = thread.sender(1);
        let mut mallory = thread.sender(3);
        let request = viewer.request_screen().unwrap();
        viewer
            .open(&alice.seal(&screen("alice", &request)).unwrap())
            .unwrap();
        let id = prompt_id().unwrap();
        let answer = Body::PromptAnswer {
            slot: slot("alice"),
            id,
            outcome: PromptOutcome::Accepted,
        };
        let received = viewer.open(&alice.seal(&answer).unwrap()).unwrap();
        assert_eq!(received.body, answer);
        let forged = mallory.seal(&answer).unwrap();
        assert_eq!(viewer.open(&forged), Err(FrameError::NotTheirSlot));
        let unknown = alice
            .seal_wire(WireBody::PromptAnswer {
                slot: "alice.claude",
                id,
                outcome: 4,
            })
            .unwrap();
        assert_eq!(viewer.open(&unknown), Err(FrameError::Malformed));
    }

    #[test]
    fn every_prompt_outcome_code_round_trips() {
        for outcome in [
            PromptOutcome::Queued,
            PromptOutcome::Accepted,
            PromptOutcome::Rejected,
            PromptOutcome::Dropped,
        ] {
            assert_eq!(PromptOutcome::from_code(outcome.code()), Some(outcome));
        }
        assert_eq!(PromptOutcome::from_code(4), None);
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
            claims: vec![claim("alice", "src/parser.rs")],
        };
        let older = alice.seal(&first).unwrap();
        let newer = alice.seal(&Body::Claims { claims: Vec::new() }).unwrap();
        assert_eq!(
            receiver.open(&newer).unwrap().body,
            Body::Claims { claims: Vec::new() }
        );
        assert!(matches!(receiver.open(&older), Err(FrameError::Replayed)));
        assert!(matches!(receiver.open(&newer), Err(FrameError::Replayed)));
        let mut restarted = thread.sender(1);
        let again = restarted.seal(&first).unwrap();
        assert_eq!(receiver.open(&again).unwrap().body, first);
        let later = restarted
            .seal(&Body::Claims { claims: Vec::new() })
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
                claims: vec![claim("mallory", "a"), claim("alice", "b")],
            })
            .unwrap();
        assert!(matches!(
            receiver.open(&forged),
            Err(FrameError::NotTheirSlot)
        ));
        let many = Body::Claims {
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
                claims: vec![claim("mallory", what)],
            };
            assert!(
                matches!(mallory.seal(&odd), Err(FrameError::Malformed)),
                "{what:?}"
            );
            let wire = mallory
                .seal_wire(WireBody::Claims {
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
        let late = earlier.seal(&Body::Claims { claims: Vec::new() }).unwrap();
        let mut current = thread.sender(1);
        let first = current.seal(&Body::Claims { claims: Vec::new() }).unwrap();
        let next = current
            .seal(&Body::Claims {
                claims: vec![claim("alice", "docs")],
            })
            .unwrap();
        assert!(receiver.open(&first).is_ok());
        assert!(receiver.open(&late).is_ok());
        assert!(receiver.open(&next).is_ok());
        assert!(matches!(receiver.open(&late), Err(FrameError::Replayed)));
    }
}
