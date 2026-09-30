//! Threads of mahi: their signed meta document, participants and transcripts.

mod card;
mod commits;
mod fetched;
mod key;
mod meta;
mod node;
mod owners;
mod pins;
mod signer;
mod thread;
mod transcript;

pub use card::{
    CardError,
    ParticipantCard,
};
pub use commits::{
    COMMIT_NAMESPACE,
    GitSigner,
    signed_by,
};
pub use fetched::{
    Accepted,
    accept_fetched,
};
pub use key::{
    KeyError,
    ParticipantKey,
};
pub use meta::{
    InvalidMeta,
    MAX_META_BYTES,
    MAX_PARTICIPANTS,
    MetaDraft,
    MetaError,
    Participant,
    PrivateMeta,
    VerifiedMeta,
};
pub use node::{
    NodeId,
    NodeIdError,
};
pub use owners::{
    OwnerError,
    remember_owner,
    remembered_owner,
};
pub use pins::PinError;
pub use signer::{
    SignError,
    SshSigner,
};
pub use thread::{
    META_ENTRY,
    ThreadError,
    add_participant,
    create_thread,
    discard_thread,
    load_meta,
    load_meta_document,
    record_meta,
};
pub use transcript::{
    Event,
    MAX_EVENT_BYTES,
    MAX_EVENTS_PER_TURN,
    MAX_TURN_BYTES,
    TURN_ENTRY,
    TranscriptError,
    TranscriptTip,
    TurnRecord,
    append_turn,
    read_tip,
    read_turns,
    walk_turns,
};
