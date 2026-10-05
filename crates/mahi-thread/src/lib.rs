//! Threads of mahi: their signed meta document, participants and transcripts.

mod card;
mod commits;
mod fetched;
#[cfg(fuzzing)]
pub mod fuzzing;
mod handoff;
mod key;
mod meta;
mod node;
mod owners;
mod pins;
mod pull_request;
mod session_files;
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
    Refusal,
    accept_fetched,
};
pub use handoff::{
    BRIEFED_PROMPTS,
    BRIEFED_REPLIES,
    Briefing,
    MAX_BRIEFING_BYTES,
};
pub use key::{
    KeyError,
    ParticipantKey,
};
pub use meta::{
    InvalidMeta,
    MAX_META_BYTES,
    MAX_PARTICIPANTS,
    MetaDocument,
    MetaDraft,
    MetaError,
    Participant,
    PrivateMeta,
    Tombstone,
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
pub use pull_request::{
    LandedAgent,
    MAX_DRAFT_BYTES,
    PullRequestDraft,
};
pub use session_files::{
    MAX_SESSION_BYTES,
    MAX_SESSION_CHUNKS,
    MAX_SESSION_FILES,
    MAX_SESSION_PATH_BYTES,
    SESSION_CHUNK_BYTES,
    SessionError,
    SessionFile,
    SessionPath,
    SessionReader,
    SessionWriter,
    session_ref,
};
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
    tombstone_thread,
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
