//! Threads of mahi: their signed meta document and participants.

mod key;
mod meta;

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
