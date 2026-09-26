//! Identifiers, names and ref layout of mahi threads.

mod id;
mod name;
mod refs;

pub use id::{
    ParseThreadIdError,
    RandomError,
    ThreadId,
};
pub use name::{
    AgentName,
    AgentSlot,
    NameError,
    ParticipantName,
    SlotError,
};
pub use refs::{
    ParseRefError,
    RefKind,
    THREADS_PREFIX,
    ThreadRef,
};
