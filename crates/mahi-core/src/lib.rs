//! Identifiers, names and ref layout of mahi threads.

mod id;
mod name;
mod refs;
mod text;

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
pub use text::is_invisible;
