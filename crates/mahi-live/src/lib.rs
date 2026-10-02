//! mahi's live layer: iroh endpoints on `mahi-tls`, invite tickets and, later, the thread's live
//! stream.

mod endpoint;
mod frame;
#[cfg(fuzzing)]
pub mod fuzzing;
mod gossip;
mod local;
mod meta;
#[cfg(test)]
mod testing;
mod ticket;

pub use endpoint::{
    LiveError,
    LiveNode,
    Relays,
    stable_port,
};
pub use frame::{
    Body,
    FrameError,
    FrameReceiver,
    FrameSender,
    LiveKeys,
    MAX_CHUNK_BYTES,
    MAX_COLUMNS,
    MAX_FRAME_BYTES,
    MAX_PROMPT_BYTES,
    MAX_PROMPTS_PER_RUN,
    MAX_ROWS,
    MAX_SCREEN_PARTS,
    PROMPT_ID_BYTES,
    PromptOutcome,
    PromptText,
    RUN_BYTES,
    Received,
    prompt_id,
};
pub use gossip::{
    LiveTopic,
    RECEIVED_FRAMES,
};
pub use local::{
    LocalError,
    LocalMessage,
    MAX_LOCAL_FRAME_BYTES,
};
pub use meta::{
    META_ALPN,
    Peers,
};
pub use ticket::{
    AddressError,
    HostAddress,
    MAX_DIRECT_ADDRESSES,
    Ticket,
    TicketError,
    is_reachable,
};
