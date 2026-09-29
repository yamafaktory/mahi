//! mahi's live layer: iroh endpoints on `mahi-tls`, invite tickets and, later, the thread's live
//! stream.

mod endpoint;
mod frame;
mod gossip;
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
    MAX_ROWS,
    MAX_SCREEN_PARTS,
    Received,
};
pub use gossip::{
    LiveTopic,
    RECEIVED_FRAMES,
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
