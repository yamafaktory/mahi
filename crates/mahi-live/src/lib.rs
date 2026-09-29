//! mahi's live layer: iroh endpoints on `mahi-tls`, invite tickets and, later, the thread's live
//! stream.

mod endpoint;
mod frame;
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
    MAX_FRAME_BYTES,
    MAX_SCREEN_PARTS,
    Received,
};
pub use meta::{
    META_ALPN,
    MetaSource,
};
pub use ticket::{
    AddressError,
    HostAddress,
    MAX_DIRECT_ADDRESSES,
    Ticket,
    TicketError,
    is_reachable,
};
