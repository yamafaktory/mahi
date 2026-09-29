//! mahi's live layer: iroh endpoints on `mahi-tls`, invite tickets and, later, the thread's live
//! stream.

mod endpoint;
#[cfg(test)]
mod testing;
mod ticket;

pub use endpoint::{
    LiveError,
    LiveNode,
    Relays,
};
pub use ticket::{
    AddressError,
    HostAddress,
    MAX_DIRECT_ADDRESSES,
    Ticket,
    TicketError,
    is_reachable,
};
