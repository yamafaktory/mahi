//! mahi's live layer: iroh endpoints on `mahi-tls`, invite tickets and, later, the thread's live
//! stream.

mod endpoint;
mod frame;
#[cfg(any(fuzzing, feature = "fuzzing"))]
pub mod fuzzing;
mod gossip;
mod local;
mod lookup;
mod meta;
mod pair;
mod snapshots;
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
    COMMIT_BYTES,
    ClaimEntry,
    FrameError,
    FrameReceiver,
    FrameSender,
    LiveKeys,
    MAX_CHUNK_BYTES,
    MAX_CLAIM_BYTES,
    MAX_CLAIM_NOTE_BYTES,
    MAX_COLUMNS,
    MAX_FRAME_BYTES,
    MAX_FRAME_CLAIMS,
    MAX_FRAME_STATES,
    MAX_FRAME_TURN_ENDS,
    MAX_ROWS,
    MAX_SCREEN_PARTS,
    MIN_COLUMNS,
    MIN_ROWS,
    Received,
    StateEntry,
    TurnEnd,
    TurnState,
};
pub use gossip::{
    LiveTopic,
    RECEIVED_FRAMES,
};
pub use local::{
    LocalError,
    LocalMessage,
    MAX_LOCAL_CLAIMS,
    MAX_LOCAL_FRAME_BYTES,
};
pub use meta::{
    META_ALPN,
    Peers,
};
pub use pair::{
    Channel,
    CodeError,
    Confirming,
    Handshake,
    MAX_MESSAGE_BYTES,
    MAX_PLACE_BYTES,
    MAX_SEALED_BYTES,
    MAX_SLOT,
    PAIR_ALPN,
    PairError,
    PairLink,
    PairListener,
    PairingCode,
    Role,
    STEP_WAIT,
    parse_place,
    place_bytes,
};
pub use snapshots::{
    MAX_SNAPSHOTS_REQUEST_BYTES,
    SNAPSHOTS_ALPN,
    SnapshotsAnswer,
    SnapshotsRequest,
};
pub use ticket::{
    AddressError,
    HostAddress,
    MAX_DIRECT_ADDRESSES,
    Ticket,
    TicketError,
    is_reachable,
};
