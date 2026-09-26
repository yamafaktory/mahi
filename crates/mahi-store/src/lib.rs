//! Thread refs, commits and objects of mahi, stored in the project's git repository.

#[cfg(not(unix))]
compile_error!("mahi supports Linux and macOS only");

mod snapshot;
mod store;
mod worktree;

pub use gix::{
    ObjectId,
    objs::tree::EntryKind,
};
pub use snapshot::{
    GlobalPatterns,
    MAX_SNAPSHOT_DEPTH,
    MAX_SNAPSHOT_FILE_BYTES,
    Skipped,
    Snapshot,
    SnapshotCache,
};
pub use store::{
    COMMITTER_EMAIL,
    COMMITTER_NAME,
    Store,
    StoreError,
};
