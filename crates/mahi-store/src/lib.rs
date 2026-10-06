//! Thread refs, commits and objects of mahi, stored in the project's git repository.

#[cfg(not(unix))]
compile_error!("mahi supports Linux and macOS only");

mod changes;
mod diff;
mod fetch;
#[cfg(any(fuzzing, feature = "fuzzing"))]
pub mod fuzzing;
mod history;
mod merge;
mod push;
mod snapshot;
mod store;
mod trailers;
mod worktree;

pub use changes::{
    Change,
    Changes,
};
pub use diff::{
    FileDiff,
    MAX_DIFFED_BYTES,
};
pub use fetch::{
    FETCHED_PREFIX,
    MAX_FETCHED_REFS,
    MAX_HISTORY_WALK,
};
pub use gix::{
    ObjectId,
    objs::tree::EntryKind,
    protocol::transport::client::blocking_io::Transport,
};
pub use merge::{
    Applied,
    Conflict,
    Left,
    MAX_MERGE_WRITE_BYTES,
    MAX_MERGED_PATHS,
    Merged,
};
pub use push::Pushed;
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
    CommitSignature,
    CommitSigner,
    Store,
    StoreError,
};
pub use trailers::Trailed;
