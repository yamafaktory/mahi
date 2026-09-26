//! Thread refs, commits and objects of mahi, stored in the project's git repository.

#[cfg(not(unix))]
compile_error!("mahi supports Linux and macOS only");

mod store;
mod worktree;

pub use gix::{
    ObjectId,
    objs::tree::EntryKind,
};
pub use store::{
    COMMITTER_EMAIL,
    COMMITTER_NAME,
    Store,
    StoreError,
};
