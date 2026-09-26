//! Thread refs, commits and objects of mahi, stored in the project's git repository.

mod store;

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
