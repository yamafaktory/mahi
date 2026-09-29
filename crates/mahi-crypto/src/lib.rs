//! Thread keys and the encrypted blob format of mahi.
//!
//! Content is compressed with LZ4, then encrypted with age to the thread key's recipient.
//! The thread key's secret is itself encrypted to each participant.

mod key;

pub use key::{
    DERIVED_KEY_BYTES,
    DeriveError,
    OpenError,
    SealError,
    ThreadKey,
    WrapError,
    WrappedKeyError,
};
