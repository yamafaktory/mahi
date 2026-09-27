//! Runs an agent in a pseudo-terminal inside mahi's sandbox; the only crate with unsafe code.

#[cfg(not(unix))]
compile_error!("mahi supports Linux and macOS only");

mod pty;

pub use pty::{
    PtyChild,
    PtyCommand,
    PtyError,
    PtyReader,
    WindowSize,
    exit_code,
};
