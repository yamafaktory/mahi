//! Runs an agent in a pseudo-terminal inside mahi's sandbox; the only crate with unsafe code.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("mahi supports Linux and macOS only");

#[cfg(all(
    target_os = "linux",
    not(all(
        target_endian = "little",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
compile_error!("the Linux sandbox supports little-endian x86_64 and aarch64 only");

mod pty;
mod sandbox;

pub use pty::{
    PtyChild,
    PtyCommand,
    PtyError,
    PtyReader,
    WindowSize,
    exit_code,
};
pub use sandbox::{
    Access,
    Sandbox,
    SandboxError,
};
