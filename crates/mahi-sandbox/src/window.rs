use std::{
    io,
    os::fd::{
        AsFd,
        AsRawFd,
        BorrowedFd,
        OwnedFd,
    },
    sync::{
        OnceLock,
        atomic::{
            AtomicBool,
            AtomicI32,
            AtomicUsize,
            Ordering,
        },
    },
};

use rustix::{
    event::{
        PollFd,
        PollFlags,
        Timespec,
    },
    io::Errno,
};
use thiserror::Error;

static PIPE: OnceLock<(OwnedFd, OwnedFd)> = OnceLock::new();
static WRITE_END: AtomicI32 = AtomicI32::new(-1);
static LISTENING: AtomicBool = AtomicBool::new(false);
static PREVIOUS: AtomicUsize = AtomicUsize::new(0);

/// Tells when the controlling terminal's size changes, that is, when the process receives
/// `SIGWINCH`.
///
/// Only one exists at a time in a process. Dropping it stops listening and gives the signal
/// back the action it had before, the default one or being ignored. The pipe it reads from is
/// created on first use and kept for the life of the process, so a late signal never writes to
/// a closed descriptor.
#[derive(Debug)]
pub struct WindowChanges {
    read_end: BorrowedFd<'static>,
}

/// Listening for terminal size changes failed.
#[derive(Debug, Error)]
pub enum WindowError {
    /// Another [`WindowChanges`] is already listening in this process.
    #[error("terminal size changes are already being watched")]
    AlreadyWatched,
    /// Some other code in the process has its own `SIGWINCH` handler.
    #[error("another handler already watches terminal size changes")]
    ForeignHandler,
    /// Creating the pipe, installing the handler or reading the pipe failed.
    #[error("cannot watch terminal size changes")]
    Io(#[from] io::Error),
}

impl WindowChanges {
    /// Starts listening for `SIGWINCH`.
    ///
    /// # Errors
    ///
    /// Returns [`WindowError::AlreadyWatched`] if another listener exists,
    /// [`WindowError::ForeignHandler`] if something else handles the signal, or
    /// [`WindowError::Io`] if the pipe or the handler cannot be set up.
    pub fn listen() -> Result<Self, WindowError> {
        if LISTENING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(WindowError::AlreadyWatched);
        }
        match start() {
            Ok(read_end) => Ok(Self { read_end }),
            Err(error) => {
                LISTENING.store(false, Ordering::SeqCst);
                Err(error)
            }
        }
    }

    /// Blocks until the terminal's size changes at least once. Several changes that arrive
    /// together count as one.
    ///
    /// # Errors
    ///
    /// Returns [`WindowError::Io`] if reading the pipe fails.
    pub fn wait(&self) -> Result<(), WindowError> {
        let mut buffer = [0_u8; 64];
        loop {
            match rustix::io::read(self.read_end, &mut buffer) {
                Ok(_) => return Ok(()),
                Err(Errno::INTR) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
        }
    }
}

impl AsFd for WindowChanges {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.read_end
    }
}

impl Drop for WindowChanges {
    fn drop(&mut self) {
        if let Ok(current) = set_disposition(PREVIOUS.load(Ordering::SeqCst))
            && current != handler_address()
        {
            let _ = set_disposition(current);
        }
        LISTENING.store(false, Ordering::SeqCst);
    }
}

pub(crate) fn reset_in_child() -> io::Result<()> {
    set_disposition(libc::SIG_DFL).map(|_| ())
}

fn start() -> Result<BorrowedFd<'static>, WindowError> {
    let (read_end, write_end) = pipe()?;
    drain(read_end.as_fd())?;
    WRITE_END.store(write_end.as_raw_fd(), Ordering::SeqCst);
    let previous = set_disposition(handler_address())?;
    if previous != libc::SIG_DFL && previous != libc::SIG_IGN {
        let _ = set_disposition(previous);
        return Err(WindowError::ForeignHandler);
    }
    PREVIOUS.store(previous, Ordering::SeqCst);
    Ok(read_end.as_fd())
}

fn pipe() -> io::Result<&'static (OwnedFd, OwnedFd)> {
    if let Some(pipe) = PIPE.get() {
        return Ok(pipe);
    }
    let (read_end, write_end) = new_pipe()?;
    rustix::io::ioctl_fionbio(&write_end, true)?;
    Ok(PIPE.get_or_init(|| (read_end, write_end)))
}

#[cfg(target_os = "linux")]
fn new_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?)
}

#[cfg(not(target_os = "linux"))]
fn new_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read_end, write_end) = rustix::pipe::pipe()?;
    for end in [&read_end, &write_end] {
        rustix::io::fcntl_setfd(end, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok((read_end, write_end))
}

fn drain(read_end: BorrowedFd<'_>) -> io::Result<()> {
    let mut buffer = [0_u8; 64];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        let mut fds = [PollFd::new(&read_end, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&now)) {
            Ok(0) => return Ok(()),
            Ok(_) => match rustix::io::read(read_end, &mut buffer) {
                Ok(_) | Err(Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            },
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[expect(
    unsafe_code,
    reason = "rustix has no way to install a signal handler, so libc's sigaction is used"
)]
pub(crate) fn set_disposition(disposition: libc::sighandler_t) -> io::Result<libc::sighandler_t> {
    // SAFETY: `action` is zeroed, then its mask is emptied with `sigemptyset` and its
    // disposition and flags are set, so it is fully initialised. The disposition is our
    // handler, which only makes async-signal-safe calls, or one the process had before.
    // `previous` is a valid place for the old action.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&raw mut action.sa_mask);
        action.sa_sigaction = disposition;
        action.sa_flags = libc::SA_RESTART;
        let mut previous: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGWINCH, &raw const action, &raw mut previous) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(previous.sa_sigaction)
    }
}

fn handler_address() -> libc::sighandler_t {
    let handler: extern "C" fn(libc::c_int) = on_window_change;
    handler as libc::sighandler_t
}

#[expect(
    unsafe_code,
    reason = "a signal handler writes to the self-pipe with a raw descriptor"
)]
extern "C" fn on_window_change(_: libc::c_int) {
    let fd = WRITE_END.load(Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    // SAFETY: the errno location is the calling thread's own, and saving and restoring it
    // keeps the interrupted code's errno intact. `write` is async-signal-safe, the buffer is
    // valid for one byte, and the descriptor belongs to the pipe that lives for the whole
    // process. A full pipe already holds a pending change, so a failed write loses nothing.
    unsafe {
        let errno = errno_location();
        let saved = *errno;
        libc::write(fd, [1_u8].as_ptr().cast(), 1);
        *errno = saved;
    }
}

#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "the signal handler must save the thread's errno through its location"
)]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__errno_location` has no preconditions and returns the calling thread's errno.
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "the signal handler must save the thread's errno through its location"
)]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__error` has no preconditions and returns the calling thread's errno.
    unsafe { libc::__error() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raise_window_change() {
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::WINCH)
            .unwrap();
    }

    fn readable(changes: &WindowChanges, seconds: i64) -> bool {
        let mut fds = [PollFd::new(changes, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        };
        rustix::event::poll(&mut fds, Some(&timeout)).unwrap() == 1
    }

    #[test]
    fn one_listener_wakes_once_per_burst_and_gives_the_signal_back() {
        set_disposition(libc::SIG_DFL).unwrap();
        let changes = WindowChanges::listen().unwrap();
        assert!(matches!(
            WindowChanges::listen(),
            Err(WindowError::AlreadyWatched)
        ));
        for _ in 0..3 {
            raise_window_change();
        }
        assert!(readable(&changes, 5));
        changes.wait().unwrap();
        assert!(!readable(&changes, 0));
        drop(changes);
        assert_eq!(set_disposition(libc::SIG_DFL).unwrap(), libc::SIG_DFL);
        let again = WindowChanges::listen().unwrap();
        assert!(!readable(&again, 0));
        drop(again);
        let changes = WindowChanges::listen().unwrap();
        set_disposition(libc::SIG_IGN).unwrap();
        drop(changes);
        assert_eq!(set_disposition(libc::SIG_DFL).unwrap(), libc::SIG_IGN);
        set_disposition(libc::SIG_IGN).unwrap();
        let changes = WindowChanges::listen().unwrap();
        drop(changes);
        assert_eq!(set_disposition(libc::SIG_DFL).unwrap(), libc::SIG_IGN);
    }
}
