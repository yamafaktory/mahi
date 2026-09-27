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

const WATCHED: [libc::c_int; 5] = [
    libc::SIGWINCH,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGINT,
];
const WINDOW: &[usize] = &[0];
const TERMINATION: &[usize] = &[1, 2, 3, 4];

static WINDOW_PIPE: OnceLock<(OwnedFd, OwnedFd)> = OnceLock::new();
static TERMINATION_PIPE: OnceLock<(OwnedFd, OwnedFd)> = OnceLock::new();
static WRITE_ENDS: [AtomicI32; 5] = [const { AtomicI32::new(-1) }; 5];
static PREVIOUS: [AtomicUsize; 5] = [const { AtomicUsize::new(0) }; 5];
static WINDOW_LISTENING: AtomicBool = AtomicBool::new(false);
static OWNER: AtomicI32 = AtomicI32::new(0);
static TERMINATION_LISTENING: AtomicBool = AtomicBool::new(false);

/// Tells when the controlling terminal's size changes, that is, when the process receives
/// `SIGWINCH`.
///
/// Only one exists at a time in a process. Dropping it stops listening and gives the signal
/// back the action it had before, the default one or being ignored. The pipe it reads from is
/// created on first use and kept for the life of the process, so a late signal never writes to
/// a closed descriptor.
#[derive(Debug)]
pub struct WindowChanges(Watch);

/// Tells when the process is asked to stop: `SIGTERM`, `SIGHUP`, `SIGQUIT` or `SIGINT`.
///
/// While it exists, those signals no longer end the process; the caller decides what to do.
/// Only one exists at a time in a process, and dropping it gives the signals back their
/// previous actions.
#[derive(Debug)]
pub struct TerminationSignals(Watch);

/// A signal that asks the process to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// `SIGTERM`.
    Terminate,
    /// `SIGHUP`.
    Hangup,
    /// `SIGQUIT`.
    Quit,
    /// `SIGINT`.
    Interrupt,
}

/// Listening for signals failed.
#[derive(Debug, Error)]
pub enum SignalError {
    /// Another listener already watches these signals in this process.
    #[error("these signals are already being watched")]
    AlreadyWatched,
    /// Some other code in the process has its own handler for one of the signals.
    #[error("another handler already watches these signals")]
    ForeignHandler,
    /// Creating the pipe, installing a handler or reading the pipe failed.
    #[error("cannot watch signals")]
    Io(#[from] io::Error),
}

#[derive(Debug)]
struct Watch {
    read_end: BorrowedFd<'static>,
    indices: &'static [usize],
    listening: &'static AtomicBool,
}

impl WindowChanges {
    /// Starts listening for `SIGWINCH`.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::AlreadyWatched`] if another listener exists,
    /// [`SignalError::ForeignHandler`] if something else handles the signal, or
    /// [`SignalError::Io`] if the pipe or the handler cannot be set up.
    pub fn listen() -> Result<Self, SignalError> {
        Watch::start(&WINDOW_PIPE, WINDOW, &WINDOW_LISTENING).map(Self)
    }

    /// Blocks until the terminal's size changes at least once. Several changes that arrive
    /// together count as one.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Io`] if reading the pipe fails.
    pub fn wait(&self) -> Result<(), SignalError> {
        let mut buffer = [0_u8; 64];
        self.0.read(&mut buffer).map(|_| ())
    }
}

impl AsFd for WindowChanges {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.read_end
    }
}

impl TerminationSignals {
    /// Starts catching `SIGTERM`, `SIGHUP`, `SIGQUIT` and `SIGINT`.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::AlreadyWatched`] if another listener exists,
    /// [`SignalError::ForeignHandler`] if something else handles one of the signals, or
    /// [`SignalError::Io`] if the pipe or a handler cannot be set up.
    pub fn listen() -> Result<Self, SignalError> {
        Watch::start(&TERMINATION_PIPE, TERMINATION, &TERMINATION_LISTENING).map(Self)
    }

    /// Blocks until one of the signals arrives, and says which.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Io`] if reading the pipe fails.
    pub fn wait(&self) -> Result<Termination, SignalError> {
        let mut buffer = [0_u8; 1];
        loop {
            self.0.read(&mut buffer)?;
            let received = libc::c_int::from(buffer[0]);
            let termination = match received {
                libc::SIGTERM => Termination::Terminate,
                libc::SIGHUP => Termination::Hangup,
                libc::SIGQUIT => Termination::Quit,
                libc::SIGINT => Termination::Interrupt,
                _ => continue,
            };
            return Ok(termination);
        }
    }
}

impl TerminationSignals {
    /// Blocks until `input` has something to read, then returns `None`, or until one of the
    /// signals arrives, then returns it. It waits with `select`, which, unlike `poll` on macOS,
    /// works on terminals.
    ///
    /// # Errors
    ///
    /// Returns [`SignalError::Io`] if waiting or reading the pipe fails, including when a
    /// descriptor is too large for `select`.
    pub fn wait_for_input(
        &self,
        input: BorrowedFd<'_>,
    ) -> Result<Option<Termination>, SignalError> {
        loop {
            match readable(input, self.0.read_end)? {
                (_, true) => return self.wait().map(Some),
                (true, false) => return Ok(None),
                (false, false) => {}
            }
        }
    }
}

impl AsFd for TerminationSignals {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.read_end
    }
}

impl Termination {
    /// Ends the process with this signal, as if it had not been caught, so a shell that ran
    /// mahi sees it die of the signal. `SIGQUIT` is never re-raised, since its default action
    /// would dump mahi's memory, which can hold secrets, to a core file.
    pub fn reraise(self) {
        if self == Self::Quit {
            return;
        }
        if set_disposition(self.number(), libc::SIG_DFL).is_ok() {
            raise(self.number());
        }
    }

    /// Returns the signal's number.
    #[must_use]
    pub fn number(self) -> i32 {
        match self {
            Self::Terminate => libc::SIGTERM,
            Self::Hangup => libc::SIGHUP,
            Self::Quit => libc::SIGQUIT,
            Self::Interrupt => libc::SIGINT,
        }
    }
}

impl Watch {
    fn start(
        pipe: &'static OnceLock<(OwnedFd, OwnedFd)>,
        indices: &'static [usize],
        listening: &'static AtomicBool,
    ) -> Result<Self, SignalError> {
        if listening
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SignalError::AlreadyWatched);
        }
        match install(pipe, indices) {
            Ok(read_end) => Ok(Self {
                read_end,
                indices,
                listening,
            }),
            Err(error) => {
                listening.store(false, Ordering::SeqCst);
                Err(error)
            }
        }
    }

    fn read(&self, buffer: &mut [u8]) -> Result<usize, SignalError> {
        loop {
            match rustix::io::read(self.read_end, &mut *buffer) {
                Ok(read) => return Ok(read),
                Err(Errno::INTR) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        for &index in self.indices {
            restore(index);
        }
        self.listening.store(false, Ordering::SeqCst);
    }
}

fn install(
    pipe: &'static OnceLock<(OwnedFd, OwnedFd)>,
    indices: &'static [usize],
) -> Result<BorrowedFd<'static>, SignalError> {
    let (read_end, write_end) = pipe_of(pipe)?;
    drain(read_end.as_fd())?;
    OWNER.store(
        rustix::process::getpid().as_raw_nonzero().get(),
        Ordering::SeqCst,
    );
    for (installed, &index) in indices.iter().enumerate() {
        let (Some(write_slot), Some(&signal)) = (WRITE_ENDS.get(index), WATCHED.get(index)) else {
            return Err(io::Error::from(Errno::INVAL).into());
        };
        write_slot.store(write_end.as_raw_fd(), Ordering::SeqCst);
        let undo = || {
            for &done in indices.iter().take(installed) {
                restore(done);
            }
        };
        let current = match current_disposition(signal) {
            Ok(current) => current,
            Err(error) => {
                undo();
                return Err(error.into());
            }
        };
        if current != libc::SIG_DFL && current != libc::SIG_IGN {
            undo();
            return Err(SignalError::ForeignHandler);
        }
        if let Some(slot) = PREVIOUS.get(index) {
            slot.store(current, Ordering::SeqCst);
        }
        if current == libc::SIG_IGN && index != 0 {
            continue;
        }
        if let Err(error) = set_disposition(signal, handler_address()) {
            undo();
            return Err(error.into());
        }
    }
    Ok(read_end.as_fd())
}

fn restore(index: usize) {
    let (Some(&signal), Some(previous)) = (WATCHED.get(index), PREVIOUS.get(index)) else {
        return;
    };
    if let Ok(current) = set_disposition(signal, previous.load(Ordering::SeqCst))
        && current != handler_address()
    {
        let _ = set_disposition(signal, current);
    }
}

#[expect(
    unsafe_code,
    reason = "rustix has no select, which macOS needs to wait on a terminal"
)]
fn readable(first: BorrowedFd<'_>, second: BorrowedFd<'_>) -> io::Result<(bool, bool)> {
    let (first, second) = (first.as_raw_fd(), second.as_raw_fd());
    let limit = libc::c_int::try_from(libc::FD_SETSIZE).unwrap_or(libc::c_int::MAX);
    if !(0..limit).contains(&first) || !(0..limit).contains(&second) {
        return Err(Errno::INVAL.into());
    }
    // SAFETY: both descriptors are open and below FD_SETSIZE, so FD_SET and FD_ISSET stay inside
    // the set, which FD_ZERO initialises first. The other sets and the timeout are null, and
    // select only writes to the set it is given.
    unsafe {
        let mut set: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&raw mut set);
        libc::FD_SET(first, &raw mut set);
        libc::FD_SET(second, &raw mut set);
        let ready = libc::select(
            first.max(second) + 1,
            &raw mut set,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok((false, false));
            }
            return Err(error);
        }
        Ok((
            libc::FD_ISSET(first, &raw const set),
            libc::FD_ISSET(second, &raw const set),
        ))
    }
}

pub(crate) fn reset_in_child() -> io::Result<()> {
    set_disposition(libc::SIGWINCH, libc::SIG_DFL)?;
    for (index, &signal) in WATCHED.iter().enumerate().skip(1) {
        if current_disposition(signal)? != handler_address() {
            continue;
        }
        let previous = PREVIOUS
            .get(index)
            .map_or(libc::SIG_DFL, |slot| slot.load(Ordering::SeqCst));
        let disposition = if previous == libc::SIG_IGN {
            libc::SIG_IGN
        } else {
            libc::SIG_DFL
        };
        set_disposition(signal, disposition)?;
    }
    Ok(())
}

fn pipe_of(pipe: &'static OnceLock<(OwnedFd, OwnedFd)>) -> io::Result<&'static (OwnedFd, OwnedFd)> {
    if let Some(pipe) = pipe.get() {
        return Ok(pipe);
    }
    let (read_end, write_end) = new_pipe()?;
    rustix::io::ioctl_fionbio(&write_end, true)?;
    Ok(pipe.get_or_init(|| (read_end, write_end)))
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
pub(crate) fn set_disposition(
    signal: libc::c_int,
    disposition: libc::sighandler_t,
) -> io::Result<libc::sighandler_t> {
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
        if libc::sigaction(signal, &raw const action, &raw mut previous) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(previous.sa_sigaction)
    }
}

#[expect(
    unsafe_code,
    reason = "rustix has no way to read a signal's disposition, so libc's sigaction is used"
)]
fn current_disposition(signal: libc::c_int) -> io::Result<libc::sighandler_t> {
    // SAFETY: a null new action only reads the current one, and `current` is a valid place
    // for it.
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null(), &raw mut current) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(current.sa_sigaction)
    }
}

#[expect(
    unsafe_code,
    reason = "raise delivers the signal to the calling thread before it returns"
)]
fn raise(signal: libc::c_int) {
    // SAFETY: `raise` takes a valid signal number and has no other precondition.
    unsafe {
        libc::raise(signal);
    }
}

fn handler_address() -> libc::sighandler_t {
    let handler: extern "C" fn(libc::c_int) = on_signal;
    handler as libc::sighandler_t
}

#[expect(
    unsafe_code,
    reason = "a signal handler writes to a self-pipe with a raw descriptor"
)]
extern "C" fn on_signal(signal: libc::c_int) {
    let Some(index) = WATCHED.iter().position(|&watched| watched == signal) else {
        return;
    };
    let Some(fd) = WRITE_ENDS
        .get(index)
        .map(|slot| slot.load(Ordering::SeqCst))
    else {
        return;
    };
    let Ok(byte) = u8::try_from(signal) else {
        return;
    };
    if fd < 0 || rustix::process::getpid().as_raw_nonzero().get() != OWNER.load(Ordering::SeqCst) {
        return;
    }
    // SAFETY: the errno location is the calling thread's own, and saving and restoring it
    // keeps the interrupted code's errno intact. `write` is async-signal-safe, the buffer is
    // valid for one byte, and the descriptor belongs to a pipe that lives for the whole
    // process. A full pipe already holds a pending signal, so a failed write loses nothing.
    unsafe {
        let errno = errno_location();
        let saved = *errno;
        libc::write(fd, [byte].as_ptr().cast(), 1);
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

    #[expect(
        unsafe_code,
        reason = "raise delivers the signal to this thread before it returns"
    )]
    fn raise(signal: libc::c_int) {
        // SAFETY: `raise` takes a valid signal number and has no other precondition.
        assert_eq!(unsafe { libc::raise(signal) }, 0);
    }

    fn readable(fd: &impl AsFd, seconds: i64) -> bool {
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        };
        rustix::event::poll(&mut fds, Some(&timeout)).unwrap() == 1
    }

    extern "C" fn foreign_handler(_: libc::c_int) {}

    #[test]
    fn listeners_wake_on_their_signals_and_give_the_actions_back() {
        for signal in WATCHED {
            set_disposition(signal, libc::SIG_DFL).unwrap();
        }
        let changes = WindowChanges::listen().unwrap();
        assert!(matches!(
            WindowChanges::listen(),
            Err(SignalError::AlreadyWatched)
        ));
        for _ in 0..3 {
            raise(libc::SIGWINCH);
        }
        assert!(readable(&changes, 5));
        changes.wait().unwrap();
        assert!(!readable(&changes, 0));

        let termination = TerminationSignals::listen().unwrap();
        let (input, typed) = rustix::pipe::pipe().unwrap();
        rustix::io::write(&typed, b"x").unwrap();
        assert_eq!(termination.wait_for_input(input.as_fd()).unwrap(), None);
        rustix::io::read(&input, &mut [0_u8; 1]).unwrap();
        raise(libc::SIGTERM);
        assert_eq!(
            termination.wait_for_input(input.as_fd()).unwrap(),
            Some(Termination::Terminate)
        );
        raise(libc::SIGTERM);
        raise(libc::SIGHUP);
        assert!(readable(&termination, 5));
        assert_eq!(termination.wait().unwrap(), Termination::Terminate);
        assert_eq!(termination.wait().unwrap(), Termination::Hangup);
        assert!(!readable(&changes, 0));
        assert_eq!(Termination::Interrupt.number(), libc::SIGINT);
        drop(termination);
        assert_eq!(
            set_disposition(libc::SIGTERM, libc::SIG_DFL).unwrap(),
            libc::SIG_DFL
        );

        set_disposition(libc::SIGWINCH, libc::SIG_IGN).unwrap();
        drop(changes);
        assert_eq!(
            set_disposition(libc::SIGWINCH, libc::SIG_DFL).unwrap(),
            libc::SIG_IGN
        );
        set_disposition(libc::SIGWINCH, libc::SIG_IGN).unwrap();
        let changes = WindowChanges::listen().unwrap();
        drop(changes);
        assert_eq!(
            set_disposition(libc::SIGWINCH, libc::SIG_DFL).unwrap(),
            libc::SIG_IGN
        );

        set_disposition(libc::SIGHUP, libc::SIG_IGN).unwrap();
        let termination = TerminationSignals::listen().unwrap();
        assert_eq!(current_disposition(libc::SIGHUP).unwrap(), libc::SIG_IGN);
        assert_eq!(
            current_disposition(libc::SIGTERM).unwrap(),
            handler_address()
        );
        reset_in_child().unwrap();
        assert_eq!(current_disposition(libc::SIGTERM).unwrap(), libc::SIG_DFL);
        assert_eq!(current_disposition(libc::SIGHUP).unwrap(), libc::SIG_IGN);
        drop(termination);
        set_disposition(libc::SIGHUP, libc::SIG_DFL).unwrap();

        let foreign: extern "C" fn(libc::c_int) = foreign_handler;
        set_disposition(libc::SIGINT, foreign as libc::sighandler_t).unwrap();
        assert!(matches!(
            TerminationSignals::listen(),
            Err(SignalError::ForeignHandler)
        ));
        for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            assert_eq!(current_disposition(signal).unwrap(), libc::SIG_DFL);
        }
        assert_eq!(
            current_disposition(libc::SIGINT).unwrap(),
            foreign as libc::sighandler_t
        );
        set_disposition(libc::SIGINT, libc::SIG_DFL).unwrap();
        let termination = TerminationSignals::listen().unwrap();
        drop(termination);
    }
}
