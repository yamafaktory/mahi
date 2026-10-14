use std::{
    fs::File,
    io,
    os::fd::{
        FromRawFd,
        OwnedFd,
        RawFd,
    },
    sync::{
        Mutex,
        PoisonError,
    },
};

use rustix::{
    fs::FileType,
    io::FdFlags,
};

static TAKEN: Mutex<[RawFd; crate::MAX_PASSED]> = Mutex::new([-1; crate::MAX_PASSED]);

/// Takes an end of a pipe that the process which started this one left open at `fd`, as
/// [`crate::PtyCommand::pass_fd`] does, and marks it to close on exec, so no program this one
/// starts inherits it. Each number can be taken once in a process, and at most
/// [`crate::MAX_PASSED`] of them, all at startup, before this process opens anything that
/// could get the same number.
///
/// # Errors
///
/// Returns an error if `fd` is a standard stream's, if it was taken before or the most were,
/// or if it is not open or not a pipe; then the descriptor is left as it is, but a number
/// refused for not being open or a pipe still counts among those taken.
pub fn inherited_pipe(fd: RawFd) -> io::Result<File> {
    if fd <= 2 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if !take_number(fd) {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let pipe = is_pipe(fd)?;
    if !pipe {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let owned = own(fd);
    rustix::io::fcntl_setfd(&owned, FdFlags::CLOEXEC)?;
    Ok(File::from(owned))
}

fn take_number(fd: RawFd) -> bool {
    let mut taken = TAKEN.lock().unwrap_or_else(PoisonError::into_inner);
    if taken.contains(&fd) {
        return false;
    }
    let Some(free) = taken.iter_mut().find(|number| **number == -1) else {
        return false;
    };
    *free = fd;
    true
}

#[expect(
    unsafe_code,
    reason = "a descriptor known only by its number must be borrowed to be inspected"
)]
fn is_pipe(fd: RawFd) -> io::Result<bool> {
    // SAFETY: `fd` came from the process that started this one and may not be open, which
    // breaks the rule that a borrowed descriptor is open; the borrow lasts only for this one
    // `fstat`, which on a number that is not open fails with EBADF and touches nothing, and no
    // other code in this process uses the number yet.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let stat = rustix::fs::fstat(borrowed)?;
    Ok(FileType::from_raw_mode(stat.st_mode) == FileType::Fifo)
}

#[expect(
    unsafe_code,
    reason = "taking ownership of a descriptor inherited by number needs from_raw_fd"
)]
fn own(fd: RawFd) -> OwnedFd {
    // SAFETY: `fd` is open, a pipe, and above the standard streams; the caller takes it at
    // startup, before this process opens anything of its own that could share the number, and
    // `TAKEN` lets each number be taken once, so no other owner of it exists.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{
            Read,
            Write,
        },
        os::fd::{
            AsRawFd,
            IntoRawFd,
        },
    };

    use super::*;

    #[test]
    fn each_pipe_is_taken_once_two_at_most_and_a_standard_stream_never() {
        assert_eq!(
            inherited_pipe(1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let file = tempfile::tempfile().unwrap().into_raw_fd();
        assert!(inherited_pipe(file).is_err());
        *TAKEN.lock().unwrap() = [-1; crate::MAX_PASSED];
        let (closed, _writer) = rustix::pipe::pipe().unwrap();
        let number = closed.as_raw_fd();
        drop(closed);
        assert!(inherited_pipe(number).is_err());
        *TAKEN.lock().unwrap() = [-1; crate::MAX_PASSED];
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut writer = File::from(writer);
        writer.write_all(b"secret").unwrap();
        drop(writer);
        let fd = reader.into_raw_fd();
        let mut taken = inherited_pipe(fd).unwrap();
        let mut read = String::new();
        taken.read_to_string(&mut read).unwrap();
        assert_eq!(read, "secret");
        assert!(
            rustix::io::fcntl_getfd(&taken)
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
        assert_eq!(
            inherited_pipe(taken.as_raw_fd()).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let (second, _writer) = rustix::pipe::pipe().unwrap();
        let _second = inherited_pipe(second.into_raw_fd()).unwrap();
        let (third, _writer) = rustix::pipe::pipe().unwrap();
        assert_eq!(
            inherited_pipe(third.into_raw_fd()).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }
}
