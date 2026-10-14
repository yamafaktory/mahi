use std::{
    fs::File,
    io,
    os::fd::{
        FromRawFd,
        OwnedFd,
        RawFd,
    },
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

use rustix::{
    fs::FileType,
    io::FdFlags,
};

static TAKEN: AtomicBool = AtomicBool::new(false);

/// Takes the read end of a pipe that the process which started this one left open at `fd`,
/// as [`crate::PtyCommand::pass_fd`] does, and marks it to close on exec, so no program this
/// one starts inherits it. It can be taken once in a process, and must be taken at startup,
/// before this process opens anything that could get the same number.
///
/// # Errors
///
/// Returns an error if `fd` is a standard stream's, if a descriptor was taken before, or if
/// `fd` is not open or not a pipe; then it is left as it is.
pub fn inherited_pipe(fd: RawFd) -> io::Result<File> {
    if fd <= 2 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if TAKEN.swap(true, Ordering::SeqCst) {
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
    // `TAKEN` lets it be taken once, so no other owner of it exists.
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
    fn a_pipe_is_taken_once_and_a_standard_stream_never() {
        assert_eq!(
            inherited_pipe(1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let file = tempfile::tempfile().unwrap().into_raw_fd();
        assert!(inherited_pipe(file).is_err());
        TAKEN.store(false, Ordering::SeqCst);
        let (closed, _writer) = rustix::pipe::pipe().unwrap();
        let number = closed.as_raw_fd();
        drop(closed);
        assert!(inherited_pipe(number).is_err());
        TAKEN.store(false, Ordering::SeqCst);
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
        let (again, _writer) = rustix::pipe::pipe().unwrap();
        assert_eq!(
            inherited_pipe(again.into_raw_fd()).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }
}
