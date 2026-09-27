use std::{
    io,
    os::fd::{
        AsFd,
        BorrowedFd,
    },
};

use mahi_sandbox::WindowSize;
use rustix::termios::{
    OptionalActions,
    Termios,
};

const FALLBACK_SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };

/// Puts the user's terminal in raw mode, so keys reach the agent unchanged, and restores it when
/// dropped.
#[derive(Debug)]
pub(crate) struct RawMode {
    saved: Termios,
}

impl RawMode {
    pub(crate) fn enable() -> io::Result<Option<Self>> {
        let input = io::stdin();
        if !rustix::termios::isatty(input.as_fd()) {
            return Ok(None);
        }
        let saved = rustix::termios::tcgetattr(input.as_fd())?;
        let mut raw = saved.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(input.as_fd(), OptionalActions::Flush, &raw)?;
        Ok(Some(Self { saved }))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(io::stdin().as_fd(), OptionalActions::Now, &self.saved);
    }
}

pub(crate) fn size() -> WindowSize {
    size_of_terminal(io::stdin().as_fd())
        .or_else(|| size_of_terminal(io::stdout().as_fd()))
        .unwrap_or(FALLBACK_SIZE)
}

fn size_of_terminal(terminal: BorrowedFd<'_>) -> Option<WindowSize> {
    let size = rustix::termios::tcgetwinsize(terminal).ok()?;
    (size.ws_row > 0 && size.ws_col > 0).then_some(WindowSize {
        rows: size.ws_row,
        cols: size.ws_col,
    })
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use rustix::{
        fs::{
            Mode,
            OFlags,
        },
        pty::OpenptFlags,
        termios::Winsize,
    };

    use super::*;

    fn pty_pair(rows: u16, cols: u16) -> (OwnedFd, OwnedFd) {
        let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        rustix::pty::grantpt(&master).unwrap();
        rustix::pty::unlockpt(&master).unwrap();
        let name = rustix::pty::ptsname(&master, Vec::new()).unwrap();
        let slave = rustix::fs::open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY,
            Mode::empty(),
        )
        .unwrap();
        rustix::termios::tcsetwinsize(
            &slave,
            Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .unwrap();
        (master, slave)
    }

    #[test]
    fn the_size_of_a_terminal_is_read() {
        let (_master, slave) = pty_pair(40, 120);
        assert_eq!(
            size_of_terminal(slave.as_fd()),
            Some(WindowSize {
                rows: 40,
                cols: 120
            })
        );
    }

    #[test]
    fn a_terminal_without_a_size_gives_none() {
        let (_master, slave) = pty_pair(0, 0);
        assert_eq!(size_of_terminal(slave.as_fd()), None);
    }
}
