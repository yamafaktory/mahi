use std::{
    io,
    os::fd::{
        AsFd,
        BorrowedFd,
    },
    process,
    time::{
        Duration,
        Instant,
    },
};

use mahi_live::{
    MIN_COLUMNS,
    MIN_ROWS,
};
use mahi_sandbox::{
    InputWait,
    Termination,
    TerminationSignals,
    WindowSize,
};
use mahi_term::{
    BACKGROUND_QUERY,
    Background,
    BackgroundReply,
};
use rustix::termios::{
    LocalModes,
    OptionalActions,
    Termios,
};

const FALLBACK_SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };
const LONGEST_REPLY: usize = 1024;

/// How long mahi waits for the terminal to say what its background is.
pub(crate) const BACKGROUND_WAIT: Duration = Duration::from_secs(1);

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

/// Returns whether the user types into a terminal and sees the agent's output in one, which
/// the palette needs.
pub(crate) fn is_interactive() -> bool {
    rustix::termios::isatty(io::stdin().as_fd()) && rustix::termios::isatty(io::stdout().as_fd())
}

/// Returns whether mahi runs in the foreground of the `terminal` it controls, so it may change
/// the terminal's modes without being stopped.
pub(crate) fn is_foreground(terminal: BorrowedFd<'_>) -> bool {
    rustix::termios::tcgetpgrp(terminal).is_ok_and(|group| group == rustix::process::getpgrp())
}

pub(crate) fn size() -> WindowSize {
    size_of_terminal(io::stdin().as_fd())
        .or_else(|| size_of_terminal(io::stdout().as_fd()))
        .unwrap_or(FALLBACK_SIZE)
}

fn size_of_terminal(terminal: BorrowedFd<'_>) -> Option<WindowSize> {
    let size = rustix::termios::tcgetwinsize(terminal).ok()?;
    (size.ws_row > 0 && size.ws_col > 0).then_some(WindowSize {
        rows: size.ws_row.max(MIN_ROWS),
        cols: size.ws_col.max(MIN_COLUMNS),
    })
}

/// Asks the terminal behind `input` and `output` whether its background is light or dark,
/// waiting at most `wait` for the reply; a terminal that does not tell reads as dark. A stop
/// signal while it waits puts the terminal back and ends mahi with that signal.
pub(crate) fn background(
    input: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    wait: Duration,
) -> Background {
    let Ok(signals) = TerminationSignals::listen() else {
        return Background::Dark;
    };
    let Ok(saved) = rustix::termios::tcgetattr(input) else {
        return Background::Dark;
    };
    let mut raw = saved.clone();
    raw.make_raw();
    raw.local_modes.insert(LocalModes::ISIG);
    if rustix::termios::tcsetattr(input, OptionalActions::Now, &raw).is_err() {
        return Background::Dark;
    }
    let asked = read_background(input, output, wait, &signals);
    let _ = rustix::termios::tcsetattr(input, OptionalActions::Now, &saved);
    match asked {
        Ok(background) => background,
        Err(signal) => {
            drop(signals);
            signal.reraise();
            process::exit(128 + signal.number());
        }
    }
}

fn read_background(
    input: BorrowedFd<'_>,
    output: BorrowedFd<'_>,
    wait: Duration,
    signals: &TerminationSignals,
) -> Result<Background, Termination> {
    let mut written = 0;
    while let Some(rest) = BACKGROUND_QUERY
        .get(written..)
        .filter(|rest| !rest.is_empty())
    {
        let Some(count) = rustix::io::write(output, rest)
            .ok()
            .filter(|&count| count > 0)
        else {
            return Ok(Background::Dark);
        };
        written += count;
    }
    let deadline = Instant::now() + wait;
    let mut reply = Vec::with_capacity(LONGEST_REPLY);
    let mut chunk = [0; 256];
    while reply.len() < LONGEST_REPLY {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(Background::Dark);
        };
        match signals.wait_for_input_within(input, left) {
            Ok(InputWait::Input) => {}
            Ok(InputWait::Signal(signal)) => return Err(signal),
            Ok(InputWait::Timeout) | Err(_) => return Ok(Background::Dark),
        }
        let Some(read) = rustix::io::read(input, &mut chunk)
            .ok()
            .and_then(|read| chunk.get(..read))
            .filter(|read| !read.is_empty())
        else {
            return Ok(Background::Dark);
        };
        reply.extend_from_slice(read);
        match Background::from_reply(&reply) {
            BackgroundReply::Told(background) => return Ok(background),
            BackgroundReply::NotTold => return Ok(Background::Dark),
            BackgroundReply::Incomplete => {}
        }
    }
    Ok(Background::Dark)
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

    fn answered(reply: &'static [u8], wait: Duration) -> (Background, Vec<u8>) {
        let (master, slave) = pty_pair(24, 80);
        let terminal = std::thread::spawn(move || {
            let mut asked = Vec::new();
            let mut chunk = [0; 64];
            while asked.len() < BACKGROUND_QUERY.len() {
                let read = rustix::io::read(&master, &mut chunk).unwrap();
                asked.extend_from_slice(&chunk[..read]);
            }
            rustix::io::write(&master, reply).unwrap();
            (asked, master)
        });
        let background = background(slave.as_fd(), slave.as_fd(), wait);
        let (asked, _master) = terminal.join().unwrap();
        (background, asked)
    }

    #[test]
    fn a_terminal_that_tells_a_light_background_picks_the_light_palette() {
        let started = Instant::now();
        let (background, asked) = answered(
            b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\\x1b[?62;22c",
            Duration::from_secs(10),
        );
        assert_eq!(background, Background::Light);
        assert_eq!(asked, BACKGROUND_QUERY);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn the_second_answer_of_a_reply_written_in_two_parts_is_read_too() {
        let (master, slave) = pty_pair(24, 80);
        let terminal = std::thread::spawn(move || {
            let mut asked = Vec::new();
            let mut chunk = [0; 64];
            while asked.len() < BACKGROUND_QUERY.len() {
                let read = rustix::io::read(&master, &mut chunk).unwrap();
                asked.extend_from_slice(&chunk[..read]);
            }
            rustix::io::write(&master, b"\x1b]11;rgb:ffff/ffff/ffff\x07").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            rustix::io::write(&master, b"\x1b[?62;22c").unwrap();
            master
        });
        let background = background(slave.as_fd(), slave.as_fd(), Duration::from_secs(10));
        let _master = terminal.join().unwrap();
        assert_eq!(background, Background::Light);
        let mut raw = rustix::termios::tcgetattr(&slave).unwrap();
        raw.make_raw();
        rustix::termios::tcsetattr(&slave, OptionalActions::Now, &raw).unwrap();
        rustix::fs::fcntl_setfl(&slave, OFlags::NONBLOCK).unwrap();
        let mut left = [0; 16];
        assert_eq!(
            rustix::io::read(&slave, &mut left),
            Err(rustix::io::Errno::AGAIN)
        );
    }

    #[test]
    fn a_terminal_mahi_does_not_control_is_not_its_foreground() {
        let (_master, slave) = pty_pair(24, 80);
        assert!(!is_foreground(slave.as_fd()));
    }

    #[test]
    fn a_terminal_that_answers_only_the_device_query_reads_dark_at_once() {
        let started = Instant::now();
        let (background, _) = answered(b"\x1b[?62;22c", Duration::from_secs(10));
        assert_eq!(background, Background::Dark);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_terminal_that_answers_nothing_reads_dark_once_the_wait_ends() {
        let started = Instant::now();
        let (background, _) = answered(b"", Duration::from_millis(200));
        assert_eq!(background, Background::Dark);
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn the_query_leaves_the_terminals_modes_as_they_were() {
        let (_master, slave) = pty_pair(24, 80);
        let before = rustix::termios::tcgetattr(&slave).unwrap();
        let _ = background(slave.as_fd(), slave.as_fd(), Duration::from_millis(50));
        let after = rustix::termios::tcgetattr(&slave).unwrap();
        assert_eq!(after.local_modes, before.local_modes);
        assert_eq!(after.input_modes, before.input_modes);
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
    fn a_terminal_one_row_high_or_one_column_wide_is_read_as_two() {
        let (_master, slave) = pty_pair(40, 1);
        assert_eq!(
            size_of_terminal(slave.as_fd()),
            Some(WindowSize { rows: 40, cols: 2 })
        );
        let (_master, slave) = pty_pair(1, 80);
        assert_eq!(
            size_of_terminal(slave.as_fd()),
            Some(WindowSize { rows: 2, cols: 80 })
        );
    }

    #[test]
    fn a_terminal_without_a_size_gives_none() {
        let (_master, slave) = pty_pair(0, 0);
        assert_eq!(size_of_terminal(slave.as_fd()), None);
    }
}
