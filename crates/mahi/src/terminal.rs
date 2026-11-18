use std::{
    io,
    os::fd::{
        AsFd,
        BorrowedFd,
    },
    process,
    sync::Mutex,
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
    ReplySplit,
};
use rustix::termios::{
    LocalModes,
    OptionalActions,
    QueueSelector,
    Termios,
};

const FALLBACK_SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };
const LATE_WAIT: Duration = Duration::from_secs(10);

static AHEAD: Mutex<Ahead> = Mutex::new(Ahead {
    keys: Vec::new(),
    late: None,
});

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
        Ok(Some(Self {
            saved: make_raw(input.as_fd())?,
        }))
    }
}

/// Puts `input` in raw mode, keeping the keys typed before, and returns the modes it had.
fn make_raw(input: BorrowedFd<'_>) -> io::Result<Termios> {
    let saved = rustix::termios::tcgetattr(input)?;
    let mut raw = saved.clone();
    raw.make_raw();
    rustix::termios::tcsetattr(input, OptionalActions::Now, &raw)?;
    Ok(saved)
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
    let mut split = ReplySplit::default();
    let mut keys = Vec::new();
    let asked = read_background((input, output), wait, &signals, (&mut split, &mut keys));
    let _ = rustix::termios::tcsetattr(input, OptionalActions::Now, &saved);
    keep_ahead(split, keys);
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
    (input, output): (BorrowedFd<'_>, BorrowedFd<'_>),
    wait: Duration,
    signals: &TerminationSignals,
    (split, keys): (&mut ReplySplit, &mut Vec<u8>),
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
            split.give_up(keys);
            return Ok(Background::Dark);
        };
        written += count;
    }
    let deadline = Instant::now() + wait;
    let mut chunk = [0; 256];
    loop {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(Background::Dark);
        };
        match signals.wait_for_input_within(input, left) {
            Ok(InputWait::Input) => {}
            Ok(InputWait::Signal(signal)) => return Err(signal),
            Ok(InputWait::Timeout) => return Ok(Background::Dark),
            Err(_) => {
                split.give_up(keys);
                return Ok(Background::Dark);
            }
        }
        let Some(read) = rustix::io::read(input, &mut chunk)
            .ok()
            .and_then(|read| chunk.get(..read))
            .filter(|read| !read.is_empty())
        else {
            split.give_up(keys);
            return Ok(Background::Dark);
        };
        match split.read(read, keys) {
            BackgroundReply::Told(background) => return Ok(background),
            BackgroundReply::NotTold => return Ok(Background::Dark),
            BackgroundReply::Incomplete => {}
        }
    }
}

/// The keys typed while mahi asked the terminal for its background, which the first read of
/// the keys takes, and the reply that had not ended when the wait did, which later reads drop
/// until it ends or [`LATE_WAIT`] passes.
#[derive(Debug)]
struct Ahead {
    keys: Vec<u8>,
    late: Option<(ReplySplit, Instant)>,
}

impl Ahead {
    fn expire(&mut self, now: Instant) {
        if let Some((mut split, _)) = self.late.take_if(|(_, until)| now >= *until) {
            split.give_up(&mut self.keys);
        }
    }

    fn give(&mut self, buffer: &mut [u8]) -> usize {
        let count = self.keys.len().min(buffer.len());
        if let (Some(into), Some(from)) = (buffer.get_mut(..count), self.keys.get(..count)) {
            into.copy_from_slice(from);
        }
        self.keys.drain(..count);
        count
    }

    fn drop_reply(&mut self, buffer: &mut [u8], read: usize) -> KeysRead {
        let Some((split, _)) = &mut self.late else {
            return KeysRead::Keys(read);
        };
        split.read(buffer.get(..read).unwrap_or_default(), &mut self.keys);
        if split.is_ended() {
            self.late = None;
        }
        match self.give(buffer) {
            0 => KeysRead::OnlyReply,
            given => KeysRead::Keys(given),
        }
    }
}

fn keep_ahead(mut split: ReplySplit, mut keys: Vec<u8>) {
    let Ok(mut ahead) = AHEAD.lock() else {
        return;
    };
    if !split.is_ended() {
        split.wait_ended(&mut keys);
        ahead.late = Some((split, Instant::now() + LATE_WAIT));
    }
    ahead.keys = keys;
}

/// What a read of the user's keys gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeysRead {
    /// This many bytes of keys.
    Keys(usize),
    /// Only the terminal's late reply to the background query, which was dropped.
    OnlyReply,
    /// The input ended.
    Ended,
}

/// Returns whether keys typed while mahi asked the terminal for its background wait for
/// [`read_keys`], so a reader must not wait for `input` first.
pub(crate) fn holds_keys() -> bool {
    AHEAD.lock().is_ok_and(|mut ahead| {
        ahead.expire(Instant::now());
        !ahead.keys.is_empty()
    })
}

/// Reads the user's keys from `input` into `buffer`: first the keys typed while mahi asked the
/// terminal for its background, then what `input` gives, without the terminal's late reply to
/// that query.
pub(crate) fn read_keys(input: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<KeysRead> {
    {
        let mut ahead = AHEAD
            .lock()
            .map_err(|_| io::Error::other("the typed keys are lost"))?;
        ahead.expire(Instant::now());
        let given = ahead.give(buffer);
        if given > 0 {
            return Ok(KeysRead::Keys(given));
        }
    }
    let read = loop {
        match rustix::io::read(input, &mut *buffer) {
            Err(rustix::io::Errno::INTR) => {}
            read => break read?,
        }
    };
    if read == 0 {
        return Ok(KeysRead::Ended);
    }
    let mut ahead = AHEAD
        .lock()
        .map_err(|_| io::Error::other("the typed keys are lost"))?;
    Ok(ahead.drop_reply(buffer, read))
}

/// Reads more of the user's keys from `input` into `buffer`, as [`read_keys`] does: returns how
/// many it read, or `None` once the input ended.
pub(crate) fn read_more(input: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<Option<usize>> {
    Ok(match read_keys(input, buffer)? {
        KeysRead::Keys(read) => Some(read),
        KeysRead::OnlyReply => Some(0),
        KeysRead::Ended => None,
    })
}

/// What waiting for the user's keys gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeysWait {
    /// Keys can be read.
    Ready,
    /// The reader must stop.
    Quit,
    /// Nothing yet.
    Nothing,
}

/// Waits until the user's keys can be read from `input`, at once when [`read_keys`] holds some,
/// or until `quitting` becomes readable.
pub(crate) fn wait_for_keys(input: BorrowedFd<'_>, quitting: BorrowedFd<'_>) -> KeysWait {
    if holds_keys() {
        return KeysWait::Ready;
    }
    match mahi_sandbox::wait_readable(input, quitting) {
        Ok((_, true)) => KeysWait::Quit,
        Ok((false, false)) => KeysWait::Nothing,
        Ok((true, false)) | Err(_) => KeysWait::Ready,
    }
}

/// Throws away the keys typed so far on `input`, those [`read_keys`] holds too.
pub(crate) fn drop_keys(input: BorrowedFd<'_>) {
    let _ = rustix::termios::tcflush(input, QueueSelector::IFlush);
    if let Ok(mut ahead) = AHEAD.lock() {
        ahead.keys.clear();
    }
}

/// Returns whether a terminal of type `term` may answer queries: a `dumb` one, such as an
/// Emacs shell, answers none.
pub(crate) fn answers_queries(term: Option<&str>) -> bool {
    term != Some("dumb")
}

#[cfg(test)]
pub(crate) mod tests {
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

    pub(crate) fn pty_pair(rows: u16, cols: u16) -> (OwnedFd, OwnedFd) {
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

    fn keys_read(slave: &OwnedFd) -> Vec<u8> {
        let mut buffer = [0; 64];
        loop {
            match read_keys(slave.as_fd(), &mut buffer).unwrap() {
                KeysRead::Keys(read) => return buffer[..read].to_vec(),
                KeysRead::OnlyReply => {}
                KeysRead::Ended => return Vec::new(),
            }
        }
    }

    #[test]
    fn keys_typed_while_the_terminal_answers_reach_the_first_read() {
        let (background, _) = answered(
            b"r\x1b]11;rgb:ffff/ffff/ffff\x07q\x1b[?62;22c",
            Duration::from_secs(10),
        );
        assert_eq!(background, Background::Light);
        assert!(holds_keys());
        let (_master, slave) = pty_pair(24, 80);
        assert_eq!(keys_read(&slave), b"rq");
        assert!(!holds_keys());
    }

    #[test]
    fn a_reply_that_comes_after_the_wait_is_dropped_and_the_keys_after_it_read() {
        let (master, slave) = pty_pair(24, 80);
        let background = background(slave.as_fd(), slave.as_fd(), Duration::from_millis(100));
        assert_eq!(background, Background::Dark);
        make_raw(slave.as_fd()).unwrap();
        rustix::io::write(&master, b"y\x1b]11;rgb:ffff/ffff/ffff\x1b\\\x1b[?62;22cx").unwrap();
        assert_eq!(keys_read(&slave), b"yx");
        rustix::io::write(&master, b"\x1b[?62;22c").unwrap();
        assert_eq!(keys_read(&slave), b"\x1b[?62;22c");
    }

    #[test]
    fn dropping_the_keys_drops_those_typed_while_the_terminal_answered() {
        let _ = answered(b"r\x1b[?62;22c", Duration::from_secs(10));
        let (_master, slave) = pty_pair(24, 80);
        drop_keys(slave.as_fd());
        assert!(!holds_keys());
    }

    #[test]
    fn raw_mode_keeps_the_keys_typed_before_it() {
        let (master, slave) = pty_pair(24, 80);
        rustix::io::write(&master, b"k").unwrap();
        std::thread::sleep(Duration::from_millis(50));
        make_raw(slave.as_fd()).unwrap();
        rustix::fs::fcntl_setfl(&slave, OFlags::NONBLOCK).unwrap();
        let mut typed = [0; 8];
        assert_eq!(rustix::io::read(&slave, &mut typed), Ok(1));
        assert_eq!(&typed[..1], b"k");
    }

    #[test]
    fn a_late_reply_that_does_not_end_gives_its_bytes_back_once_its_wait_passes() {
        let mut split = ReplySplit::default();
        let mut keys = Vec::new();
        split.read(b"\x1b]11;rgb", &mut keys);
        let until = Instant::now() + LATE_WAIT;
        let mut ahead = Ahead {
            keys,
            late: Some((split, until)),
        };
        ahead.expire(until.checked_sub(Duration::from_millis(1)).unwrap());
        assert!(ahead.keys.is_empty());
        assert!(ahead.late.is_some());
        ahead.expire(until);
        assert_eq!(ahead.keys, b"\x1b]11;rgb");
        assert!(ahead.late.is_none());
    }

    #[test]
    fn a_terminal_that_closes_before_it_answers_leaves_no_late_reply_to_drop() {
        let (master, slave) = pty_pair(24, 80);
        let terminal = std::thread::spawn(move || {
            let mut asked = Vec::new();
            let mut chunk = [0; 64];
            while asked.len() < BACKGROUND_QUERY.len() {
                let read = rustix::io::read(&master, &mut chunk).unwrap();
                asked.extend_from_slice(&chunk[..read]);
            }
        });
        let background = background(slave.as_fd(), slave.as_fd(), Duration::from_secs(10));
        terminal.join().unwrap();
        assert_eq!(background, Background::Dark);
        assert!(AHEAD.lock().unwrap().late.is_none());
    }

    #[test]
    fn only_a_dumb_terminal_is_not_asked() {
        assert!(!answers_queries(Some("dumb")));
        for term in [None, Some("xterm-256color"), Some("dumber")] {
            assert!(answers_queries(term), "{term:?}");
        }
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
        let modes = |termios: &Termios| termios.local_modes - LocalModes::PENDIN;
        assert_eq!(modes(&after), modes(&before));
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
