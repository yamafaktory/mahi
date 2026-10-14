use std::{
    ffi::OsStr,
    io::{
        self,
        Read,
        Write,
    },
    os::unix::ffi::OsStrExt,
    path::Path,
    sync::mpsc,
    thread,
};

use mahi_sandbox::{
    PtyChild,
    PtyCommand,
    PtyError,
    WindowSize,
    exit_code,
};
use mahi_term::AgentScreen;

use crate::environment::Environment;

const READ_CHUNK: usize = 16 * 1024;
const QUEUED_WRITES: usize = 64;
const TERMINAL_OWN: [&str; 6] = [
    "KITTY_WINDOW_ID",
    "TMUX",
    "VTE_VERSION",
    "TERM_PROGRAM",
    "LINES",
    "COLUMNS",
];
const CHILD_TERM: &str = "xterm-256color";

/// What the thread reading a child's terminal tells the workspace.
#[derive(Debug)]
pub(crate) enum ChildEvent {
    /// The child `0` wrote these bytes.
    Output(usize, Vec<u8>),
    /// The child `0`'s terminal has nothing more to read.
    Closed(usize),
}

/// A mahi command the workspace runs on a pseudo-terminal of its own, and the screen its output
/// draws, which the workspace shows in a pane.
#[derive(Debug)]
pub(crate) struct Child {
    pty: PtyChild,
    writes: mpsc::SyncSender<Vec<u8>>,
    screen: AgentScreen,
    replies: Vec<u8>,
    status: Option<i32>,
}

impl Child {
    /// Returns the command that runs mahi itself with `words` in `cwd`, on a terminal of
    /// `size`, with mahi's own environment but for what describes the user's own terminal,
    /// since the child's terminal is the workspace's screen, or nothing when mahi cannot tell
    /// where its program is.
    pub(crate) fn mahi(
        environment: &Environment,
        words: &[&OsStr],
        cwd: &Path,
        size: WindowSize,
    ) -> Option<PtyCommand> {
        let program = environment.mahi_exe.as_deref()?;
        let mut command = PtyCommand::new(program, cwd, size).hold_terminal();
        for word in words {
            command = command.arg(word);
        }
        for (name, value) in &environment.whole {
            if name != "TERM" && !TERMINAL_OWN.iter().any(|own| name == own) {
                command = command.env(name, OsStr::from_bytes(value));
            }
        }
        Some(command.env("TERM", CHILD_TERM))
    }

    /// Starts `command`, made for a terminal of `size`, as the workspace's child `id`, whose
    /// output a thread of its own sends to `events`, waiting while the workspace has not taken
    /// what it sent before; another thread writes to the child, so a child that stops reading
    /// never holds the workspace up.
    ///
    /// # Errors
    ///
    /// Returns a [`PtyError`] if the program cannot be started or its terminal cannot be read
    /// or written.
    pub(crate) fn start(
        command: PtyCommand,
        size: WindowSize,
        id: usize,
        events: &mpsc::SyncSender<ChildEvent>,
    ) -> Result<Self, PtyError> {
        let pty = command.spawn()?;
        let mut reader = pty.reader()?;
        let mut keys = pty.writer()?;
        let (writes, queued) = mpsc::sync_channel::<Vec<u8>>(QUEUED_WRITES);
        thread::spawn(move || {
            for bytes in queued {
                if keys.write_all(&bytes).is_err() {
                    return;
                }
            }
        });
        let events = events.clone();
        thread::spawn(move || {
            let mut chunk = [0_u8; READ_CHUNK];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let Some(bytes) = chunk.get(..read) else {
                            break;
                        };
                        if events.send(ChildEvent::Output(id, bytes.to_vec())).is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = events.send(ChildEvent::Closed(id));
        });
        Ok(Self {
            pty,
            writes,
            screen: AgentScreen::new(size.rows, size.cols),
            replies: Vec::new(),
            status: None,
        })
    }

    /// Draws what the child wrote into its screen, answers the queries the child made of its
    /// terminal, and adds to `passed` what the child asks of the user's terminal itself. The
    /// answers to a child that has stopped reading what it was sent are dropped.
    pub(crate) fn feed(&mut self, bytes: &[u8], passed: &mut Vec<u8>) {
        self.screen.feed(bytes);
        self.screen.take_passed(passed);
        self.screen.take_replies(&mut self.replies);
        if !self.replies.is_empty() {
            let _ = self.writes.try_send(std::mem::take(&mut self.replies));
        }
    }

    /// Sends what the user typed to the child.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::WouldBlock`] when the child has stopped reading what it was
    /// sent, or [`io::ErrorKind::BrokenPipe`] when its terminal can no longer be written.
    pub(crate) fn send(&mut self, keys: &[u8]) -> io::Result<()> {
        self.writes
            .try_send(keys.to_vec())
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                mpsc::TrySendError::Disconnected(_) => io::ErrorKind::BrokenPipe.into(),
            })
    }

    /// Gives the child's terminal and its screen `size`.
    ///
    /// # Errors
    ///
    /// Returns the error of resizing the child's terminal.
    pub(crate) fn resize(&mut self, size: WindowSize) -> Result<(), PtyError> {
        self.pty.resize(size)?;
        self.screen.set_size(size.rows, size.cols);
        Ok(())
    }

    /// Returns the child's screen.
    pub(crate) fn screen(&self) -> &vt100::Screen {
        self.screen.screen()
    }

    /// Returns the child's exit code once it has exited, letting its terminal close so the
    /// thread reading it ends.
    ///
    /// # Errors
    ///
    /// Returns the error of asking whether the child has exited.
    pub(crate) fn exited(&mut self) -> Result<Option<i32>, PtyError> {
        if self.status.is_none()
            && let Some(status) = self.pty.try_wait()?
        {
            self.status = Some(exit_code(status));
            if let Some(terminal) = self.pty.take_terminal() {
                thread::spawn(move || drop(terminal));
            }
        }
        Ok(self.status)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{
        Duration,
        Instant,
    };

    use super::*;

    const SIZE: WindowSize = WindowSize { rows: 6, cols: 40 };

    fn shell(script: &str) -> PtyCommand {
        PtyCommand::new(Path::new("/bin/sh"), Path::new("/"), SIZE)
            .hold_terminal()
            .env("PATH", "/usr/bin:/bin")
            .arg("-c")
            .arg(script)
    }

    fn run_until(
        child: &mut Child,
        events: &mpsc::Receiver<ChildEvent>,
        done: impl Fn(&Child) -> bool,
    ) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut passed = Vec::new();
        while !done(child) {
            assert!(Instant::now() < deadline, "{}", child.screen().contents());
            child.exited().unwrap();
            match events.recv_timeout(Duration::from_millis(50)) {
                Ok(ChildEvent::Output(0, bytes)) => child.feed(&bytes, &mut passed),
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    #[test]
    fn what_a_child_writes_is_drawn_on_its_screen_and_its_exit_code_kept() {
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        let mut child = Child::start(
            shell("printf 'hello from a child'; exit 3"),
            SIZE,
            0,
            &sender,
        )
        .unwrap();
        run_until(&mut child, &events, |child| {
            child.screen().contents().contains("hello from a child") && child.status.is_some()
        });
        assert_eq!(child.exited().unwrap(), Some(3));
    }

    #[test]
    fn keys_reach_the_child_and_a_resize_reaches_its_terminal() {
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        let mut child = Child::start(
            shell("read line; echo \"got $line\"; read again; stty size"),
            SIZE,
            0,
            &sender,
        )
        .unwrap();
        child.send(b"abc\r").unwrap();
        run_until(&mut child, &events, |child| {
            child.screen().contents().contains("got abc")
        });
        child.resize(WindowSize { rows: 7, cols: 33 }).unwrap();
        child.send(b"\r").unwrap();
        run_until(&mut child, &events, |child| {
            child.screen().contents().contains("7 33")
        });
        assert_eq!(child.screen().size(), (7, 33));
    }

    #[test]
    fn mahi_runs_itself_with_the_words_and_its_environment_but_not_its_terminals() {
        let variable =
            |name: &str, value: &[u8]| (name.into(), zeroize::Zeroizing::new(value.to_vec()));
        let environment = Environment {
            mahi_exe: Some("/bin/sh".into()),
            whole: vec![
                variable("PATH", b"/usr/bin:/bin"),
                variable("MAHI_SEEN", b"carried"),
                variable("TMUX", b"/tmp/tmux"),
                variable("TERM", b"xterm-kitty"),
            ],
            ..Environment::default()
        };
        let words = [
            OsStr::new("-c"),
            OsStr::new("echo \"$MAHI_SEEN $0 tmux=$TMUX term=$TERM\""),
            OsStr::new("word"),
        ];
        let command = Child::mahi(&environment, &words, Path::new("/"), SIZE).unwrap();
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        let mut child = Child::start(command, SIZE, 0, &sender).unwrap();
        run_until(&mut child, &events, |child| {
            child
                .screen()
                .contents()
                .contains("carried word tmux= term=xterm-256color")
        });
        assert!(Child::mahi(&Environment::default(), &words, Path::new("/"), SIZE).is_none());
    }

    #[test]
    fn a_child_that_ends_closes_its_terminal_and_passes_on_its_title() {
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        let mut child =
            Child::start(shell("printf '\\033]2;a title\\007done'"), SIZE, 0, &sender).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut passed = Vec::new();
        loop {
            assert!(Instant::now() < deadline, "{}", child.screen().contents());
            child.exited().unwrap();
            match events.recv_timeout(Duration::from_millis(50)) {
                Ok(ChildEvent::Output(_, bytes)) => child.feed(&bytes, &mut passed),
                Ok(ChildEvent::Closed(0)) => break,
                Ok(ChildEvent::Closed(_)) | Err(_) => {}
            }
        }
        assert!(child.screen().contents().contains("done"));
        assert_eq!(child.exited().unwrap(), Some(0));
        assert!(
            String::from_utf8_lossy(&passed).contains("a title"),
            "{passed:?}"
        );
    }

    #[test]
    fn a_child_that_stops_reading_never_holds_the_workspace_up() {
        let (sender, _events) = mpsc::sync_channel(QUEUED_WRITES);
        let mut child = Child::start(shell("sleep 5"), SIZE, 0, &sender).unwrap();
        let started = Instant::now();
        let typed = [b'x'; 4096];
        let refused = (0..1000).find_map(|_| child.send(&typed).err());
        assert_eq!(
            refused.map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        let mut passed = Vec::new();
        for _ in 0..1000 {
            child.feed(b"\x1b[6n", &mut passed);
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_childs_terminal_queries_are_answered() {
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        let mut child = Child::start(
            shell(
                "stty -echo -icanon min 0 time 20; printf '\\033[6n'; \
                 answer=$(dd bs=1 count=6 2>/dev/null | od -An -c | tr -d ' \\n'); \
                 echo \"answer=$answer\"",
            ),
            SIZE,
            0,
            &sender,
        )
        .unwrap();
        run_until(&mut child, &events, |child| {
            child.screen().contents().contains("answer=")
        });
        assert!(
            child.screen().contents().contains("answer=033[1;1R"),
            "{}",
            child.screen().contents()
        );
    }
}
