use std::{
    ffi::OsStr,
    io::{
        self,
        Read,
        Write,
    },
    os::{
        fd::{
            AsRawFd,
            OwnedFd,
        },
        unix::ffi::OsStrExt,
    },
    path::Path,
    sync::mpsc,
    thread,
    time::{
        Duration,
        Instant,
    },
};

use age::secrecy::ExposeSecret;
use mahi_identity::LocalIdentity;
use mahi_sandbox::{
    PtyChild,
    PtyCommand,
    PtyError,
    WindowSize,
    exit_code,
};
use mahi_term::{
    AgentScreen,
    AgentState,
    KeyScanner,
    ListPlace,
    PaletteKey,
    Segment,
    TabBar,
    ThreadView,
    WorkspaceAgent,
    WorkspaceTab,
};
use ratatui_core::{
    buffer::Buffer,
    layout::{
        Position,
        Rect,
    },
};

use crate::environment::{
    Environment,
    KEY_FD,
};

const READ_CHUNK: usize = 16 * 1024;
const STOP_POLL: Duration = Duration::from_millis(20);
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
const FAILED_HINTS: [(&str, &str); 2] = [("any key", "close it"), ("palette key 0", "threads")];
const HINTS: [(&str, &str); 6] = [
    ("palette key", "then:"),
    ("←→", "tab"),
    ("0-9", "tab"),
    ("↑↓", "agent"),
    ("b", "list"),
    ("palette key", "again: to the agent"),
];

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
    hidden: Vec<u8>,
    status: Option<i32>,
}

impl Child {
    /// Returns the command that runs mahi itself with `words` in `cwd`, on a terminal of
    /// `size`, with mahi's own environment but for what describes the user's own terminal,
    /// since the child's terminal is the workspace's screen, and with the user's unlocked mahi
    /// `key`, if any, on a pipe only the child inherits; or nothing when mahi cannot tell where
    /// its program is.
    ///
    /// # Errors
    ///
    /// Returns the error of making the pipe the key goes through.
    pub(crate) fn mahi(
        environment: &Environment,
        words: &[&OsStr],
        (cwd, size): (&Path, WindowSize),
        key: Option<&LocalIdentity>,
    ) -> io::Result<Option<PtyCommand>> {
        let Some(program) = environment.mahi_exe.as_deref() else {
            return Ok(None);
        };
        let mut command = PtyCommand::new(program, cwd, size).hold_terminal();
        for word in words {
            command = command.arg(word);
        }
        for (name, value) in &environment.whole {
            if name != "TERM" && name != KEY_FD && !TERMINAL_OWN.iter().any(|own| name == own) {
                command = command.env(name, OsStr::from_bytes(value));
            }
        }
        if let Some(key) = key {
            let pipe = key_pipe(key)?;
            command = command
                .env(KEY_FD, pipe.as_raw_fd().to_string())
                .pass_fd(pipe);
        }
        Ok(Some(command.env("TERM", CHILD_TERM)))
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
            hidden: Vec::new(),
            status: None,
        })
    }

    /// Draws what the child wrote into its screen, answers the queries the child made of its
    /// terminal, and adds to `passed`, when the child is shown, what it asks of the user's
    /// terminal itself; a hidden child's asks are dropped, its key modes left unapplied. The
    /// answers to a child that has stopped reading what it was sent are dropped.
    pub(crate) fn feed(&mut self, bytes: &[u8], passed: Option<&mut Vec<u8>>) {
        self.screen.feed(bytes);
        if let Some(passed) = passed {
            self.screen.take_passed(passed);
        } else {
            self.screen.undo(&mut self.hidden);
            self.hidden.clear();
        }
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

    /// Asks the child to end, as a stop signal does.
    pub(crate) fn stop(&mut self) {
        let _ = self.pty.terminate();
    }

    /// Writes into `out` what applies the child's key modes to the user's terminal, once it
    /// is shown.
    pub(crate) fn show(&mut self, out: &mut Vec<u8>) {
        self.screen.take_passed(out);
    }

    /// Writes into `out` what takes the child's key modes off the user's terminal, once it is
    /// no longer shown.
    pub(crate) fn hide(&mut self, out: &mut Vec<u8>) {
        self.screen.undo(out);
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

/// What the workspace shows: the thread list, tab 0, and a tab for each thread whose agents
/// run as its children, with the keys that move between them.
#[derive(Debug)]
pub(crate) struct Workspace {
    tabs: Vec<Tab>,
    selected: usize,
    events: mpsc::Receiver<ChildEvent>,
    sender: mpsc::SyncSender<ChildEvent>,
    next_id: usize,
    scanner: KeyScanner,
    armed: bool,
    list_shown: bool,
    size: WindowSize,
    passed: Vec<u8>,
    applied: Option<usize>,
    pending: Vec<u8>,
}

/// A thread's tab: the agents the workspace runs for it.
#[derive(Debug)]
struct Tab {
    title: String,
    agents: Vec<Running>,
    selected: usize,
}

/// An agent the workspace runs, as the mahi command that runs it.
#[derive(Debug)]
struct Running {
    id: usize,
    name: String,
    shown: String,
    child: Child,
    closed: bool,
    ending: Ending,
}

/// How far an agent whose command ended is from leaving its tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Running,
    Drawn,
    Failed,
    Closed,
}

/// What a workspace key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Moved {
    /// Nothing the screen shows changed.
    Nothing,
    /// Another tab or agent is shown, or the list was hidden or shown.
    Shown,
}

impl Workspace {
    /// Starts a workspace with no thread open, whose keys follow `palette_key`.
    pub(crate) fn new(palette_key: PaletteKey) -> Self {
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        Self {
            tabs: Vec::new(),
            selected: 0,
            events,
            sender,
            next_id: 0,
            scanner: KeyScanner::new(palette_key),
            armed: false,
            list_shown: true,
            size: WindowSize { rows: 2, cols: 2 },
            passed: Vec::new(),
            applied: None,
            pending: Vec::new(),
        }
    }

    /// Returns whether a thread's tab is open.
    pub(crate) fn has_tabs(&self) -> bool {
        !self.tabs.is_empty()
    }

    /// Returns whether an agent runs in a thread's tab, one whose command has not ended.
    pub(crate) fn is_running(&self) -> bool {
        self.tabs
            .iter()
            .flat_map(|tab| tab.agents.iter())
            .any(|running| running.ending == Ending::Running)
    }

    /// Returns whether the thread list is shown.
    pub(crate) fn shows_threads(&self) -> bool {
        self.selected == 0
    }

    /// Starts the mahi command `words`, shown to the user as `shown`, as the agent `name` in the
    /// tab of the thread `title`, which opens if it is not open yet, or in a tab of its own
    /// when the thread is `new`, and shows it; the child gets the user's unlocked mahi `key`, if
    /// any.
    ///
    /// # Errors
    ///
    /// Returns what to tell the user when the command cannot be started.
    pub(crate) fn open(
        &mut self,
        environment: &Environment,
        (title, name, shown): (&str, &str, &str),
        (words, new): (&[String], bool),
        key: Option<&LocalIdentity>,
    ) -> Result<(), String> {
        let failed = |error: &dyn std::fmt::Display| format!("{shown} cannot start: {error}");
        let cwd = std::env::current_dir().map_err(|error| failed(&error))?;
        let words: Vec<&OsStr> = words.iter().map(OsStr::new).collect();
        let command = Child::mahi(environment, &words, (&cwd, self.size), key)
            .map_err(|error| failed(&error))?
            .ok_or_else(|| failed(&"mahi cannot find its own program"))?;
        let id = self.next_id;
        let child =
            Child::start(command, self.size, id, &self.sender).map_err(|error| failed(&error))?;
        self.next_id += 1;
        let running = Running {
            id,
            name: name.to_owned(),
            shown: shown.to_owned(),
            child,
            closed: false,
            ending: Ending::Running,
        };
        let open = (!new)
            .then(|| self.tabs.iter().position(|tab| tab.title == title))
            .flatten();
        let index = if let Some(index) = open {
            index
        } else {
            self.tabs.push(Tab {
                title: title.to_owned(),
                agents: Vec::new(),
                selected: 0,
            });
            self.tabs.len() - 1
        };
        if let Some(tab) = self.tabs.get_mut(index) {
            tab.agents.push(running);
            tab.selected = tab.agents.len() - 1;
        }
        self.selected = index + 1;
        Ok(())
    }

    /// Draws what the children wrote since the last call into their screens, and writes to
    /// `out` what the shown agent asks of the user's terminal itself; returns whether the
    /// shown agent's screen changed.
    pub(crate) fn take_output(&mut self, out: &mut Vec<u8>) -> bool {
        let shown = self.shown_id().filter(|&id| self.applied == Some(id));
        let mut changed = false;
        while let Ok(event) = self.events.try_recv() {
            match event {
                ChildEvent::Output(id, bytes) => {
                    let mut passed = std::mem::take(&mut self.passed);
                    passed.clear();
                    let is_shown = shown == Some(id);
                    if let Some(running) = self.running_mut(id) {
                        running.child.feed(&bytes, is_shown.then_some(&mut passed));
                    }
                    if is_shown {
                        out.extend_from_slice(&passed);
                        changed = true;
                    }
                    self.passed = passed;
                }
                ChildEvent::Closed(id) => {
                    if let Some(running) = self.running_mut(id) {
                        running.closed = true;
                    }
                }
            }
        }
        changed
    }

    /// Takes away the agents whose command succeeded, once their last screen was drawn, and
    /// those whose command failed, once the user closed them, and the tabs left without any;
    /// returns what to tell the user about the last one to end, and whether what the screen
    /// shows changed.
    pub(crate) fn take_ended(&mut self) -> (Option<String>, bool) {
        let mut told = None;
        let mut changed = false;
        for tab in &mut self.tabs {
            for running in &mut tab.agents {
                let Some(code) = running.child.exited().unwrap_or(Some(1)) else {
                    continue;
                };
                if !running.closed {
                    continue;
                }
                let ending = match (running.ending, code) {
                    (Ending::Running, 0) => Ending::Drawn,
                    (Ending::Drawn, _) => {
                        told = Some(format!("{}: done", running.shown));
                        Ending::Closed
                    }
                    (Ending::Running, code) => {
                        told = Some(format!(
                            "{} failed with exit code {code}; a key in its pane closes it",
                            running.shown
                        ));
                        Ending::Failed
                    }
                    (ending, _) => ending,
                };
                changed |= ending != running.ending;
                running.ending = ending;
            }
            if tab
                .agents
                .iter()
                .any(|running| running.ending == Ending::Closed)
            {
                changed = true;
                let selected = tab.agents.get(tab.selected).map(|running| running.id);
                for running in &mut tab.agents {
                    if running.ending == Ending::Closed && self.applied == Some(running.id) {
                        running.child.hide(&mut self.pending);
                        self.applied = None;
                    }
                }
                tab.agents
                    .retain(|running| running.ending != Ending::Closed);
                tab.selected = selected
                    .and_then(|id| tab.agents.iter().position(|running| running.id == id))
                    .unwrap_or_else(|| tab.selected.min(tab.agents.len().saturating_sub(1)));
            }
        }
        if self.tabs.iter().any(|tab| tab.agents.is_empty()) {
            let selected = self
                .selected
                .checked_sub(1)
                .filter(|&index| {
                    self.tabs
                        .get(index)
                        .is_some_and(|tab| !tab.agents.is_empty())
                })
                .map_or(0, |index| {
                    1 + self
                        .tabs
                        .iter()
                        .take(index)
                        .filter(|tab| !tab.agents.is_empty())
                        .count()
                });
            self.tabs.retain(|tab| !tab.agents.is_empty());
            self.selected = selected;
            if self.tabs.is_empty() {
                self.armed = false;
            }
        }
        (told, changed)
    }

    /// Writes into `out` what puts the user's terminal in the key modes of the agent shown
    /// now, taking off those of the one shown before.
    pub(crate) fn apply_shown(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pending);
        self.pending.clear();
        let shown = self.shown_id();
        if shown == self.applied {
            return;
        }
        if let Some(old) = self.applied.take()
            && let Some(running) = self.running_mut(old)
        {
            running.child.hide(out);
        }
        if let Some(new) = shown
            && let Some(running) = self.running_mut(new)
        {
            running.child.show(out);
        }
        self.applied = shown;
    }

    /// Returns how many agents run in the workspace's tabs.
    pub(crate) fn running_count(&self) -> usize {
        self.tabs
            .iter()
            .flat_map(|tab| tab.agents.iter())
            .filter(|running| running.ending == Ending::Running)
            .count()
    }

    /// Asks every agent's command to end, as a stop signal does, and waits for them
    /// for at most `within`, reading what they write meanwhile so none waits on its terminal;
    /// returns how many still run, which dropping the workspace then kills.
    pub(crate) fn stop_all(&mut self, within: Duration) -> usize {
        for running in self.tabs.iter_mut().flat_map(|tab| tab.agents.iter_mut()) {
            running.child.stop();
        }
        let deadline = Instant::now() + within;
        let mut out = Vec::new();
        loop {
            self.take_output(&mut out);
            out.clear();
            let left = self
                .tabs
                .iter_mut()
                .flat_map(|tab| tab.agents.iter_mut())
                .map(|running| matches!(running.child.exited(), Ok(None)))
                .filter(|&runs| runs)
                .count();
            if left == 0 || Instant::now() >= deadline {
                return left;
            }
            thread::sleep(STOP_POLL);
        }
    }

    /// Gives every agent's terminal `size`.
    pub(crate) fn resize(&mut self, size: WindowSize) {
        if size == self.size {
            return;
        }
        self.size = size;
        for running in self.tabs.iter_mut().flat_map(|tab| tab.agents.iter_mut()) {
            let _ = running.child.resize(size);
        }
    }

    /// Takes what the user typed: the workspace's own keys, which follow the palette key, and
    /// on a thread's tab the rest, for its shown agent; on the thread list the rest goes to
    /// `threads`.
    pub(crate) fn type_keys(&mut self, typed: &[u8], threads: &mut Vec<u8>) -> Moved {
        let before = (self.selected, self.shown_id(), self.list_shown);
        let mut scanner =
            std::mem::replace(&mut self.scanner, KeyScanner::new(PaletteKey::default()));
        for segment in scanner.scan(typed) {
            match segment {
                Segment::Palette(key) => {
                    if self.armed {
                        self.armed = false;
                        self.send(key);
                    } else {
                        self.armed = true;
                    }
                }
                Segment::Pass(bytes) if self.armed => {
                    self.armed = false;
                    let (step, rest) = workspace_key(bytes);
                    if let Some(step) = step {
                        self.step(step);
                    }
                    self.pass(rest, threads);
                }
                Segment::Pass(bytes) => self.pass(bytes, threads),
            }
        }
        self.scanner = scanner;
        if (self.selected, self.shown_id(), self.list_shown) == before {
            Moved::Nothing
        } else {
            Moved::Shown
        }
    }

    fn pass(&mut self, bytes: &[u8], threads: &mut Vec<u8>) {
        if self.selected == 0 {
            threads.extend_from_slice(bytes);
        } else {
            self.send(bytes);
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(running) = self.shown_mut() {
            if running.ending == Ending::Failed {
                running.ending = Ending::Closed;
            } else {
                let _ = running.child.send(bytes);
            }
        }
    }

    fn step(&mut self, step: Step) {
        let last = self.tabs.len();
        match step {
            Step::To(index) if index <= last => self.selected = index,
            Step::To(_) => {}
            Step::Next => self.selected = (self.selected + 1) % (last + 1),
            Step::Previous => self.selected = (self.selected + last) % (last + 1),
            Step::NextAgent | Step::PreviousAgent => {
                if let Some(tab) = self
                    .selected
                    .checked_sub(1)
                    .and_then(|index| self.tabs.get_mut(index))
                    && !tab.agents.is_empty()
                {
                    let count = tab.agents.len();
                    let forward = if step == Step::NextAgent {
                        1
                    } else {
                        count - 1
                    };
                    tab.selected = (tab.selected + forward) % count;
                }
            }
            Step::List => self.list_shown = !self.list_shown,
        }
    }

    /// Returns where the list of a thread's agents goes on a terminal `columns` wide.
    pub(crate) fn list_place(&self, columns: u16) -> ListPlace {
        if self.list_shown {
            ListPlace::shown_at(columns)
        } else {
            ListPlace::Hidden
        }
    }

    /// Draws the row of tabs into `bar` and, on a thread's tab, the tab into `body`; returns
    /// where the shown agent's cursor is.
    pub(crate) fn render(&self, bar: Rect, body: Rect, buffer: &mut Buffer) -> Option<Position> {
        let tabs: Vec<WorkspaceTab<'_>> = self
            .tabs
            .iter()
            .map(|tab| WorkspaceTab {
                title: &tab.title,
                asks: false,
            })
            .collect();
        TabBar {
            tabs: &tabs,
            selected: self.selected,
        }
        .render(bar, buffer);
        let tab = self.tabs.get(self.selected.checked_sub(1)?)?;
        let agents: Vec<WorkspaceAgent<'_>> = tab
            .agents
            .iter()
            .map(|running| WorkspaceAgent {
                owner: None,
                name: &running.name,
                state: if running.ending == Ending::Failed {
                    AgentState::Failed
                } else {
                    AgentState::Working
                },
            })
            .collect();
        let shown = tab.agents.get(tab.selected);
        let failed = shown.is_some_and(|running| running.ending == Ending::Failed);
        ThreadView {
            agents: &agents,
            selected: tab.selected,
            prompts: 0,
            list: self.list_place(body.width),
            hints: if failed { &FAILED_HINTS } else { &HINTS },
        }
        .render(shown.map(|running| running.child.screen()), body, buffer)
    }

    fn shown_id(&self) -> Option<usize> {
        let tab = self.tabs.get(self.selected.checked_sub(1)?)?;
        tab.agents.get(tab.selected).map(|running| running.id)
    }

    fn shown_mut(&mut self) -> Option<&mut Running> {
        let tab = self.tabs.get_mut(self.selected.checked_sub(1)?)?;
        tab.agents.get_mut(tab.selected)
    }

    fn running_mut(&mut self, id: usize) -> Option<&mut Running> {
        self.tabs
            .iter_mut()
            .flat_map(|tab| tab.agents.iter_mut())
            .find(|running| running.id == id)
    }
}

/// A move the workspace's keys make between tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    To(usize),
    Next,
    Previous,
    NextAgent,
    PreviousAgent,
    List,
}

/// Reads the workspace key at the start of `bytes`, typed after the palette key, and returns
/// the move it makes, if any, and what follows it.
fn workspace_key(bytes: &[u8]) -> (Option<Step>, &[u8]) {
    for (sequence, step) in [
        (&b"\x1b[C"[..], Step::Next),
        (b"\x1bOC", Step::Next),
        (b"\x1b[D", Step::Previous),
        (b"\x1bOD", Step::Previous),
        (b"\x1b[B", Step::NextAgent),
        (b"\x1bOB", Step::NextAgent),
        (b"\x1b[A", Step::PreviousAgent),
        (b"\x1bOA", Step::PreviousAgent),
        (b"b", Step::List),
    ] {
        if let Some(rest) = bytes.strip_prefix(sequence) {
            return (Some(step), rest);
        }
    }
    match bytes.split_first() {
        Some((digit @ b'0'..=b'9', rest)) => (Some(Step::To(usize::from(digit - b'0'))), rest),
        _ => (None, bytes.get(key_length(bytes)..).unwrap_or_default()),
    }
}

/// Returns how many bytes the key at the start of `bytes` takes: an escape sequence (CSI up
/// to its final byte, SS3 and the byte after it, or Escape and one byte), a character in
/// UTF-8, or one byte.
fn key_length(bytes: &[u8]) -> usize {
    match bytes {
        [0x1b, b'[', rest @ ..] => {
            2 + rest
                .iter()
                .position(|byte| (0x40..=0x7e).contains(byte))
                .map_or(rest.len(), |at| at + 1)
        }
        [0x1b, b'O', _, ..] => 3,
        [0x1b, _, ..] => 2,
        [first, ..] => match first.leading_ones() {
            2..=4 => usize::try_from(first.leading_ones())
                .unwrap_or(1)
                .min(bytes.len()),
            _ => 1,
        },
        [] => 0,
    }
}

/// Returns the read end of a pipe holding `key`'s secret, its write end closed; both ends are
/// closed on exec, so only a child given the read end keeps it.
fn key_pipe(key: &LocalIdentity) -> io::Result<OwnedFd> {
    let (reader, writer) = closed_on_exec_pipe()?;
    let mut writer = std::fs::File::from(writer);
    writer.write_all(key.to_secret().expose_secret().as_bytes())?;
    Ok(reader)
}

#[cfg(target_os = "linux")]
fn closed_on_exec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?)
}

/// Returns a pipe whose ends close on exec; macOS has no call that makes it so at once, so
/// the workspace starts its children from one thread only, which no other start can race.
#[cfg(not(target_os = "linux"))]
fn closed_on_exec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = rustix::pipe::pipe()?;
    for end in [&reader, &writer] {
        rustix::io::fcntl_setfd(end, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok((reader, writer))
}

#[cfg(test)]
mod tests {
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
                Ok(ChildEvent::Output(0, bytes)) => child.feed(&bytes, Some(&mut passed)),
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    #[test]
    fn a_workspace_key_after_the_palette_key_is_read_from_the_start_of_what_follows() {
        assert_eq!(workspace_key(b"\x1b[Cxy"), (Some(Step::Next), &b"xy"[..]));
        assert_eq!(workspace_key(b"\x1bOD"), (Some(Step::Previous), &b""[..]));
        assert_eq!(workspace_key(b"3rest"), (Some(Step::To(3)), &b"rest"[..]));
        assert_eq!(workspace_key(b"zrest"), (None, &b"rest"[..]));
        assert_eq!(
            workspace_key(b"\x1b[Arest"),
            (Some(Step::PreviousAgent), &b"rest"[..])
        );
        assert_eq!(workspace_key(b"\x1b[1;5Arest"), (None, &b"rest"[..]));
        assert_eq!(workspace_key("érest".as_bytes()), (None, &b"rest"[..]));
        assert_eq!(workspace_key(b""), (None, &b""[..]));
    }

    fn running(workspace: &mut Workspace, script: &str) -> Running {
        let id = workspace.next_id;
        workspace.next_id += 1;
        Running {
            id,
            name: "agent".to_owned(),
            shown: format!("mahi run agent{id}"),
            child: Child::start(shell(script), SIZE, id, &workspace.sender).unwrap(),
            closed: false,
            ending: Ending::Running,
        }
    }

    fn tab(title: &str, agents: Vec<Running>) -> Tab {
        Tab {
            title: title.to_owned(),
            agents,
            selected: 0,
        }
    }

    fn settle(workspace: &mut Workspace, out: &mut Vec<u8>, done: impl Fn(&Workspace) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(workspace) {
            assert!(Instant::now() < deadline);
            workspace.take_output(out);
            workspace.take_ended();
            workspace.apply_shown(out);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn moving_between_tabs_wraps_and_a_tab_that_is_not_there_is_ignored() {
        let mut workspace = Workspace::new(PaletteKey::default());
        for title in ["a", "b"] {
            let agent = running(&mut workspace, "sleep 5");
            workspace.tabs.push(tab(title, vec![agent]));
        }
        let mut threads = Vec::new();
        assert_eq!(workspace.type_keys(b"\x002", &mut threads), Moved::Shown);
        assert_eq!(workspace.selected, 2);
        assert_eq!(
            workspace.type_keys(b"\x00\x1b[C", &mut threads),
            Moved::Shown
        );
        assert_eq!(workspace.selected, 0);
        assert_eq!(
            workspace.type_keys(b"\x00\x1b[D", &mut threads),
            Moved::Shown
        );
        assert_eq!(workspace.selected, 2);
        assert_eq!(workspace.type_keys(b"\x009", &mut threads), Moved::Nothing);
        assert_eq!(workspace.selected, 2);
        workspace.type_keys(b"\x000jk", &mut threads);
        assert_eq!(threads, b"jk");
    }

    #[test]
    fn the_arrows_up_and_down_choose_the_agent_and_b_hides_the_list() {
        let mut workspace = Workspace::new(PaletteKey::default());
        let first = running(&mut workspace, "sleep 5");
        let second = running(&mut workspace, "sleep 5");
        let (first_id, second_id) = (first.id, second.id);
        workspace.tabs.push(tab("a", vec![first, second]));
        workspace.selected = 1;
        let mut threads = Vec::new();
        assert_eq!(
            workspace.type_keys(b"\x00\x1b[B", &mut threads),
            Moved::Shown
        );
        assert_eq!(workspace.shown_id(), Some(second_id));
        workspace.type_keys(b"\x00\x1b[B", &mut threads);
        assert_eq!(workspace.shown_id(), Some(first_id));
        workspace.type_keys(b"\x00\x1bOA", &mut threads);
        assert_eq!(workspace.shown_id(), Some(second_id));
        assert_eq!(workspace.list_place(120), ListPlace::Beside);
        assert_eq!(workspace.type_keys(b"\x00b", &mut threads), Moved::Shown);
        assert_eq!(workspace.list_place(120), ListPlace::Hidden);
        workspace.type_keys(b"\x00b", &mut threads);
        assert_eq!(workspace.list_place(80), ListPlace::Over);
        assert!(threads.is_empty());
    }

    #[test]
    fn a_hidden_agents_key_modes_reach_the_terminal_only_while_it_is_shown() {
        let mut workspace = Workspace::new(PaletteKey::default());
        let agent = running(&mut workspace, "printf '\\033[?1hready'; sleep 5");
        workspace.tabs.push(tab("a", vec![agent]));
        let mut out = Vec::new();
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains("ready")
        });
        assert!(
            !String::from_utf8_lossy(&out).contains("\x1b[?1h"),
            "{out:?}"
        );
        workspace.selected = 1;
        workspace.apply_shown(&mut out);
        assert!(
            String::from_utf8_lossy(&out).contains("\x1b[?1h"),
            "{out:?}"
        );
        out.clear();
        workspace.selected = 0;
        workspace.apply_shown(&mut out);
        assert!(
            String::from_utf8_lossy(&out).contains("\x1b[?1l"),
            "{out:?}"
        );
    }

    #[test]
    fn an_agent_that_ends_leaves_the_selection_on_the_one_that_was_selected() {
        let mut workspace = Workspace::new(PaletteKey::default());
        let first = running(&mut workspace, "exit 0");
        let second = running(&mut workspace, "sleep 5");
        let kept = second.id;
        let mut both = tab("a", vec![first, second]);
        both.selected = 1;
        workspace.tabs.push(both);
        workspace.selected = 1;
        let mut out = Vec::new();
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents.len() == 1
        });
        assert_eq!(workspace.shown_id(), Some(kept));
    }

    #[test]
    fn closing_a_failed_agent_changes_the_screen_and_ends_the_workspaces_own_keys() {
        let mut workspace = Workspace::new(PaletteKey::default());
        let agent = running(&mut workspace, "exit 3");
        workspace.tabs.push(tab("a", vec![agent]));
        workspace.selected = 1;
        let mut out = Vec::new();
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0].ending == Ending::Failed
        });
        assert!(!workspace.is_running());
        let mut threads = Vec::new();
        workspace.type_keys(b"x\x00", &mut threads);
        assert!(workspace.armed);
        assert_eq!(workspace.take_ended(), (None, true));
        assert!(!workspace.has_tabs());
        assert!(!workspace.armed);
        assert_eq!(workspace.selected, 0);
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
        let command = Child::mahi(&environment, &words, (Path::new("/"), SIZE), None)
            .unwrap()
            .unwrap();
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        let mut child = Child::start(command, SIZE, 0, &sender).unwrap();
        run_until(&mut child, &events, |child| {
            child
                .screen()
                .contents()
                .contains("carried word tmux= term=xterm-256color")
        });
        assert!(
            Child::mahi(
                &Environment::default(),
                &words,
                (Path::new("/"), SIZE),
                None
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn the_unlocked_key_reaches_the_child_on_its_own_pipe_and_only_when_given() {
        let environment = Environment {
            mahi_exe: Some("/bin/sh".into()),
            whole: vec![
                (
                    "PATH".into(),
                    zeroize::Zeroizing::new(b"/usr/bin:/bin".to_vec()),
                ),
                (KEY_FD.into(), zeroize::Zeroizing::new(b"7".to_vec())),
            ],
            ..Environment::default()
        };
        let words = [
            OsStr::new("-c"),
            OsStr::new(
                "echo \"fd=${MAHI_KEY_FD:-none}\"; [ -n \"$MAHI_KEY_FD\" ] && eval \"cat <&$MAHI_KEY_FD\"; echo; echo end",
            ),
        ];
        let key = LocalIdentity::generate();
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        let given = Child::mahi(&environment, &words, (Path::new("/"), SIZE), Some(&key))
            .unwrap()
            .unwrap();
        let mut child = Child::start(given, SIZE, 0, &sender).unwrap();
        run_until(&mut child, &events, |child| {
            child.screen().contents().contains("end")
        });
        let shown = child.screen().contents().replace('\n', "");
        assert!(shown.contains(key.to_secret().expose_secret()), "{shown}");
        assert!(!shown.contains("fd=7"), "{shown}");
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        let plain = Child::mahi(&environment, &words, (Path::new("/"), SIZE), None)
            .unwrap()
            .unwrap();
        let mut child = Child::start(plain, SIZE, 0, &sender).unwrap();
        run_until(&mut child, &events, |child| {
            child.screen().contents().contains("end")
        });
        assert!(child.screen().contents().contains("fd=none"));
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
                Ok(ChildEvent::Output(_, bytes)) => child.feed(&bytes, Some(&mut passed)),
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
            child.feed(b"\x1b[6n", Some(&mut passed));
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
