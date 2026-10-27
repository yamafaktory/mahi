use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::File,
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
use mahi_core::{
    AgentSlot,
    ThreadId,
};
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
    Answer,
    Dialog,
    Header,
    KeyScanner,
    ListHit,
    ListPlace,
    MouseEvent,
    Notice,
    PaletteInput,
    PaletteKey,
    PaletteKeys,
    Report,
    ReportReader,
    Segment,
    TabBar,
    TabHit,
    ThreadChoice,
    ThreadView,
    TopBar,
    Typed,
    WorkspaceAgent,
    WorkspaceTab,
    agent_mouse,
    cut_report,
    split_mouse,
};
use ratatui_core::{
    buffer::Buffer,
    layout::{
        Position,
        Rect,
    },
};

use crate::{
    environment::{
        COMMAND_FD,
        Environment,
        KEY_FD,
        REPORT_FD,
    },
    join::WAITING_FOR_HOST,
    teammates::Teammates,
    ui::{
        SPIN_EVERY,
        SPINNER,
    },
    workspace_live::WorkspaceLive,
};

const READ_CHUNK: usize = 16 * 1024;
const STOP_POLL: Duration = Duration::from_millis(20);
const TOLD_FOR: Duration = Duration::from_secs(6);
const MOUSE_ON: &[u8] = b"\x1b[?1002h\x1b[?1006h";
pub(crate) const MOUSE_OFF: &[u8] = b"\x1b[?1002l\x1b[?1006l";
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
const HOST_AGAIN: Duration = Duration::from_secs(2);
const REDRAW_WAIT: Duration = Duration::from_millis(250);
const REDRAW_QUIET: Duration = Duration::from_millis(15);
pub(crate) const NEW_TAB: &str = "new";
const SHORT_THREAD: usize = 8;
const ASKS_TOLD_EVERY: Duration = Duration::from_secs(30);
const MAX_CHILDREN: usize = 16;

/// What the thread reading a child's terminal tells the workspace.
#[derive(Debug)]
pub(crate) enum ChildEvent {
    /// The child `0` wrote these bytes.
    Output(usize, Vec<u8>),
    /// The child `0`'s terminal has nothing more to read.
    Closed(usize),
    /// The child `0` reported this about its agent.
    Report(usize, Report),
}

/// Reads on a thread of its own the reports the workspace's child `id` writes on the pipe
/// `reports`, and sends each to `events`.
fn read_reports(reports: OwnedFd, id: usize, events: &mpsc::SyncSender<ChildEvent>) {
    let events = events.clone();
    thread::spawn(move || {
        let mut pipe = File::from(reports);
        let mut reader = ReportReader::default();
        let mut chunk = [0_u8; 512];
        while let Ok(read) = pipe.read(&mut chunk) {
            let Some(bytes) = chunk.get(..read).filter(|bytes| !bytes.is_empty()) else {
                break;
            };
            let mut gone = false;
            reader.feed(bytes, |report| {
                gone |= events.send(ChildEvent::Report(id, report)).is_err();
            });
            if gone {
                break;
            }
        }
    });
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
    /// Returns the error of making the pipes the key and the reports go through.
    pub(crate) fn mahi(
        environment: &Environment,
        words: &[&OsStr],
        (cwd, size): (&Path, WindowSize),
        key: Option<&LocalIdentity>,
    ) -> io::Result<Option<(PtyCommand, OwnedFd, File)>> {
        let Some(program) = environment.mahi_exe.as_deref() else {
            return Ok(None);
        };
        let mut command = PtyCommand::new(program, cwd, size).hold_terminal();
        for word in words {
            command = command.arg(word);
        }
        for (name, value) in &environment.whole {
            let ours = [KEY_FD, REPORT_FD, COMMAND_FD]
                .iter()
                .any(|own| name == own);
            if name != "TERM" && !ours && !TERMINAL_OWN.iter().any(|own| name == own) {
                command = command.env(name, OsStr::from_bytes(value));
            }
        }
        if let Some(key) = key {
            let pipe = key_pipe(key)?;
            command = command
                .env(KEY_FD, pipe.as_raw_fd().to_string())
                .pass_fd(pipe);
        }
        let (reports, report_end) = closed_on_exec_pipe()?;
        command = command
            .env(REPORT_FD, report_end.as_raw_fd().to_string())
            .pass_fd(report_end);
        let (command_end, commands) = closed_on_exec_pipe()?;
        rustix::fs::fcntl_setfl(&commands, rustix::fs::OFlags::NONBLOCK)?;
        command = command
            .env(COMMAND_FD, command_end.as_raw_fd().to_string())
            .pass_fd(command_end);
        Ok(Some((
            command.env("TERM", CHILD_TERM),
            reports,
            File::from(commands),
        )))
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
    palette: Option<Palette>,
    told: Option<Told>,
    chosen: Option<Moved>,
    list_shown: bool,
    redraw: Option<RedrawWait>,
    palette_name: String,
    size: WindowSize,
    passed: Vec<u8>,
    applied: Option<usize>,
    pending: Vec<u8>,
    screen: WindowSize,
    mouse: MouseState,
    notice: Notice,
    live: Option<WorkspaceLive>,
    live_told: Option<String>,
    live_failed: HashSet<ThreadId>,
    live_tried: Instant,
    spin: Option<Spin>,
}

/// The spinner a tab that watches a joined thread turns until it lists an agent: its frame,
/// and when it last turned.
#[derive(Debug, Clone, Copy)]
struct Spin {
    frame: usize,
    turned: Instant,
}

/// What the workspace keeps of the mouse between reads.
#[derive(Debug, Default)]
struct MouseState {
    on: bool,
    paused: bool,
    dragging: bool,
    carried: Vec<u8>,
    joined: Vec<u8>,
    encoded: Vec<u8>,
}

/// How long drawing waits for the shown agent to redraw at a new size, and when it last
/// wrote since.
#[derive(Debug, Clone, Copy)]
struct RedrawWait {
    until: Instant,
    heard: Option<Instant>,
}

/// A thread's tab: the agents the workspace runs for it.
#[derive(Debug)]
struct Tab {
    title: String,
    thread: Option<ThreadId>,
    agents: Vec<Running>,
    selected: usize,
    watching: Option<AgentSlot>,
    watch_only: bool,
}

impl Tab {
    /// Returns whether the tab has nothing left to show: none of the user's agents, and it
    /// does not only watch the thread's teammates.
    fn is_done(&self) -> bool {
        self.agents.is_empty() && !self.watch_only
    }

    /// Returns the agents the list shows: the user's own, then the teammates' the workspace
    /// watches, from `teammates`.
    fn listed<'a>(&'a self, teammates: Option<&'a Teammates>) -> Vec<WorkspaceAgent<'a>> {
        let watched = teammates.into_iter().flat_map(Teammates::agents);
        let count = teammates.map_or(0, |teammates| teammates.agents().len());
        let mut listed = Vec::with_capacity(self.agents.len() + count);
        listed.extend(self.agents.iter().map(Running::shown_as));
        listed.extend(watched.map(|(slot, online)| WorkspaceAgent {
            owner: Some(slot.participant().as_str()),
            name: slot.agent().as_str(),
            state: if online {
                AgentState::Live
            } else {
                AgentState::Offline
            },
        }));
        listed
    }

    /// Returns the screen of the selected agent: the user's own child's, or the teammate's of
    /// `teammates`, once one of it arrived.
    fn screen<'a>(&'a self, teammates: Option<&'a Teammates>) -> Option<&'a vt100::Screen> {
        match (self.agents.get(self.selected), &self.watching) {
            (Some(running), _) => Some(running.child.screen()),
            (None, Some(slot)) => teammates?.screen(slot),
            (None, None) => None,
        }
    }

    /// Selects the agent at `index` of the list, the user's own or, past them, the teammate's
    /// of `teammates` at that place, which stays selected when the list changes.
    fn select(&mut self, index: usize, teammates: Option<&Teammates>) {
        self.selected = index;
        self.watching = index
            .checked_sub(self.agents.len())
            .and_then(|at| teammates?.agents().nth(at))
            .map(|(slot, _)| slot.clone());
    }

    /// Selects again the teammate's agent selected before the list of `teammates` changed,
    /// or the user's last agent when it is no longer listed.
    fn select_teammate(&mut self, slot: &AgentSlot, teammates: Option<&Teammates>) {
        let Some(at) =
            teammates.and_then(|watched| watched.agents().position(|(listed, _)| listed == slot))
        else {
            return;
        };
        self.select(self.agents.len() + at, teammates);
    }

    fn reselect(&mut self, teammates: Option<&Teammates>) {
        let Some(slot) = &self.watching else {
            if self.agents.is_empty() {
                self.select(0, teammates);
            }
            return;
        };
        let place = teammates
            .and_then(|teammates| teammates.agents().position(|(watched, _)| watched == slot));
        if let Some(place) = place {
            self.selected = self.agents.len() + place;
        } else {
            self.watching = None;
            self.selected = self.agents.len().saturating_sub(1);
        }
    }
}

/// What the last line of a thread's tab tells for a few seconds, after its label.
#[derive(Debug)]
struct Told {
    label: &'static str,
    text: String,
    at: Instant,
    thread: ThreadId,
}

/// Returns the teammates `live` watches in `thread`, when the workspace hosts it.
fn teammates_of(live: Option<&WorkspaceLive>, thread: Option<ThreadId>) -> Option<&Teammates> {
    live?.teammates(thread?)
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
    state: AgentState,
    told_asks: Option<Instant>,
    commands: Option<File>,
}

impl Running {
    /// Returns the agent as the list of a thread's agents shows it.
    fn shown_as(&self) -> WorkspaceAgent<'_> {
        WorkspaceAgent {
            owner: None,
            name: &self.name,
            state: if self.ending == Ending::Failed {
                AgentState::Failed
            } else {
                self.state
            },
        }
    }
}

/// How far an agent whose command ended is from leaving its tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Running,
    Drawn,
    Failed,
    Stopping,
    Closed,
}

/// What a workspace key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Moved {
    /// Nothing the screen shows changed.
    Nothing,
    /// Another tab or agent is shown, the list was hidden or shown, or the palette changed.
    Shown,
    /// `+` was clicked, to open another thread.
    New,
    /// Quit was chosen in the palette.
    Quit,
    /// An action on the shown tab's thread was chosen in the palette.
    Act(ThreadChoice, ThreadId),
}

/// The workspace's palette, open over what is shown: a menu of where to go and what to do,
/// whose keys also act at once, read as the palette reads them.
#[derive(Debug)]
struct Palette {
    menu: Dialog,
    entries: Vec<Entry>,
    keys: PaletteKeys,
    key: Vec<u8>,
}

/// What an entry of the workspace's palette does.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Step(Step),
    Agent(usize),
    Teammate(AgentSlot),
    AgentPalette,
    SendKey,
    Act(ThreadChoice),
    Leave,
    Quit,
}

const THREAD_ACTIONS: [(ThreadChoice, &str); 6] = [
    (ThreadChoice::AddAgent, "Add an agent to this thread"),
    (ThreadChoice::Handoff, "Hand off to another of your agents"),
    (ThreadChoice::Land, "Land this thread"),
    (ThreadChoice::Push, "Push the landed commits"),
    (ThreadChoice::End, "End this thread"),
    (ThreadChoice::Invite, "Invite a teammate"),
];

impl Workspace {
    /// Starts a workspace with no thread open, whose keys follow `palette_key`, and which
    /// raises its agents' notifications as `notice` says the user's terminal does.
    pub(crate) fn new(palette_key: PaletteKey, notice: Notice) -> Self {
        let (sender, events) = mpsc::sync_channel(QUEUED_WRITES);
        Self {
            tabs: Vec::new(),
            selected: 0,
            events,
            sender,
            next_id: 0,
            scanner: KeyScanner::new(palette_key),
            palette: None,
            told: None,
            chosen: None,
            list_shown: true,
            redraw: None,
            palette_name: palette_key.to_string(),
            size: WindowSize { rows: 2, cols: 2 },
            passed: Vec::new(),
            applied: None,
            pending: Vec::new(),
            screen: WindowSize { rows: 2, cols: 2 },
            mouse: MouseState::default(),
            notice,
            live: None,
            live_told: None,
            live_failed: HashSet::new(),
            live_tried: Instant::now(),
            spin: None,
        }
    }

    /// Lets the workspace host the live layer of the threads its tabs show with `live`, so
    /// its children never bind the user's node key themselves.
    pub(crate) fn host_with(&mut self, live: Option<WorkspaceLive>) {
        self.live = live;
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

    /// Shows the tab titled `title` when an agent runs in it, keeping its selected agent when
    /// that one runs and otherwise selecting the first that does; returns whether it did, so
    /// resuming its thread again starts no agent that would find its own already running.
    pub(crate) fn show_running(&mut self, title: &str) -> bool {
        let Some(index) = self.tabs.iter().position(|tab| tab.title == title) else {
            return false;
        };
        let Some(tab) = self.tabs.get_mut(index) else {
            return false;
        };
        let runs = |running: &Running| running.ending == Ending::Running;
        if !tab.agents.get(tab.selected).is_some_and(runs) {
            let Some(first) = tab.agents.iter().position(runs) else {
                return false;
            };
            tab.select(first, None);
        }
        self.selected = index + 1;
        true
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
        self.room_for_agent()?;
        let failed = |error: &dyn std::fmt::Display| format!("{shown} cannot start: {error}");
        let cwd = std::env::current_dir().map_err(|error| failed(&error))?;
        let words: Vec<&OsStr> = words.iter().map(OsStr::new).collect();
        let (command, reports, commands) = Child::mahi(environment, &words, (&cwd, self.size), key)
            .map_err(|error| failed(&error))?
            .ok_or_else(|| failed(&"mahi cannot find its own program"))?;
        let id = self.next_id;
        let child =
            Child::start(command, self.size, id, &self.sender).map_err(|error| failed(&error))?;
        read_reports(reports, id, &self.sender);
        self.next_id += 1;
        let running = Running {
            id,
            name: name.to_owned(),
            shown: shown.to_owned(),
            child,
            closed: false,
            ending: Ending::Running,
            state: AgentState::Done,
            told_asks: None,
            commands: Some(commands),
        };
        let open = (!new)
            .then(|| self.tabs.iter().position(|tab| tab.title == title))
            .flatten();
        let index = open.unwrap_or_else(|| self.add_tab(title));
        if let Some(tab) = self.tabs.get_mut(index) {
            tab.agents.push(running);
            tab.select(tab.agents.len() - 1, None);
        }
        self.selected = index + 1;
        self.palette = None;
        Ok(())
    }

    /// Adds a tab titled `title` and returns its index; the first tab starts with the list
    /// hidden on a terminal too narrow to show it beside the pane.
    fn add_tab(&mut self, title: &str) -> usize {
        if self.tabs.is_empty() {
            self.list_shown = ListPlace::shown_at(self.screen.cols) == ListPlace::Beside;
        }
        self.tabs.push(Tab {
            thread: None,
            title: title.to_owned(),
            agents: Vec::new(),
            selected: 0,
            watching: None,
            watch_only: false,
        });
        self.tabs.len() - 1
    }

    /// Draws what the children wrote since the last call into their screens, and writes to
    /// `out` what the shown agent asks of the user's terminal itself and the notifications
    /// any child reported; returns whether the shown agent's screen changed.
    pub(crate) fn take_output(&mut self, out: &mut Vec<u8>) -> bool {
        let shown = self.shown_id().filter(|&id| self.applied == Some(id));
        let mut changed = false;
        let mut shown_wrote = false;
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
                        shown_wrote = true;
                    }
                    self.passed = passed;
                }
                ChildEvent::Report(id, report) => {
                    changed |= self.take_report(id, &report, out);
                }
                ChildEvent::Closed(id) => {
                    if let Some(running) = self.running_mut(id) {
                        running.closed = true;
                    }
                }
            }
        }
        if let Some(wait) = self.redraw.as_mut().filter(|_| shown_wrote) {
            wait.heard = Some(Instant::now());
        }
        changed | self.watch_teammates()
    }

    /// Takes what the teammates' hosts sent, keeping each tab's selected teammate selected;
    /// returns whether the list or a teammate's screen changed in the thread whose tab is
    /// shown.
    fn watch_teammates(&mut self) -> bool {
        let shown = self
            .selected
            .checked_sub(1)
            .and_then(|index| self.tabs.get(index));
        let watching = shown.and_then(|tab| Some((tab.thread?, tab.watching.clone()?)));
        let thread = shown.and_then(|tab| tab.thread);
        let size = (self.size.rows, self.size.cols);
        let Some(live) = self.live.as_mut() else {
            return false;
        };
        let mut changed = live.watch(Instant::now(), thread);
        if let Some((thread, slot)) = watching {
            changed |= live.show_record(thread, &slot, size);
        }
        for tab in &mut self.tabs {
            tab.reselect(teammates_of(self.live.as_ref(), tab.thread));
        }
        changed
    }

    /// Takes away the agents whose command succeeded, once their last screen was drawn, and
    /// those whose command failed, once the user closed them, and the tabs left without any;
    /// returns what to tell the user about the last one to end, and whether what the screen
    /// shows changed.
    pub(crate) fn take_ended(&mut self) -> (Option<String>, bool) {
        self.host_again();
        let mut told = None;
        let mut changed = self.leave_purged();
        for tab in &mut self.tabs {
            for running in &mut tab.agents {
                let Some(code) = running.child.exited().unwrap_or(Some(1)) else {
                    continue;
                };
                if !running.closed {
                    continue;
                }
                let ending = match (running.ending, code) {
                    (Ending::Stopping, _) => Ending::Closed,
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
                self.palette = None;
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
                tab.reselect(teammates_of(self.live.as_ref(), tab.thread));
            }
        }
        changed |= self.close_done_tabs();
        (told.or_else(|| self.live_told.take()), changed)
    }

    /// Closes the tabs left with nothing to show, keeping the one shown when it stays, and
    /// stops hosting the threads no tab is left open on; returns whether any closed.
    fn close_done_tabs(&mut self) -> bool {
        if !self.tabs.iter().any(Tab::is_done) {
            return false;
        }
        let selected = self
            .selected
            .checked_sub(1)
            .filter(|&index| self.tabs.get(index).is_some_and(|tab| !tab.is_done()))
            .map_or(0, |index| {
                1 + self
                    .tabs
                    .iter()
                    .take(index)
                    .filter(|tab| !tab.is_done())
                    .count()
            });
        for tab in self.tabs.iter().filter(|tab| tab.is_done()) {
            let still_open = |thread| {
                self.tabs
                    .iter()
                    .any(|other| !other.is_done() && other.thread == Some(thread))
            };
            if let (Some(thread), Some(live)) = (tab.thread, self.live.as_mut())
                && !still_open(thread)
            {
                live.release(thread);
            }
        }
        self.tabs.retain(|tab| !tab.is_done());
        self.selected = selected;
        self.palette = None;
        true
    }

    /// Opens a tab that watches the teammates' agents of `thread`, which the user joined, and
    /// shows it; a tab already open on the thread is shown instead.
    pub(crate) fn watch_thread(&mut self, thread: ThreadId) {
        let open = self.tabs.iter().position(|tab| tab.thread == Some(thread));
        let index = open.unwrap_or_else(|| {
            let mut title = thread.to_string();
            title.truncate(SHORT_THREAD);
            self.add_tab(&title)
        });
        if let Some(tab) = self.tabs.get_mut(index) {
            tab.thread = Some(thread);
            tab.watch_only = true;
        }
        self.selected = index + 1;
        self.palette = None;
        self.host(thread);
    }

    /// Turns the spinner of the shown tab at `now` while it only watches a thread and lists
    /// no agent yet; returns whether what it shows changed.
    pub(crate) fn spin(&mut self, now: Instant) -> bool {
        if !self.waits_for_host() {
            return self.spin.take().is_some();
        }
        match &mut self.spin {
            None => {
                self.spin = Some(Spin {
                    frame: 0,
                    turned: now,
                });
                true
            }
            Some(spin) if now.saturating_duration_since(spin.turned) >= SPIN_EVERY => {
                spin.frame = (spin.frame + 1) % SPINNER.len();
                spin.turned = now;
                true
            }
            Some(_) => false,
        }
    }

    /// Returns the spinner's frame and what the shown tab waits for, while it waits for the
    /// thread's host.
    pub(crate) fn waiting(&self) -> Option<(&'static str, &'static str)> {
        let spin = self.spin.filter(|_| self.waits_for_host())?;
        Some((SPINNER.get(spin.frame)?, WAITING_FOR_HOST))
    }

    fn waits_for_host(&self) -> bool {
        let Some(tab) = self
            .selected
            .checked_sub(1)
            .and_then(|index| self.tabs.get(index))
        else {
            return false;
        };
        let Some(teammates) = teammates_of(self.live.as_ref(), tab.thread) else {
            return false;
        };
        tab.watch_only && tab.agents.is_empty() && teammates.agents().len() == 0
    }

    /// Closes the tabs that only watch threads their owners purged, as the live layer's
    /// checks find them, telling it; returns whether one closed.
    fn leave_purged(&mut self) -> bool {
        let Some(live) = self.live.as_mut() else {
            return false;
        };
        let watched = self
            .tabs
            .iter()
            .filter(|tab| tab.watch_only && tab.agents.is_empty())
            .filter_map(|tab| tab.thread);
        let purged = live.take_purged(Instant::now(), watched);
        self.leave_purged_threads(&purged)
    }

    /// Closes the tabs that only watch the threads of `purged`, which their owners purged,
    /// telling the last one; returns whether one closed.
    fn leave_purged_threads(&mut self, purged: &[ThreadId]) -> bool {
        let mut left = false;
        for &thread in purged {
            let before = self.tabs.len();
            self.leave_thread(thread);
            if self.tabs.len() != before {
                self.live_told = Some(format!("thread {thread} was purged by its owner"));
                left = true;
            }
        }
        left
    }

    /// Closes the tabs that only watch the teammates of `thread`, before it ends or goes, so
    /// the workspace no longer hosts it.
    pub(crate) fn leave_thread(&mut self, thread: ThreadId) {
        let mut left = false;
        for tab in &mut self.tabs {
            if tab.thread == Some(thread) && tab.agents.is_empty() {
                tab.watch_only = false;
                left = true;
            }
        }
        if left {
            self.close_done_tabs();
        }
    }

    /// Closes the shown tab when it only watches teammates, and shows the thread list.
    fn leave_tab(&mut self) {
        let shown = self.selected.checked_sub(1);
        if let Some(tab) = shown.and_then(|index| self.tabs.get_mut(index))
            && tab.agents.is_empty()
        {
            tab.watch_only = false;
            self.selected = 0;
            self.close_done_tabs();
        }
    }

    /// Writes into `out` what puts the user's terminal in the key modes of the agent shown
    /// now, taking off those of the one shown before.
    pub(crate) fn apply_shown(&mut self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pending);
        self.pending.clear();
        let wanted = self.has_tabs() && !self.mouse.paused;
        if wanted != self.mouse.on {
            out.extend_from_slice(if wanted { MOUSE_ON } else { MOUSE_OFF });
            self.mouse.on = wanted;
        }
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

    /// Writes to `out` what takes the shown agent's key modes off the user's terminal, so
    /// mahi's own dialogs read keys as the home screen does, and the next `apply_shown` puts
    /// them back.
    pub(crate) fn hide_shown(&mut self, out: &mut Vec<u8>) {
        if let Some(old) = self.applied.take()
            && let Some(running) = self.running_mut(old)
        {
            running.child.hide(out);
        }
    }

    /// Says whether another agent can start, since the workspace runs at most 16 at once, or
    /// what to tell the user when none can.
    pub(crate) fn room_for_agent(&self) -> Result<(), String> {
        if self.running_count() < MAX_CHILDREN {
            Ok(())
        } else {
            Err(format!(
                "the workspace runs at most {MAX_CHILDREN} agents at once: stop one to start another"
            ))
        }
    }

    /// Returns how many agents run in the workspace's tabs.
    pub(crate) fn running_count(&self) -> usize {
        self.tabs
            .iter()
            .flat_map(|tab| tab.agents.iter())
            .filter(|running| running.ending == Ending::Running)
            .count()
    }

    /// Returns how many agents of `thread` run in the workspace's tabs.
    pub(crate) fn running_in(&self, thread: ThreadId) -> usize {
        self.thread_agents(thread)
            .filter(|running| running.ending == Ending::Running)
            .count()
    }

    /// Asks the agents of `thread` to end, as a stop signal does, and waits for them for at
    /// most `within`, reading what every agent writes meanwhile; returns how many still run.
    /// Their tabs close once they have ended, without telling it as a failure; one that still
    /// runs at the end is counted as running again.
    pub(crate) fn stop_thread(&mut self, thread: ThreadId, within: Duration) -> usize {
        for running in self.thread_agents_mut(thread) {
            if running.ending == Ending::Running {
                running.ending = Ending::Stopping;
                running.child.stop();
            }
        }
        let deadline = Instant::now() + within;
        let mut out = Vec::new();
        loop {
            self.take_output(&mut out);
            out.clear();
            let left = self
                .thread_agents_mut(thread)
                .map(|running| matches!(running.child.exited(), Ok(None)))
                .filter(|&runs| runs)
                .count();
            if left == 0 {
                return 0;
            }
            if Instant::now() >= deadline {
                for running in self.thread_agents_mut(thread) {
                    if running.ending == Ending::Stopping
                        && matches!(running.child.exited(), Ok(None))
                    {
                        running.ending = Ending::Running;
                    }
                }
                return left;
            }
            thread::sleep(STOP_POLL);
        }
    }

    fn thread_agents(&self, thread: ThreadId) -> impl Iterator<Item = &Running> {
        self.tabs
            .iter()
            .filter(move |tab| tab.thread == Some(thread))
            .flat_map(|tab| tab.agents.iter())
    }

    fn thread_agents_mut(&mut self, thread: ThreadId) -> impl Iterator<Item = &mut Running> {
        self.tabs
            .iter_mut()
            .filter(move |tab| tab.thread == Some(thread))
            .flat_map(|tab| tab.agents.iter_mut())
    }

    /// Asks every agent's command to end, as a stop signal does, and waits for them
    /// for at most `within`, reading what they write meanwhile so none waits on its terminal;
    /// returns how many still run, which dropping the workspace then kills.
    pub(crate) fn stop_all(&mut self, within: Duration) -> usize {
        let live = self.live.take();
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
                drop(live);
                return left;
            }
            thread::sleep(STOP_POLL);
        }
    }

    /// Takes note of the user's terminal being `size`, for the clicks the workspace reads, and
    /// of the terminal's mouse reporting having been reset, as an action that left the screen
    /// may have done.
    pub(crate) fn set_screen(&mut self, size: WindowSize, reset: bool) {
        self.screen = size;
        if reset {
            self.mouse.on = false;
            self.mouse.dragging = false;
        }
    }

    /// Leaves the mouse to the terminal while `paused`, so a dialog's text can be selected,
    /// and takes it back for the tabs once it is not.
    pub(crate) fn pause_mouse(&mut self, paused: bool) {
        if paused {
            self.mouse.dragging = false;
        }
        self.mouse.paused = paused;
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
        let now = Instant::now();
        let until = self
            .redraw
            .map(|wait| wait.until)
            .filter(|&until| now < until)
            .unwrap_or(now + REDRAW_WAIT);
        self.redraw = self
            .shows_running()
            .then_some(RedrawWait { until, heard: None });
        if let Some(live) = self.live.as_mut() {
            live.forget_records();
        }
    }

    /// Says whether drawing waits at `now` for the shown agent, still running, to redraw at
    /// the size it was last given, so its pane is not drawn half blank in between: until the
    /// agent wrote and then stayed quiet for 15 ms, and at most 250 ms after the first resize
    /// it waits for, so resizing without pause cannot hold drawing longer.
    pub(crate) fn waits_for_redraw(&self, now: Instant) -> bool {
        self.redraw.is_some_and(|wait| {
            now < wait.until && wait.heard.is_none_or(|heard| now < heard + REDRAW_QUIET)
        }) && self.shows_running()
    }

    fn shows_running(&self) -> bool {
        self.selected
            .checked_sub(1)
            .and_then(|index| self.tabs.get(index))
            .and_then(|tab| tab.agents.get(tab.selected))
            .is_some_and(|running| running.ending == Ending::Running)
    }

    /// Takes what the user typed: the workspace's own keys, which follow the palette key, and
    /// on a thread's tab the rest, for its shown agent; on the thread list the rest goes to
    /// `threads`.
    pub(crate) fn type_keys(&mut self, typed: &[u8], threads: &mut Vec<u8>) -> Moved {
        let before = self.view_state();
        let mut joined = std::mem::take(&mut self.mouse.joined);
        let mut new = false;
        for piece in split_mouse(self.join_carried(typed, &mut joined)) {
            match piece {
                Typed::Keys(keys) => self.type_plain(keys, threads),
                Typed::Mouse(event) => new |= self.click(event),
            }
        }
        self.mouse.joined = joined;
        let chosen = self.chosen.take();
        if new {
            Moved::New
        } else if let Some(chosen) = chosen {
            chosen
        } else if self.view_state() == before {
            Moved::Nothing
        } else {
            Moved::Shown
        }
    }

    fn view_state(&self) -> ViewState {
        (
            self.shown_place(),
            self.shown_id(),
            self.list_shown,
            self.palette
                .as_ref()
                .and_then(|palette| palette.menu.selected()),
        )
    }

    /// Takes what was typed while no tab is open: every key goes to `threads`, and a mouse
    /// report, which the terminal may still send just after the last tab closed, is dropped.
    pub(crate) fn type_without_tabs(&mut self, typed: &[u8], threads: &mut Vec<u8>) {
        let mut joined = std::mem::take(&mut self.mouse.joined);
        for piece in split_mouse(self.join_carried(typed, &mut joined)) {
            if let Typed::Keys(keys) = piece {
                threads.extend_from_slice(keys);
            }
        }
        self.mouse.joined = joined;
        self.mouse.dragging = false;
    }

    /// Returns `typed` after what was carried from the last read, put together in `joined`
    /// when there is any, and keeps for the next read the start of a mouse report it ends
    /// with.
    fn join_carried<'t>(&mut self, typed: &'t [u8], joined: &'t mut Vec<u8>) -> &'t [u8] {
        joined.clear();
        let whole: &[u8] = if self.mouse.carried.is_empty() {
            typed
        } else {
            joined.append(&mut self.mouse.carried);
            joined.extend_from_slice(typed);
            joined
        };
        let kept = whole.len() - cut_report(whole);
        match whole.get(kept..) {
            Some(tail) if tail.starts_with(b"\x1b[<") => {
                self.mouse.carried.extend_from_slice(tail);
                whole.get(..kept).unwrap_or_default()
            }
            _ => whole,
        }
    }

    /// Acts on a mouse event: a click on the row of tabs or the list of agents is the
    /// workspace's, and the rest of a thread's tab is the shown agent's, when it asked for the
    /// mouse, as is all of a drag that began in its pane, even once the palette opened over it,
    /// which takes no other mouse event; returns whether `+` was clicked.
    fn click(&mut self, event: MouseEvent) -> bool {
        let position = Position::new(event.column, event.row);
        let area = Rect::new(0, 0, self.screen.cols, self.screen.rows);
        let (bar, body) = TopBar::split(area);
        let dragged = self.mouse.dragging && (event.is_motion() || !event.pressed);
        if !event.pressed {
            self.mouse.dragging = false;
        }
        if dragged {
            self.give_agent(event, body, position, true);
            return false;
        }
        if self.palette.is_some() {
            return false;
        }
        if bar.contains(position) {
            if !event.is_left_click() {
                return false;
            }
            let titles: Vec<WorkspaceTab<'_>> = self.tab_titles().collect();
            match (TabBar {
                tabs: &titles,
                selected: self.selected,
            })
            .tab_at(event.column - bar.x)
            {
                TabHit::Tab(index) => self.step(Step::To(index)),
                TabHit::New => return true,
                TabHit::Nothing => {}
            }
            return false;
        }
        let list = self.list_place(body.width);
        let Some(tab) = self
            .selected
            .checked_sub(1)
            .and_then(|index| self.tabs.get_mut(index))
        else {
            return false;
        };
        let teammates = teammates_of(self.live.as_ref(), tab.thread);
        let agents = tab.listed(teammates);
        let hit = ThreadView {
            agents: &agents,
            selected: tab.selected,
            list,
            hints: &[],
            waiting: None,
        }
        .list_at(body, position);
        drop(agents);
        match hit {
            Some(ListHit::Agent(index)) if event.is_left_click() => {
                tab.select(index, teammates);
                return false;
            }
            Some(_) => return false,
            None => {}
        }
        let reached = self.give_agent(event, body, position, !event.pressed || event.is_motion());
        if reached && event.pressed && !event.is_motion() {
            self.mouse.dragging = true;
        }
        false
    }

    /// Gives a mouse event at `position` to the shown agent, at its own cell of the pane drawn
    /// in `body`, the nearest one when `clamp`, if the agent asked for it; returns whether it
    /// did.
    fn give_agent(
        &mut self,
        event: MouseEvent,
        body: Rect,
        position: Position,
        clamp: bool,
    ) -> bool {
        let list = self.list_place(body.width);
        let Some(tab) = self
            .selected
            .checked_sub(1)
            .and_then(|index| self.tabs.get_mut(index))
        else {
            return false;
        };
        let point = ThreadView {
            agents: &[],
            selected: 0,
            list,
            hints: &[],
            waiting: None,
        }
        .pane_point(body, position, clamp);
        let (Some(point), Some(running)) = (point, tab.agents.get_mut(tab.selected)) else {
            return false;
        };
        self.mouse.encoded.clear();
        if !event.encode(
            agent_mouse(running.child.screen()),
            point,
            &mut self.mouse.encoded,
        ) {
            return false;
        }
        running.child.send(&self.mouse.encoded).is_ok()
    }

    fn type_plain(&mut self, typed: &[u8], threads: &mut Vec<u8>) {
        let mut scanner =
            std::mem::replace(&mut self.scanner, KeyScanner::new(PaletteKey::default()));
        for segment in scanner.scan(typed) {
            match segment {
                Segment::Palette(key) => {
                    if self.palette.take().is_some() {
                        self.send(key);
                    } else {
                        self.open_palette(key);
                    }
                }
                Segment::Pass(bytes) => {
                    let used = self.palette_keys(bytes);
                    self.pass(bytes.get(used..).unwrap_or_default(), threads);
                }
            }
        }
        self.scanner = scanner;
    }

    /// Opens the palette, which the palette key `key` opened, with the entries for what is
    /// shown: the thread list and the tabs, the shown tab's other agents, the next agent waiting,
    /// the list, the palette key itself for the shown agent, and quitting.
    fn open_palette(&mut self, key: &[u8]) {
        let mut items = Vec::new();
        let mut entries = Vec::new();
        let mut add = |item: String, key: String, entry: Entry| {
            items.push((item, key));
            entries.push(entry);
        };
        add(
            "Go to the thread list".to_owned(),
            "0".to_owned(),
            Entry::Step(Step::To(0)),
        );
        for (index, tab) in self.tabs.iter().enumerate() {
            let place = index + 1;
            let key = if place <= 9 {
                place.to_string()
            } else {
                String::new()
            };
            let shown = if place == self.selected {
                " (shown)"
            } else {
                ""
            };
            add(
                format!("Go to thread {}{shown}", tab.title),
                key,
                Entry::Step(Step::To(place)),
            );
        }
        let shown = self
            .selected
            .checked_sub(1)
            .and_then(|index| self.tabs.get(index));
        if let Some(tab) = shown {
            let teammates = teammates_of(self.live.as_ref(), tab.thread);
            let slots = teammates.into_iter().flat_map(Teammates::agents);
            let entries = (0..tab.agents.len())
                .map(Entry::Agent)
                .chain(slots.map(|(slot, _)| Entry::Teammate(slot.clone())));
            let others = tab
                .listed(teammates)
                .into_iter()
                .zip(entries)
                .enumerate()
                .filter(|(index, _)| *index != tab.selected);
            for (_, (agent, entry)) in others {
                add(agent.palette_label(), String::new(), entry);
            }
        }
        add(
            "Go to the next agent waiting for you".to_owned(),
            "Space".to_owned(),
            Entry::Step(Step::Waiting),
        );
        let list = if self.list_shown { "Hide" } else { "Show" };
        add(
            format!("{list} the agents' list"),
            "b".to_owned(),
            Entry::Step(Step::List),
        );
        if self.shows_running() {
            add(
                "Show this agent's held turns".to_owned(),
                "p".to_owned(),
                Entry::AgentPalette,
            );
            add(
                format!("Pass {} through to the agent", self.palette_name),
                self.palette_name.clone(),
                Entry::SendKey,
            );
        }
        if shown.is_some_and(|tab| tab.thread.is_some()) {
            for (choice, label) in THREAD_ACTIONS {
                add(label.to_owned(), String::new(), Entry::Act(choice));
            }
        }
        if shown.is_some_and(|tab| tab.watch_only && tab.agents.is_empty()) {
            add("Leave this tab".to_owned(), String::new(), Entry::Leave);
        }
        add("Quit mahi".to_owned(), "q".to_owned(), Entry::Quit);
        let title = shown.map_or("threads", |tab| tab.title.as_str());
        self.palette = Some(Palette {
            menu: Dialog::menu(title, items),
            entries,
            keys: PaletteKeys::default(),
            key: key.to_vec(),
        });
    }

    /// Reads `bytes` as the open palette's keys, doing what they choose and closing it when
    /// one does; returns how many it used, none when it is closed, so the rest goes on.
    fn palette_keys(&mut self, bytes: &[u8]) -> usize {
        let Some(palette) = self.palette.as_mut() else {
            return 0;
        };
        let mut chosen = None;
        let mut closed = false;
        let used = palette.keys.read(bytes, |input| {
            let entry = match input {
                PaletteInput::Text(digit @ '0'..='9') => digit
                    .to_digit(10)
                    .and_then(|digit| usize::try_from(digit).ok())
                    .map(|place| Entry::Step(Step::To(place))),
                PaletteInput::Text('b') => Some(Entry::Step(Step::List)),
                PaletteInput::Text(' ') => Some(Entry::Step(Step::Waiting)),
                PaletteInput::Text('q') => Some(Entry::Quit),
                PaletteInput::Text('p') => Some(Entry::AgentPalette),
                PaletteInput::Left => Some(Entry::Step(Step::Previous)),
                PaletteInput::Right => Some(Entry::Step(Step::Next)),
                other => match palette.menu.key(other) {
                    Some(Answer::Choice(index)) => palette.entries.get(index).cloned(),
                    Some(Answer::Cancelled) => {
                        closed = true;
                        None
                    }
                    _ => None,
                },
            };
            closed |= entry.is_some();
            chosen = entry;
            !closed
        });
        if closed {
            let key = self.palette.take().map(|palette| palette.key);
            match chosen {
                Some(Entry::Step(step)) => self.step(step),
                Some(Entry::Agent(index)) => self.show_agent(index),
                Some(Entry::Teammate(slot)) => self.show_teammate(&slot),
                Some(Entry::AgentPalette) if self.shows_running() => self.open_agent_palette(),
                Some(Entry::SendKey) if self.shows_running() => {
                    self.send(&key.unwrap_or_default());
                }
                Some(Entry::Act(choice)) => {
                    self.chosen = self.shown_thread().map(|thread| Moved::Act(choice, thread));
                }
                Some(Entry::Quit) => self.chosen = Some(Moved::Quit),
                Some(Entry::Leave) => self.leave_tab(),
                Some(Entry::AgentPalette | Entry::SendKey) | None => {}
            }
        }
        used
    }

    fn shown_thread(&self) -> Option<ThreadId> {
        self.selected
            .checked_sub(1)
            .and_then(|index| self.tabs.get(index))
            .and_then(|tab| tab.thread)
    }

    /// Shows the open tab of `thread`, telling `told`, a label and its text, on its last line;
    /// returns whether a tab of the thread is open.
    pub(crate) fn show_thread(
        &mut self,
        thread: ThreadId,
        (label, text): (&'static str, &str),
    ) -> bool {
        let Some(index) = self.tabs.iter().position(|tab| tab.thread == Some(thread)) else {
            return false;
        };
        self.selected = index + 1;
        self.palette = None;
        self.told = Some(Told {
            label,
            text: text.to_owned(),
            at: Instant::now(),
            thread,
        });
        true
    }

    /// Shows the thread list, where an action's outcome is told.
    pub(crate) fn show_threads(&mut self) {
        self.step(Step::To(0));
    }

    fn show_agent(&mut self, index: usize) {
        if let Some(tab) = self
            .selected
            .checked_sub(1)
            .and_then(|at| self.tabs.get_mut(at))
            .filter(|tab| index < tab.agents.len())
        {
            let teammates = teammates_of(self.live.as_ref(), tab.thread);
            tab.select(index, teammates);
        }
    }

    fn show_teammate(&mut self, slot: &AgentSlot) {
        if let Some(tab) = self
            .selected
            .checked_sub(1)
            .and_then(|at| self.tabs.get_mut(at))
        {
            let teammates = teammates_of(self.live.as_ref(), tab.thread);
            tab.select_teammate(slot, teammates);
        }
    }

    /// Says whether the palette is open.
    pub(crate) fn palette_open(&self) -> bool {
        self.palette.is_some()
    }

    /// Draws the open palette over `area`.
    pub(crate) fn render_palette(&self, area: Rect, buffer: &mut Buffer) {
        if let Some(palette) = &self.palette {
            palette.menu.render(area, buffer);
        }
    }

    fn pass(&mut self, bytes: &[u8], threads: &mut Vec<u8>) {
        if self.selected == 0 {
            threads.extend_from_slice(bytes);
        } else {
            self.send(bytes);
        }
    }

    /// Forgets what the tab's last line told once it has shown long enough; returns whether
    /// it did, so the screen is drawn again without it.
    pub(crate) fn forget_told(&mut self) -> bool {
        let old = self
            .told
            .as_ref()
            .is_some_and(|told| told.at.elapsed() >= TOLD_FOR);
        if old {
            self.told = None;
        }
        old
    }

    /// Asks the shown agent's mahi to open its own palette; a request its pipe has no room for
    /// is dropped, so a child that stops reading never holds the workspace up.
    fn open_agent_palette(&mut self) {
        if let Some(commands) = self
            .shown_mut()
            .and_then(|running| running.commands.as_mut())
        {
            let _ = commands.write_all(&[crate::commands::OPEN_PALETTE]);
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
            Step::List => self.list_shown = !self.list_shown,
            Step::Waiting => self.show_next_waiting(),
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

    /// Draws the top row, its tabs and `header`, into `bar` and, on a thread's tab, the tab
    /// into `body`; returns where the shown agent's cursor is.
    pub(crate) fn render(
        &self,
        header: Header<'_>,
        bar: Rect,
        body: Rect,
        buffer: &mut Buffer,
    ) -> Option<Position> {
        let tabs: Vec<WorkspaceTab<'_>> = self.tab_titles().collect();
        TopBar {
            tabs: Some(TabBar {
                tabs: &tabs,
                selected: self.selected,
            }),
            header,
        }
        .render(bar, buffer);
        let tab = self.tabs.get(self.selected.checked_sub(1)?)?;
        let teammates = teammates_of(self.live.as_ref(), tab.thread);
        let agents = tab.listed(teammates);
        let shown = tab.agents.get(tab.selected);
        let failed = shown.is_some_and(|running| running.ending == Ending::Failed);
        let screen = tab.screen(teammates);
        let failed_hints = [
            ("any key", "close it"),
            (self.palette_name.as_str(), "palette"),
        ];
        let hints = [(self.palette_name.as_str(), "palette")];
        let told = self
            .told
            .as_ref()
            .filter(|told| told.at.elapsed() < TOLD_FOR && tab.thread == Some(told.thread))
            .map(|told| [(told.label, told.text.as_str())]);
        let cursor = ThreadView {
            agents: &agents,
            selected: tab.selected,
            list: self.list_place(body.width),
            hints: match &told {
                _ if failed => &failed_hints,
                Some(told) => told,
                None => &hints,
            },
            waiting: self.waiting(),
        }
        .render(screen, body, buffer);
        cursor.filter(|_| shown.is_some())
    }

    fn tab_titles(&self) -> impl Iterator<Item = WorkspaceTab<'_>> {
        self.tabs.iter().map(|tab| WorkspaceTab {
            title: &tab.title,
            asks: tab
                .agents
                .iter()
                .any(|running| running.state == AgentState::AsksYou),
        })
    }

    /// Takes what the child `id` reported about its agent, writing to `out` the bell and a
    /// notification when it starts to ask in a tab not shown; returns whether what the screen
    /// shows changed.
    fn take_report(&mut self, id: usize, report: &Report, out: &mut Vec<u8>) -> bool {
        let Some(place) = self
            .tabs
            .iter()
            .position(|tab| tab.agents.iter().any(|running| running.id == id))
        else {
            return false;
        };
        let hidden = self.selected != place + 1;
        let Some(tab) = self.tabs.get_mut(place) else {
            return false;
        };
        if let Report::Thread(thread) = report {
            let thread = *thread;
            let renamed = tab.title == NEW_TAB;
            if renamed {
                let mut title = thread.to_string();
                title.truncate(SHORT_THREAD);
                tab.title = title;
            }
            if tab.thread.is_none() {
                tab.thread = Some(thread);
                self.host(thread);
            }
            return renamed;
        }
        let Some(running) = tab.agents.iter_mut().find(|running| running.id == id) else {
            return false;
        };
        match report {
            Report::Working => running.state = AgentState::Working,
            Report::Done => running.state = AgentState::Done,
            Report::Asks => {
                let quiet = running
                    .told_asks
                    .is_none_or(|told| told.elapsed() >= ASKS_TOLD_EVERY);
                if hidden && running.state != AgentState::AsksYou && quiet {
                    let title = format!("mahi {}", tab.title);
                    let text = format!("{} asks you", running.name);
                    self.notice.write(&title, &text, out);
                    running.told_asks = Some(Instant::now());
                }
                running.state = AgentState::AsksYou;
            }
            Report::Thread(_) => {}
        }
        true
    }

    fn host(&mut self, thread: ThreadId) {
        let Some(live) = &mut self.live else {
            return;
        };
        match live.host(thread) {
            Ok(()) => {
                self.live_failed.remove(&thread);
            }
            Err(error) => {
                if self.live_failed.insert(thread) {
                    self.live_told =
                        Some(format!("teammates cannot watch thread {thread}: {error}"));
                }
            }
        }
    }

    /// Tries again, at most every [`HOST_AGAIN`], to host the open threads the workspace does
    /// not host: one whose hosting failed, or that another of the user's mahis hosted and left.
    fn host_again(&mut self) {
        if self.live.is_none() || self.live_tried.elapsed() < HOST_AGAIN {
            return;
        }
        self.live_tried = Instant::now();
        let unhosted: Vec<ThreadId> = self
            .tabs
            .iter()
            .filter_map(|tab| tab.thread)
            .filter(|&thread| self.live.as_ref().is_some_and(|live| !live.hosts(thread)))
            .collect();
        for thread in unhosted {
            self.host(thread);
        }
    }

    /// Shows the next agent after the one shown, in any tab, that asks the user, is done or
    /// failed, if there is one.
    fn show_next_waiting(&mut self) {
        let flat: Vec<(usize, usize, bool)> = self
            .tabs
            .iter()
            .enumerate()
            .flat_map(|(tab, agents)| {
                agents
                    .agents
                    .iter()
                    .enumerate()
                    .map(move |(agent, running)| {
                        let waiting = running.ending == Ending::Failed
                            || matches!(running.state, AgentState::Done | AgentState::AsksYou);
                        (tab, agent, waiting)
                    })
            })
            .collect();
        let start = self.selected.checked_sub(1).map_or(0, |tab| {
            let agent = self.tabs.get(tab).map_or(0, |shown| shown.selected);
            flat.iter()
                .position(|&(at_tab, at_agent, _)| {
                    at_tab > tab || (at_tab == tab && at_agent > agent)
                })
                .unwrap_or(0)
        });
        let next = (0..flat.len())
            .map(|offset| (start + offset) % flat.len())
            .filter_map(|index| flat.get(index))
            .find(|&&(_, _, waiting)| waiting);
        if let Some(&(tab, agent, _)) = next {
            self.selected = tab + 1;
            if let Some(tab) = self.tabs.get_mut(tab) {
                tab.select(agent, None);
            }
        }
    }

    /// Returns the tab shown and, on a thread's tab, the place of its shown agent in its
    /// list, the user's own or a teammate's.
    fn shown_place(&self) -> (usize, Option<usize>) {
        let agent = self
            .selected
            .checked_sub(1)
            .and_then(|index| self.tabs.get(index))
            .map(|tab| tab.selected);
        (self.selected, agent)
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

/// What decides whether the screen changed: the place shown, the agent shown, whether the
/// list is shown, and the palette's selection while it is open.
type ViewState = ((usize, Option<usize>), Option<usize>, bool, Option<usize>);

/// A move the workspace's keys make between tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Waiting,
    To(usize),
    Next,
    Previous,
    List,
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
    use mahi_term::TerminalHints;

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
            state: AgentState::Done,
            told_asks: None,
            commands: None,
        }
    }

    fn tab(title: &str, agents: Vec<Running>) -> Tab {
        Tab {
            title: title.to_owned(),
            thread: None,
            agents,
            selected: 0,
            watching: None,
            watch_only: false,
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
    fn drawing_waits_after_a_resize_until_the_shown_agent_redraws_or_briefly() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let agent = running(
            &mut workspace,
            "trap 'printf redrawn' WINCH; printf ready; while :; do sleep 0.01; done",
        );
        workspace.tabs.push(tab("a", vec![agent]));
        workspace.selected = 1;
        let mut out = Vec::new();
        let shown = |workspace: &Workspace, text: &str| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains(text)
        };
        settle(&mut workspace, &mut out, |workspace| {
            shown(workspace, "ready")
        });
        assert!(!workspace.waits_for_redraw(Instant::now()));
        let start = Instant::now();
        workspace.resize(WindowSize { rows: 6, cols: 30 });
        let until = workspace.redraw.unwrap().until;
        assert!(until >= start + REDRAW_WAIT);
        assert!(workspace.waits_for_redraw(start));
        assert!(!workspace.waits_for_redraw(until));
        let far = start + Duration::from_secs(600);
        workspace.redraw.as_mut().unwrap().until = far;
        settle(&mut workspace, &mut out, |workspace| {
            shown(workspace, "redrawn")
        });
        let heard = workspace.redraw.unwrap().heard.unwrap();
        assert!(workspace.waits_for_redraw(heard + REDRAW_QUIET / 2));
        assert!(!workspace.waits_for_redraw(heard + REDRAW_QUIET));
        workspace.resize(SIZE);
        let again = workspace.redraw.unwrap();
        assert_eq!((again.until, again.heard), (far, None));
        assert!(workspace.waits_for_redraw(heard + REDRAW_QUIET));
        workspace.selected = 0;
        assert!(!workspace.waits_for_redraw(start));
        workspace.selected = 1;
        workspace.tabs[0].agents[0].ending = Ending::Drawn;
        workspace.resize(WindowSize { rows: 6, cols: 30 });
        assert!(!workspace.waits_for_redraw(start));
    }

    #[test]
    fn the_hints_name_the_palette_key_the_user_chose() {
        let mut workspace = Workspace::new(
            "f5".parse().unwrap(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let agent = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("a", vec![agent]));
        workspace.selected = 1;
        let footer = |workspace: &Workspace| {
            let mut buffer = Buffer::empty(Rect::new(0, 0, 120, 12));
            workspace.render(
                Header {
                    repository: "r",
                    remote: "none chosen",
                    remote_chosen: false,
                    remote_key: false,
                    identity: "me",
                },
                Rect::new(0, 0, 120, 1),
                Rect::new(0, 1, 120, 11),
                &mut buffer,
            );
            (0..120)
                .filter_map(|x| buffer.cell((x, 11)).map(|cell| cell.symbol().to_owned()))
                .collect::<String>()
        };
        let shown = footer(&workspace);
        assert_eq!(shown.trim_end(), "F5 palette");
        workspace.tabs[0].agents[0].ending = Ending::Failed;
        let shown = footer(&workspace);
        assert_eq!(shown.trim_end(), "any key close it  F5 palette");
    }

    #[test]
    fn resuming_a_thread_whose_agent_runs_shows_it_instead_of_starting_another() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let failed = running(&mut workspace, "sleep 5");
        let agent = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("4799a3af", vec![failed, agent]));
        workspace.tabs[0].agents[0].ending = Ending::Failed;
        assert!(!workspace.show_running("other"));
        assert!(workspace.show_running("4799a3af"));
        assert_eq!((workspace.selected, workspace.tabs[0].selected), (1, 1));
        workspace.selected = 0;
        assert!(workspace.show_running("4799a3af"));
        assert_eq!((workspace.selected, workspace.tabs[0].selected), (1, 1));
        workspace.tabs[0].selected = 2;
        workspace.tabs[0].watching = Some("bob.claude".parse().unwrap());
        assert!(workspace.show_running("4799a3af"));
        assert_eq!(workspace.tabs[0].selected, 1);
        assert!(workspace.tabs[0].watching.is_none());
        workspace.tabs[0].agents[1].ending = Ending::Drawn;
        workspace.selected = 0;
        assert!(!workspace.show_running("4799a3af"));
        assert_eq!(workspace.selected, 0);
    }

    #[test]
    fn moving_between_tabs_wraps_and_a_tab_that_is_not_there_is_ignored() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
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
    fn the_palette_lists_where_to_go_and_what_to_do_and_its_keys_act_at_once() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let first = running(&mut workspace, "sleep 5");
        let second = running(&mut workspace, "sleep 5");
        let (first_id, second_id) = (first.id, second.id);
        workspace.tabs.push(tab("a", vec![first, second]));
        workspace.selected = 1;
        let mut threads = Vec::new();
        assert_eq!(workspace.type_keys(b"\x00", &mut threads), Moved::Shown);
        let palette = workspace.palette.as_ref().unwrap();
        assert_eq!(
            palette.entries,
            [
                Entry::Step(Step::To(0)),
                Entry::Step(Step::To(1)),
                Entry::Agent(1),
                Entry::Step(Step::Waiting),
                Entry::Step(Step::List),
                Entry::AgentPalette,
                Entry::SendKey,
                Entry::Quit,
            ]
        );
        let mut buffer = Buffer::empty(Rect::new(0, 0, 80, 20));
        workspace.render_palette(buffer.area, &mut buffer);
        let drawn: String = buffer
            .content()
            .iter()
            .map(ratatui_core::buffer::Cell::symbol)
            .collect();
        for item in [
            "Go to the thread list",
            "Go to thread a (shown)",
            "Show agent agent (✓ done)",
            "Go to the next agent waiting for you",
            "Hide the agents' list",
            "Show this agent's held turns",
            "Pass Ctrl-Space through to the agent",
            "Quit mahi",
        ] {
            assert!(drawn.contains(item), "{item}: {drawn}");
        }
        assert_eq!(
            workspace.type_keys(b"\x1b[B\x1b[B", &mut threads),
            Moved::Shown
        );
        assert_eq!(workspace.type_keys(b"\r", &mut threads), Moved::Shown);
        assert!(!workspace.palette_open());
        assert_eq!(workspace.shown_id(), Some(second_id));
        assert_eq!(workspace.list_place(120), ListPlace::Beside);
        assert_eq!(workspace.type_keys(b"\x00b", &mut threads), Moved::Shown);
        assert_eq!(workspace.list_place(120), ListPlace::Hidden);
        workspace.type_keys(b"\x00b", &mut threads);
        assert_eq!(workspace.list_place(80), ListPlace::Over);
        workspace.type_keys(b"\x00", &mut threads);
        assert_eq!(workspace.type_keys(b"\x1b", &mut threads), Moved::Shown);
        assert!(!workspace.palette_open());
        assert_eq!(workspace.type_keys(b"\x00q", &mut threads), Moved::Quit);
        assert!(threads.is_empty());
        workspace.tabs[0].select(0, None);
        assert_eq!(workspace.shown_id(), Some(first_id));
    }

    #[test]
    fn the_palette_marks_only_the_shown_tab_and_none_on_the_thread_list() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let first = running(&mut workspace, "sleep 5");
        let second = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("a", vec![first]));
        workspace.tabs.push(tab("b", vec![second]));
        let drawn = |workspace: &mut Workspace| {
            let mut threads = Vec::new();
            workspace.type_keys(b"\x00", &mut threads);
            let mut buffer = Buffer::empty(Rect::new(0, 0, 80, 20));
            workspace.render_palette(buffer.area, &mut buffer);
            workspace.type_keys(b"\x1b", &mut threads);
            buffer
                .content()
                .iter()
                .map(ratatui_core::buffer::Cell::symbol)
                .collect::<String>()
        };
        workspace.selected = 2;
        let shown = drawn(&mut workspace);
        assert!(shown.contains("Go to thread a "), "{shown}");
        assert!(!shown.contains("Go to thread a (shown)"), "{shown}");
        assert!(shown.contains("Go to thread b (shown)"), "{shown}");
        workspace.selected = 0;
        let shown = drawn(&mut workspace);
        assert!(!shown.contains("(shown)"), "{shown}");
    }

    #[test]
    fn typing_on_a_teammates_agent_reaches_no_one_and_opens_nothing() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let thread: ThreadId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        workspace.watch_thread(thread);
        workspace.tabs[0].watching = Some(AgentSlot::new(
            mahi_core::ParticipantName::new("alice").unwrap(),
            mahi_core::AgentName::new("claude").unwrap(),
        ));
        let mut threads = Vec::new();
        assert_eq!(
            workspace.type_keys(b"hello\r", &mut threads),
            Moved::Nothing
        );
        assert!(threads.is_empty());
        assert!(!workspace.palette_open());
        assert!(workspace.told.is_none());
    }

    #[test]
    fn a_tab_that_watches_a_hosted_thread_spins_until_it_lists_an_agent() {
        let setup = crate::workspace_live::tests::setup();
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        workspace.host_with(Some(crate::workspace_live::tests::hosting(&setup)));
        let now = Instant::now();
        assert!(!workspace.spin(now));
        workspace.watch_thread(setup.thread);
        assert!(workspace.spin(now));
        assert_eq!(
            workspace.waiting(),
            Some(("⠋", "waiting for the thread's host"))
        );
        assert!(!workspace.spin(now + SPIN_EVERY / 2));
        assert!(workspace.spin(now + SPIN_EVERY));
        assert_eq!(workspace.waiting().map(|(frame, _)| frame), Some("⠙"));
        let agent = running(&mut workspace, "sleep 5");
        workspace.tabs[0].agents.push(agent);
        assert!(workspace.spin(now + SPIN_EVERY * 2));
        assert_eq!(workspace.waiting(), None);
        assert!(!workspace.spin(now + SPIN_EVERY * 3));
    }

    #[test]
    fn a_tab_that_watches_a_thread_the_workspace_cannot_host_does_not_spin() {
        let setup = crate::workspace_live::tests::setup();
        for live in [
            None,
            WorkspaceLive::new(&setup.environment, &setup.config, setup.store.common_dir()),
        ] {
            let mut workspace = Workspace::new(
                PaletteKey::default(),
                Notice::for_terminal(TerminalHints::default()),
            );
            workspace.host_with(live);
            workspace.watch_thread(setup.thread);
            assert!(!workspace.spin(Instant::now()));
            assert_eq!(workspace.waiting(), None);
        }
    }

    #[test]
    fn a_tab_that_watches_a_joined_thread_stays_until_the_user_leaves_it() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let thread: ThreadId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        workspace.watch_thread(thread);
        assert_eq!(workspace.selected, 1);
        assert_eq!(workspace.tabs[0].title, "01234567");
        let _ = workspace.take_ended();
        assert_eq!(workspace.tabs.len(), 1);
        workspace.watch_thread(thread);
        assert_eq!(workspace.tabs.len(), 1);
        let mut threads = Vec::new();
        workspace.type_keys(b"\x00", &mut threads);
        let entries = &workspace.palette.as_ref().unwrap().entries;
        let leave = entries
            .iter()
            .position(|entry| *entry == Entry::Leave)
            .unwrap();
        let moves = b"\x1b[B".repeat(leave);
        workspace.type_keys(&[moves, b"\r".to_vec()].concat(), &mut threads);
        assert!(workspace.tabs.is_empty());
        assert_eq!(workspace.selected, 0);
        let agent = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("01234567", vec![agent]));
        workspace.tabs[0].thread = Some(thread);
        workspace.watch_thread(thread);
        assert_eq!(workspace.tabs.len(), 1);
        assert!(workspace.tabs[0].watch_only);
        workspace.tabs[0].agents.clear();
        workspace.leave_thread(thread);
        assert!(workspace.tabs.is_empty());
    }

    #[test]
    fn showing_a_thread_selects_its_open_tab_and_tells_on_its_last_line() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let thread: ThreadId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let other: ThreadId = "fedcba9876543210fedcba9876543210".parse().unwrap();
        assert!(!workspace.show_thread(thread, ("invite", "done")));
        let agent = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("fedcba98", vec![agent]));
        workspace.tabs[0].thread = Some(other);
        let agent = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("01234567", vec![agent]));
        workspace.tabs[1].thread = Some(thread);
        assert!(workspace.shows_threads());
        assert!(workspace.show_thread(thread, ("invite", "done")));
        assert_eq!(workspace.selected, 2);
        let mut buffer = Buffer::empty(Rect::new(0, 0, 80, 20));
        workspace.render(
            Header {
                repository: "r",
                remote: "origin (private)",
                remote_chosen: true,
                remote_key: false,
                identity: "me",
            },
            Rect::new(0, 0, 80, 1),
            Rect::new(0, 1, 80, 19),
            &mut buffer,
        );
        let drawn: String = buffer
            .content()
            .iter()
            .map(ratatui_core::buffer::Cell::symbol)
            .collect();
        assert!(drawn.contains("invite done"), "{drawn}");
        assert!(workspace.palette.is_none());
        assert!(!workspace.forget_told());
        assert!(workspace.told.is_some());
        if let Some(told) = workspace.told.as_mut() {
            told.at = Instant::now().checked_sub(TOLD_FOR).unwrap();
        }
        assert!(workspace.forget_told());
        assert!(workspace.told.is_none());
        assert!(!workspace.forget_told());
    }

    #[test]
    fn a_purged_thread_closes_only_its_watching_tab_and_says_its_owner_purged_it() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let watched: ThreadId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let running_in: ThreadId = "fedcba9876543210fedcba9876543210".parse().unwrap();
        workspace.watch_thread(watched);
        let agent = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("fedcba98", vec![agent]));
        workspace.tabs[1].thread = Some(running_in);
        workspace.selected = 1;
        assert!(!workspace.leave_purged_threads(&[running_in]));
        assert_eq!(workspace.tabs.len(), 2);
        assert!(workspace.live_told.is_none());
        assert!(workspace.leave_purged_threads(&[watched]));
        assert_eq!(workspace.tabs.len(), 1);
        assert_eq!(workspace.tabs[0].thread, Some(running_in));
        assert!(workspace.shows_threads());
        assert_eq!(
            workspace.live_told.as_deref(),
            Some("thread 0123456789abcdef0123456789abcdef was purged by its owner")
        );
    }

    #[test]
    fn hiding_the_shown_agent_puts_its_key_modes_back_on_the_next_apply() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let agent = running(&mut workspace, "sleep 5");
        let id = agent.id;
        workspace.tabs.push(tab("a", vec![agent]));
        workspace.selected = 1;
        let mut out = Vec::new();
        workspace.apply_shown(&mut out);
        assert_eq!(workspace.applied, Some(id));
        out.clear();
        workspace.hide_shown(&mut out);
        assert_eq!(workspace.applied, None);
        assert_eq!(out, b"\x1b[?2004h");
        out.clear();
        workspace.apply_shown(&mut out);
        assert_eq!(workspace.applied, Some(id));
        assert_eq!(out, b"\x1b[?2004l");
    }

    #[test]
    fn the_palette_lists_the_actions_on_the_shown_thread_once_its_tab_knows_it() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let agent = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("a", vec![agent]));
        workspace.selected = 1;
        let mut threads = Vec::new();
        workspace.type_keys(b"\x00", &mut threads);
        let entries = &workspace.palette.as_ref().unwrap().entries;
        assert!(!entries.iter().any(|entry| matches!(entry, Entry::Act(_))));
        workspace.type_keys(b"\x1b", &mut threads);
        let thread: ThreadId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        workspace.tabs[0].thread = Some(thread);
        workspace.type_keys(b"\x00", &mut threads);
        let entries = &workspace.palette.as_ref().unwrap().entries;
        let actions: Vec<&Entry> = entries
            .iter()
            .filter(|entry| matches!(entry, Entry::Act(_)))
            .collect();
        assert_eq!(
            actions,
            THREAD_ACTIONS
                .map(|(choice, _)| Entry::Act(choice))
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(entries.last(), Some(&Entry::Quit));
        let mut buffer = Buffer::empty(Rect::new(0, 0, 80, 24));
        workspace.render_palette(buffer.area, &mut buffer);
        let rows: Vec<String> = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect()
            })
            .collect();
        let row_of = |item: &str| {
            rows.iter()
                .find(|row| row.contains(item))
                .unwrap_or_else(|| panic!("{item} missing: {rows:#?}"))
        };
        for item in [
            "Add an agent to this thread",
            "Hand off to another of your agents",
            "Land this thread",
            "Push the landed commits",
            "End this thread",
            "Invite a teammate",
        ] {
            row_of(item);
        }
        let sent = row_of("Pass Ctrl-Space through to the agent");
        assert_eq!(sent.matches("Ctrl-Space").count(), 2, "{rows:#?}");
        let quit = row_of("Quit mahi").trim_end_matches(['│', '╯', ' ']);
        assert!(quit.ends_with(" q"), "{rows:#?}");
        let end = entries
            .iter()
            .position(|entry| *entry == Entry::Act(ThreadChoice::End))
            .unwrap();
        workspace.type_keys(&b"\x1b[B".repeat(end), &mut threads);
        assert_eq!(
            workspace.type_keys(b"\r", &mut threads),
            Moved::Act(ThreadChoice::End, thread)
        );
        assert!(!workspace.palette_open());
        assert_eq!(workspace.type_keys(b"x", &mut threads), Moved::Nothing);
    }

    #[test]
    fn the_palettes_choices_never_act_on_what_changed_since_it_opened() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let first = running(&mut workspace, "sleep 5");
        let second = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("a", vec![first, second]));
        workspace.selected = 1;
        let mut threads = Vec::new();
        workspace.type_keys(b"\x00", &mut threads);
        workspace.tabs[0].agents[0].ending = Ending::Closed;
        workspace.take_ended();
        assert!(!workspace.palette_open());
        workspace.type_keys(b"\x00", &mut threads);
        workspace.tabs[0].agents[0].ending = Ending::Failed;
        let send = workspace.palette.as_ref().unwrap().entries.len() - 2;
        let mut keys = b"\x1b[B".repeat(send);
        keys.push(b'\r');
        workspace.type_keys(&keys, &mut threads);
        assert!(!workspace.palette_open());
        assert_eq!(workspace.tabs[0].agents[0].ending, Ending::Failed);
        workspace.set_screen(WindowSize { rows: 24, cols: 80 }, false);
        workspace.type_keys(b"\x00", &mut threads);
        assert_eq!(
            workspace.type_keys(b"\x1b[<0;3;1M\x1b[<0;3;1m", &mut threads),
            Moved::Nothing
        );
        assert_eq!(workspace.selected, 1);
        assert!(workspace.palette_open());
        workspace.mouse.dragging = true;
        workspace.type_keys(b"\x1b[<0;10;10m", &mut threads);
        assert!(!workspace.mouse.dragging);
        assert!(workspace.palette_open());
    }

    #[test]
    fn a_teammates_agent_chosen_by_its_slot_is_found_wherever_the_list_moved_it() {
        let mut both = Teammates::new("alice".parse().unwrap());
        heard(&mut both, "bob.claude");
        heard(&mut both, "bob.codex");
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let own = running(&mut workspace, "sleep 5");
        let mut tab = tab("a", vec![own]);
        let codex: AgentSlot = "bob.codex".parse().unwrap();
        tab.select_teammate(&codex, Some(&both));
        assert_eq!((tab.selected, tab.watching.as_ref()), (2, Some(&codex)));
        let mut one = Teammates::new("alice".parse().unwrap());
        heard(&mut one, "bob.codex");
        tab.select(0, Some(&one));
        tab.select_teammate(&codex, Some(&one));
        assert_eq!((tab.selected, tab.watching.as_ref()), (1, Some(&codex)));
        tab.select_teammate(&"bob.gone".parse().unwrap(), Some(&one));
        assert_eq!((tab.selected, tab.watching.as_ref()), (1, Some(&codex)));
    }

    #[test]
    fn the_palette_key_twice_reaches_the_agent_as_does_its_entry() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let agent = running(&mut workspace, "stty raw -echo; cat -v");
        workspace.tabs.push(tab("a", vec![agent]));
        workspace.selected = 1;
        let mut threads = Vec::new();
        workspace.type_keys(b"\x00\x00x", &mut threads);
        assert!(!workspace.palette_open());
        workspace.type_keys(b"\x00\x1b[B\x1b[B\x1b[B\x1b[B\x1b[B\r", &mut threads);
        workspace.type_keys(b"\x00\x1b[32;5u\x1b[32;5u", &mut threads);
        let mut out = Vec::new();
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains("^@x^@^[[32;5u")
        });
        assert!(threads.is_empty());
    }

    fn heard(teammates: &mut Teammates, slot: &str) {
        let slot: AgentSlot = slot.parse().unwrap();
        let participant = slot.participant().clone();
        teammates.apply(
            &participant,
            mahi_live::Body::Heartbeat { slot },
            Instant::now(),
        );
    }

    #[test]
    fn a_tab_lists_the_users_agents_then_the_teammates_and_keeps_a_teammate_selected() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let own = running(&mut workspace, "sleep 5");
        let mut tab = tab("a", vec![own]);
        let mut teammates = Teammates::new("alice".parse().unwrap());
        heard(&mut teammates, "bob.claude");
        let listed: Vec<(Option<&str>, &str, AgentState)> = tab
            .listed(Some(&teammates))
            .iter()
            .map(|agent| (agent.owner, agent.name, agent.state))
            .collect();
        assert_eq!(
            listed,
            [
                (None, "agent", AgentState::Done),
                (Some("bob"), "claude", AgentState::Live),
            ]
        );
        tab.select(1, Some(&teammates));
        assert_eq!(tab.watching, Some("bob.claude".parse().unwrap()));
        assert!(tab.screen(Some(&teammates)).is_none());
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        let screen = mahi_live::Body::Screen {
            slot: bob.clone(),
            rows: 2,
            columns: 20,
            challenge: [1; 16],
            part: 0,
            parts: 1,
            bytes: b"bob's screen".to_vec(),
        };
        teammates.apply(bob.participant(), screen, Instant::now());
        assert_eq!(
            tab.screen(Some(&teammates)).map(vt100::Screen::contents),
            Some("bob's screen".to_owned())
        );
        heard(&mut teammates, "bob.aider");
        tab.reselect(Some(&teammates));
        assert_eq!(tab.selected, 2);
        tab.select(0, Some(&teammates));
        assert!(tab.watching.is_none());
        tab.select(2, Some(&teammates));
        tab.reselect(None);
        assert_eq!((tab.selected, tab.watching.is_none()), (0, true));
    }

    #[test]
    fn a_move_between_teammates_agents_is_shown_and_space_from_one_goes_to_the_next_tab() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let mut teammates = Teammates::new("alice".parse().unwrap());
        heard(&mut teammates, "bob.claude");
        heard(&mut teammates, "bob.codex");
        let first = running(&mut workspace, "sleep 5");
        let second = running(&mut workspace, "sleep 5");
        let second_id = second.id;
        let mut watching = tab("a", vec![first]);
        watching.select(1, Some(&teammates));
        workspace.tabs.push(watching);
        workspace.tabs.push(tab("b", vec![second]));
        workspace.selected = 1;
        let on_first = workspace.shown_place();
        workspace.tabs[0].select(2, Some(&teammates));
        assert_ne!(workspace.shown_place(), on_first);
        workspace.step(Step::Waiting);
        assert_eq!(workspace.shown_id(), Some(second_id));
    }

    #[test]
    fn no_key_reaches_an_agent_while_a_teammates_agent_is_shown() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let own = running(&mut workspace, "read line; echo \"got $line\"; sleep 5");
        let mut tab = tab("a", vec![own]);
        let mut teammates = Teammates::new("alice".parse().unwrap());
        heard(&mut teammates, "bob.claude");
        tab.select(1, Some(&teammates));
        workspace.tabs.push(tab);
        workspace.selected = 1;
        let (mut threads, mut out) = (Vec::new(), Vec::new());
        assert_eq!(workspace.shown_id(), None);
        workspace.type_keys(b"abc\r", &mut threads);
        if let Some(tab) = workspace.tabs.first_mut() {
            tab.select(0, None);
        }
        workspace.type_keys(b"xyz\r", &mut threads);
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains("got")
        });
        let contents = workspace.tabs[0].agents[0].child.screen().contents();
        assert!(contents.contains("got xyz"), "{contents}");
        assert!(!contents.contains("abc"), "{contents}");
        assert!(threads.is_empty());
    }

    #[test]
    fn a_click_on_a_tab_selects_it_and_one_on_plus_asks_for_a_new_thread() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        workspace.set_screen(
            WindowSize {
                rows: 30,
                cols: 100,
            },
            false,
        );
        for title in ["a", "b"] {
            let agent = running(&mut workspace, "sleep 5");
            workspace.tabs.push(tab(title, vec![agent]));
        }
        let mut threads = Vec::new();
        assert_eq!(
            workspace.type_keys(b"\x1b[<0;21;1M", &mut threads),
            Moved::Shown
        );
        assert_eq!(workspace.selected, 1);
        assert_eq!(
            workspace.type_keys(b"\x1b[<0;", &mut threads),
            Moved::Nothing
        );
        assert_eq!(workspace.type_keys(b"9;1M", &mut threads), Moved::Shown);
        assert_eq!(workspace.selected, 0);
        assert_eq!(
            workspace.type_keys(b"\x1b[<0;29;1M", &mut threads),
            Moved::New
        );
        assert_eq!(
            workspace.type_keys(b"\x1b[<0;29;1m", &mut threads),
            Moved::Nothing
        );
        assert_eq!(
            workspace.type_keys(b"\x1b[<0;3;1M", &mut threads),
            Moved::Nothing
        );
        assert_eq!(workspace.selected, 0);
        assert!(threads.is_empty(), "{threads:?}");
        let mut out = Vec::new();
        workspace.apply_shown(&mut out);
        assert!(out.ends_with(MOUSE_ON), "{out:?}");
    }

    #[test]
    fn a_click_in_the_pane_reaches_an_agent_that_asked_for_the_mouse_at_its_own_cell() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        workspace.set_screen(
            WindowSize {
                rows: 30,
                cols: 100,
            },
            false,
        );
        let asking = running(
            &mut workspace,
            "stty raw -echo; printf '\\033[?1000h\\033[?1006hready'; \
             dd bs=1 count=9 2>/dev/null | od -An -c | tr -d ' \\n'; echo; echo end",
        );
        let deaf = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("a", vec![asking, deaf]));
        workspace.selected = 1;
        let mut out = Vec::new();
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains("ready")
        });
        let mut threads = Vec::new();
        workspace.type_keys(b"\x1b[<0;2;3M", &mut threads);
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains("end")
        });
        let shown = workspace.tabs[0].agents[0].child.screen().contents();
        assert!(shown.contains("033[<0;1;1M"), "{shown}");
        let deaf = workspace.tabs[0].agents[1].child.screen().contents();
        assert!(!deaf.contains("[<"), "{deaf}");
        workspace.type_keys(b"\x1b[<0;80;5M", &mut threads);
        assert_eq!(workspace.tabs[0].selected, 1);
        assert_eq!(
            workspace.type_keys(b"\x1b[<0;2;3M", &mut threads),
            Moved::Nothing
        );
        assert!(threads.is_empty(), "{threads:?}");
        workspace.tabs.clear();
        workspace.selected = 0;
        out.clear();
        workspace.mouse.on = true;
        workspace.apply_shown(&mut out);
        assert_eq!(out, MOUSE_OFF);
    }

    #[test]
    fn a_drag_that_leaves_the_pane_still_ends_at_the_agent() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        workspace.set_screen(
            WindowSize {
                rows: 30,
                cols: 100,
            },
            false,
        );
        let asking = running(
            &mut workspace,
            "stty raw -echo; printf '\\033[?1002h\\033[?1006hready'; \
             dd bs=1 count=19 2>/dev/null | od -An -c | tr -d ' \\n'; echo; echo end",
        );
        workspace.tabs.push(tab("a", vec![asking]));
        workspace.selected = 1;
        let mut out = Vec::new();
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains("ready")
        });
        let mut threads = Vec::new();
        workspace.type_keys(b"\x1b[<0;2;3M", &mut threads);
        assert!(workspace.mouse.dragging);
        workspace.type_keys(b"\x1b[<0;90;5m", &mut threads);
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains("end")
        });
        let shown = workspace.tabs[0].agents[0].child.screen().contents();
        assert!(shown.contains("033[<0;1;1M033[<0;74;3m"), "{shown}");
        assert!(!workspace.mouse.dragging);
    }

    #[test]
    fn a_report_cut_when_the_last_tab_closed_never_reaches_the_thread_list() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let mut threads = Vec::new();
        workspace.mouse.carried.extend_from_slice(b"\x1b[<0;10");
        workspace.type_without_tabs(b";5mq", &mut threads);
        assert_eq!(threads, b"q");
        assert!(workspace.mouse.carried.is_empty());
        workspace.type_without_tabs(b"ab\x1b[<0;1;1Mc", &mut threads);
        assert_eq!(threads, b"qabc");
    }

    #[test]
    fn reports_set_an_agents_state_and_name_a_new_threads_tab() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let agent = running(&mut workspace, "sleep 5");
        let id = agent.id;
        workspace.tabs.push(tab(NEW_TAB, vec![agent]));
        let thread: mahi_core::ThreadId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        assert!(workspace.take_report(id, &Report::Thread(thread), &mut Vec::new()));
        assert_eq!(workspace.tabs[0].title, "01234567");
        assert!(!workspace.take_report(id, &Report::Thread(thread), &mut Vec::new()));
        assert!(workspace.take_report(id, &Report::Asks, &mut Vec::new()));
        assert!(workspace.tab_titles().next().unwrap().asks);
        workspace.take_report(id, &Report::Done, &mut Vec::new());
        assert_eq!(workspace.tabs[0].agents[0].state, AgentState::Done);
        assert!(!workspace.take_report(99, &Report::Done, &mut Vec::new()));
    }

    #[test]
    fn p_asks_the_shown_agents_mahi_to_open_its_palette_and_sends_its_agent_nothing() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let mut agent = running(&mut workspace, "stty raw -echo; echo ready; exec cat -v");
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        agent.commands = Some(File::from(writer));
        workspace.tabs.push(tab("a", vec![agent]));
        workspace.selected = 1;
        let mut out = Vec::new();
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .contains("ready")
        });
        let mut threads = Vec::new();
        workspace.type_keys(b"\x00p", &mut threads);
        workspace.type_keys(b"x", &mut threads);
        let mut asked = [0_u8; 8];
        let read = rustix::io::read(&reader, &mut asked).unwrap();
        assert_eq!(&asked[..read], b"p");
        settle(&mut workspace, &mut out, |workspace| {
            workspace.tabs[0].agents[0]
                .child
                .screen()
                .contents()
                .split_once("ready")
                .is_some_and(|(_, after)| after.contains('x'))
        });
        let shown = workspace.tabs[0].agents[0].child.screen().contents();
        assert!(!shown.contains("^@"), "{shown}");
        assert!(!workspace.palette_open());
    }

    #[test]
    fn the_workspace_starts_no_17th_agent_while_16_run() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let agents: Vec<Running> = (0..MAX_CHILDREN - 1)
            .map(|_| running(&mut workspace, "sleep 5"))
            .collect();
        workspace.tabs.push(tab("a", agents));
        assert_eq!(workspace.room_for_agent(), Ok(()));
        let last = running(&mut workspace, "sleep 5");
        workspace.tabs.push(tab("b", vec![last]));
        assert_eq!(
            workspace.room_for_agent(),
            Err(
                "the workspace runs at most 16 agents at once: stop one to start another"
                    .to_owned()
            )
        );
        workspace.tabs[1].agents[0].ending = Ending::Failed;
        assert_eq!(workspace.room_for_agent(), Ok(()));
    }

    #[test]
    fn the_list_starts_hidden_on_a_terminal_narrower_than_100_columns() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        workspace.set_screen(WindowSize { rows: 24, cols: 99 }, false);
        assert_eq!(workspace.add_tab("a"), 0);
        assert_eq!(workspace.list_place(99), ListPlace::Hidden);
        workspace.step(Step::List);
        assert_eq!(workspace.list_place(99), ListPlace::Over);
        assert_eq!(workspace.add_tab("b"), 1);
        assert_eq!(workspace.list_place(99), ListPlace::Over);
        workspace.tabs.clear();
        workspace.set_screen(
            WindowSize {
                rows: 24,
                cols: 100,
            },
            false,
        );
        workspace.step(Step::List);
        workspace.add_tab("c");
        assert_eq!(workspace.list_place(100), ListPlace::Beside);
    }

    #[test]
    fn an_agent_that_asks_in_a_hidden_tab_rings_the_bell_and_raises_a_notification_once() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let hidden = running(&mut workspace, "sleep 5");
        let shown = running(&mut workspace, "sleep 5");
        let beside = running(&mut workspace, "sleep 5");
        let (hidden_id, shown_id, beside_id) = (hidden.id, shown.id, beside.id);
        workspace.tabs.push(tab("3e5c8646", vec![hidden]));
        workspace.tabs.push(tab("9a48f2c1", vec![shown, beside]));
        workspace.selected = 2;
        let mut out = Vec::new();
        let mut asks = |workspace: &mut Workspace, id, report| {
            out.clear();
            workspace
                .sender
                .send(ChildEvent::Report(id, report))
                .unwrap();
            workspace.take_output(&mut out);
            out.clone()
        };
        let told = b"\x1b]9;mahi 3e5c8646: agent asks you\x07\x07";
        assert_eq!(asks(&mut workspace, hidden_id, Report::Asks), told);
        assert!(asks(&mut workspace, hidden_id, Report::Asks).is_empty());
        assert!(asks(&mut workspace, hidden_id, Report::Working).is_empty());
        assert!(asks(&mut workspace, hidden_id, Report::Asks).is_empty());
        asks(&mut workspace, hidden_id, Report::Working);
        workspace.tabs[0].agents[0].told_asks = Instant::now().checked_sub(ASKS_TOLD_EVERY);
        assert_eq!(asks(&mut workspace, hidden_id, Report::Asks), told);
        assert!(asks(&mut workspace, shown_id, Report::Asks).is_empty());
        assert!(asks(&mut workspace, beside_id, Report::Asks).is_empty());
        workspace.selected = 0;
        assert_eq!(
            asks(&mut workspace, shown_id, Report::Working),
            Vec::<u8>::new()
        );
        assert_eq!(
            asks(&mut workspace, shown_id, Report::Asks),
            b"\x1b]9;mahi 9a48f2c1: agent asks you\x07\x07"
        );
    }

    #[test]
    fn a_thread_the_workspace_cannot_host_is_told_once_and_tried_again() {
        let setup = crate::workspace_live::tests::setup();
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        workspace.host_with(WorkspaceLive::new(
            &setup.environment,
            &setup.config,
            setup.store.common_dir(),
        ));
        let agent = running(&mut workspace, "sleep 5");
        let id = agent.id;
        workspace.tabs.push(tab(NEW_TAB, vec![agent]));
        workspace.take_report(id, &Report::Thread(setup.thread), &mut Vec::new());
        assert_eq!(workspace.tabs[0].thread, Some(setup.thread));
        let (told, _) = workspace.take_ended();
        let told = told.unwrap();
        assert!(told.contains("your mahi key is not unlocked"), "{told}");
        workspace.live_tried = Instant::now().checked_sub(HOST_AGAIN).unwrap();
        let (told, _) = workspace.take_ended();
        assert!(told.is_none());
        assert!(workspace.live_failed.contains(&setup.thread));
    }

    #[test]
    fn space_after_the_palette_key_shows_the_next_agent_that_waits_in_any_tab() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
        let mut agents = Vec::new();
        for _ in 0..3 {
            agents.push(running(&mut workspace, "sleep 5"));
        }
        let ids: Vec<usize> = agents.iter().map(|agent| agent.id).collect();
        let third = agents.pop().unwrap();
        workspace.tabs.push(tab("a", agents));
        workspace.tabs.push(tab("b", vec![third]));
        workspace.selected = 1;
        workspace.take_report(ids[0], &Report::Working, &mut Vec::new());
        workspace.take_report(ids[1], &Report::Done, &mut Vec::new());
        workspace.take_report(ids[2], &Report::Asks, &mut Vec::new());
        let mut threads = Vec::new();
        workspace.type_keys(b"\x00 ", &mut threads);
        assert_eq!(workspace.shown_id(), Some(ids[1]));
        workspace.type_keys(b"\x00 ", &mut threads);
        assert_eq!(workspace.shown_id(), Some(ids[2]));
        workspace.type_keys(b"\x00 ", &mut threads);
        assert_eq!(workspace.shown_id(), Some(ids[1]));
        assert!(threads.is_empty());
    }

    #[test]
    fn a_hidden_agents_key_modes_reach_the_terminal_only_while_it_is_shown() {
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
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
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
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
        let mut workspace = Workspace::new(
            PaletteKey::default(),
            Notice::for_terminal(TerminalHints::default()),
        );
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
        assert!(workspace.palette_open());
        assert_eq!(workspace.take_ended(), (None, true));
        assert!(!workspace.has_tabs());
        assert!(!workspace.palette_open());
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
        let mut child = Child::start(command.0, SIZE, 0, &sender).unwrap();
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
        let mut child = Child::start(given.0, SIZE, 0, &sender).unwrap();
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
        let mut child = Child::start(plain.0, SIZE, 0, &sender).unwrap();
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
                Ok(ChildEvent::Closed(_) | ChildEvent::Report(..)) | Err(_) => {}
            }
        }
        assert!(child.screen().contents().contains("done"));
        let code = loop {
            if let Some(code) = child.exited().unwrap() {
                break code;
            }
            assert!(Instant::now() < deadline, "the child never exited");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(code, 0);
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
