use std::{
    io::{
        self,
        Read,
        Write,
    },
    os::fd::{
        AsFd,
        OwnedFd,
    },
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicBool,
            AtomicU64,
            Ordering,
        },
        mpsc,
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use age::secrecy::SecretString;
use base64::Engine as _;
use mahi_sandbox::{
    InputWait,
    TerminationSignals,
    WindowSize,
};
use mahi_term::{
    AgentFrame,
    AnsiBackend,
    Answer,
    Dialog,
    PaletteInput,
    PaletteKeys,
    Theme,
};
use ratatui_core::{
    buffer::Buffer,
    style::Style,
    terminal::Terminal,
    text::{
        Line,
        Span,
    },
    widgets::Widget,
};
use rustix::termios::{
    LocalModes,
    OptionalActions,
    QueueSelector,
    SpecialCodeIndex,
    Termios,
};

use crate::terminal;

const MAX_ACTIVITY_LINES: usize = 200;
const MAX_ACTIVITY_LINE_CHARS: usize = 400;
const MAX_READ: usize = 1024;
const SEQUENCE_WAIT: Duration = Duration::from_millis(30);
const KEY_WAIT: Duration = Duration::from_millis(500);
const ESC: u8 = 0x1b;
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";
const LEAVE_SCREEN: &[u8] = b"\x1b[?25h\x1b[?2004l\x1b[?1049l";
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPIN_EVERY: Duration = Duration::from_millis(100);
const SPIN_AFTER: Duration = Duration::from_millis(150);
const WORKING: &str = "working…";

static SHOWING: AtomicBool = AtomicBool::new(false);
static TRUE_COLOR: AtomicBool = AtomicBool::new(true);
static BACKDROP: Mutex<Option<Buffer>> = Mutex::new(None);
static SAVED: Mutex<Option<Termios>> = Mutex::new(None);
static SAVED_STDERR: Mutex<Option<OwnedFd>> = Mutex::new(None);
static NOTICE: Mutex<Notice> = Mutex::new(Notice {
    dialog: None,
    spinning: false,
    asking: false,
    busy_since: None,
    spinner: None,
});
static DRAWING: Mutex<()> = Mutex::new(());
static DRAWN: AtomicU64 = AtomicU64::new(0);
static LEFT: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "macos")]
const CONTROL_DISABLED: u8 = 0xff;
#[cfg(target_os = "linux")]
const CONTROL_DISABLED: u8 = 0;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("mahi's full-screen views know the disabled control value of Linux and macOS only");

/// The notice a dialog shows while a command works, whether a spinner turns in its title,
/// whether a question hides it, since when a command that has shown nothing yet works, and
/// the thread that turns the spinner.
struct Notice {
    dialog: Option<Dialog>,
    spinning: bool,
    asking: bool,
    busy_since: Option<Instant>,
    spinner: Option<Spinner>,
}

/// The thread that turns the spinner, and the sender whose drop stops it.
struct Spinner {
    done: mpsc::Sender<()>,
    thread: thread::JoinHandle<()>,
}

impl Spinner {
    fn start() -> Option<Self> {
        let (done, stopped) = mpsc::channel::<()>();
        let thread = thread::Builder::new()
            .name("spinner".to_owned())
            .spawn(move || spin(&stopped))
            .ok()?;
        Some(Self { done, thread })
    }

    fn stop(self) {
        drop(self.done);
        let _ = self.thread.join();
    }
}

/// Turns the spinner every `SPIN_EVERY` until `stopped` ends: shows that mahi is working once
/// a busy command has shown nothing for `SPIN_AFTER`, and redraws a spinning notice with the
/// next frame in its title, through one terminal so only what changed is sent.
fn spin(stopped: &mpsc::Receiver<()>) {
    let mut screen: Option<Terminal<AnsiBackend<io::Stdout>>> = None;
    let mut seen = DRAWN.load(Ordering::SeqCst);
    let mut title = String::new();
    for tick in 1.. {
        if !matches!(
            stopped.recv_timeout(SPIN_EVERY),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            return;
        }
        let Ok(mut notice) = NOTICE.lock() else {
            return;
        };
        if notice.asking {
            continue;
        }
        if notice.dialog.is_none()
            && notice
                .busy_since
                .is_some_and(|since| since.elapsed() >= SPIN_AFTER)
        {
            notice.dialog = Some(Dialog::notice("mahi", vec![WORKING.to_owned()]));
            notice.spinning = true;
        }
        if !notice.spinning {
            continue;
        }
        let Some(dialog) = notice.dialog.as_mut() else {
            continue;
        };
        title.clear();
        spinner_title(tick, &mut title);
        dialog.set_title(&title);
        let Ok(_drawing) = DRAWING.lock() else {
            return;
        };
        if !is_showing() || LEFT.load(Ordering::SeqCst) {
            return;
        }
        let drawn = DRAWN.load(Ordering::SeqCst);
        if drawn != seen {
            screen = None;
            seen = drawn;
        }
        if screen.is_none() {
            let size = terminal::size();
            screen = Terminal::new(backend(size.rows, size.cols)).ok();
        }
        if let Some(screen) = screen.as_mut() {
            let _ = draw_over_backdrop(screen, dialog);
        }
    }
}

/// While it lives and a full-screen view owns the terminal, a command that shows nothing of
/// its own for `SPIN_AFTER` gets a notice that says mahi is working, and every notice goes
/// when the command ends.
#[derive(Debug)]
pub(crate) struct Busy {
    started: bool,
}

impl Busy {
    pub(crate) fn start() -> Self {
        if !is_showing() {
            return Self { started: false };
        }
        if let Ok(mut notice) = NOTICE.lock() {
            notice.busy_since = Some(Instant::now());
            if notice.spinner.is_none() {
                notice.spinner = Spinner::start();
            }
        }
        Self { started: true }
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        if self.started {
            clear_notice();
        }
    }
}

fn spinner_title(tick: usize, title: &mut String) {
    title.push_str("mahi ");
    title.push_str(
        SPINNER
            .get(tick % SPINNER.len())
            .copied()
            .unwrap_or_default(),
    );
}

/// Shows `lines` in a notice whose spinner turns until the next question or the next frame
/// of the full-screen view, when one owns the terminal.
pub(crate) fn show_notice(lines: Vec<String>) {
    if !is_showing() {
        return;
    }
    let mut title = String::new();
    spinner_title(0, &mut title);
    keep_notice(Dialog::notice(&title, lines), true);
}

/// Shows `code` in a notice that stays still while mahi waits for the teammate who types it,
/// above `paragraphs`, when a full-screen view owns the terminal.
pub(crate) fn show_code(title: &str, code: &str, paragraphs: &[&str]) {
    if is_showing() {
        keep_notice(Dialog::code(title, code, paragraphs), false);
    }
}

fn keep_notice(dialog: Dialog, spinning: bool) {
    if let Ok(mut notice) = NOTICE.lock() {
        if !notice.asking {
            let _ = show(&dialog);
        }
        notice.dialog = Some(dialog);
        notice.spinning = spinning;
        if notice.spinner.is_none() {
            notice.spinner = Spinner::start();
        }
    }
}

/// Shows that mahi is working, in place of what the notice said, when a full-screen view
/// owns the terminal.
pub(crate) fn show_working() {
    show_notice(vec![WORKING.to_owned()]);
}

/// Takes the notice away, with a working notice still to come, and stops the spinner, before
/// the full-screen view draws a frame or leaves the screen.
pub(crate) fn clear_notice() {
    let spinner = NOTICE.lock().ok().and_then(|mut notice| {
        notice.dialog = None;
        notice.busy_since = None;
        notice.spinner.take()
    });
    if let Some(spinner) = spinner {
        spinner.stop();
    }
}

fn set_asking(asking: bool) {
    if let Ok(mut notice) = NOTICE.lock() {
        notice.asking = asking;
    }
}

/// Keeps the full-screen view's last frame, which dialogs are drawn over.
pub(crate) fn keep_backdrop(frame: &Buffer) {
    if let Ok(mut kept) = BACKDROP.lock() {
        *kept = Some(frame.clone());
    }
}

/// Returns the size of the agent's terminal: the user's whole terminal, or, while the home
/// screen owns it, the pane the agent is drawn in.
pub(crate) fn agent_size() -> WindowSize {
    let size = terminal::size();
    if !is_showing() {
        return size;
    }
    let (rows, cols) = AgentFrame::agent_size(size.rows, size.cols);
    WindowSize { rows, cols }
}

/// Says whether the terminal draws 24-bit colour, as `COLORTERM` tells; dialogs then draw
/// mahi's colours exactly, and otherwise with the nearest of 256.
pub(crate) fn set_true_color(true_color: bool) {
    TRUE_COLOR.store(true_color, Ordering::SeqCst);
}

/// Returns whether a terminal whose `COLORTERM` is `colorterm` draws 24-bit colour.
pub(crate) fn draws_true_color(colorterm: Option<&str>) -> bool {
    matches!(colorterm, Some("truecolor" | "24bit"))
}

/// Returns whether the terminal draws 24-bit colour.
pub(crate) fn true_color() -> bool {
    TRUE_COLOR.load(Ordering::SeqCst)
}

/// Returns a backend that draws on standard output, in 24-bit colour only when the terminal
/// draws it.
pub(crate) fn backend(rows: u16, columns: u16) -> AnsiBackend<io::Stdout> {
    let backend = AnsiBackend::new(io::stdout(), rows, columns);
    if TRUE_COLOR.load(Ordering::SeqCst) {
        backend
    } else {
        backend.without_true_color()
    }
}

/// Returns whether a full-screen view owns the terminal, so questions are asked in dialogs.
pub(crate) fn is_showing() -> bool {
    SHOWING.load(Ordering::SeqCst)
}

/// Says that a full-screen view owns the terminal while it lives, keeping the terminal's
/// settings from before so they can be put back if mahi dies of a signal.
#[derive(Debug)]
pub(crate) struct Showing;

impl Showing {
    /// Starts the view, and makes keys make signals only while something in mahi listens for
    /// them, so a signal never ends mahi unseen with the terminal raw.
    pub(crate) fn start(saved: Option<Termios>) -> Self {
        if let Ok(mut kept) = SAVED.lock() {
            *kept = saved;
        }
        SHOWING.store(true, Ordering::SeqCst);
        TerminationSignals::on_listening(listening_started, listening_ended);
        Self
    }
}

fn listening_started() {
    if is_showing() {
        keys_make_signals(true);
    }
}

fn listening_ended() {
    if is_showing() {
        keys_make_signals(false);
    }
}

impl Drop for Showing {
    fn drop(&mut self) {
        clear_notice();
        let _drawing = DRAWING.lock();
        SHOWING.store(false, Ordering::SeqCst);
    }
}

/// Forgets the mahi key the home screen kept unlocked and puts the terminal back as it was
/// before the full-screen view, when mahi is about to die of a signal while the view owns it.
pub(crate) fn before_dying() {
    crate::unlocked::forget();
    let _drawing = DRAWING.lock();
    LEFT.store(true, Ordering::SeqCst);
    if !is_showing() {
        return;
    }
    if let Some(saved) = SAVED_STDERR.lock().ok().and_then(|mut kept| kept.take()) {
        let _ = rustix::stdio::dup2_stderr(&saved);
    }
    let mut out = io::stdout().lock();
    let _ = out.write_all(LEAVE_SCREEN);
    let _ = out.flush();
    if let Some(saved) = SAVED.lock().ok().and_then(|kept| kept.clone()) {
        let _ = rustix::termios::tcsetattr(io::stdin(), OptionalActions::Now, &saved);
    }
}

/// While it lives and a full-screen view owns the terminal, a stop signal puts the terminal
/// back and ends mahi with that signal, for steps that wait without listening for signals
/// themselves; it stops listening when dropped, so the next step can listen. On lines it does
/// nothing, since the prompts there listen themselves.
#[derive(Debug)]
pub(crate) struct StopOnSignal {
    quit: Option<std::os::unix::net::UnixStream>,
    watcher: Option<thread::JoinHandle<()>>,
}

impl StopOnSignal {
    pub(crate) fn start() -> Self {
        let listened = is_showing()
            .then(TerminationSignals::listen)
            .and_then(Result::ok);
        let Some((signals, (quit, quitting))) =
            listened.zip(std::os::unix::net::UnixStream::pair().ok())
        else {
            return Self {
                quit: None,
                watcher: None,
            };
        };
        let watcher = thread::spawn(move || {
            loop {
                match signals.wait_for_input_within(quitting.as_fd(), KEY_WAIT) {
                    Ok(InputWait::Timeout) => {}
                    Ok(InputWait::Signal(signal)) => {
                        before_dying();
                        signal.reraise();
                        std::process::exit(128 + signal.number());
                    }
                    Ok(InputWait::Input) | Err(_) => return,
                }
            }
        });
        Self {
            quit: Some(quit),
            watcher: Some(watcher),
        }
    }
}

impl Drop for StopOnSignal {
    fn drop(&mut self) {
        drop(self.quit.take());
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

/// Lets Ctrl-C make a signal, or makes it a plain key, keeping the rest of the terminal raw;
/// Ctrl-\ and Ctrl-Z never make one, since a quit dumps core and a stop leaves the view half
/// drawn.
pub(crate) fn keys_make_signals(on: bool) {
    let Ok(mut modes) = rustix::termios::tcgetattr(io::stdin()) else {
        return;
    };
    modes.local_modes.set(LocalModes::ISIG, on);
    modes.special_codes[SpecialCodeIndex::VQUIT] = CONTROL_DISABLED;
    modes.special_codes[SpecialCodeIndex::VSUSP] = CONTROL_DISABLED;
    let _ = rustix::termios::tcsetattr(io::stdin(), OptionalActions::Now, &modes);
}

fn keys_make_signals_now() -> bool {
    rustix::termios::tcgetattr(io::stdin())
        .is_ok_and(|modes| modes.local_modes.contains(LocalModes::ISIG))
}

/// Asks questions in dialogs drawn over the full screen, reading keys raw from standard input.
/// What it is told is drawn at once in a notice, which stays while a command works and shows
/// again above the next question; it never goes to standard error, so nothing said this way
/// is kept in the activity.
#[derive(Default)]
pub(crate) struct DialogPrompt {
    said: Vec<String>,
    keys: PaletteKeys,
}

impl std::fmt::Debug for DialogPrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialogPrompt").finish_non_exhaustive()
    }
}

impl DialogPrompt {
    pub(crate) fn say(&mut self, line: &str) {
        self.said.push(line.to_owned());
        show_notice(self.said.clone());
    }

    pub(crate) fn secret(&mut self, question: &str) -> io::Result<SecretString> {
        self.secret_shown_as(question, true)
    }

    /// Asks for a secret the user may see while typing it, such as a pairing code.
    pub(crate) fn shown_secret(&mut self, question: &str) -> io::Result<SecretString> {
        self.secret_shown_as(question, false)
    }

    fn secret_shown_as(&mut self, question: &str, masked: bool) -> io::Result<SecretString> {
        let dialog = Dialog::input(
            question.trim_end_matches([' ', ':']),
            self.take_said(),
            masked,
        );
        match self.ask(dialog)? {
            Answer::Text(text) => Ok(SecretString::from(text.to_string())),
            _ => Err(cancelled()),
        }
    }

    pub(crate) fn answer(&mut self, question: &str) -> io::Result<String> {
        let trimmed = question.trim_end();
        let mut lines = self.take_said();
        if let Some(asked) = trimmed.strip_suffix("[y/N]") {
            lines.push(asked.trim_end().to_owned());
            return match self.ask(Dialog::confirm("Confirm", lines))? {
                Answer::Confirmed(true) => Ok("y".to_owned()),
                Answer::Confirmed(false) => Ok("n".to_owned()),
                _ => Err(cancelled()),
            };
        }
        lines.push(trimmed.to_owned());
        match self.ask(Dialog::input("mahi asks", lines, false))? {
            Answer::Text(text) => Ok(text.trim().to_owned()),
            _ => Err(cancelled()),
        }
    }

    pub(crate) fn pick(&mut self, options: &[(&str, &str)]) -> io::Result<String> {
        let lines = self.take_said();
        let labels = options
            .iter()
            .map(|(_, label)| (*label).to_owned())
            .collect();
        match self.ask(Dialog::choose("mahi asks", lines, labels))? {
            Answer::Choice(index) => options
                .get(index)
                .map(|(answer, _)| (*answer).to_owned())
                .ok_or_else(cancelled),
            _ => Err(cancelled()),
        }
    }

    fn take_said(&mut self) -> Vec<String> {
        std::mem::take(&mut self.said)
    }

    /// Shows `dialog` until it is answered, then a notice that mahi is working. Keys typed
    /// before it showed are thrown away, so none answers it unseen; Ctrl-C is a key while it
    /// waits, and a stop signal puts the terminal back and ends mahi.
    pub(crate) fn ask(&mut self, mut dialog: Dialog) -> io::Result<Answer> {
        let signalling = keys_make_signals_now();
        keys_make_signals(false);
        let _ = rustix::termios::tcflush(io::stdin(), QueueSelector::IFlush);
        set_asking(true);
        let answer = self.read_answer(&mut dialog);
        set_asking(false);
        show_working();
        keys_make_signals(signalling);
        answer
    }

    fn read_answer(&mut self, dialog: &mut Dialog) -> io::Result<Answer> {
        let signals = TerminationSignals::listen().ok();
        keys_make_signals(false);
        let mut buffer = zeroize::Zeroizing::new([0_u8; MAX_READ]);
        loop {
            show(dialog)?;
            let Some(read) = read_keys(signals.as_ref(), &mut buffer)? else {
                return Ok(Answer::Cancelled);
            };
            let mut chunk = buffer.get(..read).unwrap_or_default();
            if !self.keys.is_pasting()
                && let Some(after) = after_paste_tail(chunk)
            {
                chunk = after;
            }
            let mut answered = None;
            self.keys.read(chunk, |input| {
                if let Some(answer) = dialog.key(input) {
                    answered = Some(answer);
                    return false;
                }
                input != PaletteInput::Escape
            });
            if let Some(answer) = answered {
                return Ok(answer);
            }
        }
    }
}

/// Reads what was typed, waiting briefly for the rest of a sequence that starts with an escape
/// when it can wait with a timeout; `None` at the end of the input.
fn read_keys(
    signals: Option<&TerminationSignals>,
    buffer: &mut [u8; MAX_READ],
) -> io::Result<Option<usize>> {
    if let Some(signals) = signals {
        loop {
            match signals
                .wait_for_input_within(io::stdin().as_fd(), KEY_WAIT)
                .map_err(io::Error::other)?
            {
                InputWait::Input => break,
                InputWait::Timeout => {}
                InputWait::Signal(signal) => {
                    before_dying();
                    signal.reraise();
                    std::process::exit(128 + signal.number());
                }
            }
        }
    }
    let mut read = read_input(buffer)?;
    if read == 0 {
        return Ok(None);
    }
    while let Some(signals) = signals
        && buffer.get(read - 1) == Some(&ESC)
        && read < MAX_READ
    {
        match signals
            .wait_for_input_within(io::stdin().as_fd(), SEQUENCE_WAIT)
            .map_err(io::Error::other)?
        {
            InputWait::Input => {
                let more = read_input(buffer.get_mut(read..).unwrap_or_default())?;
                if more == 0 {
                    break;
                }
                read += more;
            }
            InputWait::Timeout | InputWait::Signal(_) => break,
        }
    }
    Ok(Some(read))
}

/// Returns what follows the end of a bracketed paste that `chunk` ends without starting it:
/// the rest of a paste whose start was thrown away, which must not be read as typed keys.
fn after_paste_tail(chunk: &[u8]) -> Option<&[u8]> {
    let find = |marker: &[u8]| {
        chunk
            .windows(marker.len())
            .position(|window| window == marker)
    };
    let end = find(PASTE_END)?;
    if find(PASTE_START).is_some_and(|start| start < end) {
        return None;
    }
    chunk.get(end + PASTE_END.len()..)
}

fn read_input(buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match rustix::io::read(io::stdin(), &mut *buffer) {
            Err(rustix::io::Errno::INTR) => {}
            read => return read.map_err(io::Error::from),
        }
    }
}

/// Shows `text`, which a command prints, in a dialog titled `title` under `intro`, until the
/// user presses Enter. Text `to_send` to someone, such as a card or a ticket, also goes to the
/// clipboard through the terminal when it is one line, since copying it off the screen would
/// take the dialog's border and line breaks with it; the dialog shows even if that fails.
pub(crate) fn show_printed(title: &str, intro: &str, text: &str, to_send: bool) -> io::Result<()> {
    let mut lines = Vec::with_capacity(text.lines().count() + 2);
    if !intro.is_empty() {
        lines.push(intro.to_owned());
    }
    lines.extend(text.lines().map(str::to_owned));
    if let Some(only) = only_line(text).filter(|_| to_send) {
        let mut out = io::stdout().lock();
        let copied = out
            .write_all(&clipboard_sequence(only))
            .and_then(|()| out.flush())
            .is_ok();
        if copied {
            lines.push(
                "It is also on your clipboard, if your terminal lets mahi put it there.".to_owned(),
            );
        }
    }
    DialogPrompt::default()
        .ask(Dialog::message(title, lines))
        .map(|_| ())
}

fn only_line(text: &str) -> Option<&str> {
    let mut written = text.lines().filter(|line| !line.is_empty());
    match (written.next(), written.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

fn clipboard_sequence(text: &str) -> Vec<u8> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let mut sequence = Vec::with_capacity(encoded.len() + 8);
    sequence.extend_from_slice(b"\x1b]52;c;");
    sequence.extend_from_slice(encoded.as_bytes());
    sequence.push(0x07);
    sequence
}

/// Draws `dialog` over the full-screen view's last frame.
fn show(dialog: &Dialog) -> io::Result<()> {
    let Ok(_drawing) = DRAWING.lock() else {
        return Ok(());
    };
    if !is_showing() {
        return Ok(());
    }
    DRAWN.fetch_add(1, Ordering::SeqCst);
    let size = terminal::size();
    let mut screen = Terminal::new(backend(size.rows, size.cols))?;
    screen.clear()?;
    draw_over_backdrop(&mut screen, dialog)
}

/// Draws `dialog` over the full-screen view's last frame, or over a line that says mahi works
/// when the view kept none of this size.
fn draw_over_backdrop(
    screen: &mut Terminal<AnsiBackend<io::Stdout>>,
    dialog: &Dialog,
) -> io::Result<()> {
    screen.draw(|frame| {
        let area = frame.area();
        let kept = BACKDROP.lock();
        match kept
            .as_ref()
            .ok()
            .and_then(|kept| kept.as_ref())
            .filter(|kept| kept.area == area)
        {
            Some(kept) => frame.buffer_mut().content.clone_from(&kept.content),
            None => Line::from(vec![
                Span::styled(" mahi ", Theme::selected()),
                Span::styled("  working", Style::new().fg(Theme::MUTED)),
            ])
            .render(area, frame.buffer_mut()),
        }
        drop(kept);
        dialog.render(area, frame.buffer_mut());
    })?;
    Ok(())
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "the question was cancelled")
}

#[cfg(not(target_vendor = "apple"))]
fn cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?)
}

#[cfg(target_vendor = "apple")]
fn cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = rustix::pipe::pipe()?;
    for end in [&reader, &writer] {
        rustix::io::fcntl_setfd(end, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok((reader, writer))
}

/// Sends what mahi writes to standard error into the activity while it lives, so commands run
/// from a full-screen view do not write over it; standard error is put back when it ends.
#[derive(Debug)]
pub(crate) struct Captured {
    saved: Option<OwnedFd>,
    lines: Arc<Mutex<Vec<String>>>,
    generation: Arc<AtomicU64>,
}

impl Captured {
    pub(crate) fn start() -> io::Result<Self> {
        let saved = io::stderr().as_fd().try_clone_to_owned()?;
        let (reader, writer) = cloexec_pipe()?;
        rustix::stdio::dup2_stderr(&writer)?;
        drop(writer);
        if let Ok(mut kept) = SAVED_STDERR.lock() {
            *kept = saved.try_clone().ok();
        }
        let lines = Arc::new(Mutex::new(Vec::new()));
        let generation = Arc::new(AtomicU64::new(0));
        let (collected, counted) = (Arc::clone(&lines), Arc::clone(&generation));
        thread::spawn(move || collect(reader, &collected, &counted));
        Ok(Self {
            saved: Some(saved),
            lines,
            generation,
        })
    }

    /// Returns a number that changes each time a line is added.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Returns the lines written so far, oldest first.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|lines| lines.clone())
            .unwrap_or_default()
    }
}

impl Drop for Captured {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            let _ = rustix::stdio::dup2_stderr(&saved);
        }
    }
}

fn collect(reader: OwnedFd, lines: &Mutex<Vec<String>>, generation: &AtomicU64) {
    let mut file = std::fs::File::from(reader);
    let mut pending = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        pending.extend_from_slice(buffer.get(..read).unwrap_or_default());
        while let Some(end) = pending.iter().position(|&byte| byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let text: String = String::from_utf8_lossy(&line)
                .trim_end()
                .chars()
                .take(MAX_ACTIVITY_LINE_CHARS)
                .collect();
            if text.is_empty() {
                continue;
            }
            if let Ok(mut held) = lines.lock() {
                held.push(text);
                let excess = held.len().saturating_sub(MAX_ACTIVITY_LINES);
                held.drain(..excess);
            }
            generation.fetch_add(1, Ordering::SeqCst);
        }
        if pending.len() > MAX_ACTIVITY_LINE_CHARS * 4 {
            pending.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn title(tick: usize) -> String {
        let mut title = String::new();
        spinner_title(tick, &mut title);
        title
    }

    #[test]
    fn the_spinner_turns_through_its_frames_and_starts_again() {
        assert_eq!(title(0), "mahi ⠋");
        assert_eq!(title(1), "mahi ⠙");
        assert_eq!(title(SPINNER.len()), title(0));
        assert_ne!(title(3), title(4));
    }

    #[test]
    fn nothing_spins_while_no_full_screen_view_shows() {
        let busy = Busy::start();
        assert!(!busy.started);
        show_working();
        assert!(NOTICE.lock().unwrap().spinner.is_none());
    }

    #[test]
    fn only_a_terminal_that_says_so_draws_24_bit_colour() {
        assert!(draws_true_color(Some("truecolor")));
        assert!(draws_true_color(Some("24bit")));
        assert!(!draws_true_color(Some("256")));
        assert!(!draws_true_color(None));
    }

    #[test]
    fn only_text_of_one_line_is_put_on_the_clipboard_whatever_blank_lines_surround_it() {
        assert_eq!(only_line(""), None);
        assert_eq!(only_line("\n\n"), None);
        assert_eq!(only_line("card\n"), Some("card"));
        assert_eq!(only_line("\ncard\n\n"), Some("card"));
        assert_eq!(only_line("a\nb\n"), None);
    }

    #[test]
    fn the_clipboard_gets_the_text_base64_encoded_in_one_terminal_sequence() {
        assert_eq!(
            clipboard_sequence("mahi card \u{1b}]0;x\u{7}"),
            b"\x1b]52;c;bWFoaSBjYXJkIBtdMDt4Bw==\x07"
        );
    }

    #[test]
    fn both_ends_of_the_capture_pipe_close_on_exec() {
        let (reader, writer) = cloexec_pipe().unwrap();
        for end in [&reader, &writer] {
            let flags = rustix::io::fcntl_getfd(end).unwrap();
            assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        }
    }

    #[test]
    fn only_the_tail_of_a_paste_whose_start_is_missing_is_dropped() {
        assert_eq!(
            after_paste_tail(b"rest of a paste y\r\x1b[201~n"),
            Some(&b"n"[..])
        );
        assert_eq!(after_paste_tail(b"\x1b[200~whole paste\x1b[201~"), None);
        assert_eq!(after_paste_tail(b"y"), None);
        assert_eq!(after_paste_tail(b"\x1b[200~start only"), None);
    }
}
