use std::{
    fmt::Write as _,
    io::{
        self,
        Write,
    },
    sync::{
        Arc,
        Mutex,
        MutexGuard,
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    AgentSlot,
    is_invisible,
};
use mahi_sandbox::{
    PtyResizer,
    WindowSize,
};
use mahi_store::ObjectId;
use mahi_term::{
    OutputTracker,
    PaletteInput,
    PaletteItem,
    PaletteKey,
    PaletteKeys,
    PaletteView,
    Preview,
};

use crate::{
    held_queue::{
        Choice,
        HeldQueue,
        Waiting,
    },
    inject::AgentInput,
};

const MAX_HELD_BYTES: usize = 1024 * 1024;
const TITLE: &str = "Held turns";
const EMPTY: &str = "No teammate's turn waits for you";
const HELD_DETAIL: &str = "changes agent settings";
const HELD_READ: &str = "PgDn reads on · Ctrl-X skips · Esc closes";
const HELD_DECIDE: &str = "Enter takes · Ctrl-X skips · Esc closes";
const HELD_INTRO: &str = "Its turn changes what agents read as their settings or instructions:";
const HELD_UNTOLD: &str = "(mahi could not tell which paths)";
const HELD_BEHIND: &str = "Its later turns wait behind it.";
const OPEN_GUARD: Duration = Duration::from_millis(500);
const CLEAR: &[u8] = b"\x1b[2J";
const REPAINT_PAUSE: Duration = Duration::from_millis(100);

/// Where the screen writes the agent's output and mahi's palette: straight to the user's
/// terminal, or into a pane mahi draws.
pub(crate) trait ScreenOut: Write {
    /// Takes the agent's terminal's new `size` before the agent draws for it.
    fn resize(&mut self, _size: WindowSize) {}

    /// Stops drawing, since the agent ended: what comes later is dropped.
    fn finish(&mut self) {}

    /// Returns whether the palette is drawn over the agent's screen as a layer of its own,
    /// so the agent keeps drawing beneath it and nothing has to be redrawn when it closes.
    fn overlays(&self) -> bool {
        false
    }

    /// Returns where the palette is drawn.
    fn palette_out(&mut self) -> &mut dyn Write
    where
        Self: Sized,
    {
        self
    }

    /// Takes the palette away from the screen, where it is a layer of its own.
    fn close_palette(&mut self) {}
}

impl ScreenOut for io::Stdout {}

impl ScreenOut for Vec<u8> {}

/// The user's terminal as the palette needs it: its size, and a way to make the agent redraw
/// its screen.
pub(crate) trait AgentTerminal {
    /// Returns the terminal's size.
    fn size(&self) -> WindowSize;
    /// Makes the agent redraw its screen, by resizing its terminal one row smaller and back.
    fn repaint(&self);
}

/// The agent's terminal, whose size follows the user's: every change to it goes through one
/// lock, so a repaint never puts back a size the user's terminal no longer has.
#[derive(Debug, Clone)]
pub(crate) struct Repainter(Arc<Mutex<PtyResizer>>);

impl Repainter {
    pub(crate) fn new(resizer: PtyResizer) -> Self {
        Self(Arc::new(Mutex::new(resizer)))
    }

    /// Gives the agent's terminal the user's terminal's size, and returns it; `None` when the
    /// agent's terminal is gone.
    pub(crate) fn follow(&self) -> Option<WindowSize> {
        self.follow_to(crate::ui::agent_size())
    }

    /// Gives the agent's terminal `size`, and returns it; `None` when the agent's terminal is
    /// gone.
    pub(crate) fn follow_to(&self, size: WindowSize) -> Option<WindowSize> {
        let resizer = self.0.lock().ok()?;
        resizer.resize(size).ok()?;
        Some(size)
    }
}

impl AgentTerminal for Repainter {
    fn size(&self) -> WindowSize {
        crate::ui::agent_size()
    }

    fn repaint(&self) {
        if let Ok(resizer) = self.0.lock() {
            let size = crate::ui::agent_size();
            let _ = resizer.resize(WindowSize {
                rows: size.rows.saturating_sub(1).max(1),
                cols: size.cols,
            });
        }
        let restore = self.clone();
        thread::spawn(move || {
            thread::sleep(REPAINT_PAUSE);
            restore.follow();
        });
    }
}

/// The user's screen, shared by the agent's output and the palette: while the palette is open,
/// the agent's output is held back, and the palette is drawn only where the agent's output is
/// outside any sequence it began.
#[derive(Debug)]
pub(crate) struct Screen<W, T> {
    state: Mutex<State<W>>,
    terminal: T,
    waiting: Option<Arc<HeldQueue>>,
    hint: String,
}

/// What a line of the palette stands for: a teammate's snapshot that waits because it changes
/// agent settings, by its teammate and its commit.
type Entry = (AgentSlot, ObjectId);

#[derive(Debug)]
struct State<W> {
    out: W,
    tracker: OutputTracker,
    mode: Mode,
    held: Vec<u8>,
    filter: String,
    selected: usize,
    selected_id: Option<Entry>,
    scroll: usize,
    page: usize,
    read_whole: Option<Entry>,
    keys: PaletteKeys,
    guard: Guard,
}

/// Whether the palette drops the keys typed to it, as it does when it opened on its own: until
/// it shows, then for 500 ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guard {
    Off,
    UntilShown,
    Until(Instant),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Agent,
    Opening,
    Open,
}

impl<W: ScreenOut, T: AgentTerminal> Screen<W, T> {
    /// Starts a screen that writes to `out`, with the palette closed.
    pub(crate) fn new(out: W, terminal: T, key: PaletteKey) -> Self {
        Self {
            state: Mutex::new(State {
                out,
                tracker: OutputTracker::default(),
                mode: Mode::Agent,
                held: Vec::new(),
                filter: String::new(),
                selected: 0,
                selected_id: None,
                scroll: 0,
                page: 0,
                read_whole: None,
                keys: PaletteKeys::default(),
                guard: Guard::Off,
            }),
            terminal,
            waiting: None,
            hint: format!("Esc closes · {key} twice sends {key} to the agent"),
        }
    }

    /// Lists the teammates' snapshots in `waiting` that wait because they change agent
    /// settings, to take or to skip.
    pub(crate) fn with_waiting(mut self, waiting: Arc<HeldQueue>) -> Self {
        self.waiting = Some(waiting);
        self
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, State<W>>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("the screen's lock is poisoned"))
    }

    /// Writes the agent's `bytes`, or holds them back while the palette is open.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn output(&self, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.out.overlays() {
            state.tracker.feed(bytes);
            state.out.write_all(bytes)?;
            return state.out.flush();
        }
        match state.mode {
            Mode::Agent => {
                state.tracker.feed(bytes);
                state.out.write_all(bytes)?;
            }
            Mode::Opening => {
                let written = state.tracker.feed_until_drawable(bytes);
                let (now, later) = bytes.split_at(written);
                state.out.write_all(now)?;
                if state.tracker.can_draw() {
                    state.held.extend_from_slice(later);
                    state.mode = Mode::Open;
                    self.draw(&mut state)?;
                }
            }
            Mode::Open if state.held.len() + bytes.len() > MAX_HELD_BYTES => {
                state.held.extend_from_slice(bytes);
                self.release(&mut state)?;
            }
            Mode::Open => state.held.extend_from_slice(bytes),
        }
        state.out.flush()
    }

    /// Returns whether the palette is open or about to be.
    pub(crate) fn is_open(&self) -> bool {
        self.lock().is_ok_and(|state| state.mode != Mode::Agent)
    }

    /// Returns whether the palette waits for the agent to finish a sequence before it opens.
    pub(crate) fn is_opening(&self) -> bool {
        self.lock().is_ok_and(|state| state.mode == Mode::Opening)
    }

    /// Opens the palette, at once when the agent's output is outside any sequence, or else as
    /// soon as it is.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn open(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.mode != Mode::Agent {
            return Ok(());
        }
        if state.out.overlays() || state.tracker.can_draw() {
            state.mode = Mode::Open;
            self.draw(&mut state)?;
        } else {
            state.mode = Mode::Opening;
        }
        state.out.flush()
    }

    /// Opens the palette on its own, for a snapshot that waits: the keys that come before it
    /// shows and in its first 500 ms are dropped, so a key meant for the agent decides nothing.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn open_guarded(&self) -> io::Result<()> {
        {
            let mut state = self.lock()?;
            if state.mode != Mode::Agent {
                return Ok(());
            }
            state.guard = Guard::UntilShown;
        }
        self.open()
    }

    /// Opens the palette now, although the agent left a sequence unfinished, since it wrote
    /// nothing to finish it.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn open_now(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.mode == Mode::Opening {
            state.mode = Mode::Open;
            self.draw(&mut state)?;
        }
        state.out.flush()
    }

    /// Takes `bytes` the user typed, while the palette is open, and returns how many it used:
    /// none when the palette is closed, and those up to Escape when that closes it, so the
    /// rest goes to the agent.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn typed(&self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.lock()?;
        if state.mode == Mode::Agent {
            return Ok(0);
        }
        let guarded = match state.guard {
            Guard::Off => false,
            Guard::UntilShown => true,
            Guard::Until(until) => Instant::now() < until,
        };
        if guarded {
            return Ok(bytes.len());
        }
        let State {
            keys,
            filter,
            selected,
            selected_id,
            scroll,
            page,
            read_whole,
            ..
        } = &mut *state;
        let mut changed = false;
        let mut escaped = false;
        let mut closing = false;
        let used = keys.read(bytes, |input| {
            match input {
                PaletteInput::Escape => escaped = true,
                PaletteInput::Text(character) | PaletteInput::Pasted(character) => {
                    filter.push(character);
                    (*selected, *selected_id) = (0, None);
                    changed = true;
                }
                PaletteInput::Backspace => {
                    if filter.pop().is_some() {
                        (*selected, *selected_id) = (0, None);
                        changed = true;
                    }
                }
                PaletteInput::Up if *selected > 0 => {
                    (*selected, *selected_id) = (*selected - 1, None);
                    changed = true;
                }
                PaletteInput::Down => {
                    (*selected, *selected_id) = (selected.saturating_add(1), None);
                    changed = true;
                }
                PaletteInput::PageDown => {
                    *scroll = scroll.saturating_add((*page).max(1));
                    changed = true;
                }
                PaletteInput::PageUp => {
                    *scroll = scroll.saturating_sub((*page).max(1));
                    changed = true;
                }
                PaletteInput::Enter | PaletteInput::Reject => {
                    let choice = if input == PaletteInput::Enter {
                        Choice::Take
                    } else {
                        Choice::Skip
                    };
                    let id = selected_id
                        .clone()
                        .or_else(|| self.entry_at(filter, *selected));
                    let read = choice == Choice::Skip || (id.is_some() && id == *read_whole);
                    if read && id.as_ref().is_some_and(|id| self.choose(id, choice)) {
                        *selected_id = None;
                        changed = true;
                        closing |= choice == Choice::Take;
                    }
                }
                PaletteInput::Up | PaletteInput::Tab | PaletteInput::Left | PaletteInput::Right => {
                }
            }
            !escaped && !closing
        });
        if escaped || closing {
            self.release(&mut state)?;
        } else if changed && state.mode == Mode::Open {
            self.draw(&mut state)?;
        }
        state.out.flush()?;
        Ok(used)
    }

    /// Redraws the open palette for the terminal's new size, on a cleared screen, since the
    /// agent's own redraw is held back until the palette closes.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn resized(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.mode == Mode::Open {
            if state.out.overlays() {
                state.out.close_palette();
            } else {
                state.out.write_all(CLEAR)?;
            }
            self.draw(&mut state)?;
        }
        state.out.flush()
    }

    /// Closes the palette: writes what the agent wrote meanwhile and makes it repaint.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn close(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.mode != Mode::Agent {
            self.release(&mut state)?;
        }
        state.out.flush()
    }

    /// Closes the palette and stops drawing for good, since the agent ended.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn finish(&self) -> io::Result<()> {
        let closed = self.close();
        let mut state = self.lock()?;
        state.out.finish();
        closed
    }

    /// Gives the output the agent's terminal's new `size` and then, under the same lock, lets
    /// `follow` resize the agent's terminal, so every byte the agent writes for the new size
    /// is read at that size; returns what `follow` returns.
    ///
    /// # Errors
    ///
    /// Returns an error when the screen's lock is poisoned.
    pub(crate) fn follow_size<R>(
        &self,
        size: WindowSize,
        follow: impl FnOnce() -> R,
    ) -> io::Result<R> {
        let mut state = self.lock()?;
        state.out.resize(size);
        Ok(follow())
    }

    fn release(&self, state: &mut State<W>) -> io::Result<()> {
        let was_open = state.mode == Mode::Open;
        let held = std::mem::take(&mut state.held);
        state.tracker.feed(&held);
        state.mode = Mode::Agent;
        state.filter.clear();
        state.selected = 0;
        state.selected_id = None;
        state.scroll = 0;
        state.read_whole = None;
        state.keys = PaletteKeys::default();
        state.guard = Guard::Off;
        state.out.write_all(&held)?;
        state.out.close_palette();
        if was_open && !state.out.overlays() {
            self.terminal.repaint();
        }
        Ok(())
    }

    fn draw(&self, state: &mut State<W>) -> io::Result<()> {
        if state.guard == Guard::UntilShown {
            state.guard = Guard::Until(Instant::now() + OPEN_GUARD);
        }
        let size = self.terminal.size();
        let lines = self.waiting_lines(&state.filter);
        if let Some(position) = state
            .selected_id
            .as_ref()
            .and_then(|id| lines.iter().position(|line| line.id == *id))
        {
            state.selected = position;
        }
        state.selected = state.selected.min(lines.len().saturating_sub(1));
        let selected_id = lines.get(state.selected).map(|line| line.id.clone());
        if selected_id != state.selected_id {
            state.scroll = 0;
        }
        state.selected_id.clone_from(&selected_id);
        let text = selected_id.as_ref().and_then(|id| self.text_of(id));
        let read_whole = selected_id.is_some() && state.read_whole == selected_id;
        let hint = match (&text, read_whole) {
            (None, _) => self.hint.as_str(),
            (Some(_), false) => HELD_READ,
            (Some(_), true) => HELD_DECIDE,
        };
        let items: Vec<PaletteItem<'_>> = lines
            .iter()
            .map(|line| PaletteItem {
                label: &line.from,
                detail: &line.detail,
            })
            .collect();
        let view = PaletteView {
            title: TITLE,
            filter: &state.filter,
            items: &items,
            selected: state.selected,
            empty: EMPTY,
            hint,
            preview: text.as_deref().map(|text| Preview {
                text,
                scroll: state.scroll,
            }),
            true_color: crate::ui::true_color(),
        };
        let drawn = view.draw(size.rows, size.cols, &mut state.out.palette_out())?;
        state.page = drawn.page;
        state.scroll = state.scroll.min(drawn.lines.saturating_sub(drawn.page));
        if text.is_some() && drawn.page > 0 && drawn.shows_end(state.scroll) {
            let newly_read = state.read_whole != selected_id;
            state.read_whole = selected_id;
            if newly_read {
                return self.draw(state);
            }
        }
        Ok(())
    }

    fn waiting_lines(&self, filter: &str) -> Vec<Line> {
        let mut lines = Vec::new();
        let now = Instant::now();
        if let Some(waiting) = &self.waiting {
            waiting.each(|held| {
                let from = held.from.to_string();
                if contains_ignoring_case(&from, filter)
                    || contains_ignoring_case(HELD_DETAIL, filter)
                {
                    let mut detail = String::with_capacity(HELD_DETAIL.len() + 8);
                    push_age(&mut detail, now.saturating_duration_since(held.since));
                    detail.push_str(" · ");
                    detail.push_str(HELD_DETAIL);
                    lines.push(Line {
                        id: (held.from.clone(), held.held.commit),
                        from,
                        detail,
                    });
                }
            });
        }
        lines
    }

    fn entry_at(&self, filter: &str, index: usize) -> Option<Entry> {
        self.waiting_lines(filter)
            .into_iter()
            .nth(index)
            .map(|line| line.id)
    }

    fn text_of(&self, (from, commit): &Entry) -> Option<String> {
        self.waiting
            .as_ref()?
            .waiting(from)
            .filter(|waiting| waiting.held.commit == *commit)
            .map(|waiting| held_text(&waiting))
    }

    fn choose(&self, (from, commit): &Entry, choice: Choice) -> bool {
        self.waiting
            .as_ref()
            .is_some_and(|waiting| waiting.choose((from, *commit), choice))
    }

    /// Redraws the open palette, so the held turns that came and their ages show.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn tick(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if state.mode == Mode::Open {
            self.draw(&mut state)?;
        }
        state.out.flush()
    }
}

struct Line {
    id: Entry,
    from: String,
    detail: String,
}

/// Returns what the palette shows of a snapshot that waits: the paths it changes that hold
/// it, each without control or invisible characters, and that the teammate's later turns
/// wait behind it.
fn held_text(waiting: &Waiting) -> String {
    let mut text = String::from(HELD_INTRO);
    text.push('\n');
    for path in &waiting.held.paths {
        text.push_str("  ");
        text.extend(path.chars().map(|c| {
            if c.is_control() || is_invisible(c) {
                '?'
            } else {
                c
            }
        }));
        text.push('\n');
    }
    let more = waiting
        .held
        .changed
        .saturating_sub(waiting.held.paths.len());
    if waiting.held.paths.is_empty() {
        let _ = writeln!(text, "  {HELD_UNTOLD}");
    } else if more > 0 {
        let _ = writeln!(text, "  and {more} more");
    }
    text.push_str(HELD_BEHIND);
    text
}

fn contains_ignoring_case(text: &str, part: &str) -> bool {
    part.is_empty()
        || text
            .as_bytes()
            .windows(part.len())
            .any(|window| window.eq_ignore_ascii_case(part.as_bytes()))
}

impl<W: ScreenOut, T: AgentTerminal> AgentInput for Screen<W, T> {
    fn palette_open(&self) -> bool {
        self.is_open()
    }
}

fn push_age(out: &mut String, age: Duration) {
    let seconds = age.as_secs();
    let (count, unit) = match seconds {
        0..60 => (seconds, 's'),
        60..3600 => (seconds / 60, 'm'),
        _ => (seconds / 3600, 'h'),
    };
    let _ = write!(out, "{count}{unit}");
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{
        AtomicUsize,
        Ordering,
    };

    use super::*;

    #[derive(Debug, Default)]
    struct FakeTerminal {
        repaints: AtomicUsize,
    }

    impl AgentTerminal for &FakeTerminal {
        fn size(&self) -> WindowSize {
            WindowSize { rows: 24, cols: 80 }
        }

        fn repaint(&self) {
            self.repaints.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn screen(terminal: &FakeTerminal) -> Screen<Vec<u8>, &FakeTerminal> {
        Screen::new(Vec::new(), terminal, PaletteKey::CTRL_SPACE)
    }

    fn written(screen: &Screen<Vec<u8>, &FakeTerminal>) -> Vec<u8> {
        std::mem::take(&mut screen.lock().unwrap().out)
    }

    fn shown(bytes: &[u8]) -> String {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(bytes);
        parser.screen().contents()
    }

    fn has_box(bytes: &[u8]) -> bool {
        String::from_utf8_lossy(bytes).contains('╭')
    }

    #[derive(Debug, Default)]
    struct Recording {
        drawn: Vec<u8>,
        events: Arc<Mutex<Vec<String>>>,
        finished: bool,
        overlay: Option<Vec<u8>>,
        overlays: bool,
    }

    impl Write for Recording {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.finished {
                self.drawn.extend_from_slice(bytes);
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ScreenOut for Recording {
        fn resize(&mut self, size: WindowSize) {
            self.events
                .lock()
                .unwrap()
                .push(format!("resize {}x{}", size.rows, size.cols));
        }

        fn finish(&mut self) {
            self.finished = true;
            self.events.lock().unwrap().push("finish".to_owned());
        }

        fn overlays(&self) -> bool {
            self.overlays
        }

        fn palette_out(&mut self) -> &mut dyn Write {
            if self.overlays {
                self.overlay.get_or_insert_with(Vec::new)
            } else {
                self
            }
        }

        fn close_palette(&mut self) {
            self.overlay = None;
        }
    }

    #[test]
    fn a_palette_drawn_over_the_agent_lets_it_draw_and_closes_without_a_repaint() {
        let terminal = FakeTerminal::default();
        let screen = Screen::new(
            Recording {
                overlays: true,
                ..Recording::default()
            },
            &terminal,
            PaletteKey::CTRL_SPACE,
        );
        screen.output(b"\x1b]2;unfinished").unwrap();
        screen.open().unwrap();
        assert!(!screen.is_opening());
        assert!(screen.is_open());
        screen.output(b"\x07more").unwrap();
        {
            let state = screen.lock().unwrap();
            assert_eq!(state.out.drawn, b"\x1b]2;unfinished\x07more");
            assert!(has_box(state.out.overlay.as_deref().unwrap()));
        }
        screen.resized().unwrap();
        assert!(has_box(
            screen.lock().unwrap().out.overlay.as_deref().unwrap()
        ));
        screen.typed(b"\x1b").unwrap();
        assert!(!screen.is_open());
        assert!(screen.lock().unwrap().out.overlay.is_none());
        assert_eq!(terminal.repaints.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_resize_reaches_the_screen_before_the_agent_and_nothing_is_drawn_after_finish() {
        let terminal = FakeTerminal::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let screen = Screen::new(
            Recording {
                events: Arc::clone(&events),
                ..Recording::default()
            },
            &terminal,
            PaletteKey::CTRL_SPACE,
        );
        screen.output(b"agent").unwrap();
        let followed = screen
            .follow_size(WindowSize { rows: 3, cols: 4 }, || {
                events.lock().unwrap().push("follow".to_owned());
                7
            })
            .unwrap();
        assert_eq!(followed, 7);
        assert_eq!(screen.lock().unwrap().out.drawn, b"agent");
        screen.finish().unwrap();
        screen.output(b"late").unwrap();
        assert_eq!(screen.lock().unwrap().out.drawn, b"agent");
        assert_eq!(*events.lock().unwrap(), ["resize 3x4", "follow", "finish"]);
    }

    #[test]
    fn the_agents_output_passes_until_the_palette_opens_then_waits_for_it_to_close() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.output(b"hello").unwrap();
        assert_eq!(written(&screen), b"hello");
        screen.open().unwrap();
        assert!(screen.is_open());
        let drawn = written(&screen);
        assert!(has_box(&drawn));
        assert!(shown(&drawn).contains("Ctrl-Space twice"));
        screen.output(b"one ").unwrap();
        screen.output(b"two").unwrap();
        assert!(written(&screen).is_empty());
        screen.close().unwrap();
        assert!(!screen.is_open());
        assert_eq!(written(&screen), b"one two");
        assert_eq!(terminal.repaints.load(Ordering::SeqCst), 1);
        screen.output(b"after").unwrap();
        assert_eq!(written(&screen), b"after");
    }

    #[test]
    fn the_palette_waits_for_the_agent_to_finish_a_sequence() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.output(b"\x1b[1;3").unwrap();
        written(&screen);
        screen.open().unwrap();
        assert!(screen.is_opening());
        assert!(written(&screen).is_empty());
        screen.output(b"1mred").unwrap();
        let out = written(&screen);
        assert!(out.starts_with(b"1m\x1b7"), "{out:?}");
        assert!(has_box(&out));
        assert!(!out.ends_with(b"red"));
        screen.close().unwrap();
        assert_eq!(written(&screen), b"red");

        screen.output(b"\x1b]0;stuck").unwrap();
        written(&screen);
        screen.open().unwrap();
        assert!(written(&screen).is_empty());
        screen.open_now().unwrap();
        assert!(has_box(&written(&screen)));
        assert!(!screen.is_opening());
    }

    #[test]
    fn closing_before_the_palette_is_drawn_does_not_repaint() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.output(b"\x1b[").unwrap();
        screen.open().unwrap();
        screen.close().unwrap();
        assert!(!screen.is_open());
        assert_eq!(terminal.repaints.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn too_much_held_output_closes_the_palette() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.open().unwrap();
        written(&screen);
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..16 {
            screen.output(&chunk).unwrap();
        }
        assert!(screen.is_open());
        screen.output(b"y").unwrap();
        assert!(!screen.is_open());
        let out = written(&screen);
        assert_eq!(out.len(), MAX_HELD_BYTES + 1);
        assert_eq!(terminal.repaints.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_resize_redraws_only_an_open_palette() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.resized().unwrap();
        assert!(written(&screen).is_empty());
        screen.open().unwrap();
        written(&screen);
        screen.resized().unwrap();
        let out = written(&screen);
        assert!(out.starts_with(CLEAR));
        assert!(has_box(&out));
    }

    #[test]
    fn typed_text_filters_and_escape_closes_but_pasted_text_never_does() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.open().unwrap();
        written(&screen);
        screen.typed(b"fix").unwrap();
        assert!(shown(&written(&screen)).contains("› fix"));
        screen.typed(b"\x7f").unwrap();
        let shortened = shown(&written(&screen));
        assert!(shortened.contains("› fi") && !shortened.contains("› fix"));
        screen.typed(b"\x1b[200~\x1b\r\x1b[201~").unwrap();
        assert!(screen.is_open());
        written(&screen);
        assert_eq!(screen.typed(b"\x1b[27uhello").unwrap(), 5);
        assert!(!screen.is_open());
        assert_eq!(screen.typed(b"hello").unwrap(), 0);
        assert_eq!(terminal.repaints.load(Ordering::SeqCst), 1);
        screen.open().unwrap();
        let reopened = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(reopened.contains("› "));
        assert!(!reopened.contains("fi"));
    }

    fn held(teammate: &str, commit: u8, paths: &[&str]) -> (AgentSlot, crate::held::HeldSettings) {
        let paths: Vec<String> = paths.iter().map(|path| (*path).to_owned()).collect();
        (
            teammate.parse().unwrap(),
            crate::held::HeldSettings::new(ObjectId::from_bytes_or_panic(&[commit; 20]), &paths),
        )
    }

    #[test]
    fn held_turns_are_listed_filtered_and_selected() {
        let terminal = FakeTerminal::default();
        let waiting = Arc::new(HeldQueue::default());
        let screen = screen(&terminal).with_waiting(Arc::clone(&waiting));
        waiting.show(vec![
            held("bob.claude", 1, &["CLAUDE.md"]),
            held("carol.codex", 2, &["AGENTS.md"]),
        ]);
        screen.open().unwrap();
        let drawn = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(drawn.contains(TITLE), "{drawn}");
        assert!(drawn.contains("bob.claude"), "{drawn}");
        assert!(drawn.contains("0s · changes agent settings"), "{drawn}");
        assert!(drawn.contains("carol.codex"), "{drawn}");
        screen.typed(b"carol").unwrap();
        let filtered = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(
            filtered.contains("carol") && !filtered.contains("bob"),
            "{filtered}"
        );
        screen.typed(b"\x7f\x7f\x7f\x7f\x7f\x1b[B\x1b[B").unwrap();
        let carol = (
            "carol.codex".parse().unwrap(),
            ObjectId::from_bytes_or_panic(&[2; 20]),
        );
        assert_eq!(screen.lock().unwrap().selected_id, Some(carol));
        let bob = (
            "bob.claude".parse().unwrap(),
            ObjectId::from_bytes_or_panic(&[1; 20]),
        );
        screen.typed(b"\x1b[A").unwrap();
        assert_eq!(screen.lock().unwrap().selected_id, Some(bob.clone()));
        waiting.show(vec![
            held("bob.claude", 1, &["CLAUDE.md"]),
            held("carol.codex", 2, &["AGENTS.md"]),
            held("dave.claude", 3, &[".mcp.json"]),
        ]);
        written(&screen);
        screen.tick().unwrap();
        let ticked = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(ticked.contains("dave.claude"), "{ticked}");
        assert_eq!(screen.lock().unwrap().selected_id, Some(bob));
        assert!(contains_ignoring_case("Fix The Parser", "the pars"));
        assert!(!contains_ignoring_case("fix", "fixes"));
    }

    #[test]
    fn ages_read_in_seconds_minutes_or_hours() {
        for (seconds, shown) in [
            (0, "0s"),
            (59, "59s"),
            (60, "1m"),
            (3599, "59m"),
            (7200, "2h"),
        ] {
            let mut out = String::new();
            push_age(&mut out, Duration::from_secs(seconds));
            assert_eq!(out, shown);
        }
    }

    #[test]
    fn a_palette_with_nothing_held_says_no_teammates_turn_waits() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.open().unwrap();
        assert!(String::from_utf8_lossy(&written(&screen)).contains(EMPTY));
    }

    fn held_screen(terminal: &FakeTerminal) -> (Screen<Vec<u8>, &FakeTerminal>, Arc<HeldQueue>) {
        let waiting = Arc::new(HeldQueue::default());
        let screen = screen(terminal).with_waiting(Arc::clone(&waiting));
        let record = crate::held::HeldSettings::new(
            mahi_store::ObjectId::from_bytes_or_panic(&[1; 20]),
            &[
                "CLAUDE.md".to_owned(),
                ".claude/set\x1b]0;x\x07.json".to_owned(),
            ],
        );
        waiting.show(vec![("bob.claude".parse().unwrap(), record)]);
        (screen, waiting)
    }

    #[test]
    fn a_held_snapshot_shows_its_paths_cleaned_and_enter_takes_it_and_closes() {
        let terminal = FakeTerminal::default();
        let (screen, waiting) = held_screen(&terminal);
        screen.open().unwrap();
        let drawn = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(drawn.contains("bob.claude"), "{drawn}");
        assert!(drawn.contains("changes agent settings"), "{drawn}");
        assert!(drawn.contains("CLAUDE.md"), "{drawn}");
        assert!(drawn.contains(".claude/set?]0;x?.json"), "{drawn}");
        assert!(drawn.contains("Its later turns wait behind it."), "{drawn}");
        assert!(drawn.contains(" takes"), "{drawn}");
        assert!(drawn.contains(" skips"), "{drawn}");
        screen.typed(b"\r").unwrap();
        assert!(!screen.is_open());
        let choices = waiting.take_choices();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].2, Choice::Take);
    }

    #[test]
    fn ctrl_x_skips_a_held_snapshot_and_tab_does_nothing_to_it() {
        let terminal = FakeTerminal::default();
        let (screen, waiting) = held_screen(&terminal);
        screen.open().unwrap();
        screen.typed(b"\t").unwrap();
        assert!(waiting.take_choices().is_empty());
        screen.typed(b"\x18").unwrap();
        assert!(screen.is_open());
        let choices = waiting.take_choices();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].2, Choice::Skip);
    }

    #[test]
    fn the_palette_opened_for_a_held_snapshot_drops_keys_for_its_first_half_second() {
        let terminal = FakeTerminal::default();
        let (screen, waiting) = held_screen(&terminal);
        screen.open_guarded().unwrap();
        assert!(screen.is_open());
        assert_eq!(screen.typed(b"\r").unwrap(), 1);
        assert!(screen.is_open());
        assert!(waiting.take_choices().is_empty());
        thread::sleep(OPEN_GUARD + Duration::from_millis(50));
        screen.typed(b"\r").unwrap();
        assert!(!screen.is_open());
        assert_eq!(waiting.take_choices().len(), 1);
    }

    #[test]
    fn the_guard_starts_only_once_the_palette_shows_and_holds_every_key_until_then() {
        let terminal = FakeTerminal::default();
        let (screen, waiting) = held_screen(&terminal);
        screen.output(b"\x1b[").unwrap();
        screen.open_guarded().unwrap();
        assert!(screen.is_opening());
        thread::sleep(OPEN_GUARD + Duration::from_millis(50));
        assert_eq!(screen.typed(b"\x18").unwrap(), 1);
        assert!(waiting.take_choices().is_empty());
        screen.output(b"m").unwrap();
        assert!(!screen.is_opening());
        screen.typed(b"\x18").unwrap();
        assert!(waiting.take_choices().is_empty());
        thread::sleep(OPEN_GUARD + Duration::from_millis(50));
        screen.typed(b"\x18").unwrap();
        assert_eq!(waiting.take_choices().len(), 1);
    }

    #[test]
    fn a_long_held_turn_is_taken_only_after_it_was_read_to_the_end() {
        let terminal = FakeTerminal::default();
        let waiting = Arc::new(HeldQueue::default());
        let screen = screen(&terminal).with_waiting(Arc::clone(&waiting));
        let paths: Vec<String> = (1..=20).map(|n| format!("dir{n}/CLAUDE.md")).collect();
        let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        waiting.show(vec![held("bob.claude", 1, &paths)]);
        screen.open().unwrap();
        let first = shown(&written(&screen));
        assert!(
            first.contains("dir1/CLAUDE.md") && !first.contains(HELD_BEHIND),
            "{first}"
        );
        assert!(first.contains("PgDn reads on"), "{first}");
        screen.typed(b"\r").unwrap();
        assert!(screen.is_open());
        assert!(waiting.take_choices().is_empty());
        for _ in 0..3 {
            screen.typed(b"\x1b[6~").unwrap();
        }
        let end = shown(&written(&screen));
        assert!(end.contains(HELD_BEHIND), "{end}");
        assert!(end.contains("Enter takes"), "{end}");
        screen.typed(b"\r").unwrap();
        assert!(!screen.is_open());
        assert_eq!(waiting.take_choices().len(), 1);
    }
}
