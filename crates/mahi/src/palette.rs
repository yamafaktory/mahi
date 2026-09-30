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

use mahi_live::PROMPT_ID_BYTES;
use mahi_sandbox::{
    PtyResizer,
    WindowSize,
};
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
    inject::AgentInput,
    prompts::{
        Decision,
        Prompts,
    },
    terminal,
};

const MAX_HELD_BYTES: usize = 1024 * 1024;
const TITLE: &str = "mahi";
const EMPTY: &str = "No prompts waiting";
const HINT_READ: &str = "PgDn reads on · Ctrl-X rejects · Esc closes";
const HINT_DECIDE: &str = "Enter accepts · Tab always · Ctrl-X rejects · Esc closes";
const NO_TEAMMATES: &str = "Teammates cannot watch this run, so no prompts come";
const CLEAR: &[u8] = b"\x1b[2J";
const REPAINT_PAUSE: Duration = Duration::from_millis(100);
const DETAIL_CHARS: usize = 200;

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
        let resizer = self.0.lock().ok()?;
        let size = terminal::size();
        resizer.resize(size).ok()?;
        Some(size)
    }
}

impl AgentTerminal for Repainter {
    fn size(&self) -> WindowSize {
        terminal::size()
    }

    fn repaint(&self) {
        if let Ok(resizer) = self.0.lock() {
            let size = terminal::size();
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
    prompts: Option<Arc<Prompts>>,
    hint: String,
}

#[derive(Debug)]
struct State<W> {
    out: W,
    tracker: OutputTracker,
    mode: Mode,
    held: Vec<u8>,
    filter: String,
    selected: usize,
    selected_id: Option<[u8; PROMPT_ID_BYTES]>,
    scroll: usize,
    page: usize,
    read_whole: Option<[u8; PROMPT_ID_BYTES]>,
    keys: PaletteKeys,
    notice: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Agent,
    Opening,
    Open,
}

impl<W: Write, T: AgentTerminal> Screen<W, T> {
    /// Starts a screen that writes to `out`, with the palette closed; the palette lists the
    /// teammates' `prompts`, when teammates can send any.
    pub(crate) fn new(out: W, terminal: T, key: PaletteKey, prompts: Option<Arc<Prompts>>) -> Self {
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
                notice: Vec::new(),
            }),
            terminal,
            prompts,
            hint: format!("Esc closes · {key} twice sends {key} to the agent"),
        }
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
        match state.mode {
            Mode::Agent => {
                state.tracker.feed(bytes);
                state.out.write_all(bytes)?;
                write_notice(&mut state)?;
            }
            Mode::Opening => {
                let written = state.tracker.feed_until_drawable(bytes);
                let (now, later) = bytes.split_at(written);
                state.out.write_all(now)?;
                if state.tracker.can_draw() {
                    state.held.extend_from_slice(later);
                    state.mode = Mode::Open;
                    write_notice(&mut state)?;
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

    /// Writes `notice`, the sequence that asks the terminal for a notification, where the
    /// agent's output allows it: at once when it does, and otherwise as soon as it does,
    /// replacing a notice still waiting.
    ///
    /// # Errors
    ///
    /// Returns the error writing to the screen gives.
    pub(crate) fn notify(&self, notice: &[u8]) -> io::Result<()> {
        let mut state = self.lock()?;
        state.notice.clear();
        state.notice.extend_from_slice(notice);
        if state.mode == Mode::Open {
            let pending = std::mem::take(&mut state.notice);
            state.out.write_all(&pending)?;
        } else if state.mode == Mode::Agent {
            write_notice(&mut state)?;
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
        if state.tracker.can_draw() {
            state.mode = Mode::Open;
            self.draw(&mut state)?;
        } else {
            state.mode = Mode::Opening;
        }
        state.out.flush()
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
                PaletteInput::Text(character) => {
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
                PaletteInput::Enter | PaletteInput::Tab | PaletteInput::Reject => {
                    let decision = match input {
                        PaletteInput::Enter => Decision::Accept,
                        PaletteInput::Tab => Decision::AlwaysAccept,
                        _ => Decision::Reject,
                    };
                    let id = selected_id.or_else(|| self.id_at(filter, *selected));
                    let read = decision == Decision::Reject || (id.is_some() && id == *read_whole);
                    if read
                        && let Some((id, prompts)) = id.zip(self.prompts.as_ref())
                        && prompts.decide(id, decision)
                    {
                        *selected_id = None;
                        changed = true;
                        closing |= decision != Decision::Reject;
                    }
                }
                PaletteInput::Up => {}
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
            state.out.write_all(CLEAR)?;
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
        state.out.write_all(&held)?;
        write_notice(state)?;
        if was_open {
            self.terminal.repaint();
        }
        Ok(())
    }

    fn draw(&self, state: &mut State<W>) -> io::Result<()> {
        let size = self.terminal.size();
        let lines = self.waiting_lines(&state.filter);
        if let Some(position) = state
            .selected_id
            .and_then(|id| lines.iter().position(|line| line.id == id))
        {
            state.selected = position;
        }
        state.selected = state.selected.min(lines.len().saturating_sub(1));
        let selected_id = lines.get(state.selected).map(|line| line.id);
        if selected_id != state.selected_id {
            state.scroll = 0;
        }
        state.selected_id = selected_id;
        let text = selected_id
            .zip(self.prompts.as_ref())
            .and_then(|(id, prompts)| prompts.text_of(id));
        let read_whole = selected_id.is_some() && state.read_whole == selected_id;
        let hint = match (&text, read_whole) {
            (None, _) => self.hint.as_str(),
            (Some(_), false) => HINT_READ,
            (Some(_), true) => HINT_DECIDE,
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
            empty: if self.prompts.is_some() {
                EMPTY
            } else {
                NO_TEAMMATES
            },
            hint,
            preview: text.as_deref().map(|text| Preview {
                text,
                scroll: state.scroll,
            }),
        };
        let drawn = view.draw(size.rows, size.cols, &mut state.out)?;
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
        let Some(prompts) = &self.prompts else {
            return lines;
        };
        let now = Instant::now();
        prompts.each_waiting(|waiting| {
            let from = waiting.from.as_str();
            let text = waiting.text.as_str();
            if contains_ignoring_case(from, filter) || contains_ignoring_case(text, filter) {
                let mut detail = String::with_capacity(DETAIL_CHARS + 8);
                push_age(&mut detail, now.saturating_duration_since(waiting.at));
                detail.push_str(" · ");
                detail.extend(text.chars().take(DETAIL_CHARS));
                lines.push(Line {
                    id: waiting.id,
                    from: from.to_owned(),
                    detail,
                });
            }
        });
        lines
    }

    fn id_at(&self, filter: &str, index: usize) -> Option<[u8; PROMPT_ID_BYTES]> {
        let mut found = None;
        let mut seen = 0;
        self.prompts.as_ref()?.each_waiting(|waiting| {
            let shown = contains_ignoring_case(waiting.from.as_str(), filter)
                || contains_ignoring_case(waiting.text.as_str(), filter);
            if shown && found.is_none() {
                if seen == index {
                    found = Some(waiting.id);
                }
                seen += 1;
            }
        });
        found
    }

    /// Redraws the open palette, so the prompts that came and their ages show.
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
    id: [u8; PROMPT_ID_BYTES],
    from: String,
    detail: String,
}

fn contains_ignoring_case(text: &str, part: &str) -> bool {
    part.is_empty()
        || text
            .as_bytes()
            .windows(part.len())
            .any(|window| window.eq_ignore_ascii_case(part.as_bytes()))
}

impl<W: Write, T: AgentTerminal> AgentInput for Screen<W, T> {
    fn palette_open(&self) -> bool {
        self.is_open()
    }

    fn bracketed_paste(&self) -> bool {
        self.lock()
            .is_ok_and(|state| state.tracker.bracketed_paste())
    }
}

fn write_notice<W: Write>(state: &mut State<W>) -> io::Result<()> {
    if state.notice.is_empty() || !state.tracker.is_ground() {
        return Ok(());
    }
    let notice = std::mem::take(&mut state.notice);
    state.out.write_all(&notice)
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
        Screen::new(
            Vec::new(),
            terminal,
            PaletteKey::CTRL_SPACE,
            Some(Arc::new(Prompts::default())),
        )
    }

    fn written(screen: &Screen<Vec<u8>, &FakeTerminal>) -> Vec<u8> {
        std::mem::take(&mut screen.lock().unwrap().out)
    }

    fn has_box(bytes: &[u8]) -> bool {
        String::from_utf8_lossy(bytes).contains('╭')
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
        assert!(String::from_utf8_lossy(&drawn).contains("Ctrl-Space twice"));
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
        assert!(String::from_utf8_lossy(&written(&screen)).contains("› fix"));
        screen.typed(b"\x7f").unwrap();
        let shortened = String::from_utf8_lossy(&written(&screen)).into_owned();
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

    #[test]
    fn waiting_prompts_are_listed_filtered_and_selected() {
        let terminal = FakeTerminal::default();
        let prompts = Arc::new(Prompts::default());
        let screen = Screen::new(
            Vec::new(),
            &terminal,
            PaletteKey::CTRL_SPACE,
            Some(Arc::clone(&prompts)),
        );
        let text = |text: &str| mahi_live::PromptText::new(text.to_owned()).unwrap();
        let name = |name: &str| mahi_core::ParticipantName::new(name).unwrap();
        prompts.offer(name("bob"), [1; 16], text("fix the parser test"));
        prompts.offer(name("carol"), [2; 16], text("add a changelog entry"));
        screen.open().unwrap();
        let drawn = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(drawn.contains("bob"), "{drawn}");
        assert!(drawn.contains("0s · fix the parser test"), "{drawn}");
        assert!(drawn.contains("carol"), "{drawn}");
        screen.typed(b"changelog").unwrap();
        let filtered = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(
            filtered.contains("carol") && !filtered.contains("bob"),
            "{filtered}"
        );
        screen
            .typed(b"\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x1b[B\x1b[B")
            .unwrap();
        assert_eq!(screen.lock().unwrap().selected_id, Some([2; 16]));
        prompts.offer(name("dave"), [3; 16], text("x".repeat(8000).as_str()));
        screen.typed(b"\x1b[A").unwrap();
        assert_eq!(screen.lock().unwrap().selected_id, Some([1; 16]));
        written(&screen);
        screen.tick().unwrap();
        let ticked = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(ticked.contains("dave"), "{ticked}");
        assert_eq!(screen.lock().unwrap().selected_id, Some([1; 16]));
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
    fn without_a_live_layer_the_palette_says_no_prompts_come() {
        let terminal = FakeTerminal::default();
        let screen = Screen::new(Vec::new(), &terminal, PaletteKey::CTRL_SPACE, None);
        screen.open().unwrap();
        assert!(String::from_utf8_lossy(&written(&screen)).contains("Teammates cannot watch"));
    }

    #[test]
    fn enter_accepts_and_closes_ctrl_x_rejects_and_stays_and_tab_always_accepts() {
        let terminal = FakeTerminal::default();
        let prompts = Arc::new(Prompts::default());
        let screen = Screen::new(
            Vec::new(),
            &terminal,
            PaletteKey::CTRL_SPACE,
            Some(Arc::clone(&prompts)),
        );
        let text = |text: &str| mahi_live::PromptText::new(text.to_owned()).unwrap();
        let name = |name: &str| mahi_core::ParticipantName::new(name).unwrap();
        prompts.offer(name("bob"), [1; 16], text("one"));
        prompts.offer(name("carol"), [2; 16], text("two"));
        prompts.offer(name("dave"), [3; 16], text("three"));
        screen.open().unwrap();
        assert_eq!(screen.typed(b"\x18").unwrap(), 1);
        assert!(screen.is_open());
        assert_eq!(screen.lock().unwrap().selected_id, Some([2; 16]));
        screen.typed(b"\r").unwrap();
        assert!(!screen.is_open());
        assert_eq!(prompts.next_accepted().unwrap().id, [2; 16]);
        screen.open().unwrap();
        screen.typed(b"\t").unwrap();
        assert!(!screen.is_open());
        assert_eq!(prompts.next_accepted().unwrap().id, [3; 16]);
        assert_eq!(
            prompts.offer(name("dave"), [4; 16], text("four")),
            mahi_live::PromptOutcome::Accepted
        );
        screen.open().unwrap();
        screen.typed(b"\r").unwrap();
        assert!(screen.is_open());
        assert!(!screen.bracketed_paste());
        screen.close().unwrap();
        screen.output(b"\x1b[?2004h").unwrap();
        assert!(screen.bracketed_paste());
    }

    #[test]
    fn a_long_prompt_is_accepted_only_after_it_was_read_to_the_end() {
        let terminal = FakeTerminal::default();
        let prompts = Arc::new(Prompts::default());
        let screen = Screen::new(
            Vec::new(),
            &terminal,
            PaletteKey::CTRL_SPACE,
            Some(Arc::clone(&prompts)),
        );
        let long = (1..=60).fold(String::new(), |mut long, n| {
            writeln!(long, "step {n}").unwrap();
            long
        });
        let name = mahi_core::ParticipantName::new("bob").unwrap();
        prompts.offer(name, [1; 16], mahi_live::PromptText::new(long).unwrap());
        screen.open().unwrap();
        let first = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(
            first.contains("step 1") && !first.contains("step 60"),
            "{first}"
        );
        assert!(first.contains("PgDn reads on"), "{first}");
        screen.typed(b"\r\t").unwrap();
        assert!(screen.is_open());
        assert!(prompts.next_accepted().is_none());
        for _ in 0..3 {
            screen.typed(b"\x1b[6~").unwrap();
        }
        let end = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(end.contains("step 60"), "{end}");
        assert!(end.contains("Enter accepts"), "{end}");
        screen.typed(b"\r").unwrap();
        assert!(!screen.is_open());
        assert_eq!(prompts.next_accepted().unwrap().id, [1; 16]);
    }

    #[test]
    fn a_notice_waiting_while_the_palette_was_forced_open_comes_after_the_held_output() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.output(b"\x1b]0;tit").unwrap();
        screen.open().unwrap();
        screen.notify(b"NOTICE").unwrap();
        screen.open_now().unwrap();
        written(&screen);
        screen.output(b"le\x07after").unwrap();
        screen.close().unwrap();
        let out = written(&screen);
        let notice = out.windows(6).position(|window| window == b"NOTICE");
        assert_eq!(notice, Some(out.len() - 6), "{out:?}");
        assert!(out.starts_with(b"le\x07after"));
        screen.output(b"\x1b7saved").unwrap();
        written(&screen);
        screen.notify(b"TOLD").unwrap();
        assert_eq!(written(&screen), b"TOLD");
    }

    #[test]
    fn a_notice_waits_for_the_agent_to_finish_a_sequence() {
        let terminal = FakeTerminal::default();
        let screen = screen(&terminal);
        screen.notify(b"\x07").unwrap();
        assert_eq!(written(&screen), b"\x07");
        screen.output(b"\x1b[1;3").unwrap();
        written(&screen);
        screen.notify(b"first").unwrap();
        screen.notify(b"second").unwrap();
        assert!(written(&screen).is_empty());
        screen.output(b"1m").unwrap();
        assert_eq!(written(&screen), b"1msecond");
        screen.open().unwrap();
        written(&screen);
        screen.notify(b"open").unwrap();
        assert_eq!(written(&screen), b"open");
    }
}
