use std::{
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
    time::Duration,
};

use mahi_sandbox::{
    PtyResizer,
    WindowSize,
};
use mahi_term::{
    OutputTracker,
    PaletteInput,
    PaletteKey,
    PaletteKeys,
    PaletteView,
};

use crate::terminal;

const MAX_HELD_BYTES: usize = 1024 * 1024;
const TITLE: &str = "mahi";
const EMPTY: &str = "No prompts waiting";
const CLEAR: &[u8] = b"\x1b[2J";
const REPAINT_PAUSE: Duration = Duration::from_millis(100);

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
    hint: String,
}

#[derive(Debug)]
struct State<W> {
    out: W,
    tracker: OutputTracker,
    mode: Mode,
    held: Vec<u8>,
    filter: String,
    keys: PaletteKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Agent,
    Opening,
    Open,
}

impl<W: Write, T: AgentTerminal> Screen<W, T> {
    /// Starts a screen that writes to `out`, with the palette closed.
    pub(crate) fn new(out: W, terminal: T, key: PaletteKey) -> Self {
        Self {
            state: Mutex::new(State {
                out,
                tracker: OutputTracker::default(),
                mode: Mode::Agent,
                held: Vec::new(),
                filter: String::new(),
                keys: PaletteKeys::default(),
            }),
            terminal,
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
        let State { keys, filter, .. } = &mut *state;
        let mut changed = false;
        let mut escaped = false;
        let used = keys.read(bytes, |input| {
            match input {
                PaletteInput::Escape => escaped = true,
                PaletteInput::Text(character) => {
                    filter.push(character);
                    changed = true;
                }
                PaletteInput::Backspace => changed |= filter.pop().is_some(),
                PaletteInput::Enter
                | PaletteInput::Tab
                | PaletteInput::Reject
                | PaletteInput::Up
                | PaletteInput::Down => {}
            }
            !escaped
        });
        if escaped {
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
        state.keys = PaletteKeys::default();
        state.out.write_all(&held)?;
        if was_open {
            self.terminal.repaint();
        }
        Ok(())
    }

    fn draw(&self, state: &mut State<W>) -> io::Result<()> {
        let size = self.terminal.size();
        let view = PaletteView {
            title: TITLE,
            filter: &state.filter,
            items: &[],
            selected: 0,
            empty: EMPTY,
            hint: &self.hint,
        };
        view.draw(size.rows, size.cols, &mut state.out)
    }
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
        assert_eq!(screen.typed(b"\x1b[27uhello").unwrap(), 5);
        assert!(!screen.is_open());
        assert_eq!(screen.typed(b"hello").unwrap(), 0);
        assert_eq!(terminal.repaints.load(Ordering::SeqCst), 1);
        screen.open().unwrap();
        let reopened = String::from_utf8_lossy(&written(&screen)).into_owned();
        assert!(reopened.contains("› "));
        assert!(!reopened.contains("fi"));
    }
}
