use std::{
    io::{
        self,
        Write,
    },
    sync::mpsc,
};

use mahi_sandbox::WindowSize;
use mahi_term::{
    AgentFrame,
    AgentScreen,
    AnsiBackend,
};
use ratatui_core::terminal::Terminal;

use crate::{
    palette::ScreenOut,
    ui,
};

const BEGIN_SYNC: &[u8] = b"\x1b[?2026h";
const END_SYNC: &[u8] = b"\x1b[?2026l";

/// Where an agent's output goes: straight to the user's terminal, or, while the home screen
/// owns it, into a pane mahi draws between its own header and keys.
pub(crate) enum Out {
    Direct(io::Stdout),
    Pane(Box<Pane>),
}

impl Out {
    /// Returns where the output of an agent described by `title` goes: a pane when the home
    /// screen owns the terminal, the terminal itself otherwise. Answers mahi gives the agent's
    /// terminal queries in a pane go to `replies`, to be written to the agent.
    pub(crate) fn for_agent(
        title: &str,
        palette_key: Option<&str>,
        replies: mpsc::SyncSender<Vec<u8>>,
    ) -> io::Result<Self> {
        if ui::is_showing() {
            Ok(Self::Pane(Box::new(Pane::new(
                title,
                palette_key,
                replies,
            )?)))
        } else {
            Ok(Self::Direct(io::stdout()))
        }
    }
}

impl std::fmt::Debug for Out {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Direct(_) => "Out::Direct",
            Self::Pane(_) => "Out::Pane",
        })
    }
}

impl Write for Out {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(out) => out.write(bytes),
            Self::Pane(pane) => {
                pane.feed(bytes);
                Ok(bytes.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Direct(out) => out.flush(),
            Self::Pane(pane) => pane.draw(),
        }
    }
}

impl ScreenOut for Out {
    fn pass_through(&mut self, notice: &[u8]) -> io::Result<()> {
        match self {
            Self::Direct(out) => out.write_all(notice),
            Self::Pane(pane) => {
                if !pane.finished {
                    pane.notices.extend_from_slice(notice);
                }
                Ok(())
            }
        }
    }

    fn resize(&mut self, size: WindowSize) {
        if let Self::Pane(pane) = self {
            pane.resize(size);
        }
    }

    fn finish(&mut self) {
        if let Self::Pane(pane) = self {
            pane.finish();
        }
    }

    fn overlays(&self) -> bool {
        matches!(self, Self::Pane(_))
    }

    fn palette_out(&mut self) -> &mut dyn Write {
        match self {
            Self::Direct(out) => out,
            Self::Pane(pane) => pane.overlay(),
        }
    }

    fn close_palette(&mut self) {
        if let Self::Pane(pane) = self {
            pane.overlay = None;
        }
    }
}

/// What mahi draws over the agent's screen in the pane, such as its palette, as a screen of
/// its own whose written cells cover the agent's.
struct Overlay(vt100::Parser);

impl Write for Overlay {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.process(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An agent's terminal drawn inside mahi's frame: the agent's output goes into mahi's own
/// screen of it, drawn in the pane; mahi's answers to the agent's queries go back to it, and
/// what it asks of the user's terminal itself is passed on after each frame.
pub(crate) struct Pane {
    screen: AgentScreen,
    overlay: Option<Overlay>,
    terminal: Terminal<AnsiBackend<io::Stdout>>,
    title: String,
    hint: Option<String>,
    replies: mpsc::SyncSender<Vec<u8>>,
    notices: Vec<u8>,
    scratch: Vec<u8>,
    finished: bool,
}

impl Pane {
    fn new(
        title: &str,
        palette_key: Option<&str>,
        replies: mpsc::SyncSender<Vec<u8>>,
    ) -> io::Result<Self> {
        let size = crate::terminal::size();
        let (rows, columns) = AgentFrame::agent_size(size.rows, size.cols);
        let mut terminal = Terminal::new(ui::backend(size.rows, size.cols))?;
        terminal.clear()?;
        let mut pane = Self {
            screen: AgentScreen::new(rows, columns),
            overlay: None,
            terminal,
            title: title.to_owned(),
            hint: palette_key.map(str::to_owned),
            replies,
            notices: Vec::new(),
            scratch: Vec::new(),
            finished: false,
        };
        pane.draw()?;
        Ok(pane)
    }

    fn feed(&mut self, bytes: &[u8]) {
        if self.finished {
            return;
        }
        self.screen.feed(bytes);
        let mut replies = Vec::new();
        self.screen.take_replies(&mut replies);
        if !replies.is_empty() {
            let _ = self.replies.try_send(replies);
        }
    }

    fn resize(&mut self, size: WindowSize) {
        self.screen.set_size(size.rows, size.cols);
    }

    fn overlay(&mut self) -> &mut Overlay {
        let (rows, columns) = self.screen.screen().size();
        self.overlay
            .get_or_insert_with(|| Overlay(vt100::Parser::new(rows, columns, 0)))
    }

    fn draw(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        let size = crate::terminal::size();
        let (rows, columns) = AgentFrame::agent_size(size.rows, size.cols);
        self.screen.set_size(rows, columns);
        self.terminal.backend_mut().resize(size.rows, size.cols);
        self.terminal.autoresize()?;
        let all = [
            (
                self.hint.as_deref().unwrap_or_default(),
                "teammates' prompts",
            ),
            ("exit the agent", "back to the threads"),
        ];
        let first = usize::from(self.hint.is_none());
        let frame = AgentFrame {
            title: &self.title,
            hints: all.get(first..).unwrap_or_default(),
        };
        let screen = self.screen.screen();
        let overlay = self.overlay.as_ref().map(|overlay| overlay.0.screen());
        io::stdout().lock().write_all(BEGIN_SYNC)?;
        let drawn = self.terminal.draw(|drawing| {
            let area = drawing.area();
            if let Some(cursor) = frame.render(screen, overlay, area, drawing.buffer_mut()) {
                drawing.set_cursor_position(cursor);
            }
        });
        self.scratch.clear();
        if drawn.is_ok() {
            self.screen.take_passed(&mut self.scratch);
        }
        self.scratch.append(&mut self.notices);
        self.scratch.extend_from_slice(END_SYNC);
        let mut out = io::stdout().lock();
        out.write_all(&self.scratch)?;
        out.flush()?;
        drawn.map(|_| ())
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.scratch.clear();
        self.screen.undo(&mut self.scratch);
        self.scratch.append(&mut self.notices);
        let mut out = io::stdout().lock();
        let _ = out.write_all(&self.scratch);
        let _ = out.flush();
    }
}

impl Drop for Pane {
    fn drop(&mut self) {
        self.finish();
    }
}
