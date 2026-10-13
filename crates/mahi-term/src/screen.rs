use std::io::{
    self,
    Write,
};

use mahi_core::is_invisible;
use ratatui_core::{
    backend::{
        Backend,
        ClearType,
        WindowSize,
    },
    buffer::Cell,
    layout::{
        Position,
        Size,
    },
    style::{
        Color,
        Modifier,
    },
};
use unicode_width::UnicodeWidthStr;

const MODIFIERS: [(Modifier, u8); 9] = [
    (Modifier::BOLD, 1),
    (Modifier::DIM, 2),
    (Modifier::ITALIC, 3),
    (Modifier::UNDERLINED, 4),
    (Modifier::SLOW_BLINK, 5),
    (Modifier::RAPID_BLINK, 6),
    (Modifier::REVERSED, 7),
    (Modifier::HIDDEN, 8),
    (Modifier::CROSSED_OUT, 9),
];

/// A `ratatui` backend that draws with plain escape sequences into any writer, so mahi's
/// full-screen views share the terminal handling and key reading mahi already has.
///
/// A cell's text that holds a control or invisible character is drawn as one `?` per column,
/// so no text drawn can move the cursor or send the terminal a command. What it writes is kept
/// until [`Backend::flush`], which sends a frame in one write. It supports full-screen and
/// fixed viewports only: it neither asks the terminal where its cursor is nor scrolls.
#[derive(Debug)]
pub struct AnsiBackend<W: Write> {
    out: W,
    pending: Vec<u8>,
    size: Size,
    cursor: Position,
    true_color: bool,
}

/// The colours and attributes the terminal was last told to draw with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pen {
    fg: Color,
    bg: Color,
    modifier: Modifier,
}

impl Default for Pen {
    fn default() -> Self {
        Self {
            fg: Color::Reset,
            bg: Color::Reset,
            modifier: Modifier::empty(),
        }
    }
}

impl<W: Write> AnsiBackend<W> {
    /// Makes a backend that writes to `out`, for a terminal of `rows` rows and `columns`
    /// columns.
    pub fn new(out: W, rows: u16, columns: u16) -> Self {
        Self {
            out,
            pending: Vec::new(),
            size: Size::new(columns, rows),
            cursor: Position::ORIGIN,
            true_color: true,
        }
    }

    /// Draws colours given as red, green and blue with the nearest of the terminal's 256
    /// colours instead, for a terminal that does not draw 24-bit colour.
    #[must_use]
    pub fn without_true_color(mut self) -> Self {
        self.true_color = false;
        self
    }

    /// Records the terminal's new size, which the next draw fills.
    pub fn resize(&mut self, rows: u16, columns: u16) {
        self.size = Size::new(columns, rows);
    }

    /// Returns the writer, which holds everything up to the last flush.
    pub fn writer(&mut self) -> &mut W {
        &mut self.out
    }

    fn move_to(&mut self, position: Position) -> io::Result<()> {
        write!(
            self.pending,
            "\x1b[{};{}H",
            u32::from(position.y) + 1,
            u32::from(position.x) + 1
        )?;
        self.cursor = position;
        Ok(())
    }

    fn set_pen(&mut self, pen: Pen) -> io::Result<()> {
        self.pending.extend_from_slice(b"\x1b[0");
        for (modifier, code) in MODIFIERS {
            if pen.modifier.contains(modifier) {
                write!(self.pending, ";{code}")?;
            }
        }
        let (fg, bg) = (self.fitted(pen.fg), self.fitted(pen.bg));
        write_color(&mut self.pending, fg, 30)?;
        write_color(&mut self.pending, bg, 40)?;
        self.pending.push(b'm');
        Ok(())
    }
}

impl<W: Write> AnsiBackend<W> {
    fn fitted(&self, color: Color) -> Color {
        match color {
            Color::Rgb(red, green, blue) if !self.true_color => {
                Color::Indexed(nearest_indexed(red, green, blue))
            }
            color => color,
        }
    }
}

/// Returns the colour of the xterm 256-colour palette's cube or grey ramp nearest to `red`,
/// `green` and `blue`.
fn nearest_indexed(red: u8, green: u8, blue: u8) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let level = |value: u8| {
        LEVELS
            .iter()
            .zip(0_u8..)
            .min_by_key(|(level, _)| level.abs_diff(value))
            .map_or((0, 0), |(&level, index)| (index, level))
    };
    let distance = |(r, g, b): (u8, u8, u8)| {
        [(r, red), (g, green), (b, blue)]
            .iter()
            .map(|(a, b)| u32::from(a.abs_diff(*b)).pow(2))
            .sum::<u32>()
    };
    let (r, g, b) = (level(red), level(green), level(blue));
    let average = (u16::from(red) + u16::from(green) + u16::from(blue)) / 3;
    let grey_step = u8::try_from(average.saturating_sub(3) / 10)
        .unwrap_or(23)
        .min(23);
    let grey = 8 + 10 * grey_step;
    if distance((grey, grey, grey)) < distance((r.1, g.1, b.1)) {
        232 + grey_step
    } else {
        16 + 36 * r.0 + 6 * g.0 + b.0
    }
}

fn write_color(out: &mut impl Write, color: Color, base: u8) -> io::Result<()> {
    let bright = base + 60;
    match color {
        Color::Reset => Ok(()),
        Color::Black => write!(out, ";{base}"),
        Color::Red => write!(out, ";{}", base + 1),
        Color::Green => write!(out, ";{}", base + 2),
        Color::Yellow => write!(out, ";{}", base + 3),
        Color::Blue => write!(out, ";{}", base + 4),
        Color::Magenta => write!(out, ";{}", base + 5),
        Color::Cyan => write!(out, ";{}", base + 6),
        Color::Gray => write!(out, ";{}", base + 7),
        Color::DarkGray => write!(out, ";{bright}"),
        Color::LightRed => write!(out, ";{}", bright + 1),
        Color::LightGreen => write!(out, ";{}", bright + 2),
        Color::LightYellow => write!(out, ";{}", bright + 3),
        Color::LightBlue => write!(out, ";{}", bright + 4),
        Color::LightMagenta => write!(out, ";{}", bright + 5),
        Color::LightCyan => write!(out, ";{}", bright + 6),
        Color::White => write!(out, ";{}", bright + 7),
        Color::Indexed(index) => write!(out, ";{};5;{index}", base + 8),
        Color::Rgb(red, green, blue) => write!(out, ";{};2;{red};{green};{blue}", base + 8),
    }
}

fn drawable(symbol: &str) -> bool {
    !symbol.chars().any(|c| c.is_control() || is_invisible(c))
}

impl<W: Write> Backend for AnsiBackend<W> {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        let mut pen = None;
        let mut next = None;
        for (x, y, cell) in content {
            let position = Position::new(x, y);
            if next != Some(position) {
                self.move_to(position)?;
            }
            let wanted = Pen {
                fg: cell.fg,
                bg: cell.bg,
                modifier: cell.modifier,
            };
            if pen != Some(wanted) {
                self.set_pen(wanted)?;
                pen = Some(wanted);
            }
            let symbol = cell.symbol();
            let width = symbol.width();
            if drawable(symbol) {
                self.pending.extend_from_slice(symbol.as_bytes());
            } else {
                let columns = width.max(1);
                self.pending.resize(self.pending.len() + columns, b'?');
            }
            let after = Position::new(x.saturating_add(1), y);
            self.cursor = after;
            next = (width == 1).then_some(after);
        }
        if pen.is_some() {
            self.set_pen(Pen::default())?;
        }
        Ok(())
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        self.pending.extend_from_slice(b"\x1b[?25l");
        Ok(())
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        self.pending.extend_from_slice(b"\x1b[?25h");
        Ok(())
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Ok(self.cursor)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        self.move_to(position.into())
    }

    fn clear(&mut self) -> io::Result<()> {
        self.clear_region(ClearType::All)
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        self.pending.extend_from_slice(match clear_type {
            ClearType::All => b"\x1b[2J",
            ClearType::AfterCursor => b"\x1b[0J",
            ClearType::BeforeCursor => b"\x1b[1J",
            ClearType::CurrentLine => b"\x1b[2K",
            ClearType::UntilNewLine => b"\x1b[0K",
        });
        Ok(())
    }

    fn size(&self) -> io::Result<Size> {
        Ok(self.size)
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: self.size,
            pixels: Size::default(),
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.write_all(&self.pending)?;
        self.pending.clear();
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use ratatui_core::{
        buffer::Buffer,
        layout::Rect,
        style::Style,
        terminal::Terminal,
        text::Line,
        widgets::Widget,
    };

    use super::*;

    fn drawn(rows: u16, columns: u16, render: impl Fn(Rect, &mut Buffer)) -> vt100::Parser {
        let mut terminal = Terminal::new(AnsiBackend::new(Vec::new(), rows, columns)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render(area, frame.buffer_mut());
            })
            .unwrap();
        let mut parser = vt100::Parser::new(rows, columns, 0);
        parser.process(terminal.backend_mut().writer());
        parser
    }

    #[test]
    fn text_lands_where_ratatui_puts_it() {
        let parser = drawn(4, 20, |area, buffer| {
            Line::from("threads").render(area, buffer);
            Line::from("q quit").render(Rect::new(2, 3, 18, 1), buffer);
        });
        let screen = parser.screen();
        assert_eq!(screen.contents_between(0, 0, 0, 7), "threads");
        assert_eq!(screen.contents_between(3, 2, 3, 8), "q quit");
        assert_eq!(screen.contents_between(1, 0, 1, 20).trim(), "");
    }

    #[test]
    fn colours_given_as_rgb_take_the_nearest_of_256_without_true_color() {
        assert_eq!(nearest_indexed(0x83, 0x21, 0x61), 89);
        assert_eq!(nearest_indexed(0xd8, 0x64, 0xaf), 169);
        assert_eq!(nearest_indexed(0, 0, 0), 16);
        assert_eq!(nearest_indexed(255, 255, 255), 231);
        assert_eq!(nearest_indexed(128, 128, 128), 244);
        assert_eq!(nearest_indexed(240, 240, 240), 255);
        assert_eq!(nearest_indexed(2, 2, 2), 16);
        assert_eq!(nearest_indexed(8, 8, 8), 232);
        assert_eq!(nearest_indexed(95, 95, 95), 59);
        assert_eq!(nearest_indexed(95, 95, 100), 241);
        let mut out = Vec::new();
        let mut backend = AnsiBackend::new(&mut out, 1, 4).without_true_color();
        let mut cell = ratatui_core::buffer::Cell::new("x");
        cell.set_fg(Color::Rgb(0x83, 0x21, 0x61));
        backend.draw([(0, 0, &cell)].into_iter()).unwrap();
        Backend::flush(&mut backend).unwrap();
        let written = String::from_utf8(out).unwrap();
        assert!(written.contains(";38;5;89"), "{written:?}");
        assert!(!written.contains(";38;2;"), "{written:?}");
    }

    #[test]
    fn colours_and_attributes_reach_the_terminal() {
        let parser = drawn(2, 20, |area, buffer| {
            Line::styled(
                "sel",
                Style::new()
                    .fg(Color::Black)
                    .bg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            )
            .render(area, buffer);
            Line::styled("rgb", Style::new().fg(Color::Rgb(1, 2, 3)))
                .render(Rect::new(0, 1, 20, 1), buffer);
        });
        let screen = parser.screen();
        let selected = screen.cell(0, 0).unwrap();
        assert!(selected.bold() && selected.inverse());
        assert_eq!(selected.fgcolor(), vt100::Color::Idx(0));
        assert_eq!(selected.bgcolor(), vt100::Color::Idx(14));
        assert_eq!(
            screen.cell(1, 0).unwrap().fgcolor(),
            vt100::Color::Rgb(1, 2, 3)
        );
        let plain = screen.cell(1, 5).unwrap();
        assert!(!plain.bold() && plain.bgcolor() == vt100::Color::Default);
    }

    #[test]
    fn control_and_invisible_characters_are_drawn_as_question_marks() {
        let mut backend = AnsiBackend::new(Vec::new(), 2, 20);
        let cells = [
            Cell::new("\x1b"),
            Cell::new("\u{202e}"),
            Cell::new("\u{9b}"),
            Cell::new("x"),
        ];
        backend
            .draw((0_u16..).zip(&cells).map(|(x, cell)| (x, 0, cell)))
            .unwrap();
        assert!(backend.writer().is_empty());
        backend.flush().unwrap();
        let mut parser = vt100::Parser::new(2, 20, 0);
        parser.process(backend.writer());
        let screen = parser.screen();
        assert_eq!(screen.contents_between(0, 0, 0, 4), "???x");
        assert_eq!(screen.cursor_position(), (0, 4));
    }

    #[test]
    fn a_wide_symbol_replaced_by_marks_covers_both_its_columns() {
        let mut terminal = Terminal::new(AnsiBackend::new(Vec::new(), 2, 20)).unwrap();
        terminal
            .draw(|frame| Line::from("abcdef").render(frame.area(), frame.buffer_mut()))
            .unwrap();
        terminal
            .draw(|frame| {
                Line::from("\u{1f469}\u{200d}\u{1f4bb}cdef")
                    .render(frame.area(), frame.buffer_mut());
            })
            .unwrap();
        let mut parser = vt100::Parser::new(2, 20, 0);
        parser.process(terminal.backend_mut().writer());
        assert_eq!(parser.screen().contents_between(0, 0, 0, 6), "??cdef");
    }

    #[test]
    fn a_wide_character_is_followed_by_text_in_the_right_column() {
        let mut terminal = Terminal::new(AnsiBackend::new(Vec::new(), 2, 20)).unwrap();
        terminal
            .draw(|frame| Line::from("ab仓cd").render(frame.area(), frame.buffer_mut()))
            .unwrap();
        let mut parser = vt100::Parser::new(2, 20, 0);
        parser.process(terminal.backend_mut().writer());
        let screen = parser.screen();
        assert_eq!(screen.cell(0, 2).unwrap().contents(), "仓");
        assert_eq!(screen.cell(0, 4).unwrap().contents(), "c");
        assert_eq!(screen.cell(0, 5).unwrap().contents(), "d");
    }

    #[test]
    fn a_resize_is_what_the_next_draw_fills() {
        let mut backend = AnsiBackend::new(Vec::new(), 24, 80);
        assert_eq!(backend.size().unwrap(), Size::new(80, 24));
        backend.resize(10, 30);
        assert_eq!(
            backend.window_size().unwrap().columns_rows,
            Size::new(30, 10)
        );
    }
}
