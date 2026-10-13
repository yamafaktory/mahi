use ratatui_core::{
    buffer::Buffer,
    layout::{
        Constraint,
        Layout,
        Position,
        Rect,
    },
    style::{
        Color,
        Modifier,
        Style,
    },
    text::{
        Line,
        Span,
    },
    widgets::Widget,
};
use ratatui_widgets::{
    block::Block,
    borders::BorderType,
};

use crate::{
    Theme,
    dialog::shown,
    key_hints,
};

const CHROME_ROWS: u16 = 4;
const CHROME_COLUMNS: u16 = 2;

/// The frame mahi draws around an agent that runs inside its home screen: a header naming the
/// run, the agent's screen in a bordered pane, and the keys that reach mahi.
#[derive(Debug, Clone, Copy)]
pub struct AgentFrame<'a> {
    /// What runs, such as the agent and its thread.
    pub title: &'a str,
    /// The keys mahi reads while the agent runs, and what they do.
    pub hints: &'a [(&'a str, &'a str)],
}

impl AgentFrame<'_> {
    /// Returns the rows and columns the agent's terminal gets inside a screen of `rows` and
    /// `columns`, at least two of each.
    #[must_use]
    pub fn agent_size(rows: u16, columns: u16) -> (u16, u16) {
        (
            rows.saturating_sub(CHROME_ROWS).max(2),
            columns.saturating_sub(CHROME_COLUMNS).max(2),
        )
    }

    /// Draws the frame into `area` with the agent's `screen` inside it and, over it, what
    /// `overlay` holds, such as mahi's palette; returns where the agent's cursor is on the
    /// screen when the agent shows it and nothing lies over it.
    pub fn render(
        &self,
        screen: &vt100::Screen,
        overlay: Option<&vt100::Screen>,
        area: Rect,
        buffer: &mut Buffer,
    ) -> Option<Position> {
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);
        let bar = Style::new().bg(Color::Indexed(236));
        buffer.set_style(header, bar);
        Line::from(vec![
            Span::styled(" mahi ", Theme::selected()),
            Span::styled(
                format!(" {} ", shown(self.title)),
                Theme::title().patch(bar),
            ),
        ])
        .render(header, buffer);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::ACCENT));
        let inner = block.inner(body);
        block.render(body, buffer);
        Line::from(key_hints(self.hints)).render(footer, buffer);
        draw_screen(screen, inner, buffer, false);
        if let Some(overlay) = overlay {
            draw_screen(overlay, inner, buffer, true);
            return None;
        }
        let (row, column) = screen.cursor_position();
        let cursor = Position::new(inner.x.saturating_add(column), inner.y.saturating_add(row));
        (!screen.hide_cursor() && inner.contains(cursor)).then_some(cursor)
    }
}

fn draw_screen(screen: &vt100::Screen, area: Rect, buffer: &mut Buffer, only_written: bool) {
    let (rows, columns) = screen.size();
    for row in 0..rows.min(area.height) {
        for column in 0..columns.min(area.width) {
            let Some(cell) = screen
                .cell(row, column)
                .filter(|cell| !only_written || cell.has_contents())
            else {
                continue;
            };
            let Some(target) = buffer.cell_mut((area.x + column, area.y + row)) else {
                continue;
            };
            if cell.is_wide_continuation() {
                target.reset();
                continue;
            }
            let wide_at_edge = cell.is_wide() && column + 1 >= area.width;
            let symbol = cell.contents();
            if symbol.is_empty() || wide_at_edge {
                target.set_symbol(" ");
            } else {
                target.set_symbol(symbol);
            }
            target.set_style(style_of(cell));
        }
    }
}

fn style_of(cell: &vt100::Cell) -> Style {
    let mut modifier = Modifier::empty();
    for (on, flag) in [
        (cell.bold(), Modifier::BOLD),
        (cell.dim(), Modifier::DIM),
        (cell.italic(), Modifier::ITALIC),
        (cell.underline(), Modifier::UNDERLINED),
        (cell.inverse(), Modifier::REVERSED),
    ] {
        if on {
            modifier |= flag;
        }
    }
    Style::new()
        .fg(color_of(cell.fgcolor()))
        .bg(color_of(cell.bgcolor()))
        .add_modifier(modifier)
}

fn color_of(color: vt100::Color) -> Color {
    match color {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(index) => Color::Indexed(index),
        vt100::Color::Rgb(red, green, blue) => Color::Rgb(red, green, blue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drawn(parser: &vt100::Parser, area: Rect) -> (Buffer, Option<Position>) {
        let mut buffer = Buffer::empty(area);
        let frame = AgentFrame {
            title: "you.claude · thread t1",
            hints: &[("ctrl-space", "palette")],
        };
        let cursor = frame.render(parser.screen(), None, area, &mut buffer);
        (buffer, cursor)
    }

    fn row(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect()
    }

    #[test]
    fn the_agents_screen_is_drawn_inside_the_frame_with_its_colours_and_cursor() {
        let area = Rect::new(0, 0, 30, 8);
        let (rows, columns) = AgentFrame::agent_size(area.height, area.width);
        assert_eq!((rows, columns), (4, 28));
        let mut parser = vt100::Parser::new(rows, columns, 0);
        parser.process(b"hello\r\n\x1b[1;31mred\x1b[0m \x1b[38;2;1;2;3mrgb\x1b[0m");
        let (buffer, cursor) = drawn(&parser, area);
        assert!(
            row(&buffer, 0).starts_with(" mahi  you.claude · thread t1"),
            "{}",
            row(&buffer, 0)
        );
        assert_eq!(row(&buffer, 2), "│hello                       │");
        assert_eq!(row(&buffer, 3), "│red rgb                     │");
        assert!(row(&buffer, 7).starts_with("ctrl-space palette"));
        let red = &buffer[(1, 3)];
        assert_eq!(red.fg, Color::Indexed(1));
        assert!(red.modifier.contains(Modifier::BOLD));
        assert_eq!(buffer[(5, 3)].fg, Color::Rgb(1, 2, 3));
        assert_eq!(cursor, Some(Position::new(8, 3)));
        parser.process(b"\x1b[?25l");
        assert_eq!(drawn(&parser, area).1, None);
    }

    #[test]
    fn wide_characters_take_two_cells_and_one_cut_at_the_edge_is_left_blank() {
        let area = Rect::new(0, 0, 8, 6);
        let (rows, columns) = AgentFrame::agent_size(area.height, area.width);
        let mut parser = vt100::Parser::new(rows, columns, 0);
        parser.process("界a\r\n".as_bytes());
        let (buffer, _) = drawn(&parser, area);
        assert_eq!(buffer[(1, 2)].symbol(), "界");
        assert_eq!(buffer[(3, 2)].symbol(), "a");
        let mut wider = vt100::Parser::new(rows, columns + 4, 0);
        wider.process("abcde界".as_bytes());
        let (buffer, _) = drawn(&wider, area);
        assert_eq!(row(&buffer, 2), "│abcde │");
    }

    #[test]
    fn an_overlay_covers_only_what_it_wrote_and_hides_the_agents_cursor() {
        let area = Rect::new(0, 0, 20, 7);
        let (rows, columns) = AgentFrame::agent_size(area.height, area.width);
        let mut agent = vt100::Parser::new(rows, columns, 0);
        agent.process(b"agent line one\r\nagent line two");
        let mut overlay = vt100::Parser::new(rows, columns, 0);
        overlay.process(b"\x1b[2;3H[box ]");
        let mut buffer = Buffer::empty(area);
        let frame = AgentFrame {
            title: "t",
            hints: &[],
        };
        let cursor = frame.render(agent.screen(), Some(overlay.screen()), area, &mut buffer);
        assert_eq!(cursor, None);
        assert_eq!(row(&buffer, 2), "│agent line one    │");
        assert_eq!(row(&buffer, 3), "│ag[box ]ne two    │");
    }

    #[test]
    fn a_tiny_screen_draws_without_panicking() {
        let mut parser = vt100::Parser::new(1, 1, 0);
        parser.process(b"x");
        for (width, height) in [(0, 0), (1, 1), (2, 3), (3, 5)] {
            drawn(&parser, Rect::new(0, 0, width, height));
        }
        assert_eq!(AgentFrame::agent_size(0, 0), (2, 2));
    }
}
