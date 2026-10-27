use std::{
    borrow::Cow,
    cell,
    fmt,
};

use mahi_core::is_invisible;
use ratatui_core::{
    buffer::Buffer,
    layout::{
        Constraint,
        Layout,
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
    widgets::{
        StatefulWidget,
        Widget,
    },
};
use ratatui_widgets::{
    block::{
        Block,
        Padding,
    },
    borders::BorderType,
    clear::Clear,
    list::{
        List,
        ListItem,
        ListState,
    },
    paragraph::{
        Paragraph,
        Wrap,
    },
    table::{
        Cell,
        Row,
        Table,
    },
};
use zeroize::Zeroizing;

use crate::PaletteInput;

const CODE_MARK: &str = "🔑  ";
const MAX_INPUT_CHARS: usize = 1024;
const MAX_WIDTH: u16 = 76;
const TABLE_GAP: usize = 2;
const MASK: char = '•';

/// The colours mahi's full-screen views use.
#[derive(Debug, Clone, Copy)]
pub struct Theme;

impl Theme {
    /// Titles, borders and the keys shown in hints: Royal Plum lightened, to read on a dark
    /// terminal.
    pub const ACCENT: Color = Color::Rgb(0xd8, 0x64, 0xaf);
    /// The selected row and mahi's badge: Royal Plum, #832161.
    pub const PLUM: Color = Color::Rgb(0x83, 0x21, 0x61);
    /// Text that matters less.
    pub const MUTED: Color = Color::DarkGray;
    /// A question that waits for the user.
    pub const WARN: Color = Color::Yellow;
    /// Something that failed.
    pub const ERROR: Color = Color::LightRed;
    /// Something that worked.
    pub const OK: Color = Color::Green;

    /// Returns the style of a selected row.
    #[must_use]
    pub fn selected() -> Style {
        Style::new()
            .fg(Color::White)
            .bg(Self::PLUM)
            .add_modifier(Modifier::BOLD)
    }

    /// Returns the style of a title.
    #[must_use]
    pub fn title() -> Style {
        Style::new().fg(Self::ACCENT).add_modifier(Modifier::BOLD)
    }

    /// Returns the style of a command or a name the user types, written between backticks.
    #[must_use]
    pub fn code() -> Style {
        Style::new().fg(Self::WARN).add_modifier(Modifier::BOLD)
    }

    /// Returns the style of quieter text.
    #[must_use]
    pub fn muted() -> Style {
        Style::new().fg(Self::MUTED)
    }
}

/// A modal dialog drawn over a full-screen view: a message, a table to read, a yes or no
/// question, a line to type, masked or not, or a list to pick from. What is typed never shows
/// in `Debug` output.
pub struct Dialog {
    title: String,
    lines: Vec<String>,
    kind: Kind,
}

enum Kind {
    Message,
    Table {
        header: [String; 3],
        rows: Vec<[String; 3]>,
        offset: usize,
        last_offset: cell::Cell<usize>,
    },
    Notice,
    Code {
        code: Zeroizing<String>,
    },
    Confirm {
        yes: bool,
    },
    Input {
        text: Zeroizing<String>,
        masked: bool,
    },
    Choose {
        items: Vec<String>,
        selected: usize,
    },
    Menu {
        items: Vec<(String, String)>,
        selected: usize,
    },
}

/// What a dialog's user chose; a typed line never shows in `Debug` output.
#[derive(PartialEq, Eq)]
pub enum Answer {
    /// The message was read.
    Ok,
    /// Yes, or no, to the question.
    Confirmed(bool),
    /// The line typed.
    Text(Zeroizing<String>),
    /// The index of the item picked.
    Choice(usize),
    /// Escape or Ctrl-C: the dialog was closed without an answer.
    Cancelled,
}

impl fmt::Debug for Dialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dialog")
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("Ok"),
            Self::Confirmed(yes) => write!(f, "Confirmed({yes})"),
            Self::Text(_) => f.write_str("Text(..)"),
            Self::Choice(index) => write!(f, "Choice({index})"),
            Self::Cancelled => f.write_str("Cancelled"),
        }
    }
}

impl Dialog {
    /// Makes a dialog that shows `lines` until the user presses Enter or Escape.
    #[must_use]
    pub fn message(title: &str, lines: Vec<String>) -> Self {
        Self::with(title, lines, Kind::Message)
    }

    /// Makes a dialog that shows `lines` above a table of three columns, `header` naming them,
    /// until the user presses Enter or Escape.
    #[must_use]
    pub fn table(
        title: &str,
        lines: Vec<String>,
        header: [String; 3],
        rows: Vec<[String; 3]>,
    ) -> Self {
        Self::with(
            title,
            lines,
            Kind::Table {
                header,
                rows,
                offset: 0,
                last_offset: cell::Cell::new(usize::MAX),
            },
        )
    }

    /// Makes a dialog that shows `lines` while mahi works, answering no key: what a command
    /// says during a long step, such as a pairing code while it waits.
    #[must_use]
    pub fn notice(title: &str, lines: Vec<String>) -> Self {
        Self::with(title, lines, Kind::Notice)
    }

    /// Makes a notice that shows `code` on a line of its own, after a key and in the colour of
    /// something to type, above `paragraphs` set apart by blank lines; Ctrl-C stops what it
    /// waits for.
    #[must_use]
    pub fn code(title: &str, code: &str, paragraphs: &[&str]) -> Self {
        let mut lines = Vec::with_capacity(paragraphs.len() * 2);
        for paragraph in paragraphs {
            lines.push(String::new());
            lines.push((*paragraph).to_owned());
        }
        Self::with(
            title,
            lines,
            Kind::Code {
                code: Zeroizing::new(code.to_owned()),
            },
        )
    }

    /// Puts `title` in place of the dialog's title, reusing its buffer, as a notice whose
    /// spinner turns does every frame.
    pub fn set_title(&mut self, title: &str) {
        self.title.clear();
        self.title.push_str(title);
    }

    /// Makes a yes or no question, `no` selected first.
    #[must_use]
    pub fn confirm(title: &str, lines: Vec<String>) -> Self {
        Self::with(title, lines, Kind::Confirm { yes: false })
    }

    /// Makes a line to type, shown as dots when `masked`.
    #[must_use]
    pub fn input(title: &str, lines: Vec<String>, masked: bool) -> Self {
        Self::with(
            title,
            lines,
            Kind::Input {
                text: Zeroizing::new(String::with_capacity(MAX_INPUT_CHARS * 4)),
                masked,
            },
        )
    }

    /// Makes a list to pick one of `items` from.
    #[must_use]
    pub fn choose(title: &str, lines: Vec<String>, items: Vec<String>) -> Self {
        Self::with(title, lines, Kind::Choose { items, selected: 0 })
    }

    /// Makes a menu of `items`, each an action and the key that does it at once, which the
    /// caller reads; the menu itself only moves between them and picks one.
    #[must_use]
    pub fn menu(title: &str, items: Vec<(String, String)>) -> Self {
        Self::with(title, Vec::new(), Kind::Menu { items, selected: 0 })
    }

    fn with(title: &str, lines: Vec<String>, kind: Kind) -> Self {
        Self {
            title: title.to_owned(),
            lines,
            kind,
        }
    }

    /// Returns which item of a list or a menu is selected; `None` for any other dialog.
    #[must_use]
    pub fn selected(&self) -> Option<usize> {
        match &self.kind {
            Kind::Choose { selected, .. } | Kind::Menu { selected, .. } => Some(*selected),
            _ => None,
        }
    }

    /// Adds a line above the question, as the commands that ask say things first.
    pub fn push_line(&mut self, line: &str) {
        self.lines.push(line.to_owned());
    }

    /// Reads one key and returns the answer it completes, if any. Pasted text goes into a line
    /// being typed and nowhere else, so a paste never answers a question.
    pub fn key(&mut self, input: PaletteInput) -> Option<Answer> {
        if input == PaletteInput::Escape {
            return Some(Answer::Cancelled);
        }
        match &mut self.kind {
            Kind::Message => (input == PaletteInput::Enter).then_some(Answer::Ok),
            Kind::Table {
                offset,
                last_offset,
                ..
            } => match input {
                PaletteInput::Up | PaletteInput::Text('k') => {
                    *offset = (*offset).min(last_offset.get()).saturating_sub(1);
                    None
                }
                PaletteInput::Down | PaletteInput::Text('j') => {
                    *offset = (*offset + 1).min(last_offset.get());
                    None
                }
                PaletteInput::Enter => Some(Answer::Ok),
                _ => None,
            },
            Kind::Notice | Kind::Code { .. } => None,
            Kind::Confirm { yes } => match input {
                PaletteInput::Text('y' | 'Y') => Some(Answer::Confirmed(true)),
                PaletteInput::Text('n' | 'N') => Some(Answer::Confirmed(false)),
                PaletteInput::Tab
                | PaletteInput::Up
                | PaletteInput::Down
                | PaletteInput::Text('h' | 'j' | 'k' | 'l') => {
                    *yes = !*yes;
                    None
                }
                PaletteInput::Enter => Some(Answer::Confirmed(*yes)),
                _ => None,
            },
            Kind::Input { text, .. } => match input {
                PaletteInput::Enter => Some(Answer::Text(std::mem::take(text))),
                PaletteInput::Backspace => {
                    text.pop();
                    None
                }
                PaletteInput::Text(c) | PaletteInput::Pasted(c)
                    if !hidden(c) && text.chars().count() < MAX_INPUT_CHARS =>
                {
                    text.push(c);
                    None
                }
                _ => None,
            },
            Kind::Choose { items, selected } => match input {
                PaletteInput::Up | PaletteInput::Text('k') => {
                    *selected = selected.saturating_sub(1);
                    None
                }
                PaletteInput::Down | PaletteInput::Text('j') if *selected + 1 < items.len() => {
                    *selected += 1;
                    None
                }
                PaletteInput::Enter if !items.is_empty() => Some(Answer::Choice(*selected)),
                PaletteInput::Text(c) => c
                    .to_digit(10)
                    .and_then(|digit| usize::try_from(digit).ok())
                    .and_then(|digit| digit.checked_sub(1))
                    .filter(|index| *index < items.len())
                    .map(Answer::Choice),
                _ => None,
            },
            Kind::Menu { items, selected } => match input {
                PaletteInput::Up | PaletteInput::Text('k') => {
                    *selected = selected.saturating_sub(1);
                    None
                }
                PaletteInput::Down | PaletteInput::Text('j') if *selected + 1 < items.len() => {
                    *selected += 1;
                    None
                }
                PaletteInput::Enter if !items.is_empty() => Some(Answer::Choice(*selected)),
                _ => None,
            },
        }
    }

    /// Draws the dialog centred in `area`, over whatever is drawn there, sized to its text as
    /// wrapped, with a list that scrolls to its selected item.
    pub fn render(&self, area: Rect, buffer: &mut Buffer) {
        let width = area.width.saturating_sub(4).min(self.wanted_width());
        let text_width = usize::from(width.saturating_sub(4)).max(1);
        let mut text: Vec<Line<'_>> = Vec::with_capacity(self.lines.len() + 2);
        if let Kind::Code { code } = &self.kind {
            text.push(Line::default());
            text.push(Line::from(vec![
                Span::raw(CODE_MARK),
                Span::styled(shown(code), Theme::code()),
            ]));
        }
        text.extend(self.lines.iter().map(|line| marked(line)));
        let code_rows = match &self.kind {
            Kind::Code { code } => {
                1 + wrapped_rows(&format!("{CODE_MARK}{}", shown(code)), text_width, false)
            }
            _ => 0,
        };
        let text_rows: usize = code_rows
            + self
                .lines
                .iter()
                .map(|line| wrapped_rows(line, text_width, has_marks(line)))
                .sum::<usize>();
        let extra_rows = match &self.kind {
            Kind::Message | Kind::Notice | Kind::Code { .. } => 0,
            Kind::Confirm { .. } | Kind::Input { .. } => 2,
            Kind::Choose { items, .. } => items.len() + 1,
            Kind::Menu { items, .. } => items.len(),
            Kind::Table { rows, .. } => rows.len() + 2,
        };
        let tight = text_rows + extra_rows + 3;
        let room = usize::from(area.height.saturating_sub(2));
        let hints = self.hints(tight > room);
        let gap = u16::from(!hints.is_empty() && tight < room);
        let wanted = tight + usize::from(gap);
        let height = u16::try_from(wanted)
            .unwrap_or(u16::MAX)
            .min(area.height.saturating_sub(2))
            .max(5);
        let [_, middle, _] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .areas(area);
        let [_, boxed, _] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Length(width),
            Constraint::Fill(1),
        ])
        .areas(middle);
        Clear.render(boxed, buffer);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::ACCENT))
            .padding(Padding::horizontal(1))
            .title(Line::from(format!(" {} ", shown(&self.title))).style(Theme::title()));
        let inner = block.inner(boxed);
        block.render(boxed, buffer);
        let extra = u16::try_from(extra_rows).unwrap_or(u16::MAX);
        let [words_size, below_size] = if matches!(self.kind, Kind::Table { .. }) {
            [
                Constraint::Length(
                    u16::try_from(text_rows)
                        .unwrap_or(u16::MAX)
                        .min(inner.height.saturating_sub(gap + 4)),
                ),
                Constraint::Fill(1),
            ]
        } else {
            [Constraint::Fill(1), Constraint::Max(extra)]
        };
        let [words, below, _, hints_area] = Layout::vertical([
            words_size,
            below_size,
            Constraint::Length(gap),
            Constraint::Length(1),
        ])
        .areas(inner);
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .render(words, buffer);
        self.render_below(below, buffer);
        Line::from(hints).render(hints_area, buffer);
    }

    fn wanted_width(&self) -> u16 {
        let widest = match &self.kind {
            Kind::Choose { items, .. } => items
                .iter()
                .enumerate()
                .map(|(index, item)| digits(index + 1) + Span::raw(shown(item)).width() + 7)
                .max(),
            Kind::Menu { items, .. } => {
                let (action, key) = menu_widths(items);
                Some(action + key + 8)
            }
            Kind::Table { header, rows, .. } => {
                let [first, second, third] = column_widths(header, rows);
                Some(first + second + third + 2 * TABLE_GAP + 4)
            }
            _ => None,
        };
        widest.map_or(MAX_WIDTH, |widest| {
            u16::try_from(widest).unwrap_or(u16::MAX).max(MAX_WIDTH)
        })
    }

    fn render_below(&self, area: Rect, buffer: &mut Buffer) {
        let [_, rest] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        match &self.kind {
            Kind::Message | Kind::Notice | Kind::Code { .. } => {}
            Kind::Table {
                header,
                rows,
                offset,
                last_offset,
            } => {
                let shown_rows = usize::from(rest.height.saturating_sub(1));
                let last = rows.len().saturating_sub(shown_rows);
                last_offset.set(last);
                let first = (*offset).min(last);
                let widths = column_widths(header, rows)
                    .map(|width| Constraint::Length(u16::try_from(width).unwrap_or(u16::MAX)));
                Widget::render(
                    Table::new(
                        rows.iter().skip(first).take(shown_rows).map(table_row),
                        widths,
                    )
                    .header(
                        Row::new(header.iter().map(|name| Cell::from(shown(name))))
                            .style(Theme::muted()),
                    )
                    .column_spacing(u16::try_from(TABLE_GAP).unwrap_or(1)),
                    rest,
                    buffer,
                );
            }
            Kind::Confirm { yes } => {
                Line::from(vec![
                    button("Yes", *yes),
                    Span::raw("  "),
                    button("No", !*yes),
                ])
                .render(rest, buffer);
            }
            Kind::Input { text, masked, .. } => {
                let typed: Cow<'_, str> = if *masked {
                    Cow::Owned(std::iter::repeat_n(MASK, text.chars().count()).collect())
                } else {
                    Cow::Borrowed(text.as_str())
                };
                let room = usize::from(rest.width).saturating_sub(3);
                Line::from(vec![
                    Span::styled("› ", Theme::title()),
                    Span::raw(tail(&typed, room)),
                    Span::styled("▏", Style::new().fg(Theme::ACCENT)),
                ])
                .render(rest, buffer);
            }
            Kind::Choose { items, selected } => {
                let list = List::new(
                    items
                        .iter()
                        .enumerate()
                        .map(|(index, item)| ListItem::new(choice(index, item))),
                )
                .highlight_style(Theme::selected());
                let mut state = ListState::default().with_selected(Some(*selected));
                StatefulWidget::render(list, rest, buffer, &mut state);
            }
            Kind::Menu { items, selected } => {
                let (widest, key_width) = menu_widths(items);
                let action_width =
                    widest.min(usize::from(area.width).saturating_sub(key_width + 4));
                let list = List::new(
                    items
                        .iter()
                        .map(|(item, key)| ListItem::new(menu_line(item, key, action_width))),
                )
                .highlight_style(Theme::selected());
                let mut state = ListState::default().with_selected(Some(*selected));
                StatefulWidget::render(list, area, buffer, &mut state);
            }
        }
    }

    fn hints(&self, cramped: bool) -> Vec<Span<'static>> {
        let pairs: &[(&str, &str)] = match self.kind {
            Kind::Table { .. } if cramped => &[("↑↓ jk", "scroll"), ("enter", "close")],
            Kind::Message | Kind::Table { .. } => &[("enter", "close")],
            Kind::Notice => &[],
            Kind::Code { .. } => &[("ctrl-c", "stop")],
            Kind::Confirm { .. } => &[
                ("y", "yes"),
                ("n", "no"),
                ("tab", "switch"),
                ("esc", "cancel"),
            ],
            Kind::Input { .. } => &[("enter", "done"), ("esc", "cancel")],
            Kind::Choose { .. } => &[("↑↓ jk", "move"), ("enter", "pick"), ("esc", "cancel")],
            Kind::Menu { .. } => &[("↑↓", "move"), ("enter", "run"), ("esc", "close")],
        };
        key_hints(pairs)
    }
}

/// Returns the end of `text` that fits in `room` columns, so the cursor after it shows.
fn tail(text: &str, room: usize) -> &str {
    let mut width = 0;
    let start = text
        .char_indices()
        .rev()
        .take_while(|(_, c)| {
            width += unicode_width::UnicodeWidthChar::width(*c).unwrap_or(0);
            width <= room
        })
        .last()
        .map_or(text.len(), |(at, _)| at);
    text.get(start..).unwrap_or_default()
}

/// Returns the spans that show `pairs` of keys and what they do, keys in the accent colour.
#[must_use]
pub fn key_hints(pairs: &[(&str, &str)]) -> Vec<Span<'static>> {
    let mut spans = Vec::with_capacity(pairs.len() * 3);
    for (index, (key, what)) in pairs.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", Theme::muted()));
        }
        spans.push(Span::styled((*key).to_owned(), Theme::title()));
        spans.push(Span::styled(format!(" {what}"), Theme::muted()));
    }
    spans
}

fn table_row(row: &[String; 3]) -> Row<'_> {
    let [key, action, about] = row;
    Row::new([
        Cell::from(Span::styled(shown(key), Theme::title())),
        Cell::from(Span::styled(
            shown(action),
            Style::new().add_modifier(Modifier::BOLD),
        )),
        Cell::from(Span::raw(shown(about))),
    ])
}

fn column_widths(header: &[String; 3], rows: &[[String; 3]]) -> [usize; 3] {
    let mut widths = [0; 3];
    for row in std::iter::once(header).chain(rows) {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(Span::raw(shown(cell)).width());
        }
    }
    widths
}

fn digits(number: usize) -> usize {
    number.checked_ilog10().map_or(1, |log| log as usize + 1)
}

fn menu_widths(items: &[(String, String)]) -> (usize, usize) {
    items
        .iter()
        .fold((0, 0), |(action, key), (item, item_key)| {
            (
                action.max(Span::raw(shown(item)).width()),
                key.max(Span::raw(shown(item_key)).width()),
            )
        })
}

fn menu_line(item: &str, key: &str, action_width: usize) -> Line<'static> {
    let item = shown(item);
    let item = cut_to(&item, action_width);
    let pad = action_width.saturating_sub(Span::raw(item.as_ref()).width());
    Line::from(vec![
        Span::raw(format!(" {item}{}", " ".repeat(pad + 2))),
        Span::styled(format!("{} ", shown(key)), Theme::title()),
    ])
}

fn cut_to(text: &str, width: usize) -> Cow<'_, str> {
    if Span::raw(text).width() <= width {
        return Cow::Borrowed(text);
    }
    let mut cut = String::with_capacity(text.len());
    for c in text.chars() {
        cut.push(c);
        if Span::raw(cut.as_str()).width() >= width {
            cut.pop();
            break;
        }
    }
    if width > 0 {
        cut.push('…');
    }
    Cow::Owned(cut)
}

fn choice(index: usize, item: &str) -> Line<'static> {
    Line::from(format!(" {} {} ", index + 1, shown(item)))
}

fn button(label: &str, on: bool) -> Span<'static> {
    let text = format!(" {label} ");
    if on {
        Span::styled(text, Theme::selected())
    } else {
        Span::styled(text, Theme::muted())
    }
}

fn has_marks(line: &str) -> bool {
    let marks = line.matches('`').count();
    marks > 0 && marks.is_multiple_of(2)
}

fn marked(line: &str) -> Line<'_> {
    if !has_marks(line) {
        return Line::from(shown(line));
    }
    Line::from(
        line.split('`')
            .enumerate()
            .filter(|(_, part)| !part.is_empty())
            .map(|(index, part)| {
                if index.is_multiple_of(2) {
                    Span::raw(shown(part))
                } else {
                    Span::styled(shown(part), Theme::code())
                }
            })
            .collect::<Vec<_>>(),
    )
}

fn wrapped_rows(line: &str, width: usize, marks: bool) -> usize {
    let width_of = |text: &str| -> usize {
        text.chars()
            .filter(|c| !(marks && *c == '`'))
            .map(|c| unicode_width::UnicodeWidthChar::width(c).unwrap_or(1))
            .sum()
    };
    let mut rows = 1;
    let mut column = 0;
    for word in line.split(' ') {
        let mut word = width_of(word);
        let needed = if column == 0 { word } else { word + 1 };
        if column + needed <= width {
            column += needed;
            continue;
        }
        if column > 0 {
            rows += 1;
        }
        while word > width {
            rows += 1;
            word -= width;
        }
        column = word;
    }
    rows
}

pub(crate) fn shown(text: &str) -> Cow<'_, str> {
    if text.chars().any(hidden) {
        Cow::Owned(
            text.chars()
                .map(|c| if hidden(c) { '?' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

pub(crate) fn hidden(c: char) -> bool {
    c.is_control() || is_invisible(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drawn(dialog: &Dialog) -> String {
        let area = Rect::new(0, 0, 80, 20);
        let mut buffer = Buffer::empty(area);
        dialog.render(area, &mut buffer);
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    + "\n"
            })
            .collect()
    }

    #[test]
    fn a_code_shows_on_a_line_of_its_own_in_the_colour_of_something_to_type() {
        let dialog = Dialog::code(
            "Invite a teammate",
            "884-neptune-outfielder",
            &[
                "Tell this code to your teammate.",
                "Waiting up to 10 minutes.",
            ],
        );
        let area = Rect::new(0, 0, 80, 16);
        let mut buffer = Buffer::empty(area);
        dialog.render(area, &mut buffer);
        let rows: Vec<String> = (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        let at = rows
            .iter()
            .position(|row| row.contains("884-neptune-outfielder"))
            .unwrap();
        assert!(rows[at].contains("🔑"), "{rows:#?}");
        assert!(
            rows[at - 1].trim_matches([' ', '│']).is_empty(),
            "{rows:#?}"
        );
        let told = rows
            .iter()
            .position(|row| row.contains("Tell this code"))
            .unwrap();
        let waits = rows
            .iter()
            .position(|row| row.contains("Waiting up to"))
            .unwrap();
        assert_eq!(told, at + 2, "{rows:#?}");
        assert_eq!(waits, told + 2, "{rows:#?}");
        assert!(
            rows.iter().any(|row| row.contains("ctrl-c stop")),
            "{rows:#?}"
        );
        let column = rows[at]
            .find("884")
            .map(|byte| rows[at][..byte].chars().count())
            .unwrap();
        let cell = &buffer[(
            u16::try_from(column).unwrap() + 1,
            u16::try_from(at).unwrap(),
        )];
        assert_eq!(cell.style().fg, Theme::code().fg);
        assert!(!format!("{dialog:?}").contains("884"));
    }

    #[test]
    fn a_code_that_wraps_on_a_narrow_terminal_leaves_room_for_every_paragraph() {
        let dialog = Dialog::code(
            "Invite a teammate",
            "884-neptune-outfielder",
            &[
                "Tell this code to your teammate.",
                "Waiting up to 10 minutes.",
            ],
        );
        let area = Rect::new(0, 0, 30, 24);
        let mut buffer = Buffer::empty(area);
        dialog.render(area, &mut buffer);
        let drawn: String = (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    + "\n"
            })
            .collect();
        assert!(drawn.contains("minutes."), "{drawn}");
        assert!(drawn.contains("ctrl-c stop"), "{drawn}");
    }

    #[test]
    fn a_line_leaves_out_a_pasted_newline_and_shows_its_end() {
        let area = Rect::new(0, 0, 40, 10);
        let mut line = Dialog::input("Name", Vec::new(), false);
        assert_eq!(line.key(PaletteInput::Pasted('\n')), None);
        let Some(Answer::Text(text)) = line.key(PaletteInput::Enter) else {
            panic!("the line was not taken");
        };
        assert_eq!(text.as_str(), "");
        let mut long = Dialog::input("Name", Vec::new(), false);
        for c in "a".repeat(100).chars().chain("END".chars()) {
            long.key(PaletteInput::Text(c));
        }
        let mut buffer = Buffer::empty(area);
        long.render(area, &mut buffer);
        let drawn: String = buffer
            .content
            .iter()
            .map(ratatui_core::buffer::Cell::symbol)
            .collect();
        assert!(drawn.contains("aaEND▏"), "{drawn}");
    }

    #[test]
    fn a_retitled_notice_draws_its_new_title() {
        let mut notice = Dialog::notice("mahi ⠋", vec!["working…".to_owned()]);
        notice.set_title("mahi ⠙");
        let area = Rect::new(0, 0, 40, 8);
        let mut buffer = Buffer::empty(area);
        notice.render(area, &mut buffer);
        let drawn: String = buffer
            .content
            .iter()
            .map(ratatui_core::buffer::Cell::symbol)
            .collect();
        assert!(drawn.contains("mahi ⠙"), "{drawn}");
        assert!(!drawn.contains("⠋"), "{drawn}");
    }

    #[test]
    fn a_menu_shows_each_action_with_its_key_and_leaves_the_keys_to_its_caller() {
        let mut menu = Dialog::menu(
            "4799a3af",
            vec![
                ("Threads".to_owned(), "0".to_owned()),
                ("Next agent waiting for you".to_owned(), "Space".to_owned()),
            ],
        );
        let shown = drawn(&menu);
        assert!(shown.contains(" 4799a3af "), "{shown}");
        assert!(shown.contains(" Threads                     0 "), "{shown}");
        assert!(
            shown.contains(" Next agent waiting for you  Space "),
            "{shown}"
        );
        assert!(shown.contains("↑↓ move  enter run  esc close"), "{shown}");
        assert_eq!(menu.key(PaletteInput::Text('2')), None);
        assert_eq!(menu.key(PaletteInput::Text('q')), None);
        assert_eq!(menu.key(PaletteInput::Down), None);
        assert_eq!(menu.key(PaletteInput::Down), None);
        assert_eq!(menu.selected(), Some(1));
        assert_eq!(menu.key(PaletteInput::Enter), Some(Answer::Choice(1)));
        assert_eq!(menu.key(PaletteInput::Text('k')), None);
        assert_eq!(menu.key(PaletteInput::Enter), Some(Answer::Choice(0)));
        assert_eq!(menu.key(PaletteInput::Escape), Some(Answer::Cancelled));
    }

    #[test]
    fn a_menu_too_wide_for_the_screen_cuts_its_long_actions_and_keeps_every_key() {
        let long = format!("Show {}'s agent {}", "a".repeat(32), "日本".repeat(16));
        let menu = Dialog::menu(
            "4799a3af",
            vec![
                (long.clone(), String::new()),
                (
                    "Pass Ctrl-Space through to the agent".to_owned(),
                    "Ctrl-Space".to_owned(),
                ),
                ("Quit mahi".to_owned(), "q".to_owned()),
            ],
        );
        let shown = drawn(&menu);
        let row_of = |item: &str| {
            shown
                .lines()
                .find(|row| row.contains(item))
                .unwrap_or_else(|| panic!("{item} missing:\n{shown}"))
                .trim_end_matches([' ', '│'])
        };
        assert!(row_of("Quit mahi").ends_with(" q"), "{shown}");
        assert_eq!(
            row_of("Pass Ctrl-Space through")
                .matches("Ctrl-Space")
                .count(),
            2,
            "{shown}"
        );
        let cut = row_of("Show aaaa");
        assert!(cut.ends_with('…'), "{shown}");
    }

    #[test]
    fn a_menu_wider_than_its_least_width_that_fits_keeps_its_widest_action_whole() {
        let widest = format!("Act {}", "x".repeat(80));
        let menu = Dialog::menu(
            "4799a3af",
            vec![
                (widest.clone(), "k".to_owned()),
                ("Quit".to_owned(), "q".to_owned()),
            ],
        );
        let area = Rect::new(0, 0, 140, 20);
        let mut buffer = Buffer::empty(area);
        menu.render(area, &mut buffer);
        let shown: String = (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    + "\n"
            })
            .collect();
        assert!(shown.contains(&format!(" {widest}  k ")), "{shown}");
        assert!(!shown.contains('…'), "{shown}");
    }

    #[test]
    fn a_cut_action_ends_in_an_ellipsis_within_its_width_even_with_wide_characters() {
        assert_eq!(cut_to("Quit", 4), "Quit");
        assert_eq!(cut_to("Quit mahi", 4), "Qui…");
        assert_eq!(cut_to("日本日本", 4), "日…");
        assert_eq!(cut_to("日本日本", 5), "日本…");
        assert_eq!(cut_to("Quit", 0), "");
        assert_eq!(cut_to("Quit", 1), "…");
        let joined = "ab❤\u{FE0F}cdefgh";
        for width in 0..=10 {
            let cut = cut_to(joined, width);
            assert!(
                unicode_width::UnicodeWidthStr::width(cut.as_ref()) <= width,
                "{cut:?} is wider than {width}"
            );
        }
    }

    #[test]
    fn a_confirmation_answers_y_n_or_the_selected_button() {
        let mut dialog = Dialog::confirm("Land", vec!["Land thread t1?".to_owned()]);
        assert_eq!(
            dialog.key(PaletteInput::Enter),
            Some(Answer::Confirmed(false))
        );
        assert_eq!(dialog.key(PaletteInput::Tab), None);
        assert_eq!(
            dialog.key(PaletteInput::Enter),
            Some(Answer::Confirmed(true))
        );
        assert_eq!(
            dialog.key(PaletteInput::Text('n')),
            Some(Answer::Confirmed(false))
        );
        assert_eq!(dialog.key(PaletteInput::Pasted('y')), None);
        assert_eq!(dialog.key(PaletteInput::Escape), Some(Answer::Cancelled));
        assert!(drawn(&dialog).contains("Land thread t1?"));
    }

    #[test]
    fn a_masked_input_takes_typed_and_pasted_text_and_shows_only_dots() {
        let mut dialog = Dialog::input("Passphrase", vec!["For your mahi key".to_owned()], true);
        for c in "secret".chars() {
            assert_eq!(dialog.key(PaletteInput::Text(c)), None);
        }
        dialog.key(PaletteInput::Pasted('!'));
        dialog.key(PaletteInput::Backspace);
        dialog.key(PaletteInput::Text('\u{202e}'));
        let screen = drawn(&dialog);
        assert!(!screen.contains("secret"), "{screen}");
        assert!(screen.contains("••••••"), "{screen}");
        assert_eq!(
            dialog.key(PaletteInput::Enter),
            Some(Answer::Text(Zeroizing::new("secret".to_owned())))
        );
    }

    #[test]
    fn a_list_is_picked_with_arrows_numbers_or_enter() {
        let items = vec!["claude".to_owned(), "codex".to_owned()];
        let mut dialog = Dialog::choose("New thread", vec![], items);
        assert_eq!(dialog.key(PaletteInput::Down), None);
        assert_eq!(dialog.key(PaletteInput::Down), None);
        assert_eq!(dialog.key(PaletteInput::Enter), Some(Answer::Choice(1)));
        assert_eq!(dialog.key(PaletteInput::Text('1')), Some(Answer::Choice(0)));
        assert_eq!(dialog.key(PaletteInput::Text('9')), None);
        let screen = drawn(&dialog);
        assert!(
            screen.contains("1 claude") && screen.contains("2 codex"),
            "{screen}"
        );
        let mut empty = Dialog::choose("Nothing", vec![], Vec::new());
        assert_eq!(empty.key(PaletteInput::Enter), None);
    }

    #[test]
    fn vim_keys_move_through_a_list_and_toggle_a_confirmation() {
        let items = vec!["claude".to_owned(), "codex".to_owned()];
        let mut dialog = Dialog::choose("New thread", vec![], items);
        assert_eq!(dialog.key(PaletteInput::Text('j')), None);
        assert_eq!(dialog.key(PaletteInput::Text('j')), None);
        assert_eq!(dialog.key(PaletteInput::Enter), Some(Answer::Choice(1)));
        assert_eq!(dialog.key(PaletteInput::Text('k')), None);
        assert_eq!(dialog.key(PaletteInput::Text('k')), None);
        assert_eq!(dialog.key(PaletteInput::Enter), Some(Answer::Choice(0)));
        assert_eq!(dialog.key(PaletteInput::Pasted('j')), None);
        assert_eq!(dialog.key(PaletteInput::Enter), Some(Answer::Choice(0)));
        assert!(drawn(&dialog).contains("↑↓ jk move"));
        let mut confirm = Dialog::confirm("Land", vec![]);
        assert_eq!(confirm.key(PaletteInput::Text('j')), None);
        assert_eq!(
            confirm.key(PaletteInput::Enter),
            Some(Answer::Confirmed(true))
        );
        assert_eq!(confirm.key(PaletteInput::Text('k')), None);
        assert_eq!(
            confirm.key(PaletteInput::Enter),
            Some(Answer::Confirmed(false))
        );
    }

    #[test]
    fn a_list_widens_to_show_its_longest_choice_on_a_wide_screen() {
        let key = "SHA256:9lCADCGWTRLnYe6Xfuxf/iM1fm8hgVyG6H4+uAqsdLE someone@a-long-host.example";
        let dialog = Dialog::choose("mahi asks", vec![], vec![key.to_owned()]);
        let area = Rect::new(0, 0, 120, 12);
        let mut buffer = Buffer::empty(area);
        dialog.render(area, &mut buffer);
        let screen: String = (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        assert!(screen.contains(key), "{screen}");
        assert_eq!(
            [digits(1), digits(9), digits(10), digits(100)],
            [1, 1, 2, 3]
        );
        let narrow = Rect::new(0, 0, 40, 12);
        let mut buffer = Buffer::empty(narrow);
        dialog.render(narrow, &mut buffer);
    }

    #[test]
    fn text_between_backticks_is_highlighted_without_its_marks() {
        let dialog = Dialog::message(
            "Token",
            vec![
                "run `claude setup-token` in another terminal".to_owned(),
                "a lone ` stays".to_owned(),
            ],
        );
        let area = Rect::new(0, 0, 80, 10);
        let mut buffer = Buffer::empty(area);
        dialog.render(area, &mut buffer);
        let screen = drawn(&dialog);
        assert!(
            screen.contains("run claude setup-token in another"),
            "{screen}"
        );
        assert!(screen.contains("a lone ` stays"), "{screen}");
        let highlighted = (0..area.height)
            .flat_map(|y| (0..area.width).map(move |x| (x, y)))
            .filter(|&position| buffer[position].style().fg == Theme::code().fg)
            .map(|position| buffer[position].symbol().to_owned())
            .collect::<String>();
        assert_eq!(highlighted, "claude setup-token");
        assert_eq!(wrapped_rows("`ab` cd", 5, true), 1);
        assert_eq!(wrapped_rows("`ab` cd", 5, false), 2);
    }

    #[test]
    fn a_table_taller_than_the_screen_keeps_its_text_and_scrolls_its_rows() {
        let mut dialog = Dialog::table(
            "Help",
            vec!["What the keys do".to_owned()],
            ["key", "action", "what it does"].map(str::to_owned),
            (0..30)
                .map(|row| [format!("k{row}"), "act".to_owned(), format!("row {row}")])
                .collect(),
        );
        let area = Rect::new(0, 0, 80, 24);
        let draw = |dialog: &Dialog| {
            let mut buffer = Buffer::empty(area);
            dialog.render(area, &mut buffer);
            (0..area.height)
                .map(|y| {
                    (0..area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                        + "\n"
                })
                .collect::<String>()
        };
        let top = draw(&dialog);
        for wanted in [
            "What the keys do",
            "key",
            "row 0 ",
            "↑↓ jk scroll",
            "enter close",
        ] {
            assert!(top.contains(wanted), "{wanted}: {top}");
        }
        assert!(!top.contains("row 29"), "{top}");
        assert!(top.contains("row 15") && !top.contains("row 16"), "{top}");
        for _ in 0..40 {
            assert_eq!(dialog.key(PaletteInput::Text('j')), None);
        }
        let bottom = draw(&dialog);
        assert!(bottom.contains("row 29"), "{bottom}");
        assert!(!bottom.contains("row 0 "), "{bottom}");
        assert!(bottom.contains("What the keys do"), "{bottom}");
        dialog.key(PaletteInput::Up);
        let up = draw(&dialog);
        assert!(!up.contains("row 29"), "{up}");
        assert!(up.contains("row 28"), "{up}");
        for _ in 0..40 {
            dialog.key(PaletteInput::Text('k'));
        }
        assert_eq!(draw(&dialog), top);
        let short = Rect::new(0, 0, 80, 9);
        let mut buffer = Buffer::empty(short);
        dialog.render(short, &mut buffer);
        let cramped: String = (0..short.height)
            .map(|y| {
                (0..short.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        assert!(
            cramped.contains("row 0 ") && cramped.contains("scroll"),
            "{cramped}"
        );
        for _ in 0..40 {
            dialog.key(PaletteInput::Down);
        }
        let tall = Rect::new(0, 0, 80, 30);
        let mut buffer = Buffer::empty(tall);
        dialog.render(tall, &mut buffer);
        let grown: String = (0..tall.height)
            .map(|y| {
                (0..tall.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        assert!(grown.contains("row 29"), "{grown}");
        dialog.key(PaletteInput::Up);
        let mut buffer = Buffer::empty(tall);
        dialog.render(tall, &mut buffer);
        let moved: String = (0..tall.height)
            .map(|y| {
                (0..tall.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        assert!(!moved.contains("row 29"), "{moved}");
        assert_eq!(dialog.key(PaletteInput::Enter), Some(Answer::Ok));
    }

    #[test]
    fn a_table_lines_up_its_columns_widens_to_fit_and_closes_on_enter() {
        let about = "a description long enough to need more than the usual width of a dialog";
        let mut dialog = Dialog::table(
            "Help",
            vec!["What the keys do".to_owned()],
            ["key", "action", "what it does"].map(str::to_owned),
            vec![
                ["n", "new", "start a thread"].map(str::to_owned),
                ["q esc", "quit", about].map(str::to_owned),
            ],
        );
        let area = Rect::new(0, 0, 120, 14);
        let mut buffer = Buffer::empty(area);
        dialog.render(area, &mut buffer);
        let screen: String = (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    + "\n"
            })
            .collect();
        assert!(screen.contains("key    action  what it does"), "{screen}");
        assert!(screen.contains("n      new     start a thread"), "{screen}");
        assert!(
            screen.contains(&format!("q esc  quit    {about}")),
            "{screen}"
        );
        let rows: Vec<&str> = screen.lines().collect();
        let last = rows
            .iter()
            .position(|row| row.contains("q esc  quit"))
            .unwrap();
        assert!(
            rows[last + 1].trim_matches([' ', '│']).is_empty(),
            "{screen}"
        );
        assert!(rows[last + 2].contains("enter close"), "{screen}");
        assert!(!screen.contains("scroll"), "{screen}");
        assert_eq!(dialog.key(PaletteInput::Text('q')), None);
        assert_eq!(dialog.key(PaletteInput::Enter), Some(Answer::Ok));
    }

    #[test]
    fn a_message_closes_on_enter_and_shows_hidden_characters_as_marks() {
        let mut dialog = Dialog::message("Done", vec!["ended t1\u{1b}[2J".to_owned()]);
        assert!(drawn(&dialog).contains("ended t1?[2J"));
        assert_eq!(dialog.key(PaletteInput::Text('x')), None);
        assert_eq!(dialog.key(PaletteInput::Enter), Some(Answer::Ok));
    }

    #[test]
    fn long_lines_wrap_and_every_choice_still_shows() {
        let long = "Push this clone's threads to origin (git@github.com:someone/a-long-project-name.git), so teammates and your other machines can pick them up? The agents' snapshots go only to a private remote.".to_owned();
        let dialog = Dialog::choose(
            "mahi asks",
            vec![long],
            vec![
                "Private: push the agents' snapshots too".to_owned(),
                "Public: keep the snapshots here".to_owned(),
                "Don't push threads".to_owned(),
            ],
        );
        let screen = drawn(&dialog);
        assert!(screen.contains("Don't push threads"), "{screen}");
        assert_eq!(wrapped_rows("aaa bbb", 3, false), 2);
        assert_eq!(
            wrapped_rows("a https://example.org/a/very/long/path", 10, false),
            5
        );
        assert_eq!(wrapped_rows("", 10, false), 1);
        assert!(screen.contains("enter pick"), "{screen}");
        let many: Vec<String> = (0..40).map(|index| format!("key {index}")).collect();
        let mut list = Dialog::choose("Keys", vec![], many);
        for _ in 0..35 {
            list.key(PaletteInput::Down);
        }
        assert!(drawn(&list).contains("key 35"), "{}", drawn(&list));
    }

    #[test]
    fn debug_output_never_shows_what_was_typed() {
        let mut dialog = Dialog::input("Passphrase", vec![], true);
        for c in "hunter2".chars() {
            dialog.key(PaletteInput::Text(c));
        }
        assert!(!format!("{dialog:?}").contains("hunter2"));
        let answer = dialog.key(PaletteInput::Enter).unwrap();
        assert_eq!(format!("{answer:?}"), "Text(..)");
    }

    #[test]
    fn a_tiny_area_draws_without_panicking() {
        let input = Dialog::input("t", vec!["a long line ".repeat(20)], false);
        let table = Dialog::table(
            "t",
            vec!["a long line ".repeat(20)],
            ["key", "action", "what it does"].map(str::to_owned),
            vec![["q esc", "quit", "leave mahi"].map(str::to_owned); 30],
        );
        let mut buffer = Buffer::empty(Rect::new(0, 0, 40, 7));
        input.render(buffer.area, &mut buffer);
        let short: String = buffer
            .content()
            .iter()
            .map(ratatui_core::buffer::Cell::symbol)
            .collect();
        assert!(short.contains('›'), "{short}");
        for dialog in [input, table] {
            for (width, height) in [(0, 0), (1, 1), (6, 3), (20, 5)] {
                let area = Rect::new(0, 0, width, height);
                let mut buffer = Buffer::empty(area);
                dialog.render(area, &mut buffer);
            }
        }
    }
}
