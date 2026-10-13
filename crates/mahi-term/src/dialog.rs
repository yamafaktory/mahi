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

    fn with(title: &str, lines: Vec<String>, kind: Kind) -> Self {
        Self {
            title: title.to_owned(),
            lines,
            kind,
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
            Kind::Notice => None,
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
        }
    }

    /// Draws the dialog centred in `area`, over whatever is drawn there, sized to its text as
    /// wrapped, with a list that scrolls to its selected item.
    pub fn render(&self, area: Rect, buffer: &mut Buffer) {
        let width = area.width.saturating_sub(4).min(self.wanted_width());
        let text_width = usize::from(width.saturating_sub(4)).max(1);
        let text: Vec<Line<'_>> = self.lines.iter().map(|line| marked(line)).collect();
        let text_rows: usize = self
            .lines
            .iter()
            .map(|line| wrapped_rows(line, text_width, has_marks(line)))
            .sum();
        let extra_rows = match &self.kind {
            Kind::Message | Kind::Notice => 0,
            Kind::Confirm { .. } | Kind::Input { .. } => 2,
            Kind::Choose { items, .. } => items.len() + 1,
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
            Kind::Message | Kind::Notice => {}
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
            Kind::Input { text, masked } => {
                let typed: String = if *masked {
                    std::iter::repeat_n(MASK, text.chars().count()).collect()
                } else {
                    text.to_string()
                };
                Line::from(vec![
                    Span::styled("› ", Theme::title()),
                    Span::raw(typed),
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
        }
    }

    fn hints(&self, cramped: bool) -> Vec<Span<'static>> {
        let pairs: &[(&str, &str)] = match self.kind {
            Kind::Table { .. } if cramped => &[("↑↓ jk", "scroll"), ("enter", "close")],
            Kind::Message | Kind::Table { .. } => &[("enter", "close")],
            Kind::Notice => &[],
            Kind::Confirm { .. } => &[
                ("y", "yes"),
                ("n", "no"),
                ("tab", "switch"),
                ("esc", "cancel"),
            ],
            Kind::Input { .. } => &[("enter", "done"), ("esc", "cancel")],
            Kind::Choose { .. } => &[("↑↓ jk", "move"), ("enter", "pick"), ("esc", "cancel")],
        };
        key_hints(pairs)
    }
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
