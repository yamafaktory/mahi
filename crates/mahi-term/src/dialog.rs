use std::{
    borrow::Cow,
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
};
use zeroize::Zeroizing;

use crate::PaletteInput;

const MAX_INPUT_CHARS: usize = 1024;
const MAX_WIDTH: u16 = 76;
const MASK: char = '•';

/// The colours mahi's full-screen views use.
#[derive(Debug, Clone, Copy)]
pub struct Theme;

impl Theme {
    /// Titles, selections and the keys shown in hints.
    pub const ACCENT: Color = Color::Cyan;
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
            .fg(Color::Black)
            .bg(Self::ACCENT)
            .add_modifier(Modifier::BOLD)
    }

    /// Returns the style of a title.
    #[must_use]
    pub fn title() -> Style {
        Style::new().fg(Self::ACCENT).add_modifier(Modifier::BOLD)
    }

    /// Returns the style of quieter text.
    #[must_use]
    pub fn muted() -> Style {
        Style::new().fg(Self::MUTED)
    }
}

/// A modal dialog drawn over a full-screen view: a message, a yes or no question, a line to
/// type, masked or not, or a list to pick from. What is typed never shows in `Debug` output.
pub struct Dialog {
    title: String,
    lines: Vec<String>,
    kind: Kind,
}

enum Kind {
    Message,
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
            Kind::Notice => None,
            Kind::Confirm { yes } => match input {
                PaletteInput::Text('y' | 'Y') => Some(Answer::Confirmed(true)),
                PaletteInput::Text('n' | 'N') => Some(Answer::Confirmed(false)),
                PaletteInput::Tab
                | PaletteInput::Up
                | PaletteInput::Down
                | PaletteInput::Text('h' | 'l') => {
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
                PaletteInput::Up => {
                    *selected = selected.saturating_sub(1);
                    None
                }
                PaletteInput::Down if *selected + 1 < items.len() => {
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
        let width = area.width.saturating_sub(4).min(MAX_WIDTH);
        let text_width = usize::from(width.saturating_sub(4)).max(1);
        let text: Vec<Line<'_>> = self
            .lines
            .iter()
            .map(|line| Line::from(shown(line)))
            .collect();
        let text_rows: usize = self
            .lines
            .iter()
            .map(|line| wrapped_rows(line, text_width))
            .sum();
        let extra_rows = match &self.kind {
            Kind::Message | Kind::Notice => 0,
            Kind::Confirm { .. } | Kind::Input { .. } => 2,
            Kind::Choose { items, .. } => items.len() + 1,
        };
        let wanted = text_rows + extra_rows + 3;
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
        let [words, below, hints] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Max(extra),
            Constraint::Length(1),
        ])
        .areas(inner);
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .render(words, buffer);
        self.render_below(below, buffer);
        Line::from(self.hints()).render(hints, buffer);
    }

    fn render_below(&self, area: Rect, buffer: &mut Buffer) {
        let [_, rest] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        match &self.kind {
            Kind::Message | Kind::Notice => {}
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
                let list = List::new(items.iter().enumerate().map(|(index, item)| {
                    ListItem::new(format!(" {} {} ", index + 1, shown(item)))
                }))
                .highlight_style(Theme::selected());
                let mut state = ListState::default().with_selected(Some(*selected));
                StatefulWidget::render(list, rest, buffer, &mut state);
            }
        }
    }

    fn hints(&self) -> Vec<Span<'static>> {
        let pairs: &[(&str, &str)] = match self.kind {
            Kind::Message => &[("enter", "close")],
            Kind::Notice => &[],
            Kind::Confirm { .. } => &[
                ("y", "yes"),
                ("n", "no"),
                ("tab", "switch"),
                ("esc", "cancel"),
            ],
            Kind::Input { .. } => &[("enter", "done"), ("esc", "cancel")],
            Kind::Choose { .. } => &[("↑↓", "move"), ("enter", "pick"), ("esc", "cancel")],
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

fn button(label: &str, on: bool) -> Span<'static> {
    let text = format!(" {label} ");
    if on {
        Span::styled(text, Theme::selected())
    } else {
        Span::styled(text, Theme::muted())
    }
}

fn wrapped_rows(line: &str, width: usize) -> usize {
    let width_of = |text: &str| -> usize {
        text.chars()
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
        assert_eq!(wrapped_rows("aaa bbb", 3), 2);
        assert_eq!(
            wrapped_rows("a https://example.org/a/very/long/path", 10),
            5
        );
        assert_eq!(wrapped_rows("", 10), 1);
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
        let dialog = Dialog::input("t", vec!["a long line ".repeat(20)], false);
        for (width, height) in [(0, 0), (1, 1), (6, 3), (20, 5)] {
            let area = Rect::new(0, 0, width, height);
            let mut buffer = Buffer::empty(area);
            dialog.render(area, &mut buffer);
        }
    }
}
