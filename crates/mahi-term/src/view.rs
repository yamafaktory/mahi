use std::io::{
    self,
    Write,
};

use mahi_core::is_invisible;
use ratatui_core::{
    backend::Backend as _,
    buffer::{
        Buffer,
        Cell,
        CellWidth as _,
    },
    layout::Rect,
    style::{
        Modifier,
        Style,
    },
    text::{
        Line,
        Span,
    },
    widgets::Widget as _,
};
use ratatui_widgets::{
    block::{
        Block,
        Padding,
    },
    borders::BorderType,
    clear::Clear,
};
use unicode_width::{
    UnicodeWidthChar,
    UnicodeWidthStr,
};

use crate::{
    AnsiBackend,
    Theme,
    dialog::key_hints,
};

const WIDEST: u16 = 72;
const NARROWEST: u16 = 24;
const MOST_ITEMS: usize = 12;
const MOST_ITEMS_WITH_PREVIEW: usize = 5;
const SAVE: &[u8] = b"\x1b7";
const RESTORE: &[u8] = b"\x1b8";
const RESET: &[u8] = b"\x1b[0m";

/// One line the palette lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaletteItem<'a> {
    /// What the line is, such as the teammate a prompt comes from.
    pub label: &'a str,
    /// More about it, such as the prompt's text, shown dimmed after the label.
    pub detail: &'a str,
}

/// What the palette shows: a rounded box centred on the screen, drawn as mahi's dialogs are,
/// with its title, a filter line, the items, and a hint about its keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaletteView<'a> {
    /// The title in the top border.
    pub title: &'a str,
    /// What the user typed to filter the items.
    pub filter: &'a str,
    /// The items, of which as many as fit are shown around the selected one.
    pub items: &'a [PaletteItem<'a>],
    /// The index of the selected item.
    pub selected: usize,
    /// What the list says when it has no items.
    pub empty: &'a str,
    /// The hint below the items: keys and what they do, such as `Esc closes · Tab always`.
    pub hint: &'a str,
    /// The whole text of the selected item, shown below the list from line `scroll` on.
    pub preview: Option<Preview<'a>>,
    /// Whether the terminal draws 24-bit colour; otherwise the nearest of 256 colours is used.
    pub true_color: bool,
}

/// The whole text of the selected item, wrapped to the box, from a line on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preview<'a> {
    /// The text.
    pub text: &'a str,
    /// The first wrapped line shown.
    pub scroll: usize,
}

/// How the preview fit: how many of its wrapped lines the box shows at once, and how many it
/// has, so the caller can tell whether its end was shown and how far a page scrolls.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Drawn {
    /// The rows the box gave the preview.
    pub page: usize,
    /// The preview's wrapped lines.
    pub lines: usize,
}

impl Drawn {
    /// Returns whether the preview, from line `scroll`, showed its last line.
    #[must_use]
    pub fn shows_end(&self, scroll: usize) -> bool {
        scroll.saturating_add(self.page) >= self.lines
    }
}

impl PaletteView<'_> {
    /// Writes the escape sequences that draw the palette on a screen of `rows` by `columns`,
    /// keeping the cursor and attributes the agent had, and returns how the preview fit; a
    /// screen too small for the palette gets nothing.
    ///
    /// # Errors
    ///
    /// Returns the error `out` gives.
    pub fn draw(&self, rows: u16, columns: u16, out: &mut impl Write) -> io::Result<Drawn> {
        let width = columns.saturating_sub(4).min(WIDEST);
        let room = usize::from(rows.saturating_sub(6));
        let lines = self
            .preview
            .map(|preview| wrapped(preview.text, usize::from(width).saturating_sub(4)))
            .unwrap_or_default();
        if width < NARROWEST || room == 0 {
            return Ok(Drawn {
                page: 0,
                lines: lines.len(),
            });
        }
        let most = if self.preview.is_some() {
            MOST_ITEMS_WITH_PREVIEW
        } else {
            MOST_ITEMS
        };
        let shown = self.items.len().clamp(1, most.min(room));
        let page = lines.len().min(room.saturating_sub(shown + 1));
        let preview_rows = if page > 0 { page + 1 } else { 0 };
        let height = u16::try_from(shown + 4 + preview_rows).unwrap_or(rows);
        let area = Rect::new((columns - width) / 2, (rows - height) / 2, width, height);
        let scroll = self
            .preview
            .map_or(0, |preview| preview.scroll)
            .min(lines.len().saturating_sub(page));
        let previewed = lines.get(scroll..scroll + page).unwrap_or_default();
        let mut buffer = Buffer::empty(area);
        self.render(area, shown, previewed, &mut buffer);
        out.write_all(SAVE)?;
        let backend = AnsiBackend::new(&mut *out, rows, columns);
        let mut backend = if self.true_color {
            backend
        } else {
            backend.without_true_color()
        };
        backend.draw(cells(&buffer))?;
        backend.flush()?;
        drop(backend);
        out.write_all(RESET)?;
        out.write_all(RESTORE)?;
        Ok(Drawn {
            page,
            lines: lines.len(),
        })
    }

    fn render(&self, area: Rect, shown: usize, previewed: &[String], buffer: &mut Buffer) {
        Clear.render(area, buffer);
        let title = fitted(self.title, usize::from(area.width).saturating_sub(4), true);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(Theme::ACCENT))
            .padding(Padding::horizontal(1))
            .title(Line::from(format!(" {title} ")).style(Theme::title()));
        let inner = block.inner(area);
        block.render(area, buffer);
        let room = usize::from(inner.width);
        let mut rows = inner.rows();
        if let Some(row) = rows.next() {
            Line::from(vec![
                Span::styled("› ", Theme::title()),
                Span::raw(fitted_tail(self.filter, room.saturating_sub(3))),
                Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)),
            ])
            .render(row, buffer);
        }
        let selected = self.selected.min(self.items.len().saturating_sub(1));
        let first = selected.saturating_sub(shown - 1);
        for index in 0..shown {
            let Some(row) = rows.next() else {
                break;
            };
            let line = match self.items.get(first + index) {
                None if index == 0 => Line::styled(fitted(self.empty, room, true), Theme::muted()),
                None => Line::default(),
                Some(item) => item_line(item, room, first + index == selected),
            };
            line.render(row, buffer);
        }
        if !previewed.is_empty() {
            if let Some(row) = rows.next() {
                Line::styled("─".repeat(room), Theme::muted()).render(row, buffer);
            }
            for (text, row) in previewed.iter().zip(rows.by_ref()) {
                Line::raw(fitted(text, room, false)).render(row, buffer);
            }
        }
        if let Some(row) = rows.next() {
            let pairs: Vec<(String, String)> = self
                .hint
                .split(" · ")
                .map(|part| {
                    let part = fitted(part, room, false);
                    match part.split_once(' ') {
                        Some((key, what)) => (key.to_owned(), what.to_owned()),
                        None => (part, String::new()),
                    }
                })
                .collect();
            let pairs: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(key, what)| (key.as_str(), what.as_str()))
                .collect();
            let spans = key_hints(&pairs);
            Line::from(cut_spans(spans, room)).render(row, buffer);
        }
    }
}

fn item_line(item: &PaletteItem<'_>, room: usize, selected: bool) -> Line<'static> {
    let label = fitted(item.label, room, true);
    let used = label.width();
    let mut spans = vec![Span::raw(label)];
    if used + 2 < room {
        let detail = fitted(item.detail, room - used - 2, true);
        spans.push(Span::styled(format!("  {detail}"), Theme::muted()));
    }
    let line = Line::from(spans);
    if selected {
        line.style(Theme::selected())
    } else {
        line
    }
}

fn cut_spans(spans: Vec<Span<'static>>, room: usize) -> Vec<Span<'static>> {
    let mut used = 0;
    let mut kept = Vec::with_capacity(spans.len());
    for span in spans {
        let left = room.saturating_sub(used);
        if left == 0 {
            break;
        }
        let text = fitted(&span.content, left, false);
        used += text.width();
        kept.push(Span::styled(text, span.style));
    }
    kept
}

fn cells(buffer: &Buffer) -> impl Iterator<Item = (u16, u16, &Cell)> {
    let area = buffer.area;
    let mut skip = 0;
    (area.top()..area.bottom())
        .flat_map(move |y| (area.left()..area.right()).map(move |x| (x, y)))
        .filter_map(move |(x, y)| {
            if skip > 0 {
                skip -= 1;
                return None;
            }
            let cell = &buffer[(x, y)];
            skip = usize::from(cell.cell_width()).saturating_sub(1);
            Some((x, y, cell))
        })
}

fn wrapped(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for c in text.chars() {
        if c == '\n' {
            lines.push(std::mem::take(&mut line));
            used = 0;
            continue;
        }
        let c = if c.is_whitespace() { ' ' } else { c };
        if c.is_control() || is_invisible(c) {
            continue;
        }
        let c_width = c.width().unwrap_or(0);
        if used + c_width > width && used > 0 {
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        line.push(c);
        used += c_width;
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn shown_chars(text: &str) -> impl Iterator<Item = (char, usize)> + '_ {
    text.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control() && !is_invisible(*c))
        .map(|c| (c, c.width().unwrap_or(0)))
}

fn fitted(text: &str, room: usize, cut_mark: bool) -> String {
    let total: usize = shown_chars(text).map(|(_, width)| width).sum();
    let cut = total > room;
    let limit = if cut && cut_mark {
        room.saturating_sub(1)
    } else {
        room
    };
    let mut kept = String::with_capacity(text.len());
    let mut used = 0;
    for (c, width) in shown_chars(text) {
        if used + width > limit {
            break;
        }
        kept.push(c);
        used += width;
    }
    if cut && cut_mark && room > 0 {
        kept.push('…');
    }
    kept
}

fn fitted_tail(text: &str, room: usize) -> String {
    let total: usize = shown_chars(text).map(|(_, width)| width).sum();
    if total <= room {
        return fitted(text, room, false);
    }
    let mut kept = String::with_capacity(text.len());
    kept.push('…');
    let mut skipped = 0;
    for (c, width) in shown_chars(text) {
        if skipped + room - 1 < total {
            skipped += width;
            continue;
        }
        kept.push(c);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drawn(view: &PaletteView<'_>, rows: u16, columns: u16) -> vt100::Parser {
        let mut parser = vt100::Parser::new(rows, columns, 0);
        parser.process(b"\x1b[5;7Hagent");
        let mut out = Vec::new();
        view.draw(rows, columns, &mut out).unwrap();
        parser.process(&out);
        parser
    }

    fn view<'a>(items: &'a [PaletteItem<'a>], filter: &'a str) -> PaletteView<'a> {
        PaletteView {
            title: "mahi",
            filter,
            items,
            selected: 0,
            empty: "no prompts waiting",
            hint: "Esc close",
            preview: None,
            true_color: true,
        }
    }

    fn is_selected(parser: &vt100::Parser, row: u16, column: u16) -> bool {
        parser.screen().cell(row, column).unwrap().bgcolor() == vt100::Color::Rgb(0x83, 0x21, 0x61)
    }

    fn row(parser: &vt100::Parser, row: u16) -> String {
        parser
            .screen()
            .contents_between(row, 0, row, parser.screen().size().1)
    }

    #[test]
    fn an_empty_palette_is_a_centred_rounded_box() {
        let parser = drawn(&view(&[], ""), 24, 80);
        let screen = parser.screen();
        assert_eq!(screen.cursor_position(), (4, 11));
        let rows: Vec<String> = (0..24).map(|r| row(&parser, r)).collect();
        let top = rows.iter().position(|line| line.contains('╭')).unwrap();
        assert_eq!(top, 9);
        assert!(rows[top].trim().starts_with("╭ mahi ─"));
        assert!(rows[top].trim().ends_with('╮'));
        assert!(rows[top + 1].contains("│ › "));
        assert!(rows[top + 2].contains("no prompts waiting"));
        assert!(rows[top + 3].contains("│ Esc close"));
        assert!(rows[top + 4].trim().starts_with('╰'));
        for line in &rows[top..=top + 4] {
            assert_eq!(line.trim().chars().count(), 72, "{line}");
            assert_eq!(line.find(|c: char| c != ' '), Some(4));
        }
    }

    #[test]
    fn items_are_cut_to_the_box_and_the_selected_one_stays_in_view() {
        let long = "fix the flaky test ".repeat(10);
        let items: Vec<PaletteItem<'_>> = (0..20)
            .map(|_| PaletteItem {
                label: "bob",
                detail: &long,
            })
            .collect();
        let mut palette = view(&items, "");
        palette.selected = 19;
        let parser = drawn(&palette, 24, 80);
        let rows: Vec<String> = (0..24).map(|r| row(&parser, r)).collect();
        let shown: Vec<&String> = rows.iter().filter(|line| line.contains("│ bob")).collect();
        assert_eq!(shown.len(), MOST_ITEMS);
        for line in &shown {
            assert!(line.trim_end().ends_with("… │"), "{line}");
            assert_eq!(line.trim().chars().count(), 72);
        }
        let last = rows
            .iter()
            .rposition(|line| line.contains("│ bob"))
            .unwrap();
        let (row, column) = (u16::try_from(last).unwrap(), 6);
        assert!(is_selected(&parser, row, column));
    }

    #[test]
    fn a_long_filter_shows_its_end_and_hidden_characters_are_left_out() {
        let filter = format!("{}end", "x".repeat(100));
        let parser = drawn(&view(&[], &filter), 24, 80);
        let rows: Vec<String> = (0..24).map(|r| row(&parser, r)).collect();
        let line = rows.iter().find(|line| line.contains('›')).unwrap();
        assert!(line.contains("› …xxx"), "{line}");
        assert!(line.contains("end"), "{line}");
        assert_eq!(line.trim().chars().count(), 72);
        let items = [PaletteItem {
            label: "b\u{202e}ob\x1b[2J",
            detail: "wide \u{4e2d}\u{6587}\ttext\n",
        }];
        let parser = drawn(&view(&items, ""), 24, 80);
        let rows: Vec<String> = (0..24).map(|r| row(&parser, r)).collect();
        let line = rows.iter().find(|line| line.contains("bob")).unwrap();
        assert!(
            line.contains("bob[2J  wide \u{4e2d}\u{6587} text"),
            "{line}"
        );
        assert!(
            !rows
                .iter()
                .any(|line| line.contains("agent") && line.contains('│'))
        );
        assert!(row(&parser, 4).contains("agent"));
    }

    #[test]
    fn a_small_screen_gets_a_smaller_box_or_none() {
        let parser = drawn(&view(&[], ""), 8, 30);
        let rows: Vec<String> = (0..8).map(|r| row(&parser, r)).collect();
        let top = rows.iter().position(|line| line.contains('╭')).unwrap();
        assert_eq!(rows[top].trim().chars().count(), 26);
        let mut out = Vec::new();
        view(&[], "").draw(5, 80, &mut out).unwrap();
        assert!(out.is_empty());
        view(&[], "").draw(24, 27, &mut out).unwrap();
        assert!(out.is_empty());
    }

    const RESTORE_TEXT: &str = "\x1b8";

    #[test]
    fn halfwidth_marks_ratatui_draws_two_columns_wide_never_push_the_border_out() {
        let label = "\u{ff76}\u{ff9e}".repeat(40);
        let items = [PaletteItem {
            label: &label,
            detail: "",
        }];
        let mut out = Vec::new();
        view(&items, "").draw(24, 80, &mut out).unwrap();
        let written = String::from_utf8(out).unwrap();
        let marks: Vec<&str> = written.split('\u{ff9e}').skip(1).collect();
        assert!(!marks.is_empty(), "{written:?}");
        for after in marks {
            let mut rest = after;
            while let Some(sequence) = rest.strip_prefix("\x1b[") {
                let end = sequence.find(|c: char| ('@'..='~').contains(&c)).unwrap();
                if sequence.as_bytes()[end] != b'm' {
                    break;
                }
                rest = &sequence[end + 1..];
            }
            assert!(
                rest.starts_with("\x1b[") || rest.starts_with(RESTORE_TEXT),
                "a mark is followed by {:?}",
                after.chars().take(24).collect::<String>()
            );
        }
    }

    #[test]
    fn wide_text_never_pushes_the_right_border_out_of_place() {
        let detail = "\u{4e2d}".repeat(60);
        for columns in [60_u16, 61, 62, 63, 79, 80] {
            let items = [
                PaletteItem {
                    label: "x",
                    detail: &detail,
                },
                PaletteItem {
                    label: &detail,
                    detail: "",
                },
            ];
            let mut palette = view(&items, &detail);
            palette.title = &detail;
            palette.hint = &detail;
            palette.selected = 7;
            let parser = drawn(&palette, 24, columns);
            let screen = parser.screen();
            let width = (columns - 4).min(WIDEST);
            let left = (columns - width) / 2;
            let right = left + width - 1;
            let mut borders = 0;
            for row in 0..24 {
                let edge = screen.cell(row, right).unwrap().contents();
                if screen.cell(row, left).unwrap().contents().is_empty() {
                    continue;
                }
                borders += 1;
                assert!(
                    ["╮", "│", "┤", "╯"].contains(&edge),
                    "{columns} {row}: {edge:?}"
                );
                assert_eq!(
                    screen.cell(row, right + 1).unwrap().contents(),
                    "",
                    "{columns} {row}"
                );
            }
            assert_eq!(borders, 6, "{columns}");
            assert!(is_selected(&parser, 12, left + 2), "{columns}");
        }
    }

    #[test]
    fn the_preview_shows_the_whole_text_a_page_at_a_time() {
        let text = (1..=40)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let items = [PaletteItem {
            label: "bob",
            detail: "line 1",
        }];
        let mut palette = view(&items, "");
        palette.preview = Some(Preview {
            text: &text,
            scroll: 0,
        });
        let mut out = Vec::new();
        let fitted = palette.draw(24, 80, &mut out).unwrap();
        assert_eq!(fitted.lines, 40);
        assert_eq!(fitted.page, 18 - 2);
        assert!(!fitted.shows_end(0));
        assert!(fitted.shows_end(40 - fitted.page));
        let parser = drawn(&palette, 24, 80);
        let rows: Vec<String> = (0..24).map(|r| row(&parser, r)).collect();
        assert!(rows.iter().any(|line| line.contains("│ line 1 ")));
        assert!(rows.iter().any(|line| line.contains("│ line 16 ")));
        assert!(!rows.iter().any(|line| line.contains("line 17")));
        palette.preview = Some(Preview {
            text: &text,
            scroll: 99,
        });
        let parser = drawn(&palette, 24, 80);
        let rows: Vec<String> = (0..24).map(|r| row(&parser, r)).collect();
        assert!(rows.iter().any(|line| line.contains("│ line 40 ")));
        assert!(!rows.iter().any(|line| line.contains("│ line 24 ")));
        for line in rows
            .iter()
            .filter(|line| line.contains('│') || line.contains('╮'))
        {
            assert_eq!(line.trim().chars().count(), 72, "{line}");
        }
    }

    #[test]
    fn wrapping_cuts_long_lines_and_keeps_breaks_and_drops_hidden_characters() {
        assert_eq!(wrapped("abcdef", 4), ["abcd", "ef"]);
        assert_eq!(wrapped("a\n\nb", 4), ["a", "", "b"]);
        assert_eq!(wrapped("", 4), [""]);
        assert_eq!(
            wrapped("\u{4e2d}\u{4e2d}\u{4e2d}", 5),
            ["\u{4e2d}\u{4e2d}", "\u{4e2d}"]
        );
        assert_eq!(wrapped("a\x1b[2Jb\u{202e}c\td", 20), ["a[2Jbc d"]);
        let fitted = Drawn { page: 5, lines: 3 };
        assert!(fitted.shows_end(0));
        let none = view(&[], "").draw(3, 80, &mut Vec::new()).unwrap();
        assert_eq!(none, Drawn::default());
    }
}
