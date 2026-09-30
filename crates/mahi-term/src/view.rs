use std::io::{
    self,
    Write,
};

use mahi_core::is_invisible;
use unicode_width::UnicodeWidthChar;

const WIDEST: u16 = 72;
const NARROWEST: u16 = 24;
const MOST_ITEMS: usize = 12;
const MOST_ITEMS_WITH_PREVIEW: usize = 5;
const SAVE: &[u8] = b"\x1b7";
const RESTORE: &[u8] = b"\x1b8";
const RESET: &[u8] = b"\x1b[0m";
const BORDER: &[u8] = b"\x1b[0;2m";
const PLAIN: &[u8] = b"\x1b[0m";
const SELECTED: &[u8] = b"\x1b[0;7m";
const DIM: &[u8] = b"\x1b[0;2m";

/// One line the palette lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaletteItem<'a> {
    /// What the line is, such as the teammate a prompt comes from.
    pub label: &'a str,
    /// More about it, such as the prompt's text, shown dimmed after the label.
    pub detail: &'a str,
}

/// What the palette shows: a rounded box centred on the screen, with its title, a filter line,
/// the items, and a hint about its keys.
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
    /// The hint in the bottom border.
    pub hint: &'a str,
    /// The whole text of the selected item, shown below the list from line `scroll` on.
    pub preview: Option<Preview<'a>>,
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

struct Frame {
    top: u16,
    left: u16,
    width: usize,
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
        let frame = Frame {
            top: (rows - height) / 2 + 1,
            left: (columns - width) / 2 + 1,
            width: usize::from(width),
        };
        out.write_all(SAVE)?;
        self.draw_top(&frame, out)?;
        self.draw_filter(&frame, out)?;
        frame.line(2, out)?;
        out.write_all(BORDER)?;
        out.write_all("├".as_bytes())?;
        repeat("─", frame.width - 2, out)?;
        out.write_all("┤".as_bytes())?;
        self.draw_items(&frame, shown, out)?;
        if page > 0 {
            let scroll = self
                .preview
                .map_or(0, |preview| preview.scroll)
                .min(lines.len() - page);
            draw_preview(&frame, shown + 3, lines.get(scroll..scroll + page), out)?;
        }
        frame.line(u16::try_from(shown + 3 + preview_rows).unwrap_or(0), out)?;
        out.write_all(BORDER)?;
        out.write_all("╰─ ".as_bytes())?;
        let used = fit(self.hint, frame.width - 6, false, out)?;
        out.write_all(b" ")?;
        repeat("─", frame.width - 5 - used, out)?;
        out.write_all("╯".as_bytes())?;
        out.write_all(RESET)?;
        out.write_all(RESTORE)?;
        Ok(Drawn {
            page,
            lines: lines.len(),
        })
    }

    fn draw_top(&self, frame: &Frame, out: &mut impl Write) -> io::Result<()> {
        frame.line(0, out)?;
        out.write_all(BORDER)?;
        out.write_all("╭─ ".as_bytes())?;
        out.write_all(PLAIN)?;
        let used = fit(self.title, frame.width - 6, false, out)?;
        out.write_all(BORDER)?;
        out.write_all(b" ")?;
        repeat("─", frame.width - 5 - used, out)?;
        out.write_all("╮".as_bytes())
    }

    fn draw_filter(&self, frame: &Frame, out: &mut impl Write) -> io::Result<()> {
        frame.line(1, out)?;
        out.write_all(BORDER)?;
        out.write_all("│".as_bytes())?;
        out.write_all(PLAIN)?;
        out.write_all(" › ".as_bytes())?;
        let room = frame.width - 5;
        let used = fit_tail(self.filter, room - 1, out)?;
        out.write_all(SELECTED)?;
        out.write_all(b" ")?;
        out.write_all(PLAIN)?;
        repeat(" ", room - 1 - used, out)?;
        out.write_all(BORDER)?;
        out.write_all("│".as_bytes())
    }

    fn draw_items(&self, frame: &Frame, shown: usize, out: &mut impl Write) -> io::Result<()> {
        let selected = self.selected.min(self.items.len().saturating_sub(1));
        let first = selected.saturating_sub(shown - 1);
        let room = frame.width - 4;
        for row in 0..shown {
            frame.line(u16::try_from(row + 3).unwrap_or(0), out)?;
            out.write_all(BORDER)?;
            out.write_all("│ ".as_bytes())?;
            let used = match self.items.get(first + row) {
                None if row == 0 => {
                    out.write_all(DIM)?;
                    fit(self.empty, room, true, out)?
                }
                None => 0,
                Some(item) => {
                    out.write_all(if first + row == selected {
                        SELECTED
                    } else {
                        PLAIN
                    })?;
                    let label = fit(item.label, room, true, out)?;
                    if label + 2 < room {
                        out.write_all(b"  ")?;
                        out.write_all(DIM)?;
                        label + 2 + fit(item.detail, room - label - 2, true, out)?
                    } else {
                        label
                    }
                }
            };
            repeat(" ", room - used, out)?;
            out.write_all(BORDER)?;
            out.write_all(" │".as_bytes())?;
        }
        Ok(())
    }
}

fn draw_preview(
    frame: &Frame,
    at: usize,
    lines: Option<&[String]>,
    out: &mut impl Write,
) -> io::Result<()> {
    frame.line(u16::try_from(at).unwrap_or(0), out)?;
    out.write_all(BORDER)?;
    out.write_all("├".as_bytes())?;
    repeat("─", frame.width - 2, out)?;
    out.write_all("┤".as_bytes())?;
    let room = frame.width - 4;
    for (row, line) in lines.unwrap_or_default().iter().enumerate() {
        frame.line(u16::try_from(at + 1 + row).unwrap_or(0), out)?;
        out.write_all(BORDER)?;
        out.write_all("│ ".as_bytes())?;
        out.write_all(PLAIN)?;
        let used = fit(line, room, false, out)?;
        repeat(" ", room - used, out)?;
        out.write_all(BORDER)?;
        out.write_all(" │".as_bytes())?;
    }
    Ok(())
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

impl Frame {
    fn line(&self, offset: u16, out: &mut impl Write) -> io::Result<()> {
        write!(out, "\x1b[{};{}H", self.top + offset, self.left)
    }
}

fn repeat(piece: &str, count: usize, out: &mut impl Write) -> io::Result<()> {
    for _ in 0..count {
        out.write_all(piece.as_bytes())?;
    }
    Ok(())
}

fn shown_chars(text: &str) -> impl Iterator<Item = (char, usize)> + '_ {
    text.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control() && !is_invisible(*c))
        .map(|c| (c, c.width().unwrap_or(0)))
}

fn fit(text: &str, room: usize, cut_mark: bool, out: &mut impl Write) -> io::Result<usize> {
    let total: usize = shown_chars(text).map(|(_, width)| width).sum();
    let limit = if total > room && cut_mark {
        room.saturating_sub(1)
    } else {
        room
    };
    let mut used = 0;
    let mut buffer = [0_u8; 4];
    for (c, width) in shown_chars(text) {
        if used + width > limit {
            break;
        }
        out.write_all(c.encode_utf8(&mut buffer).as_bytes())?;
        used += width;
    }
    if total > room && cut_mark && room > 0 {
        out.write_all("…".as_bytes())?;
        used += 1;
    }
    Ok(used)
}

fn fit_tail(text: &str, room: usize, out: &mut impl Write) -> io::Result<usize> {
    let total: usize = shown_chars(text).map(|(_, width)| width).sum();
    if total <= room {
        return fit(text, room, false, out);
    }
    out.write_all("…".as_bytes())?;
    let mut skipped = 0;
    let mut used = 1;
    let mut buffer = [0_u8; 4];
    for (c, width) in shown_chars(text) {
        if skipped + room - 1 < total {
            skipped += width;
            continue;
        }
        out.write_all(c.encode_utf8(&mut buffer).as_bytes())?;
        used += width;
    }
    Ok(used)
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
        }
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
        assert!(rows[top].trim().starts_with("╭─ mahi ─"));
        assert!(rows[top].trim().ends_with('╮'));
        assert!(rows[top + 1].contains("│ › "));
        assert!(rows[top + 2].trim().starts_with('├'));
        assert!(rows[top + 3].contains("no prompts waiting"));
        assert!(rows[top + 4].trim().starts_with("╰─ Esc close ─"));
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
        assert!(parser.screen().cell(row, column).unwrap().inverse());
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
            assert!(screen.cell(13, left + 2).unwrap().inverse(), "{columns}");
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
