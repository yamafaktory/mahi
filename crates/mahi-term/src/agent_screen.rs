use std::fmt::Write as _;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;
const MOST_PASSED_BYTES: usize = 4096;
const MOST_CLIPBOARD_BYTES: usize = 128 * 1024;
const MOST_STRING_BYTES: usize = MOST_CLIPBOARD_BYTES + 64;
const MOST_REPLY_BYTES: usize = 1024;
const COLOR_QUERIES: [&[u8]; 3] = [b"10", b"11", b"12"];
const SMALLEST: u16 = 2;

/// An agent's terminal as mahi keeps it to draw it in a pane: the agent's output read into a
/// screen of its own, what the agent asks of the user's terminal itself, kept to pass on with
/// its control characters taken out, and the answers mahi gives the agent's queries.
///
/// A string the agent begins (OSC, DCS, APC, PM or SOS) is cut off past 128 KiB, so an agent
/// cannot make mahi keep an endless one.
pub struct AgentScreen {
    parser: vt100::Parser<Passed>,
    string: Str,
    modes: Modes,
}

impl std::fmt::Debug for AgentScreen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentScreen")
            .field("size", &self.parser.screen().size())
            .finish_non_exhaustive()
    }
}

/// Where the agent's output is in a string it began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Str {
    Outside,
    Escape,
    Inside(usize),
    Dropping,
    DroppingEscape,
}

/// The key modes the agent switched, which mahi mirrors on the user's terminal.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Modes {
    application_cursor: bool,
    application_keypad: bool,
    bracketed_paste: bool,
}

impl Modes {
    const AFTER_HOME: Self = Self {
        application_cursor: false,
        application_keypad: false,
        bracketed_paste: true,
    };

    fn of(screen: &vt100::Screen) -> Self {
        Self {
            application_cursor: screen.application_cursor(),
            application_keypad: screen.application_keypad(),
            bracketed_paste: screen.bracketed_paste(),
        }
    }

    fn write_changes(self, from: Self, out: &mut Vec<u8>) {
        if self.application_cursor != from.application_cursor {
            out.extend_from_slice(if self.application_cursor {
                b"\x1b[?1h"
            } else {
                b"\x1b[?1l"
            });
        }
        if self.application_keypad != from.application_keypad {
            out.extend_from_slice(if self.application_keypad {
                b"\x1b="
            } else {
                b"\x1b>"
            });
        }
        if self.bracketed_paste != from.bracketed_paste {
            out.extend_from_slice(if self.bracketed_paste {
                b"\x1b[?2004h"
            } else {
                b"\x1b[?2004l"
            });
        }
    }
}

#[derive(Default)]
struct Passed {
    discarding: bool,
    out: Vec<u8>,
    replies: Vec<u8>,
    keyboard_pushes: u16,
    other_keys: bool,
}

impl Passed {
    fn push_osc(&mut self, parts: &[&[u8]], most: usize) {
        if self.discarding {
            return;
        }
        let mut text = String::new();
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                text.push(';');
            }
            text.extend(
                String::from_utf8_lossy(part)
                    .chars()
                    .filter(|c| !c.is_control()),
            );
        }
        if self.out.len() + text.len() + 3 > most {
            return;
        }
        self.out.push(ESC);
        self.out.push(b']');
        self.out.extend_from_slice(text.as_bytes());
        self.out.push(BEL);
    }

    fn push_csi(
        &mut self,
        (first, second): (Option<u8>, Option<u8>),
        params: &[&[u16]],
        end: char,
    ) -> bool {
        let mut text = String::from("\x1b[");
        text.extend(first.map(char::from));
        for (index, param) in params.iter().enumerate() {
            if index > 0 {
                text.push(';');
            }
            for (index, value) in param.iter().enumerate() {
                if index > 0 {
                    text.push(':');
                }
                let _ = write!(text, "{value}");
            }
        }
        text.extend(second.map(char::from));
        text.push(end);
        let fits = self.out.len() + text.len() <= MOST_PASSED_BYTES;
        if fits {
            self.out.extend_from_slice(text.as_bytes());
        }
        fits
    }

    fn reply(&mut self, text: &str) {
        if self.replies.len() + text.len() <= MOST_REPLY_BYTES {
            self.replies.extend_from_slice(text.as_bytes());
        }
    }
}

fn only(params: &[&[u16]]) -> Option<u16> {
    match params {
        [] => Some(0),
        [[value]] => Some(*value),
        _ => None,
    }
}

fn colour_query(params: &[&[u8]]) -> bool {
    match params {
        [b"4", pairs @ ..] => {
            !pairs.is_empty()
                && pairs.len() % 2 == 0
                && pairs.chunks(2).all(|pair| {
                    matches!(pair, [index, b"?"] if !index.is_empty() && index.iter().all(u8::is_ascii_digit))
                })
        }
        [code, values @ ..] if COLOR_QUERIES.contains(code) => {
            !values.is_empty() && values.iter().all(|value| *value == b"?")
        }
        _ => false,
    }
}

impl vt100::Callbacks for Passed {
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        if self.out.len() < MOST_PASSED_BYTES {
            self.out.push(BEL);
        }
    }

    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        self.push_osc(&[b"2", title], MOST_PASSED_BYTES);
    }

    fn copy_to_clipboard(&mut self, _: &mut vt100::Screen, kind: &[u8], data: &[u8]) {
        let base64 = |byte: &u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=');
        if kind.iter().all(u8::is_ascii_alphabetic) && data.iter().all(base64) {
            self.push_osc(&[b"52", kind, data], MOST_CLIPBOARD_BYTES);
        }
    }

    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        first: Option<u8>,
        second: Option<u8>,
        params: &[&[u16]],
        end: char,
    ) {
        match (first, second, end, only(params)) {
            (None, None, 'n', Some(6)) => {
                let (row, column) = screen.cursor_position();
                self.reply(&format!(
                    "\x1b[{};{}R",
                    u32::from(row) + 1,
                    u32::from(column) + 1
                ));
            }
            (None, None, 'n', Some(5)) => self.reply("\x1b[0n"),
            (None | Some(b'>' | b'='), None, 'c', _)
            | (Some(b'>'), None, 'q', _)
            | (Some(b'?'), None, 'u', _)
            | (Some(b'?'), Some(b'$'), 'p', _) => {
                self.push_csi((first, second), params, end);
            }
            (Some(b'>'), None, 'u', _) => {
                if self.push_csi((first, second), params, end) {
                    self.keyboard_pushes = self.keyboard_pushes.saturating_add(1);
                }
            }
            (Some(b'<'), None, 'u', _) if self.keyboard_pushes > 0 => {
                let popped = only(params).unwrap_or(1).max(1).min(self.keyboard_pushes);
                if self.push_csi((first, second), &[&[popped]], end) {
                    self.keyboard_pushes -= popped;
                }
            }
            (Some(b'>'), None, 'm', _) if params.first() == Some(&&[4][..]) => {
                let passed = self.push_csi((first, second), params, end);
                self.other_keys = if passed {
                    params.get(1).is_some_and(|level| level != &[0])
                } else {
                    self.other_keys
                };
            }
            _ => {}
        }
    }

    fn unhandled_osc(&mut self, _: &mut vt100::Screen, params: &[&[u8]]) {
        let plain_text =
            |part: Option<&&[u8]>| part.is_some_and(|part| !part.iter().all(u8::is_ascii_digit));
        let pass = match params {
            [b"0" | b"2" | b"99", ..] | [b"777", b"notify", ..] => true,
            [b"9", rest @ ..] => plain_text(rest.first()),
            _ => colour_query(params),
        };
        if pass {
            self.push_osc(params, MOST_PASSED_BYTES);
        }
    }
}

/// Starts an empty `vt100` screen of `rows` and `columns`, at least two of each, since `vt100`
/// cannot draw a wide character or scroll in less.
#[must_use]
pub fn new_screen(rows: u16, columns: u16) -> vt100::Parser {
    vt100::Parser::new(rows.max(SMALLEST), columns.max(SMALLEST), 0)
}

/// Gives `parser`'s screen `rows` and `columns`, at least two of each, since `vt100` cannot
/// draw a wide character or scroll in less, when it does not have them yet; returns whether
/// the screen starts blank, as one that gets narrower does, with the modes it had, since
/// `vt100` panics on a wide character a narrower row cuts in two.
pub fn resize_screen<C: vt100::Callbacks + Default>(
    parser: &mut vt100::Parser<C>,
    rows: u16,
    columns: u16,
) -> bool {
    let (rows, columns) = (rows.max(SMALLEST), columns.max(SMALLEST));
    let (_, before) = parser.screen().size();
    if parser.screen().size() == (rows, columns) {
        return false;
    }
    if columns >= before {
        parser.screen_mut().set_size(rows, columns);
        return false;
    }
    let screen = parser.screen();
    let mut modes = screen.input_mode_formatted();
    if screen.alternate_screen() {
        modes.extend_from_slice(b"\x1b[?1049h");
    }
    if screen.hide_cursor() {
        modes.extend_from_slice(b"\x1b[?25l");
    }
    let callbacks = std::mem::take(parser.callbacks_mut());
    *parser = vt100::Parser::new_with_callbacks(rows, columns, 0, callbacks);
    parser.process(&modes);
    true
}

impl AgentScreen {
    /// Starts an empty screen of `rows` and `columns`, at least two of each, for a terminal on
    /// which the home screen left bracketed paste on.
    #[must_use]
    pub fn new(rows: u16, columns: u16) -> Self {
        Self {
            parser: vt100::Parser::new_with_callbacks(
                rows.max(SMALLEST),
                columns.max(SMALLEST),
                0,
                Passed::default(),
            ),
            string: Str::Outside,
            modes: Modes::AFTER_HOME,
        }
    }

    /// Returns the screen the agent drew.
    #[must_use]
    pub fn screen(&self) -> &vt100::Screen {
        self.parser.screen()
    }

    /// Gives the screen `rows` and `columns`, at least two of each, since `vt100` cannot draw
    /// a wide character or scroll in less, when it does not have them yet. A screen that gets
    /// narrower starts blank, with the agent's modes, since `vt100` panics on a wide character
    /// a narrower row cuts in two; the agent redraws for its new size anyway.
    pub fn set_size(&mut self, rows: u16, columns: u16) {
        if !resize_screen(&mut self.parser, rows, columns) {
            return;
        }
        match self.string {
            Str::Inside(_) => self.string = Str::Dropping,
            Str::Escape => self.parser.process(&[ESC]),
            Str::Outside | Str::Dropping | Str::DroppingEscape => {}
        }
    }

    /// Reads the agent's `bytes`, cutting off a string it began once it passes 128 KiB.
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut start = 0;
        for (at, &byte) in bytes.iter().enumerate() {
            let (next, keep) = step(self.string, byte);
            self.string = next;
            match keep {
                Keep::Byte => {}
                Keep::Drop => {
                    self.parser
                        .process(bytes.get(start..at).unwrap_or_default());
                    start = at + 1;
                }
                Keep::CutOff => {
                    self.parser
                        .process(bytes.get(start..at).unwrap_or_default());
                    self.parser.callbacks_mut().discarding = true;
                    self.parser.process(&[CAN]);
                    self.parser.callbacks_mut().discarding = false;
                    start = at + 1;
                }
                Keep::EscapeThenByte => {
                    self.parser
                        .process(bytes.get(start..at).unwrap_or_default());
                    self.parser.process(&[ESC]);
                    start = at;
                }
            }
        }
        self.parser.process(bytes.get(start..).unwrap_or_default());
    }

    /// Writes into `out` what to pass on to the user's terminal since the last call: the key
    /// modes the agent switched, then what it asked of the terminal.
    pub fn take_passed(&mut self, out: &mut Vec<u8>) {
        let modes = Modes::of(self.parser.screen());
        modes.write_changes(self.modes, out);
        self.modes = modes;
        let passed = &mut self.parser.callbacks_mut().out;
        out.extend_from_slice(passed);
        passed.clear();
    }

    /// Writes into `out` the answers mahi gives the agent's queries since the last call.
    pub fn take_replies(&mut self, out: &mut Vec<u8>) {
        let replies = &mut self.parser.callbacks_mut().replies;
        out.extend_from_slice(replies);
        replies.clear();
    }

    /// Writes into `out` what puts the user's terminal back as the home screen left it: the
    /// key modes, and the keyboard modes the agent pushed.
    pub fn undo(&mut self, out: &mut Vec<u8>) {
        Modes::AFTER_HOME.write_changes(self.modes, out);
        self.modes = Modes::AFTER_HOME;
        let passed = self.parser.callbacks_mut();
        passed.out.clear();
        if passed.keyboard_pushes > 0 {
            let _ = write!(Text(out), "\x1b[<{}u", passed.keyboard_pushes);
            passed.keyboard_pushes = 0;
        }
        if passed.other_keys {
            out.extend_from_slice(b"\x1b[>4m");
            passed.other_keys = false;
        }
    }
}

struct Text<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for Text<'_> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.0.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

/// What to do with one byte of the agent's output.
enum Keep {
    Byte,
    Drop,
    CutOff,
    EscapeThenByte,
}

fn step(state: Str, byte: u8) -> (Str, Keep) {
    match state {
        Str::Outside => (
            if byte == ESC {
                Str::Escape
            } else {
                Str::Outside
            },
            Keep::Byte,
        ),
        Str::Escape => (begun(byte), Keep::Byte),
        Str::Inside(length) => match byte {
            BEL | CAN | SUB => (Str::Outside, Keep::Byte),
            ESC => (Str::Escape, Keep::Byte),
            _ if length >= MOST_STRING_BYTES => (Str::Dropping, Keep::CutOff),
            _ => (Str::Inside(length + 1), Keep::Byte),
        },
        Str::Dropping => match byte {
            BEL | CAN | SUB => (Str::Outside, Keep::Drop),
            ESC => (Str::DroppingEscape, Keep::Drop),
            _ => (Str::Dropping, Keep::Drop),
        },
        Str::DroppingEscape => match byte {
            b'\\' => (Str::Outside, Keep::Drop),
            _ => (begun(byte), Keep::EscapeThenByte),
        },
    }
}

/// Returns where the agent's output is after `byte` follows an escape: in an OSC for `]`,
/// the only string `vt100` keeps, still after the escape for a byte the parser ignores or
/// executes there, and outside otherwise.
fn begun(byte: u8) -> Str {
    match byte {
        b']' => Str::Inside(0),
        CAN | SUB => Str::Outside,
        0x00..=0x1f | 0x7f..=0xff => Str::Escape,
        _ => Str::Outside,
    }
}

#[cfg(test)]
mod tests {
    use vt100::Callbacks as _;

    use super::*;

    fn taken(screen: &mut AgentScreen) -> String {
        let mut out = Vec::new();
        screen.take_passed(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn only_the_key_modes_that_changed_are_passed_on_and_the_first_take_turns_paste_off() {
        let mut out = Vec::new();
        let on = Modes {
            application_cursor: true,
            application_keypad: true,
            bracketed_paste: true,
        };
        on.write_changes(Modes::default(), &mut out);
        assert_eq!(out, b"\x1b[?1h\x1b=\x1b[?2004h");
        out.clear();
        on.write_changes(on, &mut out);
        assert!(out.is_empty());
        let mut screen = AgentScreen::new(4, 20);
        assert_eq!(taken(&mut screen), "\x1b[?2004l");
        screen.feed(b"\x1b[?2004h\x1b[?2004$p");
        assert_eq!(taken(&mut screen), "\x1b[?2004h\x1b[?2004$p");
        assert_eq!(taken(&mut screen), "");
    }

    #[test]
    fn what_the_agent_asks_of_the_terminal_is_passed_on_without_control_characters() {
        let mut screen = AgentScreen::new(4, 20);
        taken(&mut screen);
        screen.feed(b"\x07\x1b]2;my\x7ftitle\x07\x1b]52;c;aGk=\x07\x1b]52;c;a!b\x07");
        screen.feed(b"\x1b]9;done\x07\x1b]777;notify;mahi;body\x07\x1b]1337;File=x\x07");
        screen.feed("\x1b]2;a\u{9c}b\x07".as_bytes());
        screen.feed(b"\x1b]9;4;1;50\x07\x1b]777;run;x\x07\x1b]2;a;b\x07");
        assert_eq!(
            taken(&mut screen),
            "\x07\x1b]2;mytitle\x07\x1b]52;c;aGk=\x07\x1b]9;done\x07\x1b]777;notify;mahi;body\x07\
             \x1b]2;ab\x07\x1b]2;a;b\x07"
        );
        let mut full = Passed {
            out: vec![b'x'; MOST_PASSED_BYTES],
            ..Passed::default()
        };
        let mut parser = vt100::Parser::new(1, 1, 0);
        full.audible_bell(parser.screen_mut());
        full.set_window_title(parser.screen_mut(), b"t");
        assert_eq!(full.out.len(), MOST_PASSED_BYTES);
    }

    #[test]
    fn colour_queries_are_passed_on_but_colours_are_never_set() {
        let mut screen = AgentScreen::new(4, 20);
        taken(&mut screen);
        screen.feed(b"\x1b]11;?\x07\x1b]4;1;?;2;?\x07");
        screen.feed(b"\x1b]10;red;?\x07\x1b]4;1;rgb:ff/00/00;2;?\x07\x1b]4;?\x07\x1b]11;\x07");
        assert_eq!(taken(&mut screen), "\x1b]11;?\x07\x1b]4;1;?;2;?\x07");
    }

    #[test]
    fn mahi_answers_where_the_cursor_is_and_passes_on_the_terminals_queries() {
        let mut screen = AgentScreen::new(4, 20);
        taken(&mut screen);
        screen.feed(b"ab\r\ncd\x1b[6n\x1b[5n");
        let mut replies = Vec::new();
        screen.take_replies(&mut replies);
        assert_eq!(replies, b"\x1b[2;3R\x1b[0n");
        replies.clear();
        screen.take_replies(&mut replies);
        assert!(replies.is_empty());
        screen.feed(b"\x1b[c\x1b[>c\x1b[>q\x1b[?u\x1b]8;;x\x07");
        assert_eq!(taken(&mut screen), "\x1b[0c\x1b[>0c\x1b[>0q\x1b[?0u");
    }

    #[test]
    fn keyboard_modes_the_agent_pushes_are_passed_on_and_undone_at_the_end() {
        let mut screen = AgentScreen::new(4, 20);
        taken(&mut screen);
        screen.feed(b"\x1b[>1u\x1b[>3u\x1b[<1u\x1b[>4;2m\x1b[<5u\x1b[>2u\x1b[?1h");
        assert_eq!(
            taken(&mut screen),
            "\x1b[?1h\x1b[>1u\x1b[>3u\x1b[<1u\x1b[>4;2m\x1b[<1u\x1b[>2u"
        );
        let mut undone = Vec::new();
        screen.undo(&mut undone);
        assert_eq!(undone, b"\x1b[?1l\x1b[?2004h\x1b[<1u\x1b[>4m");
        undone.clear();
        screen.undo(&mut undone);
        assert!(undone.is_empty());
    }

    #[test]
    fn a_string_longer_than_the_limit_is_cut_off_and_what_follows_it_is_drawn() {
        let mut screen = AgentScreen::new(2, 10);
        taken(&mut screen);
        screen.feed(b"\x1b]52;c;");
        let long = vec![b'A'; MOST_STRING_BYTES * 2];
        for piece in long.chunks(7000) {
            screen.feed(piece);
        }
        screen.feed(b"\x07after\x1b]2;t\x1b\\");
        assert_eq!(screen.screen().contents(), "after");
        assert_eq!(taken(&mut screen), "\x1b]2;t\x07");
        screen.feed(b"\x1b]2;");
        screen.feed(&vec![b'B'; MOST_STRING_BYTES + 10]);
        screen.feed(b"\x1b[31mred\x1b]2;u\x07");
        assert!(screen.screen().contents().ends_with("red"));
        assert_eq!(taken(&mut screen), "\x1b]2;u\x07");
    }

    #[test]
    fn a_screen_is_never_smaller_than_two_by_two_which_vt100_needs() {
        let mut screen = AgentScreen::new(1, 1);
        assert_eq!(screen.screen().size(), (2, 2));
        screen.feed("  界\r\n界 x".as_bytes());
        screen.set_size(0, 1);
        assert_eq!(screen.screen().size(), (2, 2));
        screen.feed(b"\x1b[999;999H  \n\n");
    }

    #[test]
    fn a_narrower_screen_with_a_wide_character_at_its_edge_starts_blank_with_the_agents_modes() {
        let mut screen = AgentScreen::new(24, 80);
        screen.feed("\x1b[?1h\x1b[?2004h\x1b[?1049h\x1b[?25l\x1b[1;79H界".as_bytes());
        screen.set_size(24, 79);
        screen.feed(b"\x1b[1;79HA\x1b[2K");
        assert_eq!(screen.screen().size(), (24, 79));
        assert!(screen.screen().application_cursor());
        assert!(screen.screen().bracketed_paste());
        assert!(screen.screen().alternate_screen());
        assert!(screen.screen().hide_cursor());
        screen.set_size(30, 100);
        screen.feed("界界".as_bytes());
        assert_eq!(screen.screen().size(), (30, 100));
    }

    #[test]
    fn a_resized_screen_keeps_what_it_drew_unless_narrower_and_is_never_under_two_by_two() {
        let mut parser = new_screen(1, 1);
        assert_eq!(parser.screen().size(), (2, 2));
        parser.process("界".as_bytes());
        assert!(!resize_screen(&mut parser, 3, 6));
        assert_eq!(parser.screen().contents(), "界");
        assert!(!resize_screen(&mut parser, 3, 6));
        parser.process(b"\x1b[?1h\x1b[?1049h\x1b[?25l\x1b[1;5H");
        parser.process("界".as_bytes());
        assert!(resize_screen(&mut parser, 1, 1));
        assert_eq!(parser.screen().size(), (2, 2));
        assert_eq!(parser.screen().contents(), "");
        assert!(parser.screen().application_cursor());
        assert!(parser.screen().alternate_screen());
        assert!(parser.screen().hide_cursor());
        parser.process("界界x".as_bytes());
    }

    #[test]
    fn a_string_cut_by_a_narrower_screen_is_dropped_rather_than_drawn() {
        let mut screen = AgentScreen::new(4, 40);
        taken(&mut screen);
        screen.feed(b"\x1b]52;c;AAAA");
        screen.set_size(4, 30);
        screen.feed(b"BBBB\x07ok\x1b");
        assert_eq!(screen.screen().contents(), "ok");
        assert_eq!(taken(&mut screen), "");
        screen.set_size(4, 20);
        screen.feed(b"]2;t\x07");
        assert_eq!(screen.screen().contents(), "");
        assert_eq!(taken(&mut screen), "\x1b]2;t\x07");
    }

    #[test]
    fn bytes_the_parser_ignores_after_an_escape_do_not_hide_a_string_from_the_limit() {
        for byte in (0x00..=0x1f_u8).chain(0x7f..=0xff) {
            if matches!(byte, CAN | SUB) {
                continue;
            }
            let mut screen = AgentScreen::new(2, 10);
            screen.feed(&[ESC, byte, b']', b'2', b';']);
            screen.feed(&vec![b'A'; MOST_STRING_BYTES + 1]);
            assert_eq!(screen.string, Str::Dropping, "{byte:#x}");
        }
    }

    #[test]
    fn only_an_osc_counts_against_the_limit_since_vt100_keeps_no_other_string() {
        let mut screen = AgentScreen::new(2, 20);
        screen.feed(b"\x1bPq\x9c");
        screen.feed(&vec![b'A'; MOST_STRING_BYTES + 10]);
        screen.feed(b"\r\nvisible");
        assert!(screen.screen().contents().ends_with("visible"));
    }

    #[test]
    fn keyboard_modes_not_passed_on_for_want_of_room_are_not_counted() {
        let mut screen = AgentScreen::new(2, 20);
        screen.parser.callbacks_mut().out = vec![b'x'; MOST_PASSED_BYTES];
        screen.feed(b"\x1b[>1u\x1b[>4;2m");
        assert_eq!(screen.parser.callbacks().keyboard_pushes, 0);
        assert!(!screen.parser.callbacks().other_keys);
    }

    #[test]
    fn a_short_string_split_anywhere_reaches_the_screen_whole() {
        let bytes = b"x\x1b]2;title\x1b\\y\x1b]9;hi\x07z";
        for cut in 0..bytes.len() {
            let mut screen = AgentScreen::new(2, 10);
            taken(&mut screen);
            screen.feed(&bytes[..cut]);
            screen.feed(&bytes[cut..]);
            assert_eq!(screen.screen().contents(), "xyz", "{cut}");
            assert_eq!(taken(&mut screen), "\x1b]2;title\x07\x1b]9;hi\x07", "{cut}");
        }
    }
}
