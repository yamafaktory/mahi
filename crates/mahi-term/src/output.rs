const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;
const DEL: u8 = 0x7f;

/// Follows the agent's output to tell where mahi may draw: only in the ground state, outside
/// any escape sequence, control string or UTF-8 character the agent has begun, and not while
/// the agent keeps a saved cursor (`ESC 7` or `CSI s`) it has not restored, since the terminal
/// has one place to save it and mahi saves its own there while it draws.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OutputTracker {
    state: State,
    saved_cursor: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    #[default]
    Ground,
    Utf8(u8),
    Escape,
    EscapeIntermediate,
    Csi {
        bare: bool,
    },
    Osc,
    ControlString,
    StringEscape,
}

impl OutputTracker {
    /// Returns whether mahi may draw after the output so far.
    #[must_use]
    pub fn can_draw(&self) -> bool {
        self.state == State::Ground && !self.saved_cursor
    }

    /// Follows `bytes`, written after the output so far.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.step(byte);
        }
    }

    /// Follows `bytes` only as far as the first point where mahi may draw and returns how
    /// many it followed: 0 when it already may, `bytes.len()` when it never may.
    pub fn feed_until_drawable(&mut self, bytes: &[u8]) -> usize {
        for (followed, &byte) in bytes.iter().enumerate() {
            if self.can_draw() {
                return followed;
            }
            self.step(byte);
        }
        bytes.len()
    }

    fn step(&mut self, byte: u8) {
        match (self.state, byte) {
            (State::Escape, b'7') | (State::Csi { bare: true }, b's') => self.saved_cursor = true,
            (State::Escape, b'8') | (State::Csi { bare: true }, b'u') => self.saved_cursor = false,
            _ => {}
        }
        self.state = next(self.state, byte);
    }
}

fn next(state: State, byte: u8) -> State {
    if matches!(byte, CAN | SUB) {
        return State::Ground;
    }
    match state {
        State::Ground | State::Utf8(_) if byte == ESC => State::Escape,
        State::Ground => ground(byte),
        State::Utf8(left) => match byte {
            0x80..=0xbf if left > 1 => State::Utf8(left - 1),
            0x80..=0xbf => State::Ground,
            _ => ground(byte),
        },
        State::Escape => match byte {
            b'[' => State::Csi { bare: true },
            b']' => State::Osc,
            b'P' | b'X' | b'^' | b'_' => State::ControlString,
            0x20..=0x2f => State::EscapeIntermediate,
            0x00..=0x1f | DEL => State::Escape,
            _ => State::Ground,
        },
        State::EscapeIntermediate => match byte {
            ESC => State::Escape,
            0x00..=0x2f | DEL => State::EscapeIntermediate,
            _ => State::Ground,
        },
        State::Csi { .. } => match byte {
            ESC => State::Escape,
            0x40..=0x7e => State::Ground,
            0x00..=0x1f | DEL => state,
            _ => State::Csi { bare: false },
        },
        State::Osc => match byte {
            BEL => State::Ground,
            ESC => State::StringEscape,
            _ => State::Osc,
        },
        State::ControlString => match byte {
            ESC => State::StringEscape,
            _ => State::ControlString,
        },
        State::StringEscape => match byte {
            b'\\' => State::Ground,
            _ => next(State::Escape, byte),
        },
    }
}

fn ground(byte: u8) -> State {
    match byte {
        0xc2..=0xdf => State::Utf8(1),
        0xe0..=0xef => State::Utf8(2),
        0xf0..=0xf4 => State::Utf8(3),
        _ => State::Ground,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ends_in_ground(bytes: &[u8]) -> bool {
        let mut tracker = OutputTracker::default();
        tracker.feed(bytes);
        tracker.can_draw()
    }

    #[test]
    fn text_and_finished_sequences_end_in_the_ground_state() {
        for bytes in [
            &b""[..],
            b"plain text\r\n",
            b"\x1b[1;31mred\x1b[0m",
            b"\x1b]0;title\x07",
            b"\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\",
            b"\x1bP+q544e\x1b\\",
            b"\x1b7saved\x1b8",
            b"\x1b[srestored\x1b[u",
            b"\x1b[>1u\x1b[<u",
            b"\x1b7\x1b8\x1b(B\x1b=",
            "caf\u{e9} \u{4e2d} \u{1f600}".as_bytes(),
            b"\x1b[1;2\x18",
            b"\x1b]0;cut\x1a",
        ] {
            assert!(ends_in_ground(bytes), "{bytes:?}");
        }
    }

    #[test]
    fn anything_begun_and_not_finished_is_not_the_ground_state() {
        for bytes in [
            &b"\x1b"[..],
            b"\x1b[",
            b"\x1b[1;31",
            b"\x1b[?25",
            b"\x1b]0;title",
            b"\x1b]0;title\x1b",
            b"\x1bP+q54",
            b"\x1bP+q54\x07",
            b"\x1b_apc\x07",
            b"\x1b\x7f",
            b"\x1b(\x7f",
            b"\x1b7saved",
            b"\x1b[s",
            b"\x1b(",
            b"\xe4\xb8",
            b"\xf0\x9f\x98",
            b"\xc3",
        ] {
            assert!(!ends_in_ground(bytes), "{bytes:?}");
        }
    }

    #[test]
    fn following_stops_where_the_agent_finished() {
        let mut tracker = OutputTracker::default();
        assert_eq!(tracker.feed_until_drawable(b"abc"), 0);
        tracker.feed(b"\x1b[1;3");
        assert_eq!(tracker.feed_until_drawable(b"1mrest"), 2);
        assert!(tracker.can_draw());
        tracker.feed(b"\x1b]0;t");
        assert_eq!(tracker.feed_until_drawable(b"itle"), 4);
        assert!(!tracker.can_draw());
        assert_eq!(tracker.feed_until_drawable(b"\x1b\\x"), 2);
        tracker.feed(b"\xe2\x82");
        assert_eq!(tracker.feed_until_drawable(b"\xacz"), 1);
    }

    #[test]
    fn an_escape_inside_a_string_or_character_starts_a_new_sequence() {
        assert!(!ends_in_ground(b"\x1b]0;t\x1b["));
        assert!(ends_in_ground(b"\x1b]0;t\x1b[m"));
        assert!(ends_in_ground(b"\xe2\x1b[m"));
        assert!(ends_in_ground(b"\xe2x"));
    }
}
