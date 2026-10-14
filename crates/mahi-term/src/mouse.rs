use std::io::Write as _;

const MAX_NUMBER: u32 = 9999;
const MOTION: u16 = 32;
const WHEEL: u16 = 64;
const LOW_BUTTONS: u16 = 3;
const MODIFIERS: u16 = 4 | 8 | 16;
const RELEASE_X10: u16 = 3;
const MAX_X10_CODE: u16 = 255 - 32;
const LONGEST_REPORT: usize = 3 + 4 + 1 + 4 + 1 + 4 + 1;
const X10_OFFSET: u16 = 32;
const X10_LIMIT: u16 = 223;

/// A mouse event the terminal reported in the SGR encoding (mode 1006), with the cell it
/// happened in, counted from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEvent {
    /// The button and modifiers, as the terminal encodes them: 0 to 2 for the left, middle and
    /// right button, plus 4, 8 and 16 for Shift, Meta and Control, plus 32 for motion, plus 64
    /// for the wheel.
    pub code: u16,
    /// The column, from 0.
    pub column: u16,
    /// The row, from 0.
    pub row: u16,
    /// Whether a button went down or moved, rather than up.
    pub pressed: bool,
}

/// Which mouse events an agent asked its terminal to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseMode {
    /// None.
    Off,
    /// Presses only (mode 9).
    Press,
    /// Presses and releases (mode 1000).
    PressRelease,
    /// Presses, releases and motion while a button is down (mode 1002).
    ButtonMotion,
    /// Presses, releases and every motion (mode 1003).
    AnyMotion,
}

/// How an agent asked its terminal to write mouse events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEncoding {
    /// Three bytes after `CSI M`, each the number plus 32, for cells up to 223.
    X10,
    /// As X10, with each number written as a UTF-8 character (mode 1005).
    Utf8,
    /// Decimal numbers after `CSI <`, ending in `M` or `m` (mode 1006).
    Sgr,
}

/// A piece of what the user typed: keys, or a mouse event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Typed<'a> {
    /// Bytes that are not a mouse report.
    Keys(&'a [u8]),
    /// A mouse report.
    Mouse(MouseEvent),
}

impl MouseEvent {
    /// Returns whether it is a press of the left button, without motion.
    #[must_use]
    pub fn is_left_click(self) -> bool {
        self.pressed && self.code & !MODIFIERS == 0
    }

    fn has_button(self) -> bool {
        self.code & LOW_BUTTONS != LOW_BUTTONS || self.code & !(MODIFIERS | MOTION) != LOW_BUTTONS
    }

    fn is_motion(self) -> bool {
        self.code & MOTION != 0
    }

    fn is_wheel(self) -> bool {
        self.code & WHEEL != 0
    }

    /// Writes into `out` the event at `column` and `row` instead of its own, as an agent that
    /// asked for `mode` in `encoding` reads it; returns whether the agent asked for it at all.
    pub fn encode(
        self,
        (mode, encoding): (MouseMode, MouseEncoding),
        (column, row): (u16, u16),
        out: &mut Vec<u8>,
    ) -> bool {
        let wanted = match mode {
            MouseMode::Off => false,
            MouseMode::Press => self.pressed && !self.is_motion(),
            MouseMode::PressRelease => !self.is_motion(),
            MouseMode::ButtonMotion => !self.is_motion() || self.has_button(),
            MouseMode::AnyMotion => true,
        };
        if !wanted || (self.is_wheel() && !self.pressed) {
            return false;
        }
        let event = if mode == MouseMode::Press {
            Self {
                code: self.code & !MODIFIERS,
                ..self
            }
        } else {
            self
        };
        match encoding {
            MouseEncoding::Sgr => {
                let end = if event.pressed { 'M' } else { 'm' };
                let column = u32::from(column) + 1;
                let row = u32::from(row) + 1;
                let _ = write!(out, "\x1b[<{};{column};{row}{end}", event.code);
                true
            }
            MouseEncoding::X10 | MouseEncoding::Utf8 => {
                let code = if event.pressed {
                    event.code
                } else {
                    (event.code & MODIFIERS) | RELEASE_X10
                };
                let limit = if encoding == MouseEncoding::X10 {
                    X10_LIMIT
                } else {
                    2015
                };
                if column >= limit || row >= limit || code > MAX_X10_CODE {
                    return false;
                }
                out.extend_from_slice(b"\x1b[M");
                for number in [code, column + 1, row + 1] {
                    let value = u32::from(number) + u32::from(X10_OFFSET);
                    if encoding == MouseEncoding::X10 {
                        out.push(u8::try_from(value).unwrap_or(u8::MAX));
                    } else {
                        let mut buffer = [0_u8; 4];
                        let text = char::from_u32(value)
                            .unwrap_or(' ')
                            .encode_utf8(&mut buffer);
                        out.extend_from_slice(text.as_bytes());
                    }
                }
                true
            }
        }
    }
}

/// Splits `typed` into keys and the SGR mouse reports among them, in order; a report cut off
/// at the end of `typed`, or one out of bounds, stays keys.
pub fn split_mouse(typed: &[u8]) -> impl Iterator<Item = Typed<'_>> {
    let mut rest = typed;
    let mut pending: Option<MouseEvent> = None;
    std::iter::from_fn(move || {
        if let Some(event) = pending.take() {
            return Some(Typed::Mouse(event));
        }
        if rest.is_empty() {
            return None;
        }
        let mut at = 0;
        while let Some(found) = rest
            .get(at..)
            .and_then(|tail| tail.windows(3).position(|window| window == b"\x1b[<"))
        {
            let start = at + found;
            if let Some((event, length)) = rest.get(start..).and_then(parse_sgr) {
                let keys = rest.get(..start).unwrap_or_default();
                rest = rest.get(start + length..).unwrap_or_default();
                if keys.is_empty() {
                    return Some(Typed::Mouse(event));
                }
                pending = Some(event);
                return Some(Typed::Keys(keys));
            }
            at = start + 1;
        }
        let keys = rest;
        rest = &[];
        Some(Typed::Keys(keys))
    })
}

/// Returns how many bytes at the end of `typed` could be the start of a mouse report cut off
/// by the end of the read, to keep for the next one rather than read as keys.
#[must_use]
pub fn cut_report(typed: &[u8]) -> usize {
    let start = typed.len().saturating_sub(LONGEST_REPORT);
    let tail = typed.get(start..).unwrap_or_default();
    let Some(at) = tail.windows(3).rposition(|window| window == b"\x1b[<") else {
        return [&b"\x1b["[..], b"\x1b"]
            .iter()
            .find(|prefix| typed.ends_with(prefix))
            .map_or(0, |prefix| prefix.len());
    };
    let candidate = tail.get(at..).unwrap_or_default();
    let open = candidate
        .get(3..)
        .unwrap_or_default()
        .iter()
        .all(|byte| byte.is_ascii_digit() || *byte == b';');
    if open { candidate.len() } else { 0 }
}

fn parse_sgr(bytes: &[u8]) -> Option<(MouseEvent, usize)> {
    let body = bytes.strip_prefix(b"\x1b[<")?;
    let mut numbers = [0_u32; 3];
    let mut index = 0;
    let mut digits = 0;
    for (offset, &byte) in body.iter().enumerate() {
        match byte {
            b'0'..=b'9' => {
                let number = numbers.get_mut(index)?;
                *number = *number * 10 + u32::from(byte - b'0');
                digits += 1;
                if *number > MAX_NUMBER {
                    return None;
                }
            }
            b';' if digits > 0 && index < 2 => {
                index += 1;
                digits = 0;
            }
            b'M' | b'm' if digits > 0 && index == 2 => {
                let [code, column, row] = numbers;
                let event = MouseEvent {
                    code: u16::try_from(code).ok()?,
                    column: u16::try_from(column.checked_sub(1)?).ok()?,
                    row: u16::try_from(row.checked_sub(1)?).ok()?,
                    pressed: byte == b'M',
                };
                return Some((event, 3 + offset + 1));
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_reports_are_taken_out_of_the_keys_around_them() {
        let typed = b"ab\x1b[<0;10;5Mcd\x1b[<0;10;5m\x1b[<64;1;1M";
        let pieces: Vec<Typed<'_>> = split_mouse(typed).collect();
        assert_eq!(
            pieces,
            [
                Typed::Keys(b"ab"),
                Typed::Mouse(MouseEvent {
                    code: 0,
                    column: 9,
                    row: 4,
                    pressed: true
                }),
                Typed::Keys(b"cd"),
                Typed::Mouse(MouseEvent {
                    code: 0,
                    column: 9,
                    row: 4,
                    pressed: false
                }),
                Typed::Mouse(MouseEvent {
                    code: 64,
                    column: 0,
                    row: 0,
                    pressed: true
                }),
            ]
        );
    }

    #[test]
    fn a_malformed_or_cut_report_stays_keys() {
        for typed in [
            &b"\x1b[<0;10;5"[..],
            b"\x1b[<0;0;5M",
            b"\x1b[<0;10M",
            b"\x1b[<99999;1;1M",
            b"\x1b[<;1;1M",
            b"\x1b[A",
        ] {
            let pieces: Vec<Typed<'_>> = split_mouse(typed).collect();
            assert_eq!(pieces, [Typed::Keys(typed)], "{typed:?}");
        }
        assert_eq!(split_mouse(b"").count(), 0);
    }

    #[test]
    fn an_event_is_written_as_the_agent_asked_and_only_when_it_asked() {
        let click = MouseEvent {
            code: 0,
            column: 9,
            row: 4,
            pressed: true,
        };
        let release = MouseEvent {
            pressed: false,
            ..click
        };
        let drag = MouseEvent {
            code: MOTION,
            ..click
        };
        let mut out = Vec::new();
        assert!(click.encode((MouseMode::Press, MouseEncoding::Sgr), (2, 3), &mut out));
        assert_eq!(out, b"\x1b[<0;3;4M");
        out.clear();
        assert!(!release.encode((MouseMode::Press, MouseEncoding::Sgr), (2, 3), &mut out));
        assert!(!drag.encode(
            (MouseMode::PressRelease, MouseEncoding::Sgr),
            (2, 3),
            &mut out
        ));
        assert!(!click.encode((MouseMode::Off, MouseEncoding::Sgr), (2, 3), &mut out));
        assert!(out.is_empty());
        assert!(release.encode(
            (MouseMode::PressRelease, MouseEncoding::X10),
            (2, 3),
            &mut out
        ));
        assert_eq!(out, [0x1b, b'[', b'M', 3 + 32, 3 + 32, 4 + 32]);
        out.clear();
        assert!(drag.encode(
            (MouseMode::ButtonMotion, MouseEncoding::Utf8),
            (300, 3),
            &mut out
        ));
        assert_eq!(out, "\x1b[M@\u{14d}$".as_bytes());
        out.clear();
        assert!(!click.encode((MouseMode::Press, MouseEncoding::X10), (300, 3), &mut out));
        assert!(click.is_left_click());
        assert!(!release.is_left_click() && !drag.is_left_click());
    }

    #[test]
    fn extra_buttons_and_wheel_releases_are_not_clicks_or_scrolls() {
        let extra = MouseEvent {
            code: 128,
            column: 0,
            row: 0,
            pressed: true,
        };
        assert!(!extra.is_left_click());
        let shift_click = MouseEvent { code: 4, ..extra };
        assert!(shift_click.is_left_click());
        let mut out = Vec::new();
        let extra_release = MouseEvent {
            pressed: false,
            ..extra
        };
        assert!(extra_release.encode(
            (MouseMode::PressRelease, MouseEncoding::X10),
            (0, 0),
            &mut out
        ));
        assert_eq!(out, [0x1b, b'[', b'M', 3 + 32, 33, 33]);
        out.clear();
        let wheel_release = MouseEvent {
            code: 64,
            pressed: false,
            ..extra
        };
        for encoding in [MouseEncoding::X10, MouseEncoding::Sgr] {
            assert!(!wheel_release.encode((MouseMode::AnyMotion, encoding), (0, 0), &mut out));
        }
        let huge = MouseEvent {
            code: 9000,
            ..extra
        };
        assert!(!huge.encode((MouseMode::AnyMotion, MouseEncoding::X10), (0, 0), &mut out));
        let lone_motion = MouseEvent { code: 35, ..extra };
        assert!(!lone_motion.encode(
            (MouseMode::ButtonMotion, MouseEncoding::Sgr),
            (0, 0),
            &mut out
        ));
        assert!(out.is_empty());
        let control_click = MouseEvent { code: 16, ..extra };
        assert!(control_click.encode((MouseMode::Press, MouseEncoding::Sgr), (0, 0), &mut out));
        assert_eq!(out, b"\x1b[<0;1;1M");
    }

    #[test]
    fn the_start_of_a_report_at_the_end_of_a_read_is_kept_for_the_next() {
        assert_eq!(cut_report(b"ab\x1b[<0;10"), 7);
        assert_eq!(cut_report(b"ab\x1b[<"), 3);
        assert_eq!(cut_report(b"ab\x1b["), 2);
        assert_eq!(cut_report(b"ab\x1b"), 1);
        assert_eq!(cut_report(b"ab\x1b[<0;10;5M"), 0);
        assert_eq!(cut_report(b"ab\x1b[<0;x"), 0);
        assert_eq!(cut_report(b"abc"), 0);
    }
}
