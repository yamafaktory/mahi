use std::ops::Range;

use crate::key::PaletteKey;

const ESC: u8 = 0x1b;
const PASTE_START: &[u8] = b"200";
const PASTE_START_SEQUENCE: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";
const MODIFY_OTHER_KEYS: u32 = 27;
const LOCKS: u32 = 64 | 128;
const LONGEST_NUMBER: usize = 10;
const TILDE_FUNCTIONS: [(u32, u8); 12] = [
    (11, 1),
    (12, 2),
    (13, 3),
    (14, 4),
    (15, 5),
    (17, 6),
    (18, 7),
    (19, 8),
    (20, 9),
    (21, 10),
    (23, 11),
    (24, 12),
];

/// Finds the palette key in what the user types, as terminals send it by default (a control
/// byte or a function key's sequence), in the kitty keyboard protocol and in xterm's
/// `modifyOtherKeys`, and never inside a bracketed paste.
#[derive(Debug)]
pub struct KeyScanner {
    key: PaletteKey,
    pasting: bool,
    paste_start_matched: usize,
    paste_end_matched: usize,
}

/// A piece of what the user typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment<'a> {
    /// Bytes that are not the palette key, for the agent.
    Pass(&'a [u8]),
    /// A press of the palette key, as the terminal sent it.
    Palette(&'a [u8]),
}

/// The pieces of one chunk of input, in order; a release or repeat of the palette key, which
/// the kitty protocol reports, is left out.
#[derive(Debug)]
pub struct Segments<'s, 'a> {
    scanner: &'s mut KeyScanner,
    chunk: &'a [u8],
    at: usize,
    pending: Option<Segment<'a>>,
}

struct Found {
    range: Range<usize>,
    press: bool,
}

impl KeyScanner {
    /// Starts looking for `key`.
    #[must_use]
    pub fn new(key: PaletteKey) -> Self {
        Self {
            key,
            pasting: false,
            paste_start_matched: 0,
            paste_end_matched: 0,
        }
    }

    /// Returns the key it looks for.
    #[must_use]
    pub fn key(&self) -> PaletteKey {
        self.key
    }

    /// Splits `chunk`, the next bytes the user typed, into pieces. A key's sequence split
    /// between two chunks is passed on as it is; the start of a bracketed paste split between
    /// them is still recognised.
    pub fn scan<'s, 'a>(&'s mut self, chunk: &'a [u8]) -> Segments<'s, 'a> {
        Segments {
            scanner: self,
            chunk,
            at: 0,
            pending: None,
        }
    }

    fn follow_paste(&mut self, byte: u8) {
        if PASTE_END.get(self.paste_end_matched) == Some(&byte) {
            self.paste_end_matched += 1;
            if self.paste_end_matched == PASTE_END.len() {
                self.pasting = false;
                self.paste_end_matched = 0;
            }
        } else {
            self.paste_end_matched = usize::from(byte == ESC);
        }
    }
}

impl<'a> Iterator for Segments<'_, 'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Segment<'a>> {
        if let Some(segment) = self.pending.take() {
            return Some(segment);
        }
        let mut start = self.at;
        while self.at < self.chunk.len() {
            let Some(found) = self.step() else {
                continue;
            };
            let key = self
                .chunk
                .get(found.range.clone())
                .filter(|_| found.press)
                .map(Segment::Palette);
            if let Some(before) = self
                .chunk
                .get(start..found.range.start)
                .filter(|before| !before.is_empty())
            {
                self.pending = key;
                return Some(Segment::Pass(before));
            }
            if key.is_some() {
                return key;
            }
            start = self.at;
        }
        self.chunk
            .get(start..)
            .filter(|rest| !rest.is_empty())
            .map(Segment::Pass)
    }
}

impl Segments<'_, '_> {
    fn step(&mut self) -> Option<Found> {
        let start = self.at;
        let &byte = self.chunk.get(start)?;
        if self.scanner.pasting {
            self.at += 1;
            self.scanner.follow_paste(byte);
            return None;
        }
        if self.scanner.paste_start_matched > 0 {
            let matched = self.scanner.paste_start_matched;
            self.scanner.paste_start_matched = 0;
            if PASTE_START_SEQUENCE.get(matched) == Some(&byte) {
                self.at += 1;
                if matched + 1 == PASTE_START_SEQUENCE.len() {
                    self.scanner.pasting = true;
                } else {
                    self.scanner.paste_start_matched = matched + 1;
                }
                return None;
            }
        }
        if byte == ESC {
            return self.escape(start);
        }
        self.at += 1;
        (self.scanner.key.legacy_byte() == Some(byte)).then_some(Found {
            range: start..self.at,
            press: true,
        })
    }

    fn escape(&mut self, start: usize) -> Option<Found> {
        match self.chunk.get(start + 1) {
            Some(b'[') if self.chunk.get(start + 2) == Some(&b'[') => self.linux_function(start),
            Some(b'[') => self.csi(start),
            Some(b'O') => self.ss3(start),
            Some(&next) if next != ESC => {
                self.at = start + 2;
                None
            }
            Some(_) => {
                self.at = start + 1;
                None
            }
            None => {
                self.at = start + 1;
                self.scanner.paste_start_matched = 1;
                None
            }
        }
    }

    fn linux_function(&mut self, start: usize) -> Option<Found> {
        let Some(&last) = self
            .chunk
            .get(start + 3)
            .filter(|byte| byte.is_ascii_graphic())
        else {
            self.at = start + 3;
            return None;
        };
        self.at = start + 4;
        let function = last
            .checked_sub(b'@')
            .filter(|function| (1..=5).contains(function));
        (function.is_some() && self.scanner.key.function() == function).then_some(Found {
            range: start..self.at,
            press: true,
        })
    }

    fn ss3(&mut self, start: usize) -> Option<Found> {
        let Some(&last) = self
            .chunk
            .get(start + 2)
            .filter(|byte| (0x40..=0x7e).contains(*byte))
        else {
            self.at = start + 2;
            return None;
        };
        self.at = start + 3;
        let function = last
            .checked_sub(b'O')
            .filter(|function| (1..=4).contains(function));
        (function.is_some() && self.scanner.key.function() == function).then_some(Found {
            range: start..self.at,
            press: true,
        })
    }

    fn csi(&mut self, start: usize) -> Option<Found> {
        let chunk = self.chunk;
        let params_start = start + 2;
        let mut end = params_start;
        while chunk
            .get(end)
            .is_some_and(|byte| (0x30..=0x3f).contains(byte))
        {
            end += 1;
        }
        let params_end = end;
        while chunk
            .get(end)
            .is_some_and(|byte| (0x20..=0x2f).contains(byte))
        {
            end += 1;
        }
        let Some(&last) = chunk.get(end).filter(|byte| (0x40..=0x7e).contains(*byte)) else {
            self.at = end;
            if end == chunk.len()
                && let Some(partial) = chunk.get(start..)
                && PASTE_START_SEQUENCE.starts_with(partial)
            {
                self.scanner.paste_start_matched = partial.len();
            }
            return None;
        };
        self.at = end + 1;
        let params = chunk.get(params_start..params_end)?;
        if params_end != end {
            return None;
        }
        if last == b'~' && params == PASTE_START {
            self.scanner.pasting = true;
            return None;
        }
        let press = csi_key(self.scanner.key, params, last)?;
        Some(Found {
            range: start..self.at,
            press,
        })
    }
}

fn csi_key(key: PaletteKey, params: &[u8], last: u8) -> Option<bool> {
    let mut fields = params.split(|&byte| byte == b';');
    match last {
        b'u' => {
            let code = number(fields.next()?.split(|&byte| byte == b':').next()?)?;
            let (modifiers, event) = modifiers(fields.next())?;
            if !key.matches_code(code, modifiers) {
                return None;
            }
            press(event)
        }
        b'~' => {
            let first = number(fields.next()?)?;
            if first == MODIFY_OTHER_KEYS {
                let (modifiers, _) = modifiers(fields.next())?;
                let code = number(fields.next()?)?;
                return (fields.next().is_none() && key.matches_code(code, modifiers))
                    .then_some(true);
            }
            let (modifiers, event) = modifiers(fields.next())?;
            let function = TILDE_FUNCTIONS
                .iter()
                .find(|(code, _)| *code == first)
                .map(|&(_, function)| function);
            if fields.next().is_some()
                || modifiers != 0
                || function.is_none()
                || key.function() != function
            {
                return None;
            }
            press(event)
        }
        b'P' | b'Q' | b'R' | b'S' => {
            let function = Some(last - b'O');
            if params.is_empty() {
                return (key.function() == function).then_some(true);
            }
            if last == b'R' || number(fields.next()?)? != 1 {
                return None;
            }
            let (modifiers, event) = modifiers(fields.next())?;
            if fields.next().is_some() || modifiers != 0 || key.function() != function {
                return None;
            }
            press(event)
        }
        _ => None,
    }
}

fn press(event: u32) -> Option<bool> {
    match event {
        1 => Some(true),
        2 | 3 => Some(false),
        _ => None,
    }
}

fn modifiers(field: Option<&[u8]>) -> Option<(u32, u32)> {
    let Some(field) = field else {
        return Some((0, 1));
    };
    let mut parts = field.split(|&byte| byte == b':');
    let modifiers = parts
        .next()
        .filter(|part| !part.is_empty())
        .map_or(Some(1), number)?;
    let event = parts.next().map_or(Some(1), number)?;
    if parts.next().is_some() {
        return None;
    }
    Some((modifiers.checked_sub(1)? & !LOCKS, event))
}

fn number(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > LONGEST_NUMBER {
        return None;
    }
    digits.iter().try_fold(0_u32, |value, &digit| {
        let digit = u32::from(digit.checked_sub(b'0').filter(|digit| *digit <= 9)?);
        value.checked_mul(10)?.checked_add(digit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(key: &str, chunks: &[&[u8]]) -> Vec<(bool, Vec<u8>)> {
        let mut scanner = KeyScanner::new(key.parse().unwrap());
        let mut pieces: Vec<(bool, Vec<u8>)> = Vec::new();
        for chunk in chunks {
            for segment in scanner.scan(chunk) {
                match segment {
                    Segment::Pass(bytes) => match pieces.last_mut() {
                        Some((false, last)) => last.extend_from_slice(bytes),
                        _ => pieces.push((false, bytes.to_vec())),
                    },
                    Segment::Palette(bytes) => pieces.push((true, bytes.to_vec())),
                }
            }
        }
        pieces
    }

    fn pressed(key: &str, input: &[u8]) -> bool {
        pieces(key, &[input]) == [(true, input.to_vec())]
    }

    fn passed(key: &str, input: &[u8]) -> bool {
        pieces(key, &[input]) == [(false, input.to_vec())]
    }

    #[test]
    fn a_control_byte_is_the_key_and_everything_around_it_passes() {
        assert_eq!(
            pieces("ctrl-space", &[b"ab\0cd\0"]),
            [
                (false, b"ab".to_vec()),
                (true, b"\0".to_vec()),
                (false, b"cd".to_vec()),
                (true, b"\0".to_vec()),
            ]
        );
        assert!(pressed("ctrl-]", b"\x1d"));
        assert!(passed("ctrl-]", b"\0\x1c"));
        assert!(passed("ctrl-space", b"\x1b\0"));
        assert!(passed("ctrl-space", b"plain text\r"));
        assert!(passed("ctrl-space", b"\x1b\x1b\0"));
    }

    #[test]
    fn the_kitty_protocol_reports_the_key_and_its_release_is_left_out() {
        assert!(pressed("ctrl-space", b"\x1b[32;5u"));
        assert!(pressed("ctrl-space", b"\x1b[32;5:1u"));
        assert!(pressed("ctrl-space", b"\x1b[32;69u"));
        assert!(pressed("ctrl-space", b"\x1b[32:32;5;32u"));
        assert!(pieces("ctrl-space", &[b"\x1b[32;5:3u"]).is_empty());
        assert!(pieces("ctrl-space", &[b"\x1b[32;5:2u"]).is_empty());
        assert_eq!(
            pieces("ctrl-space", &[b"a\x1b[32;5:3ub"]),
            [(false, b"ab".to_vec())]
        );
        assert!(passed("ctrl-space", b"\x1b[32;6u"));
        assert!(passed("ctrl-space", b"\x1b[32u"));
        assert!(passed("ctrl-space", b"\x1b[97;5u"));
        assert!(pressed("ctrl-a", b"\x1b[97;5u"));
        assert!(pressed("ctrl-^", b"\x1b[54;6u"));
        assert!(pressed("ctrl-_", b"\x1b[95;5u"));
        assert!(passed("ctrl-space", b"\x1b[99999999999;5u"));
    }

    #[test]
    fn xterms_modify_other_keys_reports_the_key() {
        assert!(pressed("ctrl-space", b"\x1b[27;5;32~"));
        assert!(passed("ctrl-space", b"\x1b[27;5;97~"));
        assert!(pressed("ctrl-a", b"\x1b[27;5;97~"));
        assert!(passed("ctrl-space", b"\x1b[27;5;32;1~"));
    }

    #[test]
    fn function_keys_match_in_each_of_their_encodings_without_modifiers() {
        for encoding in [
            &b"\x1bOP"[..],
            b"\x1b[P",
            b"\x1b[1;1P",
            b"\x1b[11~",
            b"\x1b[1;1:1P",
        ] {
            assert!(pressed("f1", encoding), "{encoding:?}");
        }
        assert!(pressed("f3", b"\x1b[13~"));
        assert!(pressed("f3", b"\x1bOR"));
        assert!(passed("f3", b"\x1b[1;1R"));
        assert!(pressed("f5", b"\x1b[15~"));
        assert!(pressed("f12", b"\x1b[24~"));
        assert!(passed("f5", b"\x1b[15;5~"));
        assert!(passed("f5", b"\x1b[17~"));
        assert!(passed("f1", b"\x1b[1;5P"));
        assert!(pieces("f5", &[b"\x1b[15;1:3~"]).is_empty());
        assert!(passed("f1", b"\x1bOA\x1b[A"));
        assert!(passed("f1", b"\0\x1d"));
        assert!(passed("ctrl-space", b"\x1bOP"));
    }

    #[test]
    fn nothing_inside_a_bracketed_paste_opens_the_palette() {
        assert_eq!(
            pieces("ctrl-space", &[b"\x1b[200~a\0b\x1b[201~\0"]),
            [
                (false, b"\x1b[200~a\0b\x1b[201~".to_vec()),
                (true, b"\0".to_vec()),
            ]
        );
        assert_eq!(
            pieces(
                "ctrl-space",
                &[b"\x1b[200~\0\x1b\x1b[2", b"01", b"~", b"\0"]
            ),
            [
                (false, b"\x1b[200~\0\x1b\x1b[201~".to_vec()),
                (true, b"\0".to_vec()),
            ]
        );
        assert_eq!(
            pieces("f5", &[b"\x1b[200~\x1b[15~"]),
            [(false, b"\x1b[200~\x1b[15~".to_vec())]
        );
    }

    #[test]
    fn other_and_broken_sequences_pass_untouched() {
        for input in [
            &b"\x1b[<0;10;5M"[..],
            b"\x1b[I",
            b"\x1b[2;3 q",
            b"\x1b[32;5",
            b"\x1b[",
            b"\x1b",
            b"\x1bO",
            b"\x1b[32;5;\x07u",
            b"\x1b[;;;;u",
            b"\x1b[32;0u",
        ] {
            assert!(passed("ctrl-space", input), "{input:?}");
        }
        assert_eq!(
            pieces("ctrl-space", &[b"\x1b[3\0"]),
            [(false, b"\x1b[3".to_vec()), (true, b"\0".to_vec())]
        );
    }

    #[test]
    fn a_paste_start_split_between_reads_still_starts_a_paste() {
        for split in 1..PASTE_START_SEQUENCE.len() {
            let (head, tail) = PASTE_START_SEQUENCE.split_at(split);
            let mut rest = tail.to_vec();
            rest.extend_from_slice(b"a\0\x1b[15~b");
            assert_eq!(
                pieces("ctrl-space", &[b"x", head, &rest]),
                [(false, [b"x", head, &rest[..]].concat())],
                "{split}"
            );
            assert_eq!(
                pieces("f5", &[head, &rest]),
                [(false, [head, &rest[..]].concat())],
                "{split}"
            );
        }
        assert_eq!(
            pieces("ctrl-space", &[b"\x1b[20", b"1~\0"]),
            [(false, b"\x1b[201~".to_vec()), (true, b"\0".to_vec())]
        );
    }

    #[test]
    fn a_key_right_after_a_short_escape_is_still_seen() {
        assert_eq!(
            pieces("ctrl-space", &[b"\x1bO\0"]),
            [(false, b"\x1bO".to_vec()), (true, b"\0".to_vec())]
        );
        assert_eq!(
            pieces("ctrl-space", &[b"\x1bO\x1b[32;5u"]),
            [(false, b"\x1bO".to_vec()), (true, b"\x1b[32;5u".to_vec())]
        );
    }

    #[test]
    fn only_releases_and_repeats_of_the_key_are_left_out() {
        for event in [&b"0"[..], b"4", b"99"] {
            let input = [&b"\x1b[32;5:"[..], event, b"u"].concat();
            assert!(passed("ctrl-space", &input), "{event:?}");
            let tilde = [&b"\x1b[15;1:"[..], event, b"~"].concat();
            assert!(passed("f5", &tilde), "{event:?}");
        }
    }

    #[test]
    fn the_linux_console_sends_f1_to_f5_its_own_way() {
        assert!(pressed("f1", b"\x1b[[A"));
        assert!(pressed("f5", b"\x1b[[E"));
        assert!(passed("f1", b"\x1b[[B"));
        assert!(passed("f6", b"\x1b[[F"));
        assert_eq!(
            pieces("ctrl-space", &[b"\x1b[[\0"]),
            [(false, b"\x1b[[".to_vec()), (true, b"\0".to_vec())]
        );
    }

    #[test]
    fn a_sequence_split_between_reads_passes_as_it_is() {
        assert_eq!(
            pieces("ctrl-space", &[b"\x1b[32", b";5u"]),
            [(false, b"\x1b[32;5u".to_vec())]
        );
    }
}
