use mahi_core::is_invisible;

const ESC: u8 = 0x1b;
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";
const LONGEST_NUMBER: usize = 10;
const SHIFT: u32 = 1;
const CTRL: u32 = 4;
const LOCKS: u32 = 64 | 128;
const PRIVATE_USE: std::ops::RangeInclusive<char> = '\u{e000}'..='\u{f8ff}';

/// A key typed while the palette is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteInput {
    /// A character for the filter line, typed or pasted.
    Text(char),
    /// Backspace.
    Backspace,
    /// Enter, which accepts.
    Enter,
    /// Tab.
    Tab,
    /// `Ctrl-X`, which rejects.
    Reject,
    /// The up arrow.
    Up,
    /// The down arrow.
    Down,
    /// Escape, which closes the palette.
    Escape,
}

/// Reads the keys typed while the palette is open, as terminals send them by default and in
/// the kitty keyboard protocol. A bracketed paste gives only text, so nothing pasted can
/// accept or reject.
#[derive(Debug, Default)]
pub struct PaletteKeys {
    pasting: bool,
    paste_start_matched: usize,
    paste_end_matched: usize,
}

impl PaletteKeys {
    /// Reads `chunk` and calls `on` with each key it holds, until `on` returns `false`, and
    /// returns how many bytes it read. An escape alone at the end of a chunk is the Escape
    /// key; the start of a bracketed paste split between chunks is still recognised, so
    /// nothing pasted is read as a key.
    pub fn read(&mut self, chunk: &[u8], mut on: impl FnMut(PaletteInput) -> bool) -> usize {
        let mut at = 0;
        while let Some(rest) = chunk.get(at..).filter(|rest| !rest.is_empty()) {
            let (used, input) = if self.pasting {
                self.pasted(rest)
            } else {
                self.typed(rest)
            };
            at += used;
            if let Some(input) = input
                && !on(input)
            {
                break;
            }
        }
        at
    }

    fn pasted(&mut self, rest: &[u8]) -> (usize, Option<PaletteInput>) {
        let Some(&byte) = rest.first() else {
            return (0, None);
        };
        if PASTE_END.get(self.paste_end_matched) == Some(&byte) {
            self.paste_end_matched += 1;
            if self.paste_end_matched == PASTE_END.len() {
                self.pasting = false;
                self.paste_end_matched = 0;
            }
            return (1, None);
        }
        if self.paste_end_matched > 0 {
            self.paste_end_matched = 0;
            return (0, None);
        }
        let (used, character) = character(rest);
        (
            used,
            character.filter(|c| shown(*c)).map(PaletteInput::Text),
        )
    }

    fn typed(&mut self, rest: &[u8]) -> (usize, Option<PaletteInput>) {
        let Some(&byte) = rest.first() else {
            return (0, None);
        };
        let matched = std::mem::take(&mut self.paste_start_matched);
        if matched > 0 && PASTE_START.get(matched) == Some(&byte) {
            if matched + 1 == PASTE_START.len() {
                self.pasting = true;
            } else {
                self.paste_start_matched = matched + 1;
            }
            return (1, None);
        }
        if rest.starts_with(PASTE_START) {
            self.pasting = true;
            return (PASTE_START.len(), None);
        }
        if rest.len() > 1 && PASTE_START.starts_with(rest) {
            self.paste_start_matched = rest.len();
            return (rest.len(), None);
        }
        match byte {
            ESC => escape(rest),
            b'\r' | b'\n' => (1, Some(PaletteInput::Enter)),
            b'\t' => (1, Some(PaletteInput::Tab)),
            0x7f | 0x08 => (1, Some(PaletteInput::Backspace)),
            0x18 => (1, Some(PaletteInput::Reject)),
            0x00..=0x1f => (1, None),
            _ => {
                let (used, character) = character(rest);
                (
                    used,
                    character.filter(|c| shown(*c)).map(PaletteInput::Text),
                )
            }
        }
    }
}

fn shown(c: char) -> bool {
    !c.is_control() && !is_invisible(c)
}

fn character(bytes: &[u8]) -> (usize, Option<char>) {
    let Some(&first) = bytes.first() else {
        return (0, None);
    };
    let width = match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return (1, None),
    };
    let Some(encoded) = bytes.get(..width) else {
        return (1, None);
    };
    match std::str::from_utf8(encoded) {
        Ok(text) => (width, text.chars().next()),
        Err(_) => (1, None),
    }
}

fn escape(rest: &[u8]) -> (usize, Option<PaletteInput>) {
    match rest.get(1) {
        None | Some(&ESC) => (1, Some(PaletteInput::Escape)),
        Some(b'[') => csi(rest),
        Some(b'O') => match rest.get(2) {
            Some(b'A') => (3, Some(PaletteInput::Up)),
            Some(b'B') => (3, Some(PaletteInput::Down)),
            Some(byte) if (0x40..=0x7e).contains(byte) => (3, None),
            _ => (2, None),
        },
        Some(_) => (2, None),
    }
}

fn csi(rest: &[u8]) -> (usize, Option<PaletteInput>) {
    let mut end = 2;
    while rest
        .get(end)
        .is_some_and(|byte| (0x20..=0x3f).contains(byte))
    {
        end += 1;
    }
    let Some(&last) = rest.get(end).filter(|byte| (0x40..=0x7e).contains(*byte)) else {
        return (end, None);
    };
    let params = rest.get(2..end).unwrap_or_default();
    let input = match last {
        b'A' => Some(PaletteInput::Up),
        b'B' => Some(PaletteInput::Down),
        b'u' => kitty(params),
        _ => None,
    };
    (end + 1, input)
}

fn kitty(params: &[u8]) -> Option<PaletteInput> {
    let mut fields = params.split(|&byte| byte == b';');
    let code = number(fields.next()?.split(|&byte| byte == b':').next()?)?;
    let mut modifier_field = fields
        .next()
        .unwrap_or_default()
        .split(|&byte| byte == b':');
    let modifiers = match modifier_field.next().filter(|part| !part.is_empty()) {
        Some(part) => number(part)?.checked_sub(1)? & !LOCKS,
        None => 0,
    };
    let event = modifier_field.next().map_or(Some(1), number)?;
    if event == 3 {
        return None;
    }
    match (code, modifiers) {
        (27, 0) => Some(PaletteInput::Escape),
        (13, 0) => Some(PaletteInput::Enter),
        (9, 0) => Some(PaletteInput::Tab),
        (127 | 8, 0) => Some(PaletteInput::Backspace),
        (120, CTRL) => Some(PaletteInput::Reject),
        (_, 0 | SHIFT) => {
            let c = char::from_u32(code).filter(|c| shown(*c) && !PRIVATE_USE.contains(c))?;
            Some(PaletteInput::Text(if modifiers == SHIFT {
                c.to_ascii_uppercase()
            } else {
                c
            }))
        }
        _ => None,
    }
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

    fn inputs(chunks: &[&[u8]]) -> Vec<PaletteInput> {
        let mut keys = PaletteKeys::default();
        let mut inputs = Vec::new();
        for chunk in chunks {
            keys.read(chunk, |input| {
                inputs.push(input);
                true
            });
        }
        inputs
    }

    fn text(text: &str) -> Vec<PaletteInput> {
        text.chars().map(PaletteInput::Text).collect()
    }

    #[test]
    fn typed_keys_are_read_as_terminals_send_them() {
        assert_eq!(
            inputs(&[b"ab\x7f\r"]),
            [
                PaletteInput::Text('a'),
                PaletteInput::Text('b'),
                PaletteInput::Backspace,
                PaletteInput::Enter
            ]
        );
        assert_eq!(
            inputs(&[b"\t\x18\x08\n"]),
            [
                PaletteInput::Tab,
                PaletteInput::Reject,
                PaletteInput::Backspace,
                PaletteInput::Enter
            ]
        );
        assert_eq!(inputs(&[b"\x1b"]), [PaletteInput::Escape]);
        assert_eq!(
            inputs(&[b"\x1b\x1b"]),
            [PaletteInput::Escape, PaletteInput::Escape]
        );
        assert_eq!(
            inputs(&[b"\x1b[A\x1bOB"]),
            [PaletteInput::Up, PaletteInput::Down]
        );
        assert_eq!(
            inputs(&["\u{e9}\u{4e2d}".as_bytes()]),
            text("\u{e9}\u{4e2d}")
        );
        assert!(inputs(&[b"\x01\x1bx\x1b[1;5C\x1b[<0;1;1M\xff\x1bOZ"]).is_empty());
    }

    #[test]
    fn kitty_keys_are_read_and_releases_left_out() {
        assert_eq!(
            inputs(&[b"\x1b[27u\x1b[13u\x1b[9u\x1b[127u\x1b[120;5u"]),
            [
                PaletteInput::Escape,
                PaletteInput::Enter,
                PaletteInput::Tab,
                PaletteInput::Backspace,
                PaletteInput::Reject
            ]
        );
        assert_eq!(inputs(&[b"\x1b[97u\x1b[97;2u\x1b[97;65u"]), text("aAa"));
        assert!(inputs(&[b"\x1b[27;1:3u\x1b[97;5u\x1b[99999999999u"]).is_empty());
        assert_eq!(inputs(&[b"\x1b[13;1:2u"]), [PaletteInput::Enter]);
    }

    #[test]
    fn a_paste_gives_only_shown_text_even_across_reads() {
        assert_eq!(
            inputs(&[b"\x1b[200~fix\r\n\x18\x1b\tit\xe2\x80\x8b", b"!\x1b[201~\r"]),
            [text("fixit!"), vec![PaletteInput::Enter]].concat()
        );
        assert_eq!(inputs(&[b"\x1b[200~a", b"\r\x1b"]), text("a"));
    }

    #[test]
    fn invisible_and_broken_characters_are_left_out() {
        assert_eq!(inputs(&["a\u{202e}b\u{feff}".as_bytes()]), text("ab"));
        assert_eq!(inputs(&[b"\xe4\xb8", b"z"]), text("z"));
        assert_eq!(inputs(&[b"\xc3("]), text("("));
        assert!(inputs(&[b"\x1b[97;1:3u"]).is_empty());
    }

    #[test]
    fn a_paste_start_split_anywhere_still_gives_only_text() {
        for split in 1..PASTE_START.len() {
            let (head, tail) = PASTE_START.split_at(split);
            for before in [&b""[..], b"x", b"\xe2"] {
                let first = [before, head].concat();
                let second = [tail, b"evil\r\t\x18\x1b\x1b[A".as_slice(), PASTE_END].concat();
                let read = inputs(&[&first, &second]);
                let keys: Vec<&PaletteInput> = read
                    .iter()
                    .take_while(|input| **input != PaletteInput::Escape)
                    .filter(|input| !matches!(input, PaletteInput::Text(_)))
                    .collect();
                assert!(keys.is_empty(), "{split} {before:?}: {read:?}");
                if split > 1 {
                    assert!(!read.contains(&PaletteInput::Escape), "{split}: {read:?}");
                }
            }
        }
        assert_eq!(inputs(&[b"\x1b[2", b"x"]), text("x"));
    }

    #[test]
    fn reading_stops_where_the_caller_says_and_tells_how_far_it_got() {
        let mut keys = PaletteKeys::default();
        let chunk = b"ab\x1b[27urest";
        let used = keys.read(chunk, |input| input != PaletteInput::Escape);
        assert_eq!(&chunk[used..], b"rest");
        let used = keys.read(b"xyz", |_| true);
        assert_eq!(used, 3);
    }
}
