const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;

/// The parts of a control sequence (`ESC [`) whose parameters start at a given byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Csi<'bytes> {
    /// The parameter bytes, from `0x30` to `0x3f`.
    pub params: &'bytes [u8],
    /// The intermediate bytes, from `0x20` to `0x2f`, after the parameters.
    pub intermediates: &'bytes [u8],
    /// The final byte, from `0x40` to `0x7e`, or `None` when the bytes end or another byte
    /// comes first.
    pub last: Option<u8>,
    /// Where the final byte is, or would be.
    pub end: usize,
}

impl<'bytes> Csi<'bytes> {
    /// Reads the control sequence whose parameters start at `start` in `bytes`.
    #[must_use]
    pub fn at(bytes: &'bytes [u8], start: usize) -> Self {
        let in_range = |end: usize, range: std::ops::RangeInclusive<u8>| {
            bytes.get(end).is_some_and(|byte| range.contains(byte))
        };
        let mut end = start;
        while in_range(end, 0x30..=0x3f) {
            end += 1;
        }
        let middle = end;
        while in_range(end, 0x20..=0x2f) {
            end += 1;
        }
        Self {
            params: bytes.get(start..middle).unwrap_or_default(),
            intermediates: bytes.get(middle..end).unwrap_or_default(),
            last: bytes
                .get(end)
                .copied()
                .filter(|byte| (0x40..=0x7e).contains(byte)),
            end,
        }
    }

    /// Whether the sequence is an SGR mouse report.
    #[must_use]
    pub fn is_mouse(&self) -> bool {
        self.params.first() == Some(&b'<')
            && self.intermediates.is_empty()
            && matches!(self.last, Some(b'M' | b'm'))
    }

    /// Whether the sequence is a terminal's answer to the primary device attributes query.
    #[must_use]
    pub fn is_device_attributes(&self) -> bool {
        self.last == Some(b'c')
            && self.intermediates.is_empty()
            && self.params.first() == Some(&b'?')
    }
}

/// Returns where the string whose text starts at `start` in `bytes` ends: past its BEL or
/// `ESC \`, or at a control byte that cuts it. Returns `None` while it has not ended.
#[must_use]
pub fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut end = start;
    while let Some(&byte) = bytes.get(end) {
        if byte < 0x20 && byte != BEL && byte != ESC {
            return Some(end);
        }
        end += 1;
        if byte == BEL || (byte == b'\\' && bytes.get(end.wrapping_sub(2)) == Some(&ESC)) {
            return Some(end);
        }
    }
    None
}

/// Returns where the terminal's answer that starts at `at` in `bytes` ends, or `None` when no
/// answer starts there.
#[must_use]
pub fn terminal_answer_at(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&ESC) {
        return None;
    }
    match bytes.get(at + 1)? {
        b'[' => {
            let csi = Csi::at(bytes, at + 2);
            let answers = match (csi.last?, csi.intermediates) {
                (b'R', b"") => is_position_report(csi.params),
                (b'c', b"") => csi.is_device_attributes() || csi.params.first() == Some(&b'>'),
                (b'u', b"") => csi.params.first() == Some(&b'?'),
                (b'I' | b'O', b"") => csi.params.is_empty(),
                (b'y', b"$") => two_numbers(csi.params.strip_prefix(b"?").unwrap_or(csi.params)),
                _ => false,
            };
            answers.then_some(csi.end + 1)
        }
        b']' | b'P' => string_end(bytes, at + 2),
        _ => None,
    }
}

/// Whether `bytes` hold only terminal answers, one after another.
#[must_use]
pub fn is_terminal_answer(bytes: &[u8]) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        let Some(end) = terminal_answer_at(bytes, at) else {
            return false;
        };
        at = end;
    }
    true
}

/// Whether `tail` is the start of a terminal answer that more bytes can still finish.
#[must_use]
pub fn starts_answer(tail: &[u8]) -> bool {
    match tail {
        [ESC, b'[', _, ..] => {
            let csi = Csi::at(tail, 2);
            csi.last.is_none() && csi.end == tail.len()
        }
        [ESC, b']', rest @ ..] => {
            let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let after = rest.get(digits..).unwrap_or_default();
            digits > 0
                && (after.is_empty() || after.first() == Some(&b';'))
                && string_end(tail, 2).is_none()
        }
        [ESC, b'P', b'0'..=b'9' | b'>' | b'!', ..] => string_end(tail, 2).is_none(),
        _ => false,
    }
}

fn is_position_report(params: &[u8]) -> bool {
    let modified_f3 = params.starts_with(b"1;") && params != b"1;1";
    !modified_f3 && two_numbers(params)
}

fn two_numbers(params: &[u8]) -> bool {
    let mut fields = params.split(|&byte| byte == b';');
    let number = |field: Option<&[u8]>| {
        field.is_some_and(|field| !field.is_empty() && field.iter().all(u8::is_ascii_digit))
    };
    number(fields.next()) && number(fields.next()) && fields.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_ends_past_bel_or_esc_backslash_and_at_a_control_byte_that_cuts_it() {
        assert_eq!(string_end(b"\x1b]11;x\x07rest", 2), Some(7));
        assert_eq!(string_end(b"\x1b]11;x\x1b\\rest", 2), Some(8));
        assert_eq!(string_end(b"\x1b]11;x\rrest", 2), Some(6));
        assert_eq!(string_end(b"\x1b]11;x", 2), None);
    }

    #[test]
    fn the_8_bit_string_terminator_does_not_end_a_string() {
        assert_eq!(string_end(b"\x1b]2;\xc3\x9c\xc3\x9c", 2), None);
        assert_eq!(string_end(b"\x1b]11;x\x9c", 2), None);
    }

    #[test]
    fn each_kind_of_terminal_answer_is_read_whole() {
        for answer in [
            &b"\x1b[12;1R"[..],
            b"\x1b[1;1R",
            b"\x1b[12;40R",
            b"\x1b]11;rgb:0000/0000/0000\x07",
            b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\",
            b"\x1b[?62;22c",
            b"\x1b[>1;10;0c",
            b"\x1b[?0u",
            b"\x1b[I",
            b"\x1b[O",
            b"\x1b[?2026;2$y",
            b"\x1b[4;2$y",
            b"\x1bP1+r544e=787465726d\x1b\\",
            b"\x1bP1$r0m\x1b\\",
        ] {
            assert_eq!(
                terminal_answer_at(answer, 0),
                Some(answer.len()),
                "{answer:?}"
            );
            assert!(is_terminal_answer(answer), "{answer:?}");
        }
        assert!(is_terminal_answer(b"\x1b[12;1R\x1b[?0u"));
    }

    #[test]
    fn a_key_is_no_terminal_answer() {
        for key in [
            &b"\x1b[A"[..],
            b"x",
            b"\x1b[1;5D",
            b"\x1b[1;2R",
            b"\x1b[1;5R",
            b"\x1b[R",
            b"\x1b[2R",
            b"\x1b[1;2;3R",
            b"\x1b]11;rgb:0000",
            b"\x1b[2$y",
            b"\x1b[?$y",
            b"\x1b[?;;$y",
            b"\x1b[?2026;2;1$y",
            b"\x1b[99u",
            b"\x1b[27u",
            b"\x1b[c",
            b"\x1b[2I",
            b"\x1bOP",
        ] {
            assert_eq!(terminal_answer_at(key, 0), None, "{key:?}");
            assert!(!is_terminal_answer(key), "{key:?}");
        }
        assert!(!is_terminal_answer(b"\x1b[12;1Rx"));
    }

    #[test]
    fn only_a_tail_that_more_bytes_can_finish_starts_an_answer() {
        for tail in [&b"\x1b[12;"[..], b"\x1b]11", b"\x1b]11;rgb", b"\x1bP1$r"] {
            assert!(starts_answer(tail), "{tail:?}");
        }
        for tail in [
            &b"\x1b["[..],
            b"\x1b[A",
            b"\x1b]x",
            b"\x1b]11;x\x07",
            b"\x1bPq",
        ] {
            assert!(!starts_answer(tail), "{tail:?}");
        }
    }

    #[test]
    fn a_control_sequence_splits_into_its_parts() {
        let csi = Csi::at(b"\x1b[?2004;1$y", 2);
        assert_eq!(csi.params, b"?2004;1");
        assert_eq!(csi.intermediates, b"$");
        assert_eq!(csi.last, Some(b'y'));
        assert_eq!(csi.end, 10);
        assert!(Csi::at(b"\x1b[?62;22c", 2).is_device_attributes());
        assert!(!Csi::at(b"\x1b[>1;10c", 2).is_device_attributes());
        assert!(Csi::at(b"\x1b[<0;3;4M", 2).is_mouse());
    }
}
