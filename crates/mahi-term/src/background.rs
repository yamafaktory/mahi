use crate::sequence::{
    Csi,
    starts_answer,
    string_end,
    terminal_answer_at,
};

/// The query that asks a terminal for its background colour, followed by one every terminal
/// answers, so a terminal that does not tell its background is known once that answer comes.
pub const BACKGROUND_QUERY: &[u8] = b"\x1b]11;?\x1b\\\x1b[c";

const REPLY_START: &[u8] = b"\x1b]11;";
const ESC: u8 = 0x1b;
const LONGEST_REPLY: usize = 1024;
const MID_GREY_LUMINANCE: f64 = 0.184;

/// Whether the terminal's background is dark or light, which picks mahi's palette.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Background {
    /// A dark background, and the default when the terminal does not tell.
    #[default]
    Dark,
    /// A light background.
    Light,
}

/// What a terminal's reply to [`BACKGROUND_QUERY`] tells so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundReply {
    /// The terminal told its background.
    Told(Background),
    /// The terminal answered without its background, or with a colour mahi cannot read.
    NotTold,
    /// The reply is not complete yet.
    Incomplete,
}

impl Background {
    /// Returns the background `name` names, `light` or `dark`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }

    /// Returns the background's name, `light` or `dark`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    /// Reads the `bytes` a terminal sent back after [`BACKGROUND_QUERY`], complete once the
    /// answer to the device query that ends it came: a background lighter than mid grey is
    /// light.
    #[must_use]
    pub fn from_reply(bytes: &[u8]) -> BackgroundReply {
        if !holds_device_attributes(bytes) {
            return BackgroundReply::Incomplete;
        }
        let luminance = find(bytes, REPLY_START)
            .and_then(|start| string_text(bytes, start + REPLY_START.len()))
            .and_then(luminance);
        luminance.map_or(BackgroundReply::NotTold, |luminance| {
            BackgroundReply::Told(if luminance > MID_GREY_LUMINANCE {
                Self::Light
            } else {
                Self::Dark
            })
        })
    }
}

/// Splits what a terminal sends after [`BACKGROUND_QUERY`] into its reply and the keys typed
/// meanwhile. The reply ends with the answer to the device query, and every byte after it is a
/// key.
#[derive(Debug, Default)]
pub struct ReplySplit {
    held: Vec<u8>,
    reply: Vec<u8>,
    waited: bool,
    ended: bool,
}

impl ReplySplit {
    /// Reads `chunk`, appends the keys it holds to `keys`, and returns what the reply tells so
    /// far. The start of an answer that the next chunk can finish waits for it, and so does an
    /// Escape alone or with `[` until [`ReplySplit::wait_ended`]. A string that does not start
    /// as a terminal's answer does is keys, such as Alt-] and the text typed after it. A reply that grows past its bound ends,
    /// and its held bytes become keys.
    pub fn read(&mut self, chunk: &[u8], keys: &mut Vec<u8>) -> BackgroundReply {
        if self.ended {
            keys.extend_from_slice(chunk);
            return self.told();
        }
        let joined;
        let bytes = if self.held.is_empty() {
            chunk
        } else {
            let mut held = std::mem::take(&mut self.held);
            held.extend_from_slice(chunk);
            joined = held;
            &joined
        };
        let mut at = 0;
        while let Some(rest) = bytes.get(at..).filter(|rest| !rest.is_empty()) {
            if let Some(answer) = terminal_answer_at(bytes, at)
                .and_then(|end| bytes.get(at..end))
                .filter(|answer| is_reply(answer))
            {
                if self.reply.len() + answer.len() <= LONGEST_REPLY {
                    self.reply.extend_from_slice(answer);
                }
                at += answer.len();
                if answer.get(1) == Some(&b'[') && Csi::at(answer, 2).is_device_attributes() {
                    self.ended = true;
                    keys.extend_from_slice(bytes.get(at..).unwrap_or_default());
                    return self.told();
                }
                continue;
            }
            if starts_answer(rest.strip_suffix(&[ESC]).unwrap_or(rest))
                || matches!(rest, [ESC, b']' | b'P'])
                || (!self.waited && is_csi_start(rest))
            {
                self.held.extend_from_slice(rest);
                break;
            }
            keys.extend(rest.first());
            at += 1;
        }
        if self.held.len() > LONGEST_REPLY {
            self.give_up(keys);
            return self.told();
        }
        BackgroundReply::Incomplete
    }

    /// Takes in that the wait for the reply ended: an Escape that waits alone or with `[`
    /// becomes keys, and a later one does not wait.
    pub fn wait_ended(&mut self, keys: &mut Vec<u8>) {
        self.waited = true;
        if is_csi_start(&self.held) {
            keys.append(&mut self.held);
        }
    }

    /// Ends the reply where it is, and appends the bytes that wait to `keys`.
    pub fn give_up(&mut self, keys: &mut Vec<u8>) {
        self.ended = true;
        keys.append(&mut self.held);
    }

    /// Whether the reply ended, so every byte after it is a key.
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    fn told(&self) -> BackgroundReply {
        match Background::from_reply(&self.reply) {
            BackgroundReply::Incomplete => BackgroundReply::NotTold,
            told => told,
        }
    }
}

fn is_csi_start(bytes: &[u8]) -> bool {
    matches!(bytes, [ESC] | [ESC, b'['])
}

fn is_reply(answer: &[u8]) -> bool {
    if answer.get(1) == Some(&b'[') {
        return true;
    }
    let text = answer
        .strip_suffix(b"\x07")
        .or_else(|| answer.strip_suffix(b"\x1b\\"))
        .unwrap_or(answer);
    starts_answer(text)
}

fn find(bytes: &[u8], wanted: &[u8]) -> Option<usize> {
    bytes
        .windows(wanted.len())
        .position(|window| window == wanted)
}

fn string_text(bytes: &[u8], start: usize) -> Option<&[u8]> {
    let string = bytes.get(start..string_end(bytes, start)?)?;
    string
        .strip_suffix(b"\x07")
        .or_else(|| string.strip_suffix(b"\x1b\\"))
}

fn holds_device_attributes(bytes: &[u8]) -> bool {
    let starts = bytes.windows(2).enumerate();
    starts
        .filter(|(_, window)| *window == b"\x1b[")
        .any(|(at, _)| Csi::at(bytes, at + 2).is_device_attributes())
}

fn luminance(color: &[u8]) -> Option<f64> {
    let channels = color
        .strip_prefix(b"rgb:")
        .map(|channels| (channels, 3))
        .or_else(|| color.strip_prefix(b"rgba:").map(|channels| (channels, 4)))?;
    let (channels, count) = channels;
    let mut parts = channels.split(|&byte| byte == b'/');
    let mut rgb = [0.0; 3];
    for value in &mut rgb {
        *value = channel(parts.next()?)?;
    }
    let rest = parts.by_ref().count();
    (rest == count - 3).then(|| relative_luminance(rgb))
}

fn channel(digits: &[u8]) -> Option<f64> {
    if digits.is_empty() || digits.len() > 4 {
        return None;
    }
    let value = digits.iter().try_fold(0_u32, |value, &digit| {
        let digit = char::from(digit).to_digit(16)?;
        Some(value * 16 + digit)
    })?;
    let most = u32::from(u16::MAX) >> (16 - 4 * digits.len());
    Some(f64::from(value) / f64::from(most))
}

/// Returns the relative luminance of a colour whose red, green and blue are each from 0 to 1.
pub(crate) fn relative_luminance([red, green, blue]: [f64; 3]) -> f64 {
    let linear = |channel: f64| {
        if channel <= 0.040_45 {
            channel / 12.92
        } else {
            ((channel + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &[u8] = b"\x1b[?62;22c";

    fn read(reply: &[u8]) -> BackgroundReply {
        let mut whole = reply.to_vec();
        whole.extend_from_slice(DEVICE);
        Background::from_reply(&whole)
    }

    #[test]
    fn a_light_background_reads_light_and_a_dark_one_dark() {
        for (reply, background) in [
            (&b"\x1b]11;rgb:ffff/ffff/ffff\x07"[..], Background::Light),
            (b"\x1b]11;rgb:fdfd/f6f6/e3e3\x1b\\", Background::Light),
            (b"\x1b]11;rgb:ff/ff/ff\x07", Background::Light),
            (b"\x1b]11;rgba:ffff/ffff/ffff/ffff\x07", Background::Light),
            (b"\x1b]11;rgb:0000/0000/0000\x1b\\", Background::Dark),
            (b"\x1b]11;rgb:0000/2b2b/3636\x07", Background::Dark),
            (b"\x1b]11;rgb:1c1c/1a1a/2222\x07", Background::Dark),
            (b"\x1b]11;rgb:6/6/6\x07", Background::Dark),
            (b"\x1b]11;rgb:8/8/8\x07", Background::Light),
        ] {
            assert_eq!(read(reply), BackgroundReply::Told(background), "{reply:?}");
        }
    }

    #[test]
    fn a_terminal_that_answers_only_the_device_query_does_not_tell() {
        assert_eq!(read(b""), BackgroundReply::NotTold);
        for unreadable in [
            &b"\x1b]11;\x07"[..],
            b"\x1b]11;?\x07",
            b"\x1b]11;rgb:ffff/ffff\x07",
            b"\x1b]11;rgb:ffff/ffff/ffff/ffff\x07",
            b"\x1b]11;rgb:fffff/ffff/ffff\x07",
            b"\x1b]11;rgb:gg/ff/ff\x07",
            b"\x1b]11;rgb:+f/ff/ff\x07",
            b"\x1b]11;#ffffff\x07",
            b"\x1b]11;rgb:ffff/ffff/ffff\x9c",
            b"\x1b]11;rgb:ffff/ffff/ffff\rx\x07",
        ] {
            assert_eq!(read(unreadable), BackgroundReply::NotTold, "{unreadable:?}");
        }
    }

    #[test]
    fn a_reply_whose_colour_string_never_ends_does_not_tell_once_the_device_answer_comes() {
        assert_eq!(
            read(b"\x1b]11;rgb:ffff/ffff/ffff"),
            BackgroundReply::NotTold
        );
    }

    #[test]
    fn the_names_of_the_backgrounds_read_back_and_nothing_else_does() {
        for background in [Background::Light, Background::Dark] {
            assert_eq!(Background::from_name(background.as_str()), Some(background));
        }
        for other in ["", "Light", "auto"] {
            assert_eq!(Background::from_name(other), None, "{other:?}");
        }
    }

    fn split(chunks: &[&[u8]]) -> (BackgroundReply, Vec<u8>, bool) {
        let mut split = ReplySplit::default();
        let mut keys = Vec::new();
        let mut told = BackgroundReply::Incomplete;
        for chunk in chunks {
            told = split.read(chunk, &mut keys);
        }
        (told, keys, split.is_ended())
    }

    #[test]
    fn keys_typed_around_the_reply_are_kept_and_the_reply_still_tells() {
        let (told, keys, ended) = split(&[b"a\x1b]11;rgb:ffff/ffff/ffff\x07b\x1b[?62;22cc"]);
        assert_eq!(told, BackgroundReply::Told(Background::Light));
        assert_eq!(keys, b"abc");
        assert!(ended);
    }

    #[test]
    fn a_reply_split_anywhere_reads_the_same_and_gives_no_key() {
        let whole: &[u8] = b"\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[?62;22c";
        for cut in 1..whole.len() {
            let (told, keys, ended) = split(&[&whole[..cut], &whole[cut..]]);
            assert_eq!(
                told,
                BackgroundReply::Told(Background::Dark),
                "cut at {cut}"
            );
            assert_eq!(keys, b"", "cut at {cut}");
            assert!(ended, "cut at {cut}");
        }
    }

    #[test]
    fn a_key_sequence_typed_during_the_query_stays_whole() {
        let (told, keys, ended) = split(&[b"\x1b[A\x1b[1;5R\x1b", b"[?62;22c"]);
        assert_eq!(told, BackgroundReply::NotTold);
        assert_eq!(keys, b"\x1b[A\x1b[1;5R");
        assert!(ended);
    }

    #[test]
    fn every_byte_after_the_device_answer_is_a_key() {
        let (told, keys, _) = split(&[b"\x1b[?62;22c", b"\x1b]11;rgb:ffff/ffff/ffff\x07x"]);
        assert_eq!(told, BackgroundReply::NotTold);
        assert_eq!(keys, b"\x1b]11;rgb:ffff/ffff/ffff\x07x");
    }

    #[test]
    fn an_escape_alone_waits_only_while_the_query_waits() {
        let mut split = ReplySplit::default();
        let mut keys = Vec::new();
        split.read(b"a\x1b", &mut keys);
        assert_eq!(keys, b"a");
        split.wait_ended(&mut keys);
        assert_eq!(keys, b"a\x1b");
        split.read(b"\x1b", &mut keys);
        assert_eq!(keys, b"a\x1b\x1b");
        split.read(b"\x1b]11;rgb:ffff/ffff/ffff\x07\x1b[?62;22c", &mut keys);
        assert_eq!(keys, b"a\x1b\x1b");
        assert!(split.is_ended());
    }

    #[test]
    fn giving_up_hands_back_what_waits_and_ends_the_reply() {
        let mut split = ReplySplit::default();
        let mut keys = Vec::new();
        split.read(b"\x1b]11;rgb", &mut keys);
        assert_eq!(keys, b"");
        split.give_up(&mut keys);
        assert_eq!(keys, b"\x1b]11;rgb");
        assert_eq!(split.read(b"x", &mut keys), BackgroundReply::NotTold);
        assert_eq!(keys, b"\x1b]11;rgbx");
    }

    #[test]
    fn an_answer_cut_inside_its_terminator_is_held_until_it_ends() {
        let whole: &[u8] = b"\x1b]2\x1b\\\x1b[?62;22c";
        for cut in 1..whole.len() {
            let (_, keys, ended) = split(&[&whole[..cut], &whole[cut..]]);
            assert_eq!(keys, b"", "cut at {cut}");
            assert!(ended, "cut at {cut}");
        }
    }

    #[test]
    fn a_string_that_does_not_start_as_an_answer_is_keys_however_it_is_split() {
        let typed: &[u8] = b"\x1b]ab\r\x1bPPP\r";
        for cut in 0..=typed.len() {
            let (_, keys, _) = split(&[&typed[..cut], &typed[cut..], b"\x1b[?62;22c"]);
            assert_eq!(keys, typed, "cut at {cut}");
        }
    }

    #[test]
    fn a_reply_that_never_ends_gives_its_bytes_back_as_keys_past_its_bound() {
        let mut endless = b"\x1b]11;".to_vec();
        endless.resize(LONGEST_REPLY + 1, b'f');
        let (told, keys, ended) = split(&[&endless, b"x"]);
        assert_eq!(told, BackgroundReply::NotTold);
        assert_eq!(keys.len(), endless.len() + 1);
        assert!(ended);
    }

    #[test]
    fn a_reply_waits_for_the_answer_to_the_device_query() {
        let whole = b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\\x1b[?62;22c";
        let told = (0..=whole.len())
            .find(|&end| Background::from_reply(&whole[..end]) != BackgroundReply::Incomplete);
        assert_eq!(told, Some(whole.len()));
        assert_eq!(
            Background::from_reply(whole),
            BackgroundReply::Told(Background::Light)
        );
    }
}
