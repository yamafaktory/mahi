use crate::sequence::{
    Csi,
    string_end,
};

/// The query that asks a terminal for its background colour, followed by one every terminal
/// answers, so a terminal that does not tell its background is known once that answer comes.
pub const BACKGROUND_QUERY: &[u8] = b"\x1b]11;?\x1b\\\x1b[c";

const REPLY_START: &[u8] = b"\x1b]11;";
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
