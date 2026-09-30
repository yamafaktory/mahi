use std::{
    fmt,
    str::FromStr,
};

use thiserror::Error;

const SHIFT: u32 = 1;
const CTRL: u32 = 4;
const LONGEST_SHOWN: usize = 32;
const NAMED_CONTROLS: [(&str, u8); 5] = [
    ("space", 0x00),
    ("\\", 0x1c),
    ("]", 0x1d),
    ("^", 0x1e),
    ("_", 0x1f),
];
const TAKEN_LETTERS: &[u8; 5] = b"ghijm";
const LAST_FUNCTION: u8 = 12;

/// The key that opens mahi's palette: `Ctrl-Space` unless the user chose another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaletteKey(Key);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Control(u8),
    Function(u8),
}

/// A name that is not a key mahi can open its palette with.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "{0:?} cannot open the palette: use ctrl-space, ctrl-a to ctrl-z other than ctrl-g, ctrl-h, \
     ctrl-i, ctrl-j and ctrl-m, ctrl-], ctrl-\\, ctrl-^, ctrl-_, or f1 to f12"
)]
pub struct PaletteKeyError(String);

impl Default for PaletteKey {
    fn default() -> Self {
        Self::CTRL_SPACE
    }
}

impl PaletteKey {
    /// `Ctrl-Space`, the default.
    pub const CTRL_SPACE: Self = Self(Key::Control(0x00));

    pub(crate) fn legacy_byte(self) -> Option<u8> {
        match self.0 {
            Key::Control(byte) => Some(byte),
            Key::Function(_) => None,
        }
    }

    pub(crate) fn function(self) -> Option<u8> {
        match self.0 {
            Key::Function(number) => Some(number),
            Key::Control(_) => None,
        }
    }

    pub(crate) fn matches_code(self, code: u32, modifiers: u32) -> bool {
        let Key::Control(byte) = self.0 else {
            return false;
        };
        let with_or_without_shift = modifiers == CTRL || modifiers == CTRL | SHIFT;
        match byte {
            0x00 => code == u32::from(b' ') && modifiers == CTRL,
            0x01..=0x1a => code == u32::from(b'a' + byte - 1) && modifiers == CTRL,
            0x1c => code == u32::from(b'\\') && modifiers == CTRL,
            0x1d => code == u32::from(b']') && modifiers == CTRL,
            0x1e => (code == u32::from(b'^') || code == u32::from(b'6')) && with_or_without_shift,
            0x1f => (code == u32::from(b'_') || code == u32::from(b'-')) && with_or_without_shift,
            _ => false,
        }
    }
}

impl FromStr for PaletteKey {
    type Err = PaletteKeyError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let refused = || PaletteKeyError(text.chars().take(LONGEST_SHOWN).collect());
        let name = text.to_ascii_lowercase();
        if let Some(control) = name.strip_prefix("ctrl-") {
            if let Some(&(_, byte)) = NAMED_CONTROLS.iter().find(|(named, _)| *named == control) {
                return Ok(Self(Key::Control(byte)));
            }
            return match control.as_bytes() {
                &[letter] if letter.is_ascii_lowercase() && !TAKEN_LETTERS.contains(&letter) => {
                    Ok(Self(Key::Control(letter - b'a' + 1)))
                }
                _ => Err(refused()),
            };
        }
        let number = name
            .strip_prefix('f')
            .filter(|digits| !digits.starts_with('0') && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u8>().ok())
            .filter(|number| (1..=LAST_FUNCTION).contains(number))
            .ok_or_else(refused)?;
        Ok(Self(Key::Function(number)))
    }
}

impl fmt::Display for PaletteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Key::Function(number) => write!(f, "F{number}"),
            Key::Control(0x00) => f.write_str("Ctrl-Space"),
            Key::Control(byte @ 0x01..=0x1a) => write!(f, "Ctrl-{}", char::from(b'A' + byte - 1)),
            Key::Control(byte) => write!(f, "Ctrl-{}", char::from(byte + 0x40)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_offered_key_parses_and_shows_its_name() {
        let names = [
            ("ctrl-space", "Ctrl-Space"),
            ("Ctrl-Space", "Ctrl-Space"),
            ("ctrl-a", "Ctrl-A"),
            ("ctrl-z", "Ctrl-Z"),
            ("ctrl-]", "Ctrl-]"),
            ("ctrl-\\", "Ctrl-\\"),
            ("ctrl-^", "Ctrl-^"),
            ("ctrl-_", "Ctrl-_"),
            ("f1", "F1"),
            ("F12", "F12"),
        ];
        for (name, shown) in names {
            let key: PaletteKey = name.parse().unwrap();
            assert_eq!(key.to_string(), shown);
            assert_eq!(key.to_string().parse::<PaletteKey>(), Ok(key));
        }
        assert_eq!(
            "ctrl-a".parse::<PaletteKey>().unwrap().legacy_byte(),
            Some(1)
        );
        assert_eq!(
            "ctrl-]".parse::<PaletteKey>().unwrap().legacy_byte(),
            Some(0x1d)
        );
        assert_eq!(PaletteKey::default().legacy_byte(), Some(0));
        assert_eq!("f7".parse::<PaletteKey>().unwrap().function(), Some(7));
    }

    #[test]
    fn keys_that_are_also_backspace_tab_or_enter_and_unknown_names_are_refused() {
        let long = "x".repeat(100);
        for name in [
            "ctrl-g", "ctrl-h", "ctrl-i", "ctrl-j", "ctrl-m", "ctrl-[", "ctrl-1", "ctrl-",
            "ctrl-ab", "f0", "f13", "f01", "f+1", "f", "space", "", "alt-a", &long,
        ] {
            assert!(name.parse::<PaletteKey>().is_err(), "{name:?}");
        }
        let shown = long.parse::<PaletteKey>().unwrap_err().to_string();
        assert!(shown.len() < 250, "{shown}");
    }

    #[test]
    fn kitty_codes_match_the_key_with_ctrl_only() {
        let space = PaletteKey::CTRL_SPACE;
        assert!(space.matches_code(32, CTRL));
        assert!(!space.matches_code(32, CTRL | SHIFT));
        assert!(!space.matches_code(97, CTRL));
        let caret: PaletteKey = "ctrl-^".parse().unwrap();
        assert!(caret.matches_code(94, CTRL));
        assert!(caret.matches_code(54, CTRL | SHIFT));
        assert!(!caret.matches_code(54, 0));
        let letter: PaletteKey = "ctrl-q".parse().unwrap();
        assert!(letter.matches_code(u32::from(b'q'), CTRL));
        assert!(!letter.matches_code(u32::from(b'Q'), CTRL));
        assert!(!"f2".parse::<PaletteKey>().unwrap().matches_code(32, CTRL));
    }
}
