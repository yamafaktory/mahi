use std::{
    fmt,
    str::FromStr,
};

use thiserror::Error;

const BYTES: usize = 16;
const HEX_DIGITS: usize = BYTES * 2;
const SHORT_HEX_DIGITS: usize = 8;

/// A random identifier for a thread, written as 32 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadId([u8; BYTES]);

/// The operating system's random source failed.
#[derive(Debug, Error)]
#[error("random source unavailable")]
pub struct RandomError(#[source] getrandom::Error);

/// A string that is not 32 lowercase hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("thread id must be {HEX_DIGITS} lowercase hex digits")]
pub struct ParseThreadIdError;

impl ThreadId {
    /// Creates a thread ID from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError`] if the random source is unavailable.
    pub fn random() -> Result<Self, RandomError> {
        let mut bytes = [0; BYTES];
        getrandom::fill(&mut bytes).map_err(RandomError)?;
        Ok(Self(bytes))
    }

    /// Creates a thread ID from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of the thread ID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BYTES] {
        &self.0
    }

    /// Returns the first eight hex digits, as written in commit trailers.
    #[must_use]
    pub fn short(&self) -> String {
        let mut full = self.to_string();
        full.truncate(SHORT_HEX_DIGITS);
        full
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ThreadId({self})")
    }
}

impl FromStr for ThreadId {
    type Err = ParseThreadIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pairs, []) = s.as_bytes().as_chunks::<2>() else {
            return Err(ParseThreadIdError);
        };
        if pairs.len() != BYTES {
            return Err(ParseThreadIdError);
        }
        let mut bytes = [0; BYTES];
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = (hex_value(*high)? << 4) | hex_value(*low)?;
        }
        Ok(Self(bytes))
    }
}

fn hex_value(digit: u8) -> Result<u8, ParseThreadIdError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(ParseThreadIdError),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn displays_as_lowercase_hex() {
        let id = ThreadId::from_bytes([
            0x7f, 0x3a, 0x9c, 0x2e, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xab, 0xff,
        ]);
        assert_eq!(id.to_string(), "7f3a9c2e00010203040506070809abff");
    }

    #[test]
    fn short_form_is_first_eight_digits() {
        let id: ThreadId = "7f3a9c2e00010203040506070809abff".parse().unwrap();
        assert_eq!(id.short(), "7f3a9c2e");
    }

    #[test]
    fn debug_shows_hex() {
        let id = ThreadId::from_bytes([0xab; BYTES]);
        assert_eq!(
            format!("{id:?}"),
            format!("ThreadId({})", "ab".repeat(BYTES))
        );
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(ThreadId::random().unwrap(), ThreadId::random().unwrap());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!("7f3a9c2e".parse::<ThreadId>().is_err());
        assert!("".parse::<ThreadId>().is_err());
        assert!(
            "7f3a9c2e00010203040506070809abff00"
                .parse::<ThreadId>()
                .is_err()
        );
    }

    #[test]
    fn rejects_uppercase_and_non_hex() {
        assert!(
            "7F3A9C2E00010203040506070809ABFF"
                .parse::<ThreadId>()
                .is_err()
        );
        assert!(
            "7f3a9c2e00010203040506070809abfg"
                .parse::<ThreadId>()
                .is_err()
        );
        assert!(
            "+f3a9c2e00010203040506070809abff"
                .parse::<ThreadId>()
                .is_err()
        );
    }

    #[test]
    fn rejects_multibyte_characters_of_matching_byte_length() {
        let s = format!("é{}", "0".repeat(HEX_DIGITS - 2));
        assert_eq!(s.len(), HEX_DIGITS);
        assert!(s.parse::<ThreadId>().is_err());
    }

    proptest! {
        #[test]
        fn display_then_parse_round_trips(bytes in any::<[u8; BYTES]>()) {
            let id = ThreadId::from_bytes(bytes);
            prop_assert_eq!(id.to_string().parse::<ThreadId>(), Ok(id));
        }

        #[test]
        fn parsing_arbitrary_strings_never_panics(s in ".*") {
            let _ = s.parse::<ThreadId>();
        }
    }
}
