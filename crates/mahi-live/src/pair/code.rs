use std::{
    fmt::{
        self,
        Write as _,
    },
    str::FromStr,
};

use thiserror::Error;
use zeroize::{
    Zeroize,
    Zeroizing,
};

use super::words::{
    EVEN,
    ODD,
};

/// The highest slot a code names.
pub const MAX_SLOT: u16 = 999;
const MAX_CODE_BYTES: usize = 64;
const LONGEST_CODE_BYTES: usize = 3 + 1 + 11 + 1 + 11;

/// A pairing code, such as `412-merit-intention`: a slot, which says where the owner waits and
/// is not secret, and two words, the first from the PGP word list's even list and the second
/// from its odd list, which are the 16 bits of secret both sides prove they know.
///
/// It is never shown in `Debug` output, is zeroed when dropped, and cannot be compared with
/// `==`, since its words are a secret.
pub struct PairingCode {
    slot: u16,
    even: u8,
    odd: u8,
}

/// A text is not a pairing code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CodeError {
    /// It is not a number from 1 to 999 and two words joined by hyphens.
    #[error("a pairing code is a number from 1 to 999 and two words, such as 412-merit-intention")]
    Form,
    /// A word is not in its place's word list.
    #[error("a word of the pairing code is not one mahi uses; check its spelling")]
    Word,
    /// The system gave no random bytes.
    #[error("cannot draw a random pairing code")]
    Random,
}

impl PairingCode {
    /// Draws a fresh code for `slot`, with random words.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::Form`] for a slot outside 1 to 999, or [`CodeError::Random`] when
    /// the system gives no random bytes.
    pub fn random(slot: u16) -> Result<Self, CodeError> {
        if !(1..=MAX_SLOT).contains(&slot) {
            return Err(CodeError::Form);
        }
        let mut words = [0_u8; 2];
        getrandom::fill(&mut words).map_err(|_| CodeError::Random)?;
        let [even, odd] = words;
        Ok(Self { slot, even, odd })
    }

    /// Returns the slot, which says where the owner waits.
    #[must_use]
    pub fn slot(&self) -> u16 {
        self.slot
    }

    /// Returns the whole code as both sides use it for the key exchange: lowercase, with
    /// single hyphens.
    #[must_use]
    pub fn password(&self) -> Zeroizing<String> {
        let mut password = Zeroizing::new(String::with_capacity(LONGEST_CODE_BYTES));
        let _ = write!(password, "{self}");
        password
    }
}

impl Drop for PairingCode {
    fn drop(&mut self) {
        self.even.zeroize();
        self.odd.zeroize();
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PairingCode({}-..)", self.slot)
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}-{}",
            self.slot,
            EVEN[usize::from(self.even)],
            ODD[usize::from(self.odd)]
        )
    }
}

impl FromStr for PairingCode {
    type Err = CodeError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        if text.len() > MAX_CODE_BYTES {
            return Err(CodeError::Form);
        }
        let mut plain = Zeroizing::new(String::with_capacity(MAX_CODE_BYTES));
        for c in text.chars() {
            plain.push(if matches!(c, '\u{2010}'..='\u{2015}' | '\u{2212}') {
                '-'
            } else {
                c
            });
        }
        if !plain.is_ascii() {
            return Err(CodeError::Form);
        }
        let mut parts = plain.split('-');
        let (Some(slot), Some(even), Some(odd), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CodeError::Form);
        };
        if even.is_empty() || odd.is_empty() {
            return Err(CodeError::Form);
        }
        let digits = !slot.is_empty()
            && slot.len() <= 3
            && !slot.starts_with('0')
            && slot.bytes().all(|b| b.is_ascii_digit());
        let slot = digits
            .then(|| slot.parse::<u16>().ok())
            .flatten()
            .filter(|slot| (1..=MAX_SLOT).contains(slot))
            .ok_or(CodeError::Form)?;
        let find = |list: &[&str; 256], word: &str| {
            list.iter()
                .position(|known| known.eq_ignore_ascii_case(word))
                .and_then(|index| u8::try_from(index).ok())
        };
        let even = find(&EVEN, even).ok_or(CodeError::Word)?;
        let odd = find(&ODD, odd).ok_or(CodeError::Word)?;
        Ok(Self { slot, even, odd })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_reads_back_as_written_whatever_the_case_and_spaces() {
        let code: PairingCode = " 412-Aardvark-ADROITNESS\n".parse().unwrap();
        assert_eq!(code.slot(), 412);
        assert_eq!(code.to_string(), "412-aardvark-adroitness");
        assert_eq!(*code.password(), "412-aardvark-adroitness");
        assert_eq!(
            code.to_string().parse::<PairingCode>().unwrap().to_string(),
            code.to_string()
        );
        let dashed: PairingCode = "412\u{2013}aardvark\u{2014}adroitness".parse().unwrap();
        assert_eq!(dashed.to_string(), "412-aardvark-adroitness");
        let last: PairingCode = "999-zulu-yucatan".parse().unwrap();
        assert_eq!(last.slot(), MAX_SLOT);
    }

    #[test]
    fn malformed_codes_and_unknown_or_misplaced_words_are_refused() {
        for text in [
            "",
            "0-aardvark-adroitness",
            "1000-aardvark-adroitness",
            "0412-aardvark-adroitness",
            "012-aardvark-adroitness",
            "001-aardvark-adroitness",
            "+12-aardvark-adroitness",
            "412-aardvark",
            "412-aardvark-adroitness-extra",
            "412--adroitness",
            "412 aardvark adroitness",
            "412-aardvärk-adroitness",
        ] {
            assert_eq!(
                text.parse::<PairingCode>().err(),
                Some(CodeError::Form),
                "{text:?}"
            );
        }
        for text in ["412-adroitness-aardvark", "412-crater-nonsense"] {
            assert_eq!(
                text.parse::<PairingCode>().err(),
                Some(CodeError::Word),
                "{text:?}"
            );
        }
        let long = format!("1-{}-adroitness", "a".repeat(100));
        assert_eq!(long.parse::<PairingCode>().err(), Some(CodeError::Form));
        let example: Result<PairingCode, _> = "412-merit-intention".parse();
        assert!(example.is_ok());
    }

    #[test]
    fn random_codes_use_their_slot_and_vary() {
        let codes: Vec<PairingCode> = (0..16).map(|_| PairingCode::random(7).unwrap()).collect();
        assert!(codes.iter().all(|code| code.slot() == 7));
        assert!(
            codes
                .iter()
                .any(|code| code.to_string() != codes[0].to_string())
        );
        assert_eq!(PairingCode::random(0).err(), Some(CodeError::Form));
        assert_eq!(PairingCode::random(1000).err(), Some(CodeError::Form));
    }

    #[test]
    fn debug_output_hides_the_words() {
        let code: PairingCode = "412-aardvark-adroitness".parse().unwrap();
        let shown = format!("{code:?}");
        assert_eq!(shown, "PairingCode(412-..)");
    }
}
