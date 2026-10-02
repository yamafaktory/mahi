//! The messages between a mahi hosting a thread's live layer and the user's other mahis in the
//! thread, over a Unix socket only the user can reach: each frame is a 4-byte big-endian
//! length, then a kind byte and the message.

use std::io::{
    self,
    Read,
    Write,
};

use mahi_core::{
    AgentSlot,
    ParticipantName,
};
use thiserror::Error;

use crate::frame::{
    MAX_COLUMNS,
    MAX_ROWS,
    PROMPT_ID_BYTES,
    PromptOutcome,
    PromptText,
};

/// The largest frame either side sends or reads, room for a whole screen.
pub const MAX_LOCAL_FRAME_BYTES: usize = 4 << 20;
const MAX_NAME_BYTES: usize = 255;

const HELLO: u8 = 1;
const SCREEN: u8 = 2;
const OUTPUT: u8 = 3;
const RESIZE: u8 = 4;
const ANSWER: u8 = 5;
const WELCOME: u8 = 6;
const OFFER: u8 = 7;

/// A message between the host of a thread's live layer and another mahi of the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalMessage {
    /// A mahi asks the host to serve its agent `slot`, whose screen is `screen`.
    Hello {
        /// The agent.
        slot: AgentSlot,
        /// Its screen's height in rows.
        rows: u16,
        /// Its screen's width in columns.
        columns: u16,
        /// The escape sequences that draw its screen.
        screen: Vec<u8>,
    },
    /// The agent's whole screen again, after the mahi dropped output.
    Screen {
        /// Its screen's height in rows.
        rows: u16,
        /// Its screen's width in columns.
        columns: u16,
        /// The escape sequences that draw its screen.
        screen: Vec<u8>,
    },
    /// The agent's terminal output.
    Output(Vec<u8>),
    /// The agent's terminal changed size.
    Resize {
        /// Its height in rows.
        rows: u16,
        /// Its width in columns.
        columns: u16,
    },
    /// What became of a prompt the host passed on.
    Answer {
        /// The prompt.
        id: [u8; PROMPT_ID_BYTES],
        /// What became of it.
        outcome: PromptOutcome,
    },
    /// The host serves the agent.
    Welcome,
    /// A prompt a teammate sent the agent.
    Offer {
        /// The teammate.
        from: ParticipantName,
        /// The prompt's id.
        id: [u8; PROMPT_ID_BYTES],
        /// Its text.
        text: PromptText,
    },
}

/// A frame that cannot be read as a [`LocalMessage`].
#[derive(Debug, Error)]
pub enum LocalError {
    /// Reading or writing the socket failed.
    #[error("the local live connection failed")]
    Io(#[from] io::Error),
    /// The frame is larger than [`MAX_LOCAL_FRAME_BYTES`].
    #[error("a local live message is too large")]
    TooLarge,
    /// The frame does not hold a message.
    #[error("a local live message is malformed")]
    Malformed,
}

impl LocalMessage {
    /// Encodes the message as one frame, appended to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`LocalError::TooLarge`] if it does not fit in a frame, or
    /// [`LocalError::Malformed`] if a size is out of bounds.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), LocalError> {
        let start = out.len();
        let encoded = self.encode_frame(out, start);
        if encoded.is_err() {
            out.truncate(start);
        }
        encoded
    }

    fn encode_frame(&self, out: &mut Vec<u8>, start: usize) -> Result<(), LocalError> {
        out.extend_from_slice(&[0; 4]);
        match self {
            Self::Hello {
                slot,
                rows,
                columns,
                screen,
            } => {
                out.push(HELLO);
                put_name(out, &slot.to_string())?;
                put_size(out, *rows, *columns)?;
                out.extend_from_slice(screen);
            }
            Self::Screen {
                rows,
                columns,
                screen,
            } => {
                out.push(SCREEN);
                put_size(out, *rows, *columns)?;
                out.extend_from_slice(screen);
            }
            Self::Output(bytes) => {
                out.push(OUTPUT);
                out.extend_from_slice(bytes);
            }
            Self::Resize { rows, columns } => {
                out.push(RESIZE);
                put_size(out, *rows, *columns)?;
            }
            Self::Answer { id, outcome } => {
                out.push(ANSWER);
                out.extend_from_slice(id);
                out.push(outcome.code());
            }
            Self::Welcome => out.push(WELCOME),
            Self::Offer { from, id, text } => {
                out.push(OFFER);
                put_name(out, from.as_str())?;
                out.extend_from_slice(id);
                out.extend_from_slice(text.as_str().as_bytes());
            }
        }
        let length = out.len() - start - 4;
        if length > MAX_LOCAL_FRAME_BYTES {
            return Err(LocalError::TooLarge);
        }
        let length = u32::try_from(length).map_err(|_| LocalError::TooLarge)?;
        if let Some(prefix) = out.get_mut(start..start + 4) {
            prefix.copy_from_slice(&length.to_be_bytes());
        }
        Ok(())
    }

    /// Decodes a frame's body, without its length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`LocalError::Malformed`] if it does not hold a message.
    pub fn decode(body: &[u8]) -> Result<Self, LocalError> {
        let (&kind, rest) = body.split_first().ok_or(LocalError::Malformed)?;
        let mut reader = Reader(rest);
        let message = match kind {
            HELLO => {
                let slot = reader.name()?.parse().map_err(|_| LocalError::Malformed)?;
                let (rows, columns) = reader.size()?;
                Self::Hello {
                    slot,
                    rows,
                    columns,
                    screen: reader.rest().to_vec(),
                }
            }
            SCREEN => {
                let (rows, columns) = reader.size()?;
                Self::Screen {
                    rows,
                    columns,
                    screen: reader.rest().to_vec(),
                }
            }
            OUTPUT => Self::Output(reader.rest().to_vec()),
            RESIZE => {
                let (rows, columns) = reader.size()?;
                Self::Resize { rows, columns }
            }
            ANSWER => {
                let id = reader.id()?;
                let outcome =
                    PromptOutcome::from_code(reader.byte()?).ok_or(LocalError::Malformed)?;
                Self::Answer { id, outcome }
            }
            WELCOME => Self::Welcome,
            OFFER => {
                let from =
                    ParticipantName::new(reader.name()?).map_err(|_| LocalError::Malformed)?;
                let id = reader.id()?;
                let text = std::str::from_utf8(reader.rest()).map_err(|_| LocalError::Malformed)?;
                let text = PromptText::new(text.to_owned()).map_err(|_| LocalError::Malformed)?;
                Self::Offer { from, id, text }
            }
            _ => return Err(LocalError::Malformed),
        };
        reader.finish()?;
        Ok(message)
    }

    /// Writes the message as one frame.
    ///
    /// # Errors
    ///
    /// Returns [`LocalError`] if it cannot be encoded or written.
    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), LocalError> {
        let mut frame = Vec::new();
        self.encode(&mut frame)?;
        writer.write_all(&frame)?;
        Ok(())
    }

    /// Reads one frame and decodes it.
    ///
    /// # Errors
    ///
    /// Returns [`LocalError`] if the frame cannot be read, is too large, or does not hold a
    /// message.
    pub fn read_from(reader: &mut impl Read) -> Result<Self, LocalError> {
        let mut length = [0; 4];
        reader.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_LOCAL_FRAME_BYTES {
            return Err(LocalError::TooLarge);
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        Self::decode(&body)
    }
}

fn put_name(out: &mut Vec<u8>, name: &str) -> Result<(), LocalError> {
    let length = u8::try_from(name.len()).map_err(|_| LocalError::Malformed)?;
    out.push(length);
    out.extend_from_slice(name.as_bytes());
    Ok(())
}

fn put_size(out: &mut Vec<u8>, rows: u16, columns: u16) -> Result<(), LocalError> {
    if !valid_size(rows, columns) {
        return Err(LocalError::Malformed);
    }
    out.extend_from_slice(&rows.to_be_bytes());
    out.extend_from_slice(&columns.to_be_bytes());
    Ok(())
}

fn valid_size(rows: u16, columns: u16) -> bool {
    (1..=MAX_ROWS).contains(&rows) && (1..=MAX_COLUMNS).contains(&columns)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], LocalError> {
        let (taken, rest) = self
            .0
            .split_at_checked(count)
            .ok_or(LocalError::Malformed)?;
        self.0 = rest;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8, LocalError> {
        Ok(*self.take(1)?.first().ok_or(LocalError::Malformed)?)
    }

    fn name(&mut self) -> Result<&'a str, LocalError> {
        let length = usize::from(self.byte()?);
        if length > MAX_NAME_BYTES {
            return Err(LocalError::Malformed);
        }
        std::str::from_utf8(self.take(length)?).map_err(|_| LocalError::Malformed)
    }

    fn size(&mut self) -> Result<(u16, u16), LocalError> {
        let rows = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| LocalError::Malformed)?,
        );
        let columns = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| LocalError::Malformed)?,
        );
        if !valid_size(rows, columns) {
            return Err(LocalError::Malformed);
        }
        Ok((rows, columns))
    }

    fn id(&mut self) -> Result<[u8; PROMPT_ID_BYTES], LocalError> {
        self.take(PROMPT_ID_BYTES)?
            .try_into()
            .map_err(|_| LocalError::Malformed)
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }

    fn finish(&self) -> Result<(), LocalError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(LocalError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use mahi_core::AgentName;
    use proptest::prelude::*;

    use super::*;

    fn slot() -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("codex").unwrap(),
        )
    }

    fn round_trip(message: &LocalMessage) -> LocalMessage {
        let mut frame = Vec::new();
        message.encode(&mut frame).unwrap();
        LocalMessage::read_from(&mut frame.as_slice()).unwrap()
    }

    #[test]
    fn every_message_reads_back_as_written() {
        for message in [
            LocalMessage::Hello {
                slot: slot(),
                rows: 24,
                columns: 80,
                screen: b"\x1b[Hhello".to_vec(),
            },
            LocalMessage::Screen {
                rows: 1,
                columns: 1,
                screen: Vec::new(),
            },
            LocalMessage::Output(b"out\x00put".to_vec()),
            LocalMessage::Resize {
                rows: MAX_ROWS,
                columns: MAX_COLUMNS,
            },
            LocalMessage::Answer {
                id: [7; PROMPT_ID_BYTES],
                outcome: PromptOutcome::Rejected,
            },
            LocalMessage::Welcome,
            LocalMessage::Offer {
                from: ParticipantName::new("bob").unwrap(),
                id: [9; PROMPT_ID_BYTES],
                text: PromptText::new("fix the tests\nplease".to_owned()).unwrap(),
            },
        ] {
            assert_eq!(round_trip(&message), message);
        }
    }

    #[test]
    fn sizes_out_of_bounds_are_refused_both_ways() {
        let mut frame = Vec::new();
        for (rows, columns) in [(0, 80), (24, 0), (MAX_ROWS + 1, 80), (24, MAX_COLUMNS + 1)] {
            assert!(matches!(
                LocalMessage::Resize { rows, columns }.encode(&mut frame),
                Err(LocalError::Malformed)
            ));
            let mut body = vec![RESIZE];
            body.extend_from_slice(&rows.to_be_bytes());
            body.extend_from_slice(&columns.to_be_bytes());
            assert!(LocalMessage::decode(&body).is_err());
        }
        assert!(frame.is_empty());
    }

    #[test]
    fn a_frame_larger_than_4_mib_is_refused_before_reading_it() {
        let mut header = u32::try_from(MAX_LOCAL_FRAME_BYTES + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        header.push(OUTPUT);
        assert!(matches!(
            LocalMessage::read_from(&mut header.as_slice()),
            Err(LocalError::TooLarge)
        ));
        let mut frame = Vec::new();
        assert!(matches!(
            LocalMessage::Output(vec![0; MAX_LOCAL_FRAME_BYTES]).encode(&mut frame),
            Err(LocalError::TooLarge)
        ));
        assert!(frame.is_empty());
    }

    #[test]
    fn bad_names_outcomes_kinds_and_leftovers_are_refused() {
        let mut offer = vec![OFFER, 3];
        offer.extend_from_slice(b"Bob");
        offer.extend_from_slice(&[0; PROMPT_ID_BYTES]);
        offer.extend_from_slice(b"hi");
        assert!(LocalMessage::decode(&offer).is_err());
        let mut answer = vec![ANSWER];
        answer.extend_from_slice(&[0; PROMPT_ID_BYTES]);
        answer.push(9);
        assert!(LocalMessage::decode(&answer).is_err());
        answer.pop();
        answer.push(1);
        assert!(LocalMessage::decode(&answer).is_ok());
        answer.push(0);
        assert!(LocalMessage::decode(&answer).is_err());
        assert!(LocalMessage::decode(&[WELCOME, 0]).is_err());
        assert!(LocalMessage::decode(&[200]).is_err());
        assert!(LocalMessage::decode(&[]).is_err());
        let mut hello = vec![HELLO, 5];
        hello.extend_from_slice(b"alice");
        hello.extend_from_slice(&[0, 24, 0, 80]);
        assert!(LocalMessage::decode(&hello).is_err());
    }

    proptest! {
        #[test]
        fn decoding_any_bytes_never_panics(body in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = LocalMessage::decode(&body);
        }
    }
}
