use std::ops::Range;

use zeroize::Zeroize;

use super::cipher::{
    MAX_FRAME,
    Opener,
    PacketError,
};

pub(crate) const MAX_BUFFERED: usize = MAX_FRAME + (64 << 10);

#[derive(Debug, Default)]
pub(crate) struct Inbound {
    buffer: Vec<u8>,
    start: usize,
    frame: Option<usize>,
    failed: Option<PacketError>,
}

impl Inbound {
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), PacketError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.start > 0 {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        if self.buffer.len() + bytes.len() > MAX_BUFFERED {
            return Err(self.fail(PacketError::Overflow));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn room(&self) -> usize {
        if self.failed.is_some() {
            return 0;
        }
        MAX_BUFFERED - self.buffered().len()
    }

    pub(crate) fn buffered(&self) -> &[u8] {
        self.buffer.get(self.start..).unwrap_or_default()
    }

    pub(crate) fn consume(&mut self, count: usize) {
        self.start = self.start.saturating_add(count).min(self.buffer.len());
    }

    #[cfg(any(test, fuzzing, feature = "fuzzing"))]
    pub(crate) fn next(
        &mut self,
        opener: &mut Opener,
        sequence: u32,
    ) -> Result<Option<&[u8]>, PacketError> {
        let range = self.next_range(opener, sequence)?;
        Ok(range.map(|range| self.payload(range)))
    }

    pub(crate) fn next_range(
        &mut self,
        opener: &mut Opener,
        sequence: u32,
    ) -> Result<Option<Range<usize>>, PacketError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        self.open(opener, sequence)
            .map_err(|error| self.fail(error))
    }

    pub(crate) fn payload(&self, range: Range<usize>) -> &[u8] {
        self.buffer.get(range).unwrap_or_default()
    }

    fn open(
        &mut self,
        opener: &mut Opener,
        sequence: u32,
    ) -> Result<Option<Range<usize>>, PacketError> {
        let start = self.start;
        let length = if let Some(length) = self.frame {
            length
        } else {
            let Some(head) = self.buffered().first_chunk::<4>() else {
                return Ok(None);
            };
            let length = opener.frame_len(sequence, *head)?;
            self.frame = Some(length);
            length
        };
        let end = start + length;
        let Some(frame) = self.buffer.get_mut(start..end) else {
            return Ok(None);
        };
        let payload = opener.open(sequence, frame)?;
        self.start = end;
        self.frame = None;
        Ok(Some(start + payload.start..start + payload.end))
    }

    fn fail(&mut self, error: PacketError) -> PacketError {
        self.buffer.zeroize();
        self.buffer.clear();
        self.start = 0;
        self.frame = None;
        self.failed = Some(error);
        error
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::proto::cipher::{
        CipherName,
        Sealer,
    };

    #[test]
    fn a_bad_length_is_refused_before_the_rest_of_the_packet_arrives() {
        let mut inbound = Inbound::default();
        inbound.push(&[0x7f, 0xff, 0xff, 0xf8]).unwrap();
        assert_eq!(
            inbound.next(&mut Opener::clear(), 0),
            Err(PacketError::Length)
        );
    }

    #[test]
    fn after_a_failure_nothing_more_is_read_and_the_buffer_is_wiped() {
        let mut frame = Vec::new();
        let mut sealer = Sealer::new(CipherName::Aes128Gcm, &[1; 16], &[2; 12]).unwrap();
        sealer.seal(0, b"secret", &mut frame).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 1;
        let mut opener = Opener::new(CipherName::Aes128Gcm, &[1; 16], &[2; 12]).unwrap();
        let mut inbound = Inbound::default();
        inbound.push(&frame).unwrap();
        assert_eq!(
            inbound.next(&mut opener, 0),
            Err(PacketError::Authentication)
        );
        assert!(inbound.buffered().is_empty());
        assert!(inbound.buffer.iter().all(|&byte| byte == 0));
        assert_eq!(inbound.room(), 0);
        assert_eq!(
            inbound.next(&mut opener, 0),
            Err(PacketError::Authentication)
        );
        assert_eq!(inbound.push(b"more"), Err(PacketError::Authentication));
    }

    #[test]
    fn more_than_one_frame_and_a_read_is_never_buffered() {
        let mut inbound = Inbound::default();
        assert_eq!(inbound.room(), MAX_BUFFERED);
        inbound.push(&vec![0; MAX_BUFFERED - 1]).unwrap();
        assert_eq!(inbound.room(), 1);
        assert_eq!(inbound.push(&[0, 0]), Err(PacketError::Overflow));
        assert!(inbound.buffered().is_empty());
    }

    #[test]
    fn nothing_is_returned_until_a_whole_packet_is_buffered() {
        let mut frame = Vec::new();
        Sealer::clear().seal(0, b"hello", &mut frame).unwrap();
        let mut inbound = Inbound::default();
        let mut opener = Opener::clear();
        inbound.push(&frame[..3]).unwrap();
        assert_eq!(inbound.next(&mut opener, 0), Ok(None));
        inbound.push(&frame[3..frame.len() - 1]).unwrap();
        assert_eq!(inbound.next(&mut opener, 0), Ok(None));
        inbound.push(&frame[frame.len() - 1..]).unwrap();
        assert_eq!(inbound.next(&mut opener, 0), Ok(Some(&b"hello"[..])));
        assert_eq!(inbound.next(&mut opener, 1), Ok(None));
        assert!(inbound.buffered().is_empty());
    }

    #[test]
    fn opened_packets_are_freed_on_the_next_push() {
        let mut stream = Vec::new();
        let mut sealer = Sealer::clear();
        sealer.seal(0, b"one", &mut stream).unwrap();
        sealer.seal(1, b"two", &mut stream).unwrap();
        let mut inbound = Inbound::default();
        let mut opener = Opener::clear();
        inbound.push(&stream[..20]).unwrap();
        assert_eq!(inbound.next(&mut opener, 0), Ok(Some(&b"one"[..])));
        inbound.push(&stream[20..]).unwrap();
        assert_eq!(inbound.buffer.len(), stream.len() - 16);
        assert_eq!(inbound.next(&mut opener, 1), Ok(Some(&b"two"[..])));
        inbound.push(&[]).unwrap();
        assert!(inbound.buffer.is_empty());
    }

    #[test]
    fn bytes_before_the_first_packet_can_be_consumed() {
        let mut inbound = Inbound::default();
        inbound.push(b"SSH-2.0-x\r\n").unwrap();
        assert_eq!(inbound.buffered(), b"SSH-2.0-x\r\n");
        inbound.consume(4);
        assert_eq!(inbound.buffered(), b"2.0-x\r\n");
        inbound.consume(100);
        assert!(inbound.buffered().is_empty());
    }

    proptest! {
        #[test]
        fn packets_split_anywhere_come_out_whole_and_in_order(
            cipher in prop::sample::select(CipherName::ALL.to_vec()),
            payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..600), 1..6),
            cuts in proptest::collection::vec(1..97usize, 1..40),
        ) {
            let key = vec![9; cipher.key_len()];
            let iv = vec![3; cipher.iv_len()];
            let mut sealer = Sealer::new(cipher, &key, &iv).unwrap();
            let mut opener = Opener::new(cipher, &key, &iv).unwrap();
            let mut stream = Vec::new();
            for (sequence, payload) in payloads.iter().enumerate() {
                sealer.seal(u32::try_from(sequence).unwrap(), payload, &mut stream).unwrap();
            }
            let mut inbound = Inbound::default();
            let mut received = Vec::new();
            let mut sequence = 0u32;
            let mut rest = &stream[..];
            let mut cuts = cuts.iter().cycle();
            while !rest.is_empty() {
                let (piece, after) = rest.split_at((*cuts.next().unwrap()).min(rest.len()));
                rest = after;
                inbound.push(piece).unwrap();
                while let Some(payload) = inbound.next(&mut opener, sequence).unwrap() {
                    received.push(payload.to_vec());
                    sequence += 1;
                }
            }
            prop_assert_eq!(received, payloads);
            prop_assert!(inbound.buffered().is_empty());
        }
    }
}
