use std::ops::Range;

use aes_gcm::{
    AeadInPlace,
    Aes128Gcm,
    Aes256Gcm,
    KeyInit,
    Nonce,
    Tag,
};
use chacha20::{
    ChaCha20Legacy,
    cipher::{
        KeyIvInit,
        StreamCipher,
        StreamCipherSeek,
    },
};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{
    Zeroize,
    Zeroizing,
};

pub(crate) const MAX_PACKET_LENGTH: usize = 256 << 10;
pub(crate) const MAX_FRAME: usize = LENGTH_BYTES + MAX_PACKET_LENGTH + TAG_BYTES;
const LENGTH_BYTES: usize = 4;
const MIN_PADDING: usize = 4;
const TAG_BYTES: usize = 16;
const CHACHA_KEY_BYTES: usize = 32;
const GCM_IV_BYTES: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CipherName {
    ChaCha20Poly1305,
    Aes256Gcm,
    Aes128Gcm,
}

impl CipherName {
    pub(crate) const ALL: [Self; 3] = [Self::ChaCha20Poly1305, Self::Aes256Gcm, Self::Aes128Gcm];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305@openssh.com",
            Self::Aes256Gcm => "aes256-gcm@openssh.com",
            Self::Aes128Gcm => "aes128-gcm@openssh.com",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|cipher| cipher.name() == name)
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 2 * CHACHA_KEY_BYTES,
            Self::Aes256Gcm => 32,
            Self::Aes128Gcm => 16,
        }
    }

    pub(crate) fn iv_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 0,
            Self::Aes256Gcm | Self::Aes128Gcm => GCM_IV_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum PacketError {
    #[error("a packet's length is out of bounds or not a whole number of blocks")]
    Length,
    #[error("a packet's padding is out of bounds")]
    Padding,
    #[error("a packet failed authentication")]
    Authentication,
    #[error("a payload is too long to send")]
    TooLong,
    #[error("a key or nonce has the wrong length")]
    KeyLength,
    #[error("the server sent more than mahi buffers")]
    Overflow,
}

pub(crate) struct Opener(Keys);

pub(crate) struct Sealer(Keys);

enum Keys {
    Clear,
    ChaCha {
        main: Zeroizing<[u8; CHACHA_KEY_BYTES]>,
        header: Zeroizing<[u8; CHACHA_KEY_BYTES]>,
    },
    Aes256(Box<Aes256Gcm>, GcmNonce),
    Aes128(Box<Aes128Gcm>, GcmNonce),
}

struct GcmNonce {
    fixed: [u8; 4],
    invocation: u64,
}

impl GcmNonce {
    fn new(iv: &[u8]) -> Result<Self, PacketError> {
        let (fixed, invocation) = iv.split_first_chunk::<4>().ok_or(PacketError::KeyLength)?;
        let invocation: [u8; 8] = invocation.try_into().map_err(|_| PacketError::KeyLength)?;
        Ok(Self {
            fixed: *fixed,
            invocation: u64::from_be_bytes(invocation),
        })
    }

    fn next(&mut self) -> Nonce<aes_gcm::aead::consts::U12> {
        let mut nonce = Nonce::default();
        nonce[..4].copy_from_slice(&self.fixed);
        nonce[4..].copy_from_slice(&self.invocation.to_be_bytes());
        self.invocation = self.invocation.wrapping_add(1);
        nonce
    }
}

impl Keys {
    fn new(cipher: CipherName, key: &[u8], iv: &[u8]) -> Result<Self, PacketError> {
        if key.len() != cipher.key_len() || iv.len() != cipher.iv_len() {
            return Err(PacketError::KeyLength);
        }
        Ok(match cipher {
            CipherName::ChaCha20Poly1305 => {
                let (main_key, header_key) = key.split_at(CHACHA_KEY_BYTES);
                let mut main = Zeroizing::new([0; CHACHA_KEY_BYTES]);
                let mut header = Zeroizing::new([0; CHACHA_KEY_BYTES]);
                main.copy_from_slice(main_key);
                header.copy_from_slice(header_key);
                Self::ChaCha { main, header }
            }
            CipherName::Aes256Gcm => Self::Aes256(
                Box::new(Aes256Gcm::new_from_slice(key).map_err(|_| PacketError::KeyLength)?),
                GcmNonce::new(iv)?,
            ),
            CipherName::Aes128Gcm => Self::Aes128(
                Box::new(Aes128Gcm::new_from_slice(key).map_err(|_| PacketError::KeyLength)?),
                GcmNonce::new(iv)?,
            ),
        })
    }

    fn block_len(&self) -> usize {
        match self {
            Self::Clear | Self::ChaCha { .. } => 8,
            Self::Aes256(..) | Self::Aes128(..) => 16,
        }
    }

    fn tag_len(&self) -> usize {
        match self {
            Self::Clear => 0,
            _ => TAG_BYTES,
        }
    }

    fn aligned_bytes(&self) -> usize {
        match self {
            Self::Clear => LENGTH_BYTES,
            _ => 0,
        }
    }
}

fn chacha(key: &[u8; CHACHA_KEY_BYTES], sequence: u32) -> ChaCha20Legacy {
    let nonce = u64::from(sequence).to_be_bytes();
    ChaCha20Legacy::new(key.into(), &nonce.into())
}

fn poly1305(main: &[u8; CHACHA_KEY_BYTES], sequence: u32) -> Poly1305 {
    let mut key = Zeroizing::new([0; 32]);
    chacha(main, sequence).apply_keystream(&mut key[..]);
    Poly1305::new((&*key).into())
}

fn chacha_body(main: &[u8; CHACHA_KEY_BYTES], sequence: u32, body: &mut [u8]) {
    let mut cipher = chacha(main, sequence);
    cipher.seek(64u64);
    cipher.apply_keystream(body);
}

fn tag_of(tag: &[u8]) -> Result<Tag, PacketError> {
    let tag: [u8; TAG_BYTES] = tag.try_into().map_err(|_| PacketError::Length)?;
    Ok(tag.into())
}

impl Opener {
    pub(crate) fn clear() -> Self {
        Self(Keys::Clear)
    }

    pub(crate) fn new(cipher: CipherName, key: &[u8], iv: &[u8]) -> Result<Self, PacketError> {
        Keys::new(cipher, key, iv).map(Self)
    }

    pub(crate) fn frame_len(
        &self,
        sequence: u32,
        head: [u8; LENGTH_BYTES],
    ) -> Result<usize, PacketError> {
        let mut length = head;
        if let Keys::ChaCha { header: key, .. } = &self.0 {
            chacha(key, sequence).apply_keystream(&mut length);
        }
        let length =
            usize::try_from(u32::from_be_bytes(length)).map_err(|_| PacketError::Length)?;
        if !(1 + MIN_PADDING..=MAX_PACKET_LENGTH).contains(&length)
            || !(length + self.0.aligned_bytes()).is_multiple_of(self.0.block_len())
        {
            return Err(PacketError::Length);
        }
        Ok(LENGTH_BYTES + length + self.0.tag_len())
    }

    pub(crate) fn open(
        &mut self,
        sequence: u32,
        frame: &mut [u8],
    ) -> Result<Range<usize>, PacketError> {
        let head: [u8; LENGTH_BYTES] = *frame.first_chunk().ok_or(PacketError::Length)?;
        if frame.len() != self.frame_len(sequence, head)? {
            return Err(PacketError::Length);
        }
        let body_end = frame.len() - self.0.tag_len();
        let (sealed, tag) = frame.split_at_mut(body_end);
        match &mut self.0 {
            Keys::Clear => {}
            Keys::ChaCha { main, header } => {
                let expected = poly1305(main, sequence).compute_unpadded(sealed);
                if !bool::from(expected.as_slice().ct_eq(tag)) {
                    return Err(PacketError::Authentication);
                }
                let (head, body) = sealed.split_at_mut(LENGTH_BYTES);
                chacha(header, sequence).apply_keystream(head);
                chacha_body(main, sequence, body);
            }
            Keys::Aes256(cipher, nonce) => {
                let (head, body) = sealed.split_at_mut(LENGTH_BYTES);
                cipher
                    .decrypt_in_place_detached(&nonce.next(), head, body, &tag_of(tag)?)
                    .map_err(|_| PacketError::Authentication)?;
            }
            Keys::Aes128(cipher, nonce) => {
                let (head, body) = sealed.split_at_mut(LENGTH_BYTES);
                cipher
                    .decrypt_in_place_detached(&nonce.next(), head, body, &tag_of(tag)?)
                    .map_err(|_| PacketError::Authentication)?;
            }
        }
        let padding = usize::from(*sealed.get(LENGTH_BYTES).ok_or(PacketError::Padding)?);
        let payload_end = body_end
            .checked_sub(padding)
            .filter(|&end| padding >= MIN_PADDING && end > LENGTH_BYTES)
            .ok_or(PacketError::Padding)?;
        Ok(LENGTH_BYTES + 1..payload_end)
    }
}

impl Sealer {
    pub(crate) fn clear() -> Self {
        Self(Keys::Clear)
    }

    pub(crate) fn new(cipher: CipherName, key: &[u8], iv: &[u8]) -> Result<Self, PacketError> {
        Keys::new(cipher, key, iv).map(Self)
    }

    pub(crate) fn seal(
        &mut self,
        sequence: u32,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), PacketError> {
        if payload.len() > MAX_PACKET_LENGTH {
            return Err(PacketError::TooLong);
        }
        let block = self.0.block_len();
        let unpadded = self.0.aligned_bytes() + 1 + payload.len();
        let mut padding = block - unpadded % block;
        if padding < MIN_PADDING {
            padding += block;
        }
        let length = 1 + payload.len() + padding;
        if length > MAX_PACKET_LENGTH {
            return Err(PacketError::TooLong);
        }
        let length_field = u32::try_from(length).map_err(|_| PacketError::TooLong)?;
        let padding_field = u8::try_from(padding).map_err(|_| PacketError::TooLong)?;
        let start = out.len();
        out.reserve(LENGTH_BYTES + length + self.0.tag_len());
        out.extend_from_slice(&length_field.to_be_bytes());
        out.push(padding_field);
        out.extend_from_slice(payload);
        out.resize(start + LENGTH_BYTES + length, 0);
        match self.encrypt(sequence, out.get_mut(start..).unwrap_or_default()) {
            Ok(Some(tag)) => out.extend_from_slice(&tag),
            Ok(None) => {}
            Err(error) => {
                out.get_mut(start..).unwrap_or_default().zeroize();
                out.truncate(start);
                return Err(error);
            }
        }
        Ok(())
    }

    fn encrypt(
        &mut self,
        sequence: u32,
        frame: &mut [u8],
    ) -> Result<Option<[u8; TAG_BYTES]>, PacketError> {
        let (head, body) = frame.split_at_mut(LENGTH_BYTES);
        Ok(Some(match &mut self.0 {
            Keys::Clear => return Ok(None),
            Keys::ChaCha { main, header } => {
                chacha(header, sequence).apply_keystream(head);
                chacha_body(main, sequence, body);
                poly1305(main, sequence).compute_unpadded(frame).into()
            }
            Keys::Aes256(cipher, nonce) => cipher
                .encrypt_in_place_detached(&nonce.next(), head, body)
                .map_err(|_| PacketError::TooLong)?
                .into(),
            Keys::Aes128(cipher, nonce) => cipher
                .encrypt_in_place_detached(&nonce.next(), head, body)
                .map_err(|_| PacketError::TooLong)?
                .into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn payload_of(length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| u8::try_from((i * 7 + 3) % 256).unwrap())
            .collect()
    }

    fn sealed(sealer: &mut Sealer, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        sealer.seal(sequence, payload, &mut out).unwrap();
        out
    }

    fn opened(opener: &mut Opener, sequence: u32, frame: &[u8]) -> Result<Vec<u8>, PacketError> {
        let mut frame = frame.to_vec();
        let head = *frame.first_chunk().unwrap();
        assert_eq!(opener.frame_len(sequence, head)?, frame.len());
        let range = opener.open(sequence, &mut frame)?;
        Ok(frame[range].to_vec())
    }

    fn pair(cipher: CipherName, key: &[u8], iv: &[u8]) -> (Sealer, Opener) {
        (
            Sealer::new(cipher, key, iv).unwrap(),
            Opener::new(cipher, key, iv).unwrap(),
        )
    }

    #[test]
    fn chacha20_poly1305_matches_openssl_for_openssh_construction() {
        let key: Vec<u8> = (0..64).collect();
        let (mut sealer, mut opener) = pair(CipherName::ChaCha20Poly1305, &key, &[]);
        for (sequence, length, expected) in [
            (
                0,
                1,
                "94450e511ebb4231ade6a6d175950768cd2a23cef2c8ada5ecfb515a",
            ),
            (
                7,
                13,
                "a39afcb222451f52569c0c735856f9b987d8d32c34b230367ee33d83d9c68e49fce1954f32e83b988a298217",
            ),
            (
                u32::MAX,
                100,
                "b90ee4c00291068ab61bf2cfa20de9fb22d15ccb7ac9439747a04de5f68f54f9ee20d8ee1cb9337c03aa4bb5f65b00db2628cfddce8207f30a28492197842df2c5f9f60fe7d36cc17b8147632f1f1e01bd700d3f9321f16aae2342fcbfe755f16ec28f3da7a0051d46c4a336f04a4960e4164f0bdcc1d2d21e6f888358abb3bd807f7e20",
            ),
        ] {
            let frame = sealed(&mut sealer, sequence, &payload_of(length));
            assert_eq!(frame, hex(expected), "sequence {sequence}");
            assert_eq!(
                opened(&mut opener, sequence, &frame),
                Ok(payload_of(length))
            );
        }
    }

    #[test]
    fn aes_gcm_matches_openssl_and_its_invocation_counter_wraps() {
        let iv = hex("01020304fffffffffffffffe");
        for (cipher, key, expected) in [
            (
                CipherName::Aes128Gcm,
                hex("6465666768696a6b6c6d6e6f70717273"),
                [
                    "00000010c9b358bb14070a53d444d6ebaa35c8686e779a9f95b7653cd910d19dca050444",
                    "0000003035fd15edc3ad8a6470b0f5abe380dd07c821237bad9acd1c90d649a0f4bac38e8c0891b370dd59c14b127f75b8ae071b722b985d2e48cea9a03d45a4a447cd4d",
                    "00000050a656fce860d99fa74256c3b505c0cc7fed347e470f6fe4f82731041b513973f3bb2217070662d1662f82a7cb51825410cfd51d4fd866d2f23790171ad65c8da328b7cba63b2a36f3423cacaeb8bc53bcb4047bf5ada500329fb1d2439eca7ea5",
                ],
            ),
            (
                CipherName::Aes256Gcm,
                hex("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283"),
                [
                    "000000108aad9c7527349ba50b50fffc8fe8f5d3ce449ddfaa6ae3436793464cce8d5343",
                    "0000003044f0f0266c27bfe009fb703c1a138600ce123db3c87350e92bc62e6e583b54f192049e344a20df06f3b5bf1a57e56b6722cd8d51b60086dba337a538e83b805b",
                    "0000005081dd2b47a79675df3a38fe54af7f6cc1eacd39b0dda924ffe4f8185acb61ecb4116936eefdca9353521d2540a4a45dca44c078909dbe809dec61cd4b6611401787728fae0a03c49fc6a25f9c7cc30de11121d8a5deb12c551229358db2258fc4",
                ],
            ),
        ] {
            let (mut sealer, mut opener) = pair(cipher, &key, &iv);
            for (sequence, (length, expected)) in [1, 30, 64].into_iter().zip(expected).enumerate()
            {
                let sequence = u32::try_from(sequence).unwrap();
                let frame = sealed(&mut sealer, sequence, &payload_of(length));
                assert_eq!(frame, hex(expected), "{cipher:?} packet {sequence}");
                assert_eq!(
                    opened(&mut opener, sequence, &frame),
                    Ok(payload_of(length))
                );
            }
        }
    }

    #[test]
    fn clear_packets_align_the_length_field_too() {
        let mut out = Vec::new();
        Sealer::clear().seal(0, b"\x15", &mut out).unwrap();
        assert_eq!(out, [0, 0, 0, 12, 10, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(opened(&mut Opener::clear(), 0, &out), Ok(vec![0x15]));
    }

    #[test]
    fn lengths_out_of_bounds_or_off_the_block_size_are_refused() {
        let clear = Opener::clear();
        assert_eq!(clear.frame_len(0, 12u32.to_be_bytes()), Ok(16));
        for bad in [0u32, 4, 11, 13, 1 << 18 | 4, u32::MAX] {
            assert_eq!(
                clear.frame_len(0, bad.to_be_bytes()),
                Err(PacketError::Length),
                "{bad}"
            );
        }
        let largest = u32::try_from(MAX_PACKET_LENGTH).unwrap() - 4;
        assert_eq!(
            clear.frame_len(0, largest.to_be_bytes()),
            Ok(MAX_PACKET_LENGTH + 4 - 4)
        );
        let gcm = Opener::new(CipherName::Aes128Gcm, &[0; 16], &[0; 12]).unwrap();
        assert_eq!(gcm.frame_len(0, 16u32.to_be_bytes()), Ok(36));
        assert_eq!(
            gcm.frame_len(0, 8u32.to_be_bytes()),
            Err(PacketError::Length)
        );
        assert_eq!(
            gcm.frame_len(0, 24u32.to_be_bytes()),
            Err(PacketError::Length)
        );
        let max = u32::try_from(MAX_PACKET_LENGTH).unwrap();
        assert_eq!(
            gcm.frame_len(0, max.to_be_bytes()),
            Ok(MAX_PACKET_LENGTH + 20)
        );
        assert_eq!(
            gcm.frame_len(0, (max + 16).to_be_bytes()),
            Err(PacketError::Length)
        );
    }

    #[test]
    fn padding_shorter_than_four_or_longer_than_the_body_is_refused() {
        for (padding, expected) in [
            (3, Err(PacketError::Padding)),
            (4, Ok(vec![1, 1, 1, 1, 1, 1, 0])),
            (10, Ok(vec![1])),
            (11, Ok(vec![])),
            (12, Err(PacketError::Padding)),
            (255, Err(PacketError::Padding)),
        ] {
            let mut frame = vec![0, 0, 0, 12, padding];
            frame.extend_from_slice(&[1; 6]);
            frame.resize(16, 0);
            assert_eq!(
                opened(&mut Opener::clear(), 0, &frame),
                expected,
                "padding {padding}"
            );
        }
    }

    #[test]
    fn padding_is_the_fewest_bytes_from_four_that_fill_the_block() {
        for (cipher, payload, frame) in [
            (None, 7, 16),
            (None, 3, 16),
            (None, 2, 16),
            (Some(CipherName::ChaCha20Poly1305), 3, 28),
            (Some(CipherName::ChaCha20Poly1305), 4, 36),
            (Some(CipherName::Aes128Gcm), 11, 36),
            (Some(CipherName::Aes128Gcm), 12, 52),
        ] {
            let mut sealer = cipher.map_or_else(Sealer::clear, |cipher| {
                Sealer::new(
                    cipher,
                    &vec![0; cipher.key_len()],
                    &vec![0; cipher.iv_len()],
                )
                .unwrap()
            });
            assert_eq!(
                sealed(&mut sealer, 0, &vec![0; payload]).len(),
                frame,
                "{cipher:?} {payload}"
            );
        }
    }

    #[test]
    fn a_packet_of_exactly_the_largest_length_is_sealed_and_opened() {
        let (mut sealer, mut opener) = pair(CipherName::Aes256Gcm, &[5; 32], &[6; 12]);
        let payload = vec![1; MAX_PACKET_LENGTH - 5];
        let frame = sealed(&mut sealer, 0, &payload);
        assert_eq!(frame.len(), 4 + MAX_PACKET_LENGTH + 16);
        assert_eq!(opened(&mut opener, 0, &frame), Ok(payload));
    }

    #[test]
    fn a_payload_too_long_for_one_packet_is_refused() {
        let mut sealer = Sealer::new(CipherName::Aes256Gcm, &[0; 32], &[0; 12]).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            sealer.seal(0, &vec![0; MAX_PACKET_LENGTH], &mut out),
            Err(PacketError::TooLong)
        );
        assert!(
            sealer
                .seal(0, &vec![0; MAX_PACKET_LENGTH - 32], &mut out)
                .is_ok()
        );
    }

    #[test]
    fn keys_and_nonces_of_the_wrong_length_are_refused() {
        for cipher in CipherName::ALL {
            let key = vec![0; cipher.key_len()];
            let iv = vec![0; cipher.iv_len()];
            assert!(Opener::new(cipher, &key, &iv).is_ok());
            assert_eq!(
                Opener::new(cipher, &key[1..], &iv).err(),
                Some(PacketError::KeyLength)
            );
            assert_eq!(
                Sealer::new(cipher, &key, &[0; 13]).err(),
                Some(PacketError::KeyLength)
            );
            assert_eq!(CipherName::from_name(cipher.name()), Some(cipher));
        }
        assert_eq!(CipherName::from_name("aes256-ctr"), None);
    }

    fn cipher() -> impl Strategy<Value = CipherName> {
        prop::sample::select(CipherName::ALL.to_vec())
    }

    fn keyed() -> impl Strategy<Value = (CipherName, Vec<u8>, Vec<u8>)> {
        cipher().prop_flat_map(|cipher| {
            (
                Just(cipher),
                proptest::collection::vec(any::<u8>(), cipher.key_len()),
                proptest::collection::vec(any::<u8>(), cipher.iv_len()),
            )
        })
    }

    proptest! {
        #[test]
        fn opening_a_sealed_packet_gives_the_payload_back(
            (cipher, key, iv) in keyed(),
            sequence in any::<u32>(),
            payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..1200), 1..4),
        ) {
            let (mut sealer, mut opener) = pair(cipher, &key, &iv);
            for (offset, payload) in payloads.iter().enumerate() {
                let sequence = sequence.wrapping_add(u32::try_from(offset).unwrap());
                let frame = sealed(&mut sealer, sequence, payload);
                prop_assert_eq!(frame.len() % 8, 4);
                prop_assert_eq!(opened(&mut opener, sequence, &frame).unwrap(), payload.clone());
            }
        }

        #[test]
        fn any_changed_bit_is_refused(
            (cipher, key, iv) in keyed(),
            sequence in any::<u32>(),
            payload in proptest::collection::vec(any::<u8>(), 0..300),
            bit in any::<prop::sample::Index>(),
        ) {
            let (mut sealer, mut opener) = pair(cipher, &key, &iv);
            let mut frame = sealed(&mut sealer, sequence, &payload);
            let bit = bit.index(frame.len() * 8);
            frame[bit / 8] ^= 1 << (bit % 8);
            let outcome = opener.open(sequence, &mut frame);
            if bit < 32 {
                prop_assert!(outcome.is_err());
            } else {
                prop_assert_eq!(outcome, Err(PacketError::Authentication));
            }
        }

        #[test]
        fn a_wrong_sequence_number_is_refused(
            key in proptest::collection::vec(any::<u8>(), 64),
            sequence in any::<u32>(),
            other in any::<u32>(),
            payload in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            prop_assume!(sequence != other);
            let (mut sealer, mut opener) = pair(CipherName::ChaCha20Poly1305, &key, &[]);
            let mut frame = sealed(&mut sealer, sequence, &payload);
            prop_assert!(opener.open(other, &mut frame.clone()).is_err());
            let header: [u8; 32] = key[32..].try_into().unwrap();
            let mut length = [0; 4];
            chacha(&header, sequence).apply_keystream(&mut length);
            for (byte, stream) in frame.iter_mut().zip(length) {
                *byte ^= stream;
            }
            chacha(&header, other).apply_keystream(&mut frame[..4]);
            prop_assert_eq!(opener.frame_len(other, *frame.first_chunk().unwrap()), Ok(frame.len()));
            prop_assert_eq!(opener.open(other, &mut frame), Err(PacketError::Authentication));
        }

        #[test]
        fn a_replayed_gcm_packet_is_refused(
            key in proptest::collection::vec(any::<u8>(), 32),
            iv in proptest::collection::vec(any::<u8>(), 12),
            payload in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let (mut sealer, mut opener) = pair(CipherName::Aes256Gcm, &key, &iv);
            let frame = sealed(&mut sealer, 0, &payload);
            prop_assert!(opened(&mut opener, 0, &frame).is_ok());
            prop_assert_eq!(opened(&mut opener, 1, &frame), Err(PacketError::Authentication));
        }

        #[test]
        fn a_frame_cut_short_or_grown_is_refused(
            (cipher, key, iv) in keyed(),
            payload in proptest::collection::vec(any::<u8>(), 0..300),
            change in 1..20usize,
            grow in any::<bool>(),
        ) {
            let (mut sealer, mut opener) = pair(cipher, &key, &iv);
            let mut frame = sealed(&mut sealer, 0, &payload);
            if grow {
                frame.resize(frame.len() + change, 0);
            } else {
                frame.truncate(frame.len() - change);
            }
            prop_assert_eq!(opener.open(0, &mut frame), Err(PacketError::Length));
        }

        #[test]
        fn opening_any_bytes_never_panics(
            (cipher, key, iv) in keyed(),
            frame in proptest::collection::vec(any::<u8>(), 0..200),
            sequence in any::<u32>(),
        ) {
            let mut opener = Opener::new(cipher, &key, &iv).unwrap();
            let mut frame = frame;
            let _ = opener.open(sequence, &mut frame);
            let mut clear = Opener::clear();
            let _ = clear.open(sequence, &mut frame);
        }
    }
}
