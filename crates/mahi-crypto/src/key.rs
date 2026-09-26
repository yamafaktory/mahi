use std::{
    fmt,
    io::{
        self,
        Read,
        Write,
    },
    iter,
    str,
};

use age::{
    DecryptError,
    Decryptor,
    EncryptError,
    Encryptor,
    Identity,
    Recipient,
    secrecy::ExposeSecret,
    x25519,
};
use lz4_flex::block::{
    compress_into,
    decompress_into,
    get_maximum_output_size,
};
use thiserror::Error;
use zeroize::Zeroizing;

const LEN_PREFIX_BYTES: usize = 4;
const MAX_WRAPPED_SECRET_BYTES: usize = 128;

/// A thread's own age identity, which every piece of encrypted thread content is sealed to.
///
/// Its secret half never appears in `Debug` output.
pub struct ThreadKey(x25519::Identity);

/// Sealing content failed.
#[derive(Debug, Error)]
pub enum SealError {
    /// The content is larger than the format can describe (4 GiB).
    #[error("content is larger than {} bytes", u32::MAX)]
    TooLarge,
    /// age could not set up encryption.
    #[error("cannot encrypt")]
    Encrypt(#[source] EncryptError),
    /// Compressing or writing the encrypted stream failed.
    #[error("cannot write sealed content")]
    Io(#[from] io::Error),
}

/// Opening sealed content failed.
#[derive(Debug, Error)]
pub enum OpenError {
    /// The content is not age, or is not sealed to this thread key.
    #[error("cannot decrypt")]
    Decrypt(#[source] DecryptError),
    /// The content says it is larger than the limit.
    #[error("content is larger than {limit} bytes")]
    TooLarge {
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },
    /// The decrypted content is not a valid compressed block of the length it declares, or the
    /// ciphertext ends before the length.
    #[error("sealed content is malformed")]
    Malformed,
    /// Reading failed, or the ciphertext was truncated or tampered with.
    #[error("cannot read sealed content")]
    Io(#[from] io::Error),
}

/// Wrapping the thread key for participants failed.
#[derive(Debug, Error)]
pub enum WrapError {
    /// There is nobody to wrap the key for.
    #[error("thread key needs at least one participant")]
    NoParticipants,
    /// age could not set up encryption.
    #[error("cannot encrypt thread key")]
    Encrypt(#[source] EncryptError),
    /// Writing the wrapped key failed.
    #[error("cannot write wrapped thread key")]
    Io(#[from] io::Error),
}

/// Recovering a thread key from its wrapped form failed.
#[derive(Debug, Error)]
pub enum WrappedKeyError {
    /// The wrapped key is not age, or is not wrapped for this identity.
    #[error("cannot decrypt wrapped thread key")]
    Decrypt(#[from] DecryptError),
    /// Reading failed, or the wrapped key was truncated or tampered with.
    #[error("cannot read wrapped thread key")]
    Io(#[from] io::Error),
    /// The decrypted content is not an age X25519 identity.
    #[error("wrapped thread key is malformed")]
    Malformed,
}

impl ThreadKey {
    /// Generates a new random thread key.
    #[must_use]
    pub fn generate() -> Self {
        Self(x25519::Identity::generate())
    }

    /// Returns the public recipient that content is sealed to.
    #[must_use]
    pub fn recipient(&self) -> x25519::Recipient {
        self.0.to_public()
    }

    /// Compresses `plaintext` with LZ4, then encrypts it to this thread key.
    ///
    /// The encrypted payload is the plaintext length as a little-endian `u32`, followed by one
    /// LZ4 block.
    ///
    /// # Errors
    ///
    /// Returns [`SealError`] if the plaintext is 4 GiB or larger, or encryption fails.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let len = u32::try_from(plaintext.len()).map_err(|_| SealError::TooLarge)?;
        let mut payload = vec![0; LEN_PREFIX_BYTES + get_maximum_output_size(plaintext.len())];
        let (prefix, block) = payload.split_at_mut(LEN_PREFIX_BYTES);
        prefix.copy_from_slice(&len.to_le_bytes());
        let written = compress_into(plaintext, block).map_err(io::Error::other)?;
        payload.truncate(LEN_PREFIX_BYTES + written);

        let recipient = self.recipient();
        let encryptor = Encryptor::with_recipients(iter::once(&recipient as &dyn Recipient))
            .map_err(SealError::Encrypt)?;
        let mut writer = encryptor.wrap_output(Vec::new())?;
        writer.write_all(&payload)?;
        Ok(writer.finish()?)
    }

    /// Decrypts and decompresses content sealed to this thread key.
    ///
    /// The declared length is checked against `max_len` before anything is allocated for it,
    /// the output buffer has exactly that length, and the whole ciphertext is read and
    /// authenticated. Memory use stays within about twice `max_len` whatever the input.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError`] if the content is not sealed to this key, was tampered with, is
    /// malformed, or declares more than `max_len` bytes.
    pub fn open(&self, sealed: &[u8], max_len: usize) -> Result<Vec<u8>, OpenError> {
        let mut reader = Decryptor::new(sealed)
            .and_then(|decryptor| decryptor.decrypt(iter::once(&self.0 as &dyn Identity)))
            .map_err(OpenError::Decrypt)?;

        let mut prefix = [0; LEN_PREFIX_BYTES];
        read_exact_or_malformed(&mut reader, &mut prefix)?;
        let len = usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| OpenError::Malformed)?;
        if len > max_len {
            return Err(OpenError::TooLarge { limit: max_len });
        }

        let block_limit = get_maximum_output_size(len);
        let mut block = Vec::with_capacity(block_limit);
        (&mut reader)
            .take(u64::try_from(block_limit).map_err(|_| OpenError::Malformed)?)
            .read_to_end(&mut block)?;
        if reader.read(&mut [0])? != 0 {
            return Err(OpenError::Malformed);
        }

        let mut plaintext = vec![0; len];
        match decompress_into(&block, &mut plaintext) {
            Ok(written) if written == len => Ok(plaintext),
            _ => Err(OpenError::Malformed),
        }
    }

    /// Encrypts this thread key's secret to each of `participants`.
    ///
    /// Any one of the participants' identities can later recover the key with
    /// [`ThreadKey::from_wrapped`].
    ///
    /// # Errors
    ///
    /// Returns [`WrapError`] if `participants` is empty or encryption fails.
    pub fn wrap(&self, participants: &[&dyn Recipient]) -> Result<Vec<u8>, WrapError> {
        if participants.is_empty() {
            return Err(WrapError::NoParticipants);
        }
        let encryptor =
            Encryptor::with_recipients(participants.iter().copied()).map_err(WrapError::Encrypt)?;
        let secret = self.0.to_string();
        let mut writer = encryptor.wrap_output(Vec::new())?;
        writer.write_all(secret.expose_secret().as_bytes())?;
        Ok(writer.finish()?)
    }

    /// Recovers a thread key that [`ThreadKey::wrap`] encrypted for `identity`.
    ///
    /// # Errors
    ///
    /// Returns [`WrappedKeyError`] if the key is not wrapped for `identity`, was tampered with,
    /// or does not hold a thread key.
    pub fn from_wrapped(wrapped: &[u8], identity: &dyn Identity) -> Result<Self, WrappedKeyError> {
        let reader = Decryptor::new(wrapped)?.decrypt(iter::once(identity))?;
        let mut secret = Zeroizing::new(Vec::with_capacity(MAX_WRAPPED_SECRET_BYTES + 1));
        reader
            .take(MAX_WRAPPED_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut secret)?;
        if secret.len() > MAX_WRAPPED_SECRET_BYTES {
            return Err(WrappedKeyError::Malformed);
        }
        str::from_utf8(&secret)
            .ok()
            .and_then(|secret| secret.parse().ok())
            .map(Self)
            .ok_or(WrappedKeyError::Malformed)
    }
}

impl fmt::Debug for ThreadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadKey")
            .field("recipient", &self.recipient().to_string())
            .finish_non_exhaustive()
    }
}

fn read_exact_or_malformed(reader: &mut impl Read, buf: &mut [u8]) -> Result<(), OpenError> {
    reader.read_exact(buf).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            OpenError::Malformed
        } else {
            OpenError::Io(error)
        }
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const LIMIT: usize = 1 << 20;
    const AGE_CHUNK: usize = 64 * 1024 + 16;

    fn encrypt_raw(key: &ThreadKey, payload: &[u8]) -> Vec<u8> {
        let recipient = key.recipient();
        let encryptor =
            Encryptor::with_recipients(iter::once(&recipient as &dyn Recipient)).unwrap();
        let mut writer = encryptor.wrap_output(Vec::new()).unwrap();
        writer.write_all(payload).unwrap();
        writer.finish().unwrap()
    }

    fn payload(len: u32, block: &[u8]) -> Vec<u8> {
        let mut payload = len.to_le_bytes().to_vec();
        payload.extend_from_slice(block);
        payload
    }

    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    fn payload_start(sealed: &[u8]) -> usize {
        let mac_line = sealed
            .windows(4)
            .position(|window| window == b"\n---")
            .unwrap();
        let header_end = mac_line
            + 1
            + sealed[mac_line + 1..]
                .iter()
                .position(|&b| b == b'\n')
                .unwrap()
            + 1;
        header_end + 16
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = ThreadKey::generate();
        for plaintext in [
            Vec::new(),
            b"hello".to_vec(),
            vec![0; 300_000],
            incompressible(200_000),
        ] {
            let sealed = key.seal(&plaintext).unwrap();
            assert_eq!(key.open(&sealed, LIMIT).unwrap(), plaintext);
        }
    }

    #[test]
    fn sealed_content_is_age_and_hides_the_plaintext() {
        let key = ThreadKey::generate();
        let sealed = key.seal(b"a secret transcript line").unwrap();
        assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
        assert!(
            !sealed
                .windows(b"secret".len())
                .any(|window| window == b"secret")
        );
    }

    #[test]
    fn sealing_compresses() {
        let key = ThreadKey::generate();
        let plaintext = b"{\"role\":\"assistant\",\"text\":\"ok\"}\n".repeat(10_000);
        let sealed = key.seal(&plaintext).unwrap();
        assert!(sealed.len() * 10 < plaintext.len(), "{}", sealed.len());
    }

    #[test]
    fn open_with_another_key_fails() {
        let sealed = ThreadKey::generate().seal(b"x").unwrap();
        assert!(matches!(
            ThreadKey::generate().open(&sealed, LIMIT),
            Err(OpenError::Decrypt(_))
        ));
    }

    #[test]
    fn open_enforces_the_size_limit() {
        let key = ThreadKey::generate();
        let sealed = key.seal(&[7; 1000]).unwrap();
        assert_eq!(key.open(&sealed, 1000).unwrap().len(), 1000);
        assert!(matches!(
            key.open(&sealed, 999),
            Err(OpenError::TooLarge { limit: 999 })
        ));
    }

    #[test]
    fn open_refuses_a_huge_declared_length_before_decompressing() {
        let key = ThreadKey::generate();
        let sealed = key.seal(&vec![0; 64 << 20]).unwrap();
        assert!(sealed.len() < 1 << 20);
        assert!(matches!(
            key.open(&sealed, LIMIT),
            Err(OpenError::TooLarge { .. })
        ));
        let forged = encrypt_raw(&key, &payload(u32::MAX, &[0x1f, 0]));
        assert!(matches!(
            key.open(&forged, LIMIT),
            Err(OpenError::TooLarge { .. })
        ));
    }

    #[test]
    fn open_rejects_a_block_that_disagrees_with_its_declared_length() {
        let key = ThreadKey::generate();
        let block = lz4_flex::block::compress(&[5; 100]);
        for declared in [0, 10, 99, 101, 1000] {
            let sealed = encrypt_raw(&key, &payload(declared, &block));
            assert!(
                matches!(key.open(&sealed, LIMIT), Err(OpenError::Malformed)),
                "declared {declared}"
            );
        }
        let sealed = encrypt_raw(&key, &payload(100, &block));
        assert_eq!(key.open(&sealed, LIMIT).unwrap(), [5; 100]);
    }

    #[test]
    fn open_rejects_data_after_the_block() {
        let key = ThreadKey::generate();
        let mut block = lz4_flex::block::compress(b"content");
        block.extend_from_slice(b"smuggled");
        let sealed = encrypt_raw(&key, &payload(7, &block));
        assert!(matches!(
            key.open(&sealed, LIMIT),
            Err(OpenError::Malformed)
        ));
    }

    #[test]
    fn open_rejects_payloads_that_are_not_lz4() {
        let key = ThreadKey::generate();
        for raw in [
            &b""[..],
            b"\x01",
            b"\x05\0\0\0",
            b"\x05\0\0\0\xff\xff\xff\xff",
        ] {
            let sealed = encrypt_raw(&key, raw);
            assert!(
                matches!(key.open(&sealed, LIMIT), Err(OpenError::Malformed)),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn open_rejects_garbage() {
        let key = ThreadKey::generate();
        assert!(matches!(
            key.open(b"not age at all", LIMIT),
            Err(OpenError::Decrypt(_))
        ));
        assert!(matches!(key.open(b"", LIMIT), Err(OpenError::Decrypt(_))));
    }

    #[test]
    fn open_rejects_tampering_in_any_chunk() {
        let key = ThreadKey::generate();
        let sealed = key.seal(&incompressible(200_000)).unwrap();
        let start = payload_start(&sealed);
        assert!(sealed.len() - start > 3 * AGE_CHUNK);
        for index in [
            start,
            start + AGE_CHUNK - 1,
            start + AGE_CHUNK,
            start + 2 * AGE_CHUNK + 7,
            sealed.len() - 1,
        ] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert!(key.open(&tampered, LIMIT).is_err(), "byte {index}");
        }
    }

    #[test]
    fn open_rejects_truncation_including_at_chunk_boundaries() {
        let key = ThreadKey::generate();
        let sealed = key.seal(&incompressible(200_000)).unwrap();
        let start = payload_start(&sealed);
        for end in [
            start,
            start + AGE_CHUNK,
            start + 2 * AGE_CHUNK,
            start + 3 * AGE_CHUNK,
            sealed.len() - 1,
            sealed.len() - 17,
        ] {
            assert!(key.open(&sealed[..end], LIMIT).is_err(), "end {end}");
        }
    }

    #[test]
    fn open_rejects_reordered_or_extended_chunks() {
        let key = ThreadKey::generate();
        let sealed = key.seal(&incompressible(200_000)).unwrap();
        let start = payload_start(&sealed);
        let mut swapped = sealed.clone();
        let (first, second) = swapped[start..start + 2 * AGE_CHUNK].split_at_mut(AGE_CHUNK);
        first.swap_with_slice(second);
        assert!(key.open(&swapped, LIMIT).is_err());

        let mut extended = sealed.clone();
        extended.extend_from_slice(&[0; 40]);
        assert!(key.open(&extended, LIMIT).is_err());
    }

    #[test]
    fn debug_hides_the_secret() {
        let key = ThreadKey::generate();
        let debug = format!("{key:?}");
        assert!(debug.contains(&key.recipient().to_string()));
        assert!(!debug.to_uppercase().contains("AGE-SECRET-KEY"));
    }

    #[test]
    fn every_participant_can_recover_the_key_and_others_cannot() {
        let key = ThreadKey::generate();
        let alice = x25519::Identity::generate();
        let bob = x25519::Identity::generate();
        let mallory = x25519::Identity::generate();
        let wrapped = key.wrap(&[&alice.to_public(), &bob.to_public()]).unwrap();
        let sealed = key.seal(b"shared").unwrap();
        for participant in [&alice, &bob] {
            let recovered = ThreadKey::from_wrapped(&wrapped, participant).unwrap();
            assert_eq!(
                recovered.recipient().to_string(),
                key.recipient().to_string()
            );
            assert_eq!(recovered.open(&sealed, LIMIT).unwrap(), b"shared");
        }
        assert!(matches!(
            ThreadKey::from_wrapped(&wrapped, &mallory),
            Err(WrappedKeyError::Decrypt(_))
        ));
    }

    #[test]
    fn wrap_needs_a_participant() {
        assert!(matches!(
            ThreadKey::generate().wrap(&[]),
            Err(WrapError::NoParticipants)
        ));
    }

    #[test]
    fn from_wrapped_rejects_content_that_is_not_a_key() {
        let alice = x25519::Identity::generate();
        let recipient = alice.to_public();
        for content in [&b"not a key"[..], &[0xff; 10], &[b'A'; 500]] {
            let encryptor =
                Encryptor::with_recipients(iter::once(&recipient as &dyn Recipient)).unwrap();
            let mut writer = encryptor.wrap_output(Vec::new()).unwrap();
            writer.write_all(content).unwrap();
            let wrapped = writer.finish().unwrap();
            assert!(matches!(
                ThreadKey::from_wrapped(&wrapped, &alice),
                Err(WrappedKeyError::Malformed)
            ));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn arbitrary_content_round_trips(plaintext in proptest::collection::vec(any::<u8>(), 0..300_000)) {
            let key = ThreadKey::generate();
            let sealed = key.seal(&plaintext).unwrap();
            prop_assert_eq!(key.open(&sealed, LIMIT).unwrap(), plaintext);
        }

        #[test]
        fn opening_arbitrary_blocks_never_panics(
            declared in 0..4096u32,
            block in proptest::collection::vec(any::<u8>(), 0..2000),
        ) {
            let key = ThreadKey::generate();
            let _ = key.open(&encrypt_raw(&key, &payload(declared, &block)), LIMIT);
        }

        #[test]
        fn opening_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let _ = ThreadKey::generate().open(&bytes, LIMIT);
        }
    }
}
