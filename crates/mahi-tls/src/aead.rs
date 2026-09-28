use std::marker::PhantomData;

use aes_gcm::aead::{
    AeadCore,
    AeadInPlace,
    KeyInit,
    consts::{
        U12,
        U16,
    },
};
use rustls::{
    ConnectionTrafficSecrets,
    ContentType,
    Error,
    ProtocolVersion,
    crypto::cipher::{
        AeadKey,
        InboundOpaqueMessage,
        InboundPlainMessage,
        Iv,
        MessageDecrypter,
        MessageEncrypter,
        Nonce,
        OutboundOpaqueMessage,
        OutboundPlainMessage,
        PrefixedPayload,
        Tls13AeadAlgorithm,
        UnsupportedOperationError,
        make_tls13_aad,
    },
};

pub(crate) const TAG_LEN: usize = 16;

/// An AEAD with the 12-byte nonce and 16-byte tag that TLS 1.3 and QUIC use.
pub(crate) trait Cipher:
    AeadCore<NonceSize = U12, TagSize = U16> + AeadInPlace + KeyInit + Send + Sync + 'static
{
}

impl<C> Cipher for C where
    C: AeadCore<NonceSize = U12, TagSize = U16> + AeadInPlace + KeyInit + Send + Sync + 'static
{
}

/// Encrypts `data` in place and returns its tag.
pub(crate) fn seal<C: Cipher>(
    cipher: &C,
    nonce: &Nonce,
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    cipher
        .encrypt_in_place_detached(&nonce.0.into(), aad, data)
        .map(Into::into)
        .map_err(|_| Error::EncryptError)
}

/// Checks and decrypts `sealed`, which ends with its tag, in place, and returns the plaintext.
pub(crate) fn open<'a, C: Cipher>(
    cipher: &C,
    nonce: &Nonce,
    aad: &[u8],
    sealed: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    let plain_len = sealed
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::DecryptError)?;
    let (plain, tag) = sealed.split_at_mut(plain_len);
    let tag = <[u8; TAG_LEN]>::try_from(&*tag).map_err(|_| Error::DecryptError)?;
    cipher
        .decrypt_in_place_detached(&nonce.0.into(), aad, plain, &tag.into())
        .map_err(|_| Error::DecryptError)?;
    Ok(plain)
}

/// The TLS 1.3 record protection of an AEAD.
pub(crate) struct Tls13Aead<C>(PhantomData<fn() -> C>);

impl<C> Tls13Aead<C> {
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C: Cipher> Tls13AeadAlgorithm for Tls13Aead<C> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        match C::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(Records { cipher, iv }),
            Err(_) => Box::new(Unusable),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        match C::new_from_slice(key.as_ref()) {
            Ok(cipher) => Box::new(Records { cipher, iv }),
            Err(_) => Box::new(Unusable),
        }
    }

    fn key_len(&self) -> usize {
        C::key_size()
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct Records<C> {
    cipher: C,
    iv: Iv,
}

impl<C: Cipher> MessageEncrypter for Records<C> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let tag = seal(
            &self.cipher,
            &Nonce::new(&self.iv, seq),
            &make_tls13_aad(total_len),
            payload.as_mut(),
        )?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl<C: Cipher> MessageDecrypter for Records<C> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let aad = make_tls13_aad(msg.payload.len());
        let plain_len = open(
            &self.cipher,
            &Nonce::new(&self.iv, seq),
            &aad,
            &mut msg.payload,
        )?
        .len();
        msg.payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

/// Stands in for a key rustls handed over at the wrong length, which it never does: every
/// operation fails instead of panicking.
pub(crate) struct Unusable;

impl MessageEncrypter for Unusable {
    fn encrypt(
        &mut self,
        _msg: OutboundPlainMessage<'_>,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Unusable {
    fn decrypt<'a>(
        &mut self,
        _msg: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        Aes128Gcm,
        Aes256Gcm,
    };
    use chacha20poly1305::ChaCha20Poly1305;

    use super::*;
    use crate::testing::hex;

    #[test]
    fn aes_256_gcm_matches_the_gcm_specification_test_case_14() {
        let cipher = Aes256Gcm::new_from_slice(&[0; 32]).unwrap();
        let nonce = Nonce([0; 12]);
        let mut data = [0_u8; 16];
        let tag = seal(&cipher, &nonce, &[], &mut data).unwrap();
        assert_eq!(data.as_slice(), hex("cea7403d4d606b6e074ec5d3baf39d18"));
        assert_eq!(tag.as_slice(), hex("d0d1c8a799996bf0265b98b5d48ab919"));
    }

    #[test]
    fn open_reverses_seal_and_refuses_any_change() {
        let cipher = ChaCha20Poly1305::new_from_slice(&[7; 32]).unwrap();
        let nonce = Nonce([1; 12]);
        let mut sealed = b"hello".to_vec();
        let tag = seal(&cipher, &nonce, b"aad", &mut sealed).unwrap();
        sealed.extend_from_slice(&tag);
        for index in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            assert!(open(&cipher, &nonce, b"aad", &mut changed).is_err());
        }
        assert!(open(&cipher, &nonce, b"other", &mut sealed.clone()).is_err());
        assert!(open(&cipher, &Nonce([2; 12]), b"aad", &mut sealed.clone()).is_err());
        assert!(open(&cipher, &nonce, b"aad", &mut [0; TAG_LEN - 1]).is_err());
        assert_eq!(
            open(&cipher, &nonce, b"aad", &mut sealed).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn records_match_the_client_application_traffic_in_rfc_8448_section_3() {
        let key = hex("17422dda596ed5d9acd890e3c63f5051");
        let iv = Iv::from(<[u8; 12]>::try_from(hex("5b78923dee08579033e523d9")).unwrap());
        let mut records = Records {
            cipher: Aes128Gcm::new_from_slice(&key).unwrap(),
            iv,
        };
        let data: Vec<u8> = (0..50).collect();
        let cases = [
            (
                ContentType::ApplicationData,
                data.as_slice(),
                hex(
                    "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b
                     9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63a
                     eebb21694915e4",
                ),
            ),
            (
                ContentType::Alert,
                [1_u8, 0].as_slice(),
                hex("1703030013c9872760655666b74d7ff1153efd6db6d0b0e3"),
            ),
        ];
        for (seq, (typ, payload, expected)) in (0_u64..).zip(cases) {
            let message = OutboundPlainMessage {
                typ,
                version: ProtocolVersion::TLSv1_2,
                payload: payload.into(),
            };
            let sealed = records.encrypt(message, seq).unwrap().encode();
            assert_eq!(sealed, expected);

            let mut body = sealed[5..].to_vec();
            let opaque = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut body,
            );
            let plain = records.decrypt(opaque, seq).unwrap();
            assert_eq!((plain.typ, plain.payload), (typ, payload));
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_gives_a_cipher_that_only_fails() {
        let aead = Tls13Aead::<Aes128Gcm>::new();
        assert_eq!(aead.key_len(), 16);
        let mut encrypter = aead.encrypter(AeadKey::from([0; 32]), Iv::from([0; 12]));
        let message = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: b"x".as_slice().into(),
        };
        assert!(encrypter.encrypt(message, 0).is_err());
    }
}
