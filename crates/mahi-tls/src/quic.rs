use std::marker::PhantomData;

use aes::{
    Aes128,
    Aes256,
    cipher::{
        BlockEncrypt,
        KeyInit,
        generic_array::GenericArray,
    },
};
use chacha20::{
    ChaChaCore,
    cipher::{
        KeyIvInit,
        StreamCipherCore,
        StreamCipherSeekCore,
        consts::U10,
    },
};
use rustls::{
    Error,
    crypto::cipher::{
        AeadKey,
        Iv,
        Nonce,
    },
    quic,
};
use zeroize::Zeroizing;

use crate::aead::{
    Cipher,
    TAG_LEN,
    Unusable,
    open,
    seal,
};

const SAMPLE_LEN: usize = 16;
const MASK_LEN: usize = 5;
const LONG_HEADER_FORM: u8 = 0x80;

/// The block cipher a QUIC suite protects packet headers with.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HeaderCipher {
    Aes128,
    Aes256,
    ChaCha20,
}

/// The QUIC packet and header protection of a TLS 1.3 suite.
pub(crate) struct QuicAlgorithm<C> {
    header: HeaderCipher,
    confidentiality_limit: u64,
    integrity_limit: u64,
    cipher: PhantomData<fn() -> C>,
}

impl<C> QuicAlgorithm<C> {
    pub(crate) const fn new(
        header: HeaderCipher,
        confidentiality_limit: u64,
        integrity_limit: u64,
    ) -> Self {
        Self {
            header,
            confidentiality_limit,
            integrity_limit,
            cipher: PhantomData,
        }
    }
}

impl<C: Cipher> quic::Algorithm for QuicAlgorithm<C> {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        match PacketKey::<C>::new(
            key.as_ref(),
            iv,
            self.confidentiality_limit,
            self.integrity_limit,
        ) {
            Some(packet_key) => Box::new(packet_key),
            None => Box::new(Unusable),
        }
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        match HeaderKey::new(self.header, key.as_ref()) {
            Some(header_key) => Box::new(header_key),
            None => Box::new(Unusable),
        }
    }

    fn aead_key_len(&self) -> usize {
        C::key_size()
    }
}

struct PacketKey<C> {
    cipher: C,
    iv: Iv,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl<C: Cipher> PacketKey<C> {
    fn new(key: &[u8], iv: Iv, confidentiality_limit: u64, integrity_limit: u64) -> Option<Self> {
        Some(Self {
            cipher: C::new_from_slice(key).ok()?,
            iv,
            confidentiality_limit,
            integrity_limit,
        })
    }
}

impl<C: Cipher> quic::PacketKey for PacketKey<C> {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce = Nonce::new(&self.iv, packet_number);
        seal(&self.cipher, &nonce, header, payload).map(|tag| quic::Tag::from(tag.as_slice()))
    }

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce = Nonce::for_path(path_id, &self.iv, packet_number);
        seal(&self.cipher, &nonce, header, payload).map(|tag| quic::Tag::from(tag.as_slice()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = Nonce::new(&self.iv, packet_number);
        open(&self.cipher, &nonce, header, payload).map(|plain| &*plain)
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = Nonce::for_path(path_id, &self.iv, packet_number);
        open(&self.cipher, &nonce, header, payload).map(|plain| &*plain)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

enum HeaderKey {
    Aes128(Box<Aes128>),
    Aes256(Box<Aes256>),
    ChaCha20(Zeroizing<[u8; 32]>),
}

impl HeaderKey {
    fn new(cipher: HeaderCipher, key: &[u8]) -> Option<Self> {
        match cipher {
            HeaderCipher::Aes128 => Aes128::new_from_slice(key)
                .ok()
                .map(|cipher| Self::Aes128(Box::new(cipher))),
            HeaderCipher::Aes256 => Aes256::new_from_slice(key)
                .ok()
                .map(|cipher| Self::Aes256(Box::new(cipher))),
            HeaderCipher::ChaCha20 => <[u8; 32]>::try_from(key)
                .ok()
                .map(|key| Self::ChaCha20(Zeroizing::new(key))),
        }
    }

    fn mask(&self, sample: &[u8]) -> Result<[u8; MASK_LEN], Error> {
        let sample = <&[u8; SAMPLE_LEN]>::try_from(sample)
            .map_err(|_| Error::General("sample of invalid length".into()))?;
        let mut mask = [0_u8; MASK_LEN];
        match self {
            Self::Aes128(cipher) => aes_mask(&**cipher, sample, &mut mask),
            Self::Aes256(cipher) => aes_mask(&**cipher, sample, &mut mask),
            Self::ChaCha20(key) => {
                let (counter, nonce) = sample.split_at(4);
                let counter = <[u8; 4]>::try_from(counter)
                    .map_err(|_| Error::General("sample of invalid length".into()))?;
                let nonce = <[u8; 12]>::try_from(nonce)
                    .map_err(|_| Error::General("sample of invalid length".into()))?;
                let mut core = ChaChaCore::<U10>::new(&(**key).into(), &nonce.into());
                core.set_block_pos(u32::from_le_bytes(counter));
                let mut block = GenericArray::default();
                core.write_keystream_block(&mut block);
                copy_mask(&block, &mut mask);
            }
        }
        Ok(mask)
    }

    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        let [first_mask, packet_number_mask @ ..] = self.mask(sample)?;
        if packet_number.len() > packet_number_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }
        let bits = if *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            0x0f
        } else {
            0x1f
        };
        let first_plain = if masked {
            *first ^ (first_mask & bits)
        } else {
            *first
        };
        let packet_number_len = usize::from(first_plain & 0x03) + 1;
        *first ^= first_mask & bits;
        for (byte, mask) in packet_number
            .iter_mut()
            .zip(packet_number_mask)
            .take(packet_number_len)
        {
            *byte ^= mask;
        }
        Ok(())
    }
}

fn aes_mask<B: BlockEncrypt>(cipher: &B, sample: &[u8; SAMPLE_LEN], mask: &mut [u8; MASK_LEN])
where
    GenericArray<u8, B::BlockSize>: From<[u8; SAMPLE_LEN]>,
{
    let mut block = GenericArray::from(*sample);
    cipher.encrypt_block(&mut block);
    copy_mask(&block, mask);
}

fn copy_mask(block: &[u8], mask: &mut [u8; MASK_LEN]) {
    for (out, byte) in mask.iter_mut().zip(block) {
        *out = *byte;
    }
}

impl quic::HeaderProtectionKey for HeaderKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

impl quic::PacketKey for Unusable {
    fn encrypt_in_place(
        &self,
        _packet_number: u64,
        _header: &[u8],
        _payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        Err(Error::EncryptError)
    }

    fn decrypt_in_place<'a>(
        &self,
        _packet_number: u64,
        _header: &[u8],
        _payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        Err(Error::DecryptError)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        0
    }

    fn integrity_limit(&self) -> u64 {
        0
    }
}

impl quic::HeaderProtectionKey for Unusable {
    fn encrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        _packet_number: &mut [u8],
    ) -> Result<(), Error> {
        Err(Error::EncryptError)
    }

    fn decrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        _packet_number: &mut [u8],
    ) -> Result<(), Error> {
        Err(Error::DecryptError)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        Aes128Gcm,
        Aes256Gcm,
    };
    use chacha20::cipher::{
        StreamCipher,
        StreamCipherSeek,
    };
    use chacha20poly1305::ChaCha20Poly1305;
    use quic::{
        HeaderProtectionKey as _,
        Keys,
        PacketKey as _,
        Version,
    };
    use rustls::{
        Side,
        crypto::tls13::{
            Hkdf,
            HkdfUsingHmac,
            OkmBlock,
        },
    };

    use super::*;
    use crate::{
        hmac::HMAC_SHA256,
        suites::{
            AES_128_GCM_SHA256,
            AES_128_GCM_SHA256_QUIC,
        },
        testing::hex,
    };

    fn expand_label(secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
        let expander = HkdfUsingHmac(&HMAC_SHA256).expander_for_okm(&OkmBlock::new(secret));
        let label = [b"tls13 ".as_slice(), label].concat();
        let length = u16::try_from(len).unwrap().to_be_bytes();
        let label_len = [u8::try_from(label.len()).unwrap()];
        let mut output = vec![0; len];
        expander
            .expand_slice(&[&length, &label_len, &label, &[0]], &mut output)
            .unwrap();
        output
    }

    fn iv(bytes: &[u8]) -> Iv {
        Iv::from(<[u8; 12]>::try_from(bytes).unwrap())
    }

    #[test]
    fn a_server_initial_packet_matches_rfc_9001_appendix_a3() {
        let connection_id = hex("8394c8f03e515708");
        let suite = &AES_128_GCM_SHA256;
        let quic = &AES_128_GCM_SHA256_QUIC;
        let server = Keys::initial(Version::V1, suite, quic, &connection_id, Side::Server);
        let plain = hex(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739
             88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94
             0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00
             020304",
        );
        let mut header = hex("c1000000010008f067a5502a4262b50040750001");
        let mut payload = plain.clone();
        let tag = server
            .local
            .packet
            .encrypt_in_place(1, &header, &mut payload)
            .unwrap();
        let (first, rest) = header.split_at_mut(1);
        let packet_number_at = rest.len() - 2;
        server
            .local
            .header
            .encrypt_in_place(
                &payload[2..18],
                &mut first[0],
                &mut rest[packet_number_at..],
            )
            .unwrap();
        let mut packet = header.clone();
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        assert_eq!(
            packet,
            hex(
                "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a
                 5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3
                 dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84
                 022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4
                 2158407dd074ee"
            )
        );

        let client = Keys::initial(Version::V1, suite, quic, &connection_id, Side::Client);
        let (header, sealed) = packet.split_at_mut(20);
        let (first, rest) = header.split_at_mut(1);
        client
            .remote
            .header
            .decrypt_in_place(&sealed[2..18], &mut first[0], &mut rest[17..])
            .unwrap();
        assert_eq!(header, hex("c1000000010008f067a5502a4262b50040750001"));
        let opened = client
            .remote
            .packet
            .decrypt_in_place(1, header, sealed)
            .unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn a_chacha20_short_header_packet_matches_rfc_9001_appendix_a5() {
        let secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        let key = expand_label(&secret, b"quic key", 32);
        let packet_key = PacketKey::<ChaCha20Poly1305>::new(
            &key,
            iv(&expand_label(&secret, b"quic iv", 12)),
            u64::MAX,
            1 << 36,
        )
        .unwrap();
        let header_key = HeaderKey::new(
            HeaderCipher::ChaCha20,
            &expand_label(&secret, b"quic hp", 32),
        )
        .unwrap();
        let mut packet = hex("4200bff401");
        let (header, payload) = packet.split_at_mut(4);
        let tag = packet_key
            .encrypt_in_place(654_360_564, header, payload)
            .unwrap();
        packet.extend_from_slice(tag.as_ref());
        let (header, sample) = packet.split_at_mut(5);
        let (first, packet_number) = header.split_at_mut(1);
        header_key
            .encrypt_in_place(&sample[..16], &mut first[0], packet_number)
            .unwrap();
        assert_eq!(packet, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

        let (header, sample) = packet.split_at_mut(5);
        let (first, packet_number) = header.split_at_mut(1);
        header_key
            .decrypt_in_place(&sample[..16], &mut first[0], packet_number)
            .unwrap();
        let (header, sealed) = packet.split_at_mut(4);
        let opened = packet_key
            .decrypt_in_place(654_360_564, header, sealed)
            .unwrap();
        assert_eq!(opened, [0x01]);
    }

    #[test]
    fn a_multipath_packet_matches_picoquics_vector() {
        let secret: Vec<u8> = (0..32)
            .map(|byte| if byte == 25 { 35 } else { byte })
            .collect();
        let packet_key = PacketKey::<Aes128Gcm>::new(
            &expand_label(&secret, b"quic key", 16),
            iv(&expand_label(&secret, b"quic iv", 12)),
            1 << 23,
            1 << 52,
        )
        .unwrap();
        let mut payload = b"The quick brown fox jumps over the lazy dog".to_vec();
        let tag = packet_key
            .encrypt_in_place_for_path(2, 12345, b"This is a test", &mut payload)
            .unwrap();
        payload.extend_from_slice(tag.as_ref());
        assert_eq!(
            payload,
            [
                123, 139, 232, 52, 136, 25, 201, 143, 250, 89, 87, 39, 37, 63, 0, 210, 220, 227,
                186, 140, 183, 251, 13, 203, 6, 116, 204, 100, 166, 64, 43, 185, 174, 85, 212, 163,
                242, 141, 24, 166, 62, 228, 187, 137, 248, 31, 152, 126, 240, 151, 79, 51, 253,
                130, 43, 114, 173, 234, 254,
            ]
        );
        for path in [0, 1, 0xaead] {
            let mut sealed = b"payload".to_vec();
            let tag = packet_key
                .encrypt_in_place_for_path(path, 7, b"header", &mut sealed)
                .unwrap();
            sealed.extend_from_slice(tag.as_ref());
            assert!(
                packet_key
                    .decrypt_in_place_for_path(path + 1, 7, b"header", &mut sealed.clone())
                    .is_err()
            );
            let opened = packet_key
                .decrypt_in_place_for_path(path, 7, b"header", &mut sealed)
                .unwrap();
            assert_eq!(opened, b"payload");
        }
    }

    #[test]
    fn aes_256_keys_protect_packets_and_headers() {
        let packet_key = PacketKey::<Aes256Gcm>::new(&[0; 32], iv(&[0; 12]), 1, 1).unwrap();
        let mut payload = [0_u8; 16];
        let tag = packet_key.encrypt_in_place(0, &[], &mut payload).unwrap();
        assert_eq!(payload.as_slice(), hex("cea7403d4d606b6e074ec5d3baf39d18"));
        assert_eq!(tag.as_ref(), hex("d0d1c8a799996bf0265b98b5d48ab919"));
        let header_key = HeaderKey::new(HeaderCipher::Aes256, &[0; 32]).unwrap();
        assert_eq!(
            header_key.mask(&[0; 16]).unwrap(),
            [0xdc, 0x95, 0xc0, 0x78, 0xa2]
        );
    }

    #[test]
    fn header_protection_masks_only_the_packet_number_bytes_it_names() {
        let header_key = HeaderKey::new(HeaderCipher::Aes128, &[3; 16]).unwrap();
        let sample = [9_u8; 16];
        let [first_mask, rest @ ..] = header_key.mask(&sample).unwrap();
        let mut first = 0xc1;
        let mut packet_number = [0_u8; 4];
        header_key
            .encrypt_in_place(&sample, &mut first, &mut packet_number)
            .unwrap();
        assert_eq!(first, 0xc1 ^ (first_mask & 0x0f));
        assert_eq!(packet_number, [rest[0], rest[1], 0, 0]);
        header_key
            .decrypt_in_place(&sample, &mut first, &mut packet_number)
            .unwrap();
        assert_eq!((first, packet_number), (0xc1, [0; 4]));

        assert!(
            header_key
                .encrypt_in_place(&[0; 15], &mut first, &mut packet_number)
                .is_err()
        );
        assert!(
            header_key
                .encrypt_in_place(&sample, &mut first, &mut [0; 5])
                .is_err()
        );
        assert_eq!((first, packet_number), (0xc1, [0; 4]));
    }

    #[test]
    fn the_chacha20_mask_follows_the_counter_up_to_the_last_block() {
        let header_key = HeaderKey::new(HeaderCipher::ChaCha20, &[1; 32]).unwrap();
        let key = [1_u8; 32];
        for counter in [0, 1, 77, u32::MAX - 1] {
            let mut sample = [5_u8; 16];
            sample[..4].copy_from_slice(&counter.to_le_bytes());
            let mut stream = chacha20::ChaCha20::new(&key.into(), &[5_u8; 12].into());
            stream.seek(u64::from(counter) * 64);
            let mut expected = [0_u8; MASK_LEN];
            stream.apply_keystream(&mut expected);
            assert_eq!(header_key.mask(&sample).unwrap(), expected);
        }
        let mut sample = [5_u8; 16];
        sample[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        let first = header_key.mask(&sample).unwrap();
        sample[4] ^= 1;
        assert_ne!(header_key.mask(&sample).unwrap(), first);
    }

    #[test]
    fn keys_of_the_wrong_length_give_keys_that_only_fail() {
        let quic = QuicAlgorithm::<Aes128Gcm>::new(HeaderCipher::Aes128, 1, 1);
        let packet_key = quic::Algorithm::packet_key(&quic, AeadKey::from([0; 32]), iv(&[0; 12]));
        assert!(packet_key.encrypt_in_place(0, &[], &mut []).is_err());
        let header_key = quic::Algorithm::header_protection_key(&quic, AeadKey::from([0; 32]));
        assert!(
            header_key
                .encrypt_in_place(&[0; 16], &mut 0, &mut [0; 4])
                .is_err()
        );
    }
}
