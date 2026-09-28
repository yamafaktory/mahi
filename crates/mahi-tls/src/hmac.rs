use std::marker::PhantomData;

use hmac::{
    Mac,
    SimpleHmac,
    digest::{
        Digest,
        KeyInit,
        core_api::BlockSizeUser,
    },
};
use rustls::crypto::hmac::{
    Hmac,
    Key,
    Tag,
};
use sha2::{
    Sha256,
    Sha384,
};

pub(crate) static HMAC_SHA256: HmacSha<Sha256> = HmacSha(PhantomData);
pub(crate) static HMAC_SHA384: HmacSha<Sha384> = HmacSha(PhantomData);

/// HMAC over a SHA-2 hash for rustls, which builds HKDF on it.
pub(crate) struct HmacSha<D>(PhantomData<fn() -> D>);

impl<D: Digest + BlockSizeUser + Clone + Send + Sync + 'static> Hmac for HmacSha<D> {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacKey(
            <SimpleHmac<D> as KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

struct HmacKey<D: Digest + BlockSizeUser>(SimpleHmac<D>);

impl<D: Digest + BlockSizeUser + Clone + Send + Sync + 'static> Key for HmacKey<D> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut mac = self.0.clone();
        mac.update(first);
        for part in middle {
            mac.update(part);
        }
        mac.update(last);
        Tag::new(&mac.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        <D as Digest>::output_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    #[test]
    fn tags_match_rfc_4231_test_case_2() {
        let cases: [(&dyn Hmac, &str); 2] = [
            (
                &HMAC_SHA256,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &HMAC_SHA384,
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47
                 e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            ),
        ];
        for (hmac, expected) in cases {
            let expected = hex(expected);
            let key = hmac.with_key(b"Jefe");
            let tag = key.sign_concat(b"what do ya ", &[b"want ", b"for "], b"nothing?");
            assert_eq!(tag.as_ref(), expected);
            assert_eq!(key.tag_len(), expected.len());
            assert_eq!(hmac.hash_output_len(), expected.len());
        }
    }
}
