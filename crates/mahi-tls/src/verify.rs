use ed25519_dalek::{
    Signature as Ed25519Signature,
    VerifyingKey as Ed25519Key,
};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::{
    BigUint,
    Pkcs1v15Sign,
    Pss,
    RsaPublicKey,
    pkcs1::{
        self,
        der::Decode,
    },
    traits::{
        PublicKeyParts,
        SignatureScheme,
    },
};
use rustls::{
    SignatureScheme as TlsScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{
        AlgorithmIdentifier,
        InvalidSignature,
        SignatureVerificationAlgorithm,
        alg_id,
    },
};
use sha2::{
    Digest,
    Sha256,
    Sha384,
    Sha512,
};

const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 8192;
const P256_POINT_LEN: usize = 65;
const P384_POINT_LEN: usize = 97;
const UNCOMPRESSED_POINT: u8 = 0x04;

const RSA_PKCS1_SHA256_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);
const RSA_PKCS1_SHA384_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
]);
const RSA_PKCS1_SHA512_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
]);

const ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::ECDSA_P256,
    signature: alg_id::ECDSA_SHA256,
    check: Check::EcdsaP256(Hash::Sha256),
};
const ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::ECDSA_P256,
    signature: alg_id::ECDSA_SHA384,
    check: Check::EcdsaP256(Hash::Sha384),
};
const ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::ECDSA_P384,
    signature: alg_id::ECDSA_SHA256,
    check: Check::EcdsaP384(Hash::Sha256),
};
const ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::ECDSA_P384,
    signature: alg_id::ECDSA_SHA384,
    check: Check::EcdsaP384(Hash::Sha384),
};
const ED25519: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::ED25519,
    signature: alg_id::ED25519,
    check: Check::Ed25519,
};
const RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA256,
    check: Check::RsaPss(Hash::Sha256),
};
const RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA384,
    check: Check::RsaPss(Hash::Sha384),
};
const RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA512,
    check: Check::RsaPss(Hash::Sha512),
};
const RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA256,
    check: Check::RsaPkcs1(Hash::Sha256),
};
const RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA384,
    check: Check::RsaPkcs1(Hash::Sha384),
};
const RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA512,
    check: Check::RsaPkcs1(Hash::Sha512),
};
const RSA_PKCS1_SHA256_ABSENT: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: RSA_PKCS1_SHA256_ABSENT_PARAMS,
    check: Check::RsaPkcs1(Hash::Sha256),
};
const RSA_PKCS1_SHA384_ABSENT: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: RSA_PKCS1_SHA384_ABSENT_PARAMS,
    check: Check::RsaPkcs1(Hash::Sha384),
};
const RSA_PKCS1_SHA512_ABSENT: &dyn SignatureVerificationAlgorithm = &Algorithm {
    public_key: alg_id::RSA_ENCRYPTION,
    signature: RSA_PKCS1_SHA512_ABSENT_PARAMS,
    check: Check::RsaPkcs1(Hash::Sha512),
};

pub(crate) static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P256_SHA384,
        ECDSA_P384_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        RSA_PKCS1_SHA256_ABSENT,
        RSA_PKCS1_SHA384_ABSENT,
        RSA_PKCS1_SHA512_ABSENT,
    ],
    mapping: &[
        (
            TlsScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (
            TlsScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (TlsScheme::ED25519, &[ED25519]),
        (TlsScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (TlsScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (TlsScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (TlsScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (TlsScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (TlsScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

#[derive(Debug, Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(message).to_vec(),
            Self::Sha384 => Sha384::digest(message).to_vec(),
            Self::Sha512 => Sha512::digest(message).to_vec(),
        }
    }

    fn pkcs1(self) -> Pkcs1v15Sign {
        match self {
            Self::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
            Self::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
            Self::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
        }
    }

    fn pss(self) -> Pss {
        match self {
            Self::Sha256 => Pss::new::<Sha256>(),
            Self::Sha384 => Pss::new::<Sha384>(),
            Self::Sha512 => Pss::new::<Sha512>(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Check {
    EcdsaP256(Hash),
    EcdsaP384(Hash),
    Ed25519,
    RsaPkcs1(Hash),
    RsaPss(Hash),
}

/// One pair of public key and signature algorithms that certificates and handshakes are checked
/// with.
#[derive(Debug)]
struct Algorithm {
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    check: Check,
}

impl SignatureVerificationAlgorithm for Algorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        match self.check {
            Check::EcdsaP256(hash) => ecdsa_p256(public_key, &hash.digest(message), signature),
            Check::EcdsaP384(hash) => ecdsa_p384(public_key, &hash.digest(message), signature),
            Check::Ed25519 => ed25519(public_key, message, signature),
            Check::RsaPkcs1(hash) => {
                rsa_verify(public_key, hash.pkcs1(), &hash.digest(message), signature)
            }
            Check::RsaPss(hash) => {
                rsa_verify(public_key, hash.pss(), &hash.digest(message), signature)
            }
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

fn uncompressed_point(public_key: &[u8], len: usize) -> Result<&[u8], InvalidSignature> {
    if public_key.len() == len && public_key.first() == Some(&UNCOMPRESSED_POINT) {
        Ok(public_key)
    } else {
        Err(InvalidSignature)
    }
}

fn ecdsa_p256(public_key: &[u8], digest: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
    let key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(uncompressed_point(public_key, P256_POINT_LEN)?)
            .map_err(|_| InvalidSignature)?;
    let signature = p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
    key.verify_prehash(digest, &signature)
        .map_err(|_| InvalidSignature)
}

fn ecdsa_p384(public_key: &[u8], digest: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
    let key =
        p384::ecdsa::VerifyingKey::from_sec1_bytes(uncompressed_point(public_key, P384_POINT_LEN)?)
            .map_err(|_| InvalidSignature)?;
    let signature = p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
    key.verify_prehash(digest, &signature)
        .map_err(|_| InvalidSignature)
}

fn ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
    let public_key = <[u8; 32]>::try_from(public_key).map_err(|_| InvalidSignature)?;
    let signature = Ed25519Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
    Ed25519Key::from_bytes(&public_key)
        .map_err(|_| InvalidSignature)?
        .verify_strict(message, &signature)
        .map_err(|_| InvalidSignature)
}

fn rsa_verify<S: SignatureScheme>(
    public_key: &[u8],
    scheme: S,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let key = rsa_key(public_key)?;
    if BigUint::from_bytes_be(signature) >= *key.n() {
        return Err(InvalidSignature);
    }
    key.verify(scheme, digest, signature)
        .map_err(|_| InvalidSignature)
}

fn rsa_key(public_key: &[u8]) -> Result<RsaPublicKey, InvalidSignature> {
    let parsed = pkcs1::RsaPublicKey::from_der(public_key).map_err(|_| InvalidSignature)?;
    let modulus = BigUint::from_bytes_be(parsed.modulus.as_bytes());
    if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&modulus.bits()) {
        return Err(InvalidSignature);
    }
    let exponent = BigUint::from_bytes_be(parsed.public_exponent.as_bytes());
    RsaPublicKey::new_with_max_size(modulus, exponent, RSA_MAX_BITS).map_err(|_| InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    #[test]
    fn an_rfc_8032_signature_verifies_and_any_change_is_refused() {
        let public_key = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert!(
            ED25519
                .verify_signature(&public_key, b"", &signature)
                .is_ok()
        );
        assert!(
            ED25519
                .verify_signature(&public_key, b"x", &signature)
                .is_err()
        );
        let mut changed = signature.clone();
        changed[0] ^= 1;
        assert!(
            ED25519
                .verify_signature(&public_key, b"", &changed)
                .is_err()
        );
        assert!(
            ED25519
                .verify_signature(&public_key[..31], b"", &signature)
                .is_err()
        );
        assert!(
            ED25519
                .verify_signature(&public_key, b"", &signature[..63])
                .is_err()
        );
    }

    fn rsa_public_key(modulus_len: usize) -> Vec<u8> {
        let integer_len = u16::try_from(modulus_len + 1).unwrap().to_be_bytes();
        let body = [
            &[0x02, 0x82][..],
            &integer_len,
            &[0x00],
            &vec![0xc5; modulus_len],
            &[0x02, 0x03, 0x01, 0x00, 0x01],
        ]
        .concat();
        let body_len = u16::try_from(body.len()).unwrap().to_be_bytes();
        [&[0x30, 0x82][..], &body_len, &body].concat()
    }

    #[test]
    fn rsa_keys_are_taken_from_2048_to_8192_bits_only() {
        assert!(rsa_key(&rsa_public_key(256)).is_ok());
        assert!(rsa_key(&rsa_public_key(1024)).is_ok());
        assert!(rsa_key(&rsa_public_key(255)).is_err());
        assert!(rsa_key(&rsa_public_key(1025)).is_err());
        assert!(rsa_key(&rsa_public_key(256)[1..]).is_err());
    }

    #[test]
    fn an_rsa_signature_raised_by_the_modulus_is_refused() {
        let public_key = include_bytes!("../tests/data/rsa-low-public.der");
        let message = include_bytes!("../tests/data/message.bin");
        let signature = include_bytes!("../tests/data/rsa-low-pss-sha256.sig");
        assert!(
            RSA_PSS_SHA256
                .verify_signature(public_key, message, signature)
                .is_ok()
        );
        let modulus = rsa_key(public_key).unwrap().n().clone();
        let raised = (BigUint::from_bytes_be(signature) + modulus).to_bytes_be();
        assert_eq!(raised.len(), signature.len());
        for algorithm in [RSA_PSS_SHA256, RSA_PKCS1_SHA256] {
            assert!(
                algorithm
                    .verify_signature(public_key, message, &raised)
                    .is_err()
            );
        }
    }

    #[test]
    fn every_listed_algorithm_is_mapped_and_absent_params_are_bare_oids() {
        for (_, algorithms) in ALGORITHMS.mapping {
            for algorithm in *algorithms {
                assert!(ALGORITHMS.all.iter().any(|listed| {
                    listed.public_key_alg_id() == algorithm.public_key_alg_id()
                        && listed.signature_alg_id() == algorithm.signature_alg_id()
                }));
            }
        }
        for (absent, present) in [
            (RSA_PKCS1_SHA256_ABSENT_PARAMS, alg_id::RSA_PKCS1_SHA256),
            (RSA_PKCS1_SHA384_ABSENT_PARAMS, alg_id::RSA_PKCS1_SHA384),
            (RSA_PKCS1_SHA512_ABSENT_PARAMS, alg_id::RSA_PKCS1_SHA512),
        ] {
            assert_eq!(present.as_ref(), [absent.as_ref(), &[0x05, 0x00]].concat());
        }
    }
}
