use ed25519_dalek::{
    Signature,
    VerifyingKey,
};
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{
        AlgorithmIdentifier,
        InvalidSignature,
        SignatureVerificationAlgorithm,
        alg_id,
    },
};

pub(crate) static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ED25519],
    mapping: &[(SignatureScheme::ED25519, &[ED25519])],
};

const ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519;

#[derive(Debug)]
struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let public_key = <[u8; 32]>::try_from(public_key).map_err(|_| InvalidSignature)?;
        let signature = Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| InvalidSignature)?
            .verify_strict(message, &signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
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
            Ed25519
                .verify_signature(&public_key, b"", &signature)
                .is_ok()
        );
        assert!(
            Ed25519
                .verify_signature(&public_key, b"x", &signature)
                .is_err()
        );
        let mut changed = signature.clone();
        changed[0] ^= 1;
        assert!(
            Ed25519
                .verify_signature(&public_key, b"", &changed)
                .is_err()
        );
        assert!(
            Ed25519
                .verify_signature(&public_key[..31], b"", &signature)
                .is_err()
        );
        assert!(
            Ed25519
                .verify_signature(&public_key, b"", &signature[..63])
                .is_err()
        );
    }
}
