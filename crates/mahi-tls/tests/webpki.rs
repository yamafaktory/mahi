//! Certificate and signature checks with mahi's provider, against signatures made by OpenSSL and
//! the certificate chain a real iroh relay presents.

use std::{
    sync::Arc,
    time::Duration,
};

use rustls::{
    CertificateError,
    Error,
    RootCertStore,
    client::{
        WebPkiServerVerifier,
        danger::ServerCertVerifier,
    },
    pki_types::{
        AlgorithmIdentifier,
        CertificateDer,
        ServerName,
        SignatureVerificationAlgorithm,
        UnixTime,
        alg_id,
    },
};

const MESSAGE: &[u8] = include_bytes!("data/message.bin");
const RSA_PUBLIC: &[u8] = include_bytes!("data/rsa-public.der");
const P256_PUBLIC: &[u8] = include_bytes!("data/p256-public.bin");
const P384_PUBLIC: &[u8] = include_bytes!("data/p384-public.bin");
const RELAY_CHAIN: [&[u8]; 4] = [
    include_bytes!("data/relay-0.der"),
    include_bytes!("data/relay-1.der"),
    include_bytes!("data/relay-2.der"),
    include_bytes!("data/relay-3.der"),
];
const RELAY_NAME: &str = "euc1-1.relay.n0.iroh.link";
const WHILE_THE_RELAY_CERTIFICATE_IS_VALID: u64 = 1_790_000_000;

fn algorithm(
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
) -> &'static dyn SignatureVerificationAlgorithm {
    let provider = mahi_tls::provider();
    *provider
        .signature_verification_algorithms
        .all
        .iter()
        .find(|algorithm| {
            algorithm.public_key_alg_id() == public_key && algorithm.signature_alg_id() == signature
        })
        .expect("the provider lists the algorithm")
}

fn verifies(
    algorithm: &dyn SignatureVerificationAlgorithm,
    public_key: &[u8],
    signature: &[u8],
) -> bool {
    algorithm
        .verify_signature(public_key, MESSAGE, signature)
        .is_ok()
}

fn assert_only_the_original_verifies(
    algorithm: &dyn SignatureVerificationAlgorithm,
    public_key: &[u8],
    signature: &[u8],
) {
    assert!(verifies(algorithm, public_key, signature));
    assert!(
        algorithm
            .verify_signature(public_key, b"another message", signature)
            .is_err()
    );
    let mut changed = signature.to_vec();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(!verifies(algorithm, public_key, &changed));
    assert!(!verifies(algorithm, &public_key[1..], signature));
}

#[test]
fn openssl_rsa_signatures_verify_with_their_padding_and_hash_only() {
    let cases = [
        (
            alg_id::RSA_PKCS1_SHA256,
            include_bytes!("data/rsa-pkcs1-sha256.sig").as_slice(),
        ),
        (
            alg_id::RSA_PKCS1_SHA384,
            include_bytes!("data/rsa-pkcs1-sha384.sig").as_slice(),
        ),
        (
            alg_id::RSA_PKCS1_SHA512,
            include_bytes!("data/rsa-pkcs1-sha512.sig").as_slice(),
        ),
        (
            alg_id::RSA_PSS_SHA256,
            include_bytes!("data/rsa-pss-sha256.sig").as_slice(),
        ),
        (
            alg_id::RSA_PSS_SHA384,
            include_bytes!("data/rsa-pss-sha384.sig").as_slice(),
        ),
        (
            alg_id::RSA_PSS_SHA512,
            include_bytes!("data/rsa-pss-sha512.sig").as_slice(),
        ),
    ];
    for (signature_alg, signature) in cases {
        let checker = algorithm(alg_id::RSA_ENCRYPTION, signature_alg);
        assert_only_the_original_verifies(checker, RSA_PUBLIC, signature);
        for (other_alg, other) in cases {
            if other_alg != signature_alg {
                assert!(!verifies(checker, RSA_PUBLIC, other));
            }
        }
    }
}

#[test]
fn openssl_ecdsa_signatures_verify_on_their_curve_and_hash_only() {
    let cases = [
        (
            alg_id::ECDSA_P256,
            P256_PUBLIC,
            alg_id::ECDSA_SHA256,
            include_bytes!("data/p256-sha256.sig").as_slice(),
        ),
        (
            alg_id::ECDSA_P256,
            P256_PUBLIC,
            alg_id::ECDSA_SHA384,
            include_bytes!("data/p256-sha384.sig").as_slice(),
        ),
        (
            alg_id::ECDSA_P384,
            P384_PUBLIC,
            alg_id::ECDSA_SHA256,
            include_bytes!("data/p384-sha256.sig").as_slice(),
        ),
        (
            alg_id::ECDSA_P384,
            P384_PUBLIC,
            alg_id::ECDSA_SHA384,
            include_bytes!("data/p384-sha384.sig").as_slice(),
        ),
    ];
    for (curve, public_key, hash, signature) in cases {
        let checker = algorithm(curve, hash);
        assert_only_the_original_verifies(checker, public_key, signature);
        let other_hash = if hash == alg_id::ECDSA_SHA256 {
            alg_id::ECDSA_SHA384
        } else {
            alg_id::ECDSA_SHA256
        };
        assert!(!verifies(
            algorithm(curve, other_hash),
            public_key,
            signature
        ));
        let mut compressed = public_key[..public_key.len().div_ceil(2)].to_vec();
        compressed[0] = 0x02 | (public_key[public_key.len() - 1] & 1);
        assert!(!verifies(checker, &compressed, signature));
    }
}

fn relay_verifier() -> Arc<WebPkiServerVerifier> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(mahi_tls::provider()))
        .build()
        .expect("the roots and the provider make a verifier")
}

fn check_relay_chain(chain: &[Vec<u8>]) -> Result<(), Error> {
    let certificates: Vec<CertificateDer<'_>> = chain
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let (leaf, intermediates) = certificates.split_first().expect("the chain has a leaf");
    relay_verifier()
        .verify_server_cert(
            leaf,
            intermediates,
            &ServerName::try_from(RELAY_NAME).expect("the relay name is valid"),
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(WHILE_THE_RELAY_CERTIFICATE_IS_VALID)),
        )
        .map(|_| ())
}

#[test]
fn a_real_relay_chain_verifies_through_ecdsa_p384_and_a_changed_signature_does_not() {
    let chain: Vec<Vec<u8>> = RELAY_CHAIN.iter().map(|der| der.to_vec()).collect();
    check_relay_chain(&chain).unwrap();

    let mut changed = chain.clone();
    let leaf = &mut changed[0];
    let last = leaf.len() - 1;
    leaf[last] ^= 1;
    assert!(matches!(
        check_relay_chain(&changed),
        Err(Error::InvalidCertificate(CertificateError::BadSignature))
    ));
}
