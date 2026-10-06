#![no_main]

use std::{
    sync::{
        Arc,
        LazyLock,
    },
    time::Duration,
};

use rustls::{
    RootCertStore,
    client::{
        WebPkiServerVerifier,
        danger::ServerCertVerifier,
    },
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{
        AlgorithmIdentifier,
        CertificateDer,
        ServerName,
        SignatureVerificationAlgorithm,
        UnixTime,
        alg_id,
    },
};

const MESSAGE: &[u8] = include_bytes!("../../crates/mahi-tls/tests/data/message.bin");
const RSA_PUBLIC: &[u8] = include_bytes!("../../crates/mahi-tls/tests/data/rsa-public.der");
const P256_PUBLIC: &[u8] = include_bytes!("../../crates/mahi-tls/tests/data/p256-public.bin");
const P384_PUBLIC: &[u8] = include_bytes!("../../crates/mahi-tls/tests/data/p384-public.bin");
const RELAY_CHAIN: [&[u8]; 4] = [
    include_bytes!("../../crates/mahi-tls/tests/data/relay-0.der"),
    include_bytes!("../../crates/mahi-tls/tests/data/relay-1.der"),
    include_bytes!("../../crates/mahi-tls/tests/data/relay-2.der"),
    include_bytes!("../../crates/mahi-tls/tests/data/relay-3.der"),
];
const RELAY_NAME: &str = "euc1-1.relay.n0.iroh.link";
const WHILE_THE_RELAY_CERTIFICATE_IS_VALID: u64 = 1_790_000_000;

type Case = (
    AlgorithmIdentifier,
    AlgorithmIdentifier,
    &'static [u8],
    &'static [u8],
);

const SIGNED: [Case; 11] = [
    (
        alg_id::RSA_ENCRYPTION,
        alg_id::RSA_PKCS1_SHA256,
        RSA_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/rsa-pkcs1-sha256.sig"),
    ),
    (
        alg_id::RSA_ENCRYPTION,
        alg_id::RSA_PKCS1_SHA384,
        RSA_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/rsa-pkcs1-sha384.sig"),
    ),
    (
        alg_id::RSA_ENCRYPTION,
        alg_id::RSA_PKCS1_SHA512,
        RSA_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/rsa-pkcs1-sha512.sig"),
    ),
    (
        alg_id::RSA_ENCRYPTION,
        alg_id::RSA_PSS_SHA256,
        RSA_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/rsa-pss-sha256.sig"),
    ),
    (
        alg_id::RSA_ENCRYPTION,
        alg_id::RSA_PSS_SHA384,
        RSA_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/rsa-pss-sha384.sig"),
    ),
    (
        alg_id::RSA_ENCRYPTION,
        alg_id::RSA_PSS_SHA512,
        RSA_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/rsa-pss-sha512.sig"),
    ),
    (
        alg_id::RSA_ENCRYPTION,
        alg_id::RSA_PSS_SHA256,
        include_bytes!("../../crates/mahi-tls/tests/data/rsa-low-public.der"),
        include_bytes!("../../crates/mahi-tls/tests/data/rsa-low-pss-sha256.sig"),
    ),
    (
        alg_id::ECDSA_P256,
        alg_id::ECDSA_SHA256,
        P256_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/p256-sha256.sig"),
    ),
    (
        alg_id::ECDSA_P256,
        alg_id::ECDSA_SHA384,
        P256_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/p256-sha384.sig"),
    ),
    (
        alg_id::ECDSA_P384,
        alg_id::ECDSA_SHA256,
        P384_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/p384-sha256.sig"),
    ),
    (
        alg_id::ECDSA_P384,
        alg_id::ECDSA_SHA384,
        P384_PUBLIC,
        include_bytes!("../../crates/mahi-tls/tests/data/p384-sha384.sig"),
    ),
];

static ALGORITHMS: LazyLock<WebPkiSupportedAlgorithms> =
    LazyLock::new(|| mahi_tls::provider().signature_verification_algorithms);

static VERIFIER: LazyLock<Arc<WebPkiServerVerifier>> = LazyLock::new(|| {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(mahi_tls::provider()))
        .build()
        .expect("the Web PKI roots make a verifier")
});

fn algorithm(
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
) -> &'static dyn SignatureVerificationAlgorithm {
    ALGORITHMS
        .all
        .iter()
        .copied()
        .find(|algorithm| {
            algorithm.public_key_alg_id() == public_key && algorithm.signature_alg_id() == signature
        })
        .expect("mahi-tls verifies every fixture's algorithm")
}

fn take<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((length, rest)) = data.split_first_chunk::<2>() else {
        return std::mem::take(data);
    };
    let length = usize::from(u16::from_be_bytes(*length)).min(rest.len());
    let (taken, rest) = rest.split_at(length);
    *data = rest;
    taken
}

fn mutated(original: &[u8], data: &mut &[u8]) -> Vec<u8> {
    let mut bytes = original.to_vec();
    let Some((at, rest)) = data.split_first_chunk::<2>() else {
        return bytes;
    };
    *data = rest;
    let at = usize::from(u16::from_be_bytes(*at)) % original.len().max(1);
    for (offset, flip) in take(data).iter().enumerate() {
        if let Some(byte) = bytes.get_mut(at + offset) {
            *byte ^= flip;
        }
    }
    bytes
}

fn verify_chain(chain: &[Vec<u8>], name: &str, now: u64) -> bool {
    let certificates: Vec<CertificateDer<'_>> = chain
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let Some((leaf, intermediates)) = certificates.split_first() else {
        return false;
    };
    let Ok(name) = ServerName::try_from(name) else {
        return false;
    };
    VERIFIER
        .verify_server_cert(
            leaf,
            intermediates,
            &name,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(now)),
        )
        .is_ok()
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&choice, mut rest)) = data.split_first() else {
        return;
    };
    match choice % 4 {
        0 => {
            let all = ALGORITHMS.all;
            let algorithm = all[usize::from(choice / 4) % all.len()];
            let key = take(&mut rest);
            let signature = take(&mut rest);
            let _ = algorithm.verify_signature(key, rest, signature);
        }
        1 => {
            let (public_key_alg, signature_alg, key, signature) =
                SIGNED[usize::from(choice / 4) % SIGNED.len()];
            let changed_key = mutated(key, &mut rest);
            let changed_signature = mutated(signature, &mut rest);
            let changed_message = mutated(MESSAGE, &mut rest);
            let unchanged =
                changed_key == key && changed_signature == signature && changed_message == MESSAGE;
            let verified = algorithm(public_key_alg, signature_alg)
                .verify_signature(&changed_key, &changed_message, &changed_signature)
                .is_ok();
            if unchanged {
                assert!(verified, "an untouched fixture verifies");
            }
        }
        2 => {
            let which = usize::from(choice / 4) % RELAY_CHAIN.len();
            let mut chain: Vec<Vec<u8>> = RELAY_CHAIN.iter().map(|der| der.to_vec()).collect();
            chain[which] = mutated(RELAY_CHAIN[which], &mut rest);
            let unchanged = chain[which] == RELAY_CHAIN[which];
            let verified = verify_chain(&chain, RELAY_NAME, WHILE_THE_RELAY_CERTIFICATE_IS_VALID);
            if unchanged {
                assert!(verified, "the untouched relay chain verifies");
            }
        }
        _ => {
            let mut chain = Vec::new();
            while !rest.is_empty() && chain.len() < 5 {
                chain.push(take(&mut rest).to_vec());
            }
            let _ = verify_chain(&chain, "example.com", WHILE_THE_RELAY_CERTIFICATE_IS_VALID);
        }
    }
});
