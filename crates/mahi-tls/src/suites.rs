use aes_gcm::{
    Aes128Gcm,
    Aes256Gcm,
};
use chacha20poly1305::ChaCha20Poly1305;
use rustls::{
    CipherSuite,
    SupportedCipherSuite,
    Tls13CipherSuite,
    crypto::{
        CipherSuiteCommon,
        tls13::HkdfUsingHmac,
    },
};

use crate::{
    aead::Tls13Aead,
    hash::{
        SHA256,
        SHA384,
    },
    hmac::{
        HMAC_SHA256,
        HMAC_SHA384,
    },
    quic::{
        HeaderCipher,
        QuicAlgorithm,
    },
};

const AES_GCM_TLS_CONFIDENTIALITY_LIMIT: u64 = 1 << 24;
const AES_GCM_QUIC_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
const AES_GCM_QUIC_INTEGRITY_LIMIT: u64 = 1 << 52;
const CHACHA20_POLY1305_QUIC_INTEGRITY_LIMIT: u64 = 1 << 36;

pub(crate) static ALL: &[SupportedCipherSuite] = &[
    SupportedCipherSuite::Tls13(&AES_128_GCM_SHA256),
    SupportedCipherSuite::Tls13(&AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls13(&CHACHA20_POLY1305_SHA256),
];

static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA256);
static HKDF_SHA384: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA384);

static AES_128_GCM: Tls13Aead<Aes128Gcm> = Tls13Aead::new();
static AES_256_GCM: Tls13Aead<Aes256Gcm> = Tls13Aead::new();
static CHACHA20_POLY1305: Tls13Aead<ChaCha20Poly1305> = Tls13Aead::new();

pub(crate) static AES_128_GCM_SHA256_QUIC: QuicAlgorithm<Aes128Gcm> = QuicAlgorithm::new(
    HeaderCipher::Aes128,
    AES_GCM_QUIC_CONFIDENTIALITY_LIMIT,
    AES_GCM_QUIC_INTEGRITY_LIMIT,
);
static AES_256_GCM_SHA384_QUIC: QuicAlgorithm<Aes256Gcm> = QuicAlgorithm::new(
    HeaderCipher::Aes256,
    AES_GCM_QUIC_CONFIDENTIALITY_LIMIT,
    AES_GCM_QUIC_INTEGRITY_LIMIT,
);
static CHACHA20_POLY1305_SHA256_QUIC: QuicAlgorithm<ChaCha20Poly1305> = QuicAlgorithm::new(
    HeaderCipher::ChaCha20,
    u64::MAX,
    CHACHA20_POLY1305_QUIC_INTEGRITY_LIMIT,
);

pub(crate) static AES_128_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: AES_GCM_TLS_CONFIDENTIALITY_LIMIT,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &AES_128_GCM,
    quic: Some(&AES_128_GCM_SHA256_QUIC),
};

static AES_256_GCM_SHA384: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &SHA384,
        confidentiality_limit: AES_GCM_TLS_CONFIDENTIALITY_LIMIT,
    },
    hkdf_provider: &HKDF_SHA384,
    aead_alg: &AES_256_GCM,
    quic: Some(&AES_256_GCM_SHA384_QUIC),
};

static CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &CHACHA20_POLY1305,
    quic: Some(&CHACHA20_POLY1305_SHA256_QUIC),
};
