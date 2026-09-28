//! A pure-Rust rustls crypto provider for mahi's QUIC and TLS 1.3 connections, built on the
//! `RustCrypto` implementations.

mod aead;
mod hash;
mod hmac;
mod kx;
mod quic;
mod suites;
#[cfg(test)]
mod testing;
mod verify;

use std::sync::Arc;

use rustls::{
    Error,
    crypto::{
        CryptoProvider,
        GetRandomFailed,
        KeyProvider,
        SecureRandom,
    },
    pki_types::PrivateKeyDer,
    sign::SigningKey,
};

/// Returns the crypto provider mahi gives rustls and iroh: TLS 1.3 only, with AES-GCM and
/// ChaCha20-Poly1305, X25519, and QUIC packet and header protection.
///
/// It loads no private keys: whoever signs, such as iroh with its node key, brings its own
/// signer.
#[must_use]
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: suites::ALL.to_vec(),
        kx_groups: vec![kx::X25519],
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Random,
        key_provider: &NoKeys,
    }
}

#[derive(Debug)]
struct Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::fill(buf).map_err(|_| GetRandomFailed)
    }
}

#[derive(Debug)]
struct NoKeys;

impl KeyProvider for NoKeys {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General("mahi-tls loads no private keys".into()))
    }
}

#[cfg(test)]
mod tests {
    use rustls::{
        CipherSuite,
        SupportedCipherSuite,
    };

    use super::*;

    #[test]
    fn only_tls13_suites_are_offered_including_the_one_quic_starts_with() {
        let provider = provider();
        let suites: Vec<CipherSuite> = provider
            .cipher_suites
            .iter()
            .map(|suite| {
                assert!(matches!(suite, SupportedCipherSuite::Tls13(_)));
                suite.suite()
            })
            .collect();
        assert!(suites.contains(&CipherSuite::TLS13_AES_128_GCM_SHA256));
        assert_eq!(suites.len(), 3);
    }

    #[test]
    fn random_bytes_are_drawn_and_private_keys_are_refused() {
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        Random.fill(&mut first).unwrap();
        Random.fill(&mut second).unwrap();
        assert_ne!(first, second);
        let key = PrivateKeyDer::Pkcs8(vec![0_u8; 48].into());
        assert!(NoKeys.load_private_key(key).is_err());
    }
}
