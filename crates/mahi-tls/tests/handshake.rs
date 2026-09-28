//! Full TLS 1.3 handshakes between rustls peers that use only mahi's provider.

use std::{
    io::{
        Read,
        Write,
    },
    sync::Arc,
};

use ed25519_dalek::{
    Signer as _,
    SigningKey as Ed25519Key,
};
use rustls::{
    CipherSuite,
    ClientConfig,
    ClientConnection,
    DigitallySignedStruct,
    Error,
    ServerConfig,
    ServerConnection,
    SignatureAlgorithm,
    SignatureScheme,
    client::danger::{
        HandshakeSignatureValid,
        ServerCertVerified,
        ServerCertVerifier,
    },
    crypto::{
        CryptoProvider,
        verify_tls13_signature_with_raw_key,
    },
    pki_types::{
        CertificateDer,
        ServerName,
        SubjectPublicKeyInfoDer,
        UnixTime,
        alg_id,
    },
    server::{
        ClientHello,
        ResolvesServerCert,
    },
    sign::{
        CertifiedKey,
        Signer,
        SigningKey,
        public_key_to_spki,
    },
    version::TLS13,
};

#[derive(Debug, Clone)]
struct RawKey(Ed25519Key);

impl RawKey {
    fn spki(&self) -> SubjectPublicKeyInfoDer<'static> {
        public_key_to_spki(&alg_id::ED25519, self.0.verifying_key().as_bytes())
    }
}

impl SigningKey for RawKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki())
    }
}

impl Signer for RawKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[derive(Debug)]
struct Resolver(Arc<CertifiedKey>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct Pinned {
    spki: SubjectPublicKeyInfoDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if intermediates.is_empty() && end_entity.as_ref() == self.spki.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("unexpected server key".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("tls 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn only(suite: CipherSuite) -> Arc<CryptoProvider> {
    let mut provider = mahi_tls::provider();
    provider
        .cipher_suites
        .retain(|offered| offered.suite() == suite);
    assert_eq!(provider.cipher_suites.len(), 1);
    Arc::new(provider)
}

fn configs(
    provider: &Arc<CryptoProvider>,
    server_key: &RawKey,
    pinned: &RawKey,
) -> (ClientConfig, ServerConfig) {
    let certified = CertifiedKey::new(
        vec![CertificateDer::from(server_key.spki().to_vec())],
        Arc::new(server_key.clone()),
    );
    let server = ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_protocol_versions(&[&TLS13])
        .expect("the provider offers tls 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver(Arc::new(certified))));
    let client = ClientConfig::builder_with_provider(Arc::clone(provider))
        .with_protocol_versions(&[&TLS13])
        .expect("the provider offers tls 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            spki: pinned.spki(),
            provider: Arc::clone(provider),
        }))
        .with_no_client_auth();
    (client, server)
}

fn pump(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..16 {
        let mut wire = Vec::new();
        while client.wants_write() {
            client
                .write_tls(&mut wire)
                .expect("writing to memory works");
        }
        let mut sent = wire.as_slice();
        while !sent.is_empty() {
            server
                .read_tls(&mut sent)
                .expect("the connection takes the bytes");
            server.process_new_packets()?;
        }
        let mut wire = Vec::new();
        while server.wants_write() {
            server
                .write_tls(&mut wire)
                .expect("writing to memory works");
        }
        let mut sent = wire.as_slice();
        while !sent.is_empty() {
            client
                .read_tls(&mut sent)
                .expect("the connection takes the bytes");
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() && !client.wants_write() {
            return Ok(());
        }
    }
    Err(Error::General("the handshake did not finish".into()))
}

fn read_exactly(reader: &mut dyn Read, len: usize) -> Vec<u8> {
    let mut data = vec![0; len];
    reader
        .read_exact(&mut data)
        .expect("the peer sent the whole message");
    data
}

#[test]
fn every_suite_completes_a_handshake_and_carries_data_both_ways() {
    let server_key = RawKey(Ed25519Key::from_bytes(&[7; 32]));
    for suite in [
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let provider = only(suite);
        let (client_config, server_config) = configs(&provider, &server_key, &server_key);
        let name = ServerName::try_from("mahi.test").unwrap();
        let mut client = ClientConnection::new(Arc::new(client_config), name).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        pump(&mut client, &mut server).unwrap();
        assert_eq!(client.negotiated_cipher_suite().unwrap().suite(), suite);

        for round in 0..3_u8 {
            let large = vec![round; 12_000];
            client.writer().write_all(&[round; 4]).unwrap();
            server.writer().write_all(&large).unwrap();
            pump(&mut client, &mut server).unwrap();
            assert_eq!(read_exactly(&mut server.reader(), 4), [round; 4]);
            assert_eq!(read_exactly(&mut client.reader(), large.len()), large);
        }
    }
}

#[test]
fn a_server_with_another_key_is_refused() {
    let provider = Arc::new(mahi_tls::provider());
    let server_key = RawKey(Ed25519Key::from_bytes(&[7; 32]));
    let expected = RawKey(Ed25519Key::from_bytes(&[8; 32]));
    let (client_config, server_config) = configs(&provider, &server_key, &expected);
    let name = ServerName::try_from("mahi.test").unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), name).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    assert!(matches!(
        pump(&mut client, &mut server),
        Err(Error::General(reason)) if reason == "unexpected server key"
    ));
}
