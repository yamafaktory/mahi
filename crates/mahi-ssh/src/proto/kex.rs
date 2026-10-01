use std::ops::Range;

use ml_kem::{
    Decapsulate,
    KeyExport,
    ml_kem_768,
};
use sha2::{
    Digest,
    Sha256,
};
use signature::Verifier;
use ssh_key::{
    PublicKey,
    Signature,
};
use thiserror::Error;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use super::{
    cipher::CipherName,
    message::KexInit,
    wire::{
        NameList,
        Reader,
        WireError,
        put_mpint,
        put_string,
    },
};

pub(crate) const CLIENT_ID: &[u8] = b"SSH-2.0-mahi";
pub(crate) const CLIENT_KEX: &str = "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-c-v00@openssh.com";
pub(crate) const CLIENT_CIPHERS: &str =
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com";
pub(crate) const CLIENT_MACS: &str = "hmac-sha2-256-etm@openssh.com";
pub(crate) const CLIENT_COMPRESSION: &str = "none";
const STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
const MAX_ID_LINE: usize = 255;
const MAX_LINES_BEFORE_ID: usize = 32;
const MAX_BYTES_BEFORE_ID: usize = 8 << 10;
const HASH_BYTES: usize = 32;
const X25519_BYTES: usize = 32;
const MLKEM_PUBLIC_BYTES: usize = 1184;
const MLKEM_CIPHERTEXT_BYTES: usize = 1088;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum KexError {
    #[error("the server's identification line is malformed or too long")]
    Identification,
    #[error("the server does not speak SSH protocol version 2.0")]
    Version,
    #[error("the server sent too much before its identification line")]
    TooMuchBeforeIdentification,
    #[error("the server offers none of the {0} mahi supports")]
    NoCommon(Category),
    #[error(
        "the server does not offer strict key exchange (kex-strict-s-v00@openssh.com), the fix \
         for the Terrapin attack; update its SSH server"
    )]
    NoStrictKex,
    #[error("the server guessed a key exchange packet, which mahi does not accept")]
    Guessed,
    #[error("the server's key exchange value has the wrong length")]
    ServerPublic,
    #[error("the server's key exchange value gives a weak shared secret")]
    WeakSharedSecret,
    #[error("the server's host key is malformed")]
    HostKey,
    #[error("the server's host key or signature is not of the negotiated type")]
    HostKeyType,
    #[error("the server's signature of the key exchange does not verify")]
    Signature,
    #[error("cannot get random bytes from the operating system")]
    Random,
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Category {
    Kex,
    HostKey,
    Cipher,
    Compression,
}

impl std::fmt::Display for Category {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Kex => "key exchange methods",
            Self::HostKey => "host key types",
            Self::Cipher => "ciphers",
            Self::Compression => "compression methods (none)",
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct Identification {
    lines: usize,
    bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Line {
    Other { consumed: usize },
    Version { consumed: usize, id: Range<usize> },
}

impl Identification {
    pub(crate) fn read(&mut self, buffered: &[u8]) -> Result<Option<Line>, KexError> {
        if b"SSH-".starts_with(buffered) {
            return Ok(None);
        }
        let version = buffered.starts_with(b"SSH-");
        let limit = if version {
            MAX_ID_LINE
        } else {
            MAX_BYTES_BEFORE_ID - self.bytes
        };
        let window = buffered.get(..limit).unwrap_or(buffered);
        let Some(newline) = window.iter().position(|&byte| byte == b'\n') else {
            return match (buffered.len() >= limit, version) {
                (false, _) => Ok(None),
                (true, true) => Err(KexError::Identification),
                (true, false) => Err(KexError::TooMuchBeforeIdentification),
            };
        };
        let consumed = newline + 1;
        let line = buffered.get(..newline).unwrap_or_default();
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b"SSH-") {
            if consumed > MAX_ID_LINE || line.iter().any(|&byte| !(b' '..=b'~').contains(&byte)) {
                return Err(KexError::Identification);
            }
            if !(line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-")) {
                return Err(KexError::Version);
            }
            return Ok(Some(Line::Version {
                consumed,
                id: 0..line.len(),
            }));
        }
        self.lines += 1;
        self.bytes += consumed;
        if self.lines > MAX_LINES_BEFORE_ID || self.bytes > MAX_BYTES_BEFORE_ID {
            return Err(KexError::TooMuchBeforeIdentification);
        }
        Ok(Some(Line::Other { consumed }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KexMethod {
    MlKem768X25519,
    Curve25519,
}

impl KexMethod {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "mlkem768x25519-sha256" => Some(Self::MlKem768X25519),
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => Some(Self::Curve25519),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostKeyAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
}

impl HostKeyAlgorithm {
    pub(crate) const ALL: [Self; 3] = [Self::Ed25519, Self::EcdsaP256, Self::EcdsaP384];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
            Self::EcdsaP384 => "ecdsa-sha2-nistp384",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.name() == name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Algorithms {
    pub(crate) kex: KexMethod,
    pub(crate) host_key: HostKeyAlgorithm,
    pub(crate) cipher_c2s: CipherName,
    pub(crate) cipher_s2c: CipherName,
}

fn choose<'a>(
    client: NameList<'a>,
    server: NameList<'_>,
    category: Category,
) -> Result<&'a str, KexError> {
    client
        .names()
        .find(|name| server.contains(name))
        .ok_or(KexError::NoCommon(category))
}

pub(crate) fn negotiate(
    client: &KexInit<'_>,
    server: &KexInit<'_>,
    first: bool,
) -> Result<Algorithms, KexError> {
    if first && !server.kex.contains(STRICT_SERVER) {
        return Err(KexError::NoStrictKex);
    }
    if server.first_kex_follows {
        return Err(KexError::Guessed);
    }
    let kex = client
        .kex
        .names()
        .filter_map(|name| KexMethod::from_name(name).map(|method| (name, method)))
        .find(|(name, _)| server.kex.contains(name))
        .map(|(_, method)| method)
        .ok_or(KexError::NoCommon(Category::Kex))?;
    let host_key =
        HostKeyAlgorithm::from_name(choose(client.host_key, server.host_key, Category::HostKey)?)
            .ok_or(KexError::NoCommon(Category::HostKey))?;
    let cipher = |client, server| {
        CipherName::from_name(choose(client, server, Category::Cipher)?)
            .ok_or(KexError::NoCommon(Category::Cipher))
    };
    let cipher_c2s = cipher(client.cipher_c2s, server.cipher_c2s)?;
    let cipher_s2c = cipher(client.cipher_s2c, server.cipher_s2c)?;
    for (ours, theirs) in [
        (client.compression_c2s, server.compression_c2s),
        (client.compression_s2c, server.compression_s2c),
    ] {
        if choose(ours, theirs, Category::Compression)? != "none" {
            return Err(KexError::NoCommon(Category::Compression));
        }
    }
    Ok(Algorithms {
        kex,
        host_key,
        cipher_c2s,
        cipher_s2c,
    })
}

pub(crate) struct KeyShare {
    x25519: StaticSecret,
    mlkem: Option<Box<ml_kem_768::DecapsulationKey>>,
    public: Vec<u8>,
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyShare")
    }
}

impl KeyShare {
    pub(crate) fn generate(method: KexMethod) -> Result<Self, KexError> {
        let mut x25519 = Zeroizing::new([0; X25519_BYTES]);
        getrandom::fill(x25519.as_mut()).map_err(|_| KexError::Random)?;
        let seed = match method {
            KexMethod::Curve25519 => None,
            KexMethod::MlKem768X25519 => {
                let mut seed = Zeroizing::new([0; 64]);
                getrandom::fill(seed.as_mut()).map_err(|_| KexError::Random)?;
                Some(seed)
            }
        };
        Ok(Self::from_randomness(&x25519, seed.as_deref()))
    }

    pub(crate) fn from_randomness(
        x25519: &[u8; X25519_BYTES],
        mlkem_seed: Option<&[u8; 64]>,
    ) -> Self {
        let x25519 = StaticSecret::from(*x25519);
        let mlkem = mlkem_seed
            .map(|seed| Box::new(ml_kem_768::DecapsulationKey::from_seed((*seed).into())));
        let mut public = Vec::with_capacity(MLKEM_PUBLIC_BYTES + X25519_BYTES);
        if let Some(mlkem) = &mlkem {
            public.extend_from_slice(&mlkem.encapsulation_key().to_bytes());
        }
        public.extend_from_slice(x25519_dalek::PublicKey::from(&x25519).as_bytes());
        Self {
            x25519,
            mlkem,
            public,
        }
    }

    pub(crate) fn public(&self) -> &[u8] {
        &self.public
    }

    pub(crate) fn agree(&self, server_public: &[u8]) -> Result<SharedSecret, KexError> {
        match &self.mlkem {
            None => Ok(SharedSecret::Mpint(self.x25519_agree(server_public)?)),
            Some(mlkem) => {
                let (ciphertext, classical) = server_public
                    .split_at_checked(MLKEM_CIPHERTEXT_BYTES)
                    .ok_or(KexError::ServerPublic)?;
                let ciphertext = ml_kem_768::Ciphertext::try_from(ciphertext)
                    .map_err(|_| KexError::ServerPublic)?;
                let classical = self.x25519_agree(classical)?;
                let quantum = Zeroizing::new(<[u8; 32]>::from(mlkem.decapsulate(&ciphertext)));
                let mut hasher = Sha256::new();
                hasher.update(quantum.as_slice());
                hasher.update(classical.as_slice());
                Ok(SharedSecret::String(Zeroizing::new(
                    hasher.finalize().into(),
                )))
            }
        }
    }

    fn x25519_agree(&self, server_public: &[u8]) -> Result<Zeroizing<[u8; 32]>, KexError> {
        let server: [u8; X25519_BYTES] = server_public
            .try_into()
            .map_err(|_| KexError::ServerPublic)?;
        let shared = self.x25519.diffie_hellman(&server.into());
        if !shared.was_contributory() {
            return Err(KexError::WeakSharedSecret);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

pub(crate) fn verify_host_key(
    algorithm: HostKeyAlgorithm,
    key_blob: &[u8],
    signature_blob: &[u8],
    hash: &[u8; HASH_BYTES],
) -> Result<PublicKey, KexError> {
    let key = PublicKey::from_bytes(key_blob).map_err(|_| KexError::HostKey)?;
    if key.to_bytes().map_err(|_| KexError::HostKey)? != key_blob {
        return Err(KexError::HostKey);
    }
    if key.algorithm().as_str() != algorithm.name() {
        return Err(KexError::HostKeyType);
    }
    let mut reader = Reader::new(signature_blob);
    let signature_algorithm = reader.string().map_err(|_| KexError::Signature)?;
    let signature = reader.string().map_err(|_| KexError::Signature)?;
    reader.finish().map_err(|_| KexError::Signature)?;
    if signature_algorithm != algorithm.name().as_bytes() {
        return Err(KexError::HostKeyType);
    }
    let signature =
        Signature::new(key.algorithm(), signature.to_vec()).map_err(|_| KexError::Signature)?;
    key.key_data()
        .verify(hash, &signature)
        .map_err(|_| KexError::Signature)?;
    Ok(key)
}

pub(crate) enum SharedSecret {
    Mpint(Zeroizing<[u8; 32]>),
    String(Zeroizing<[u8; 32]>),
}

impl SharedSecret {
    fn put(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        match self {
            Self::Mpint(secret) => put_mpint(out, secret.as_ref()),
            Self::String(secret) => put_string(out, secret.as_ref()),
        }
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SharedSecret")
    }
}

pub(crate) struct ExchangeInputs<'a> {
    pub(crate) client_id: &'a [u8],
    pub(crate) server_id: &'a [u8],
    pub(crate) client_kexinit: &'a [u8],
    pub(crate) server_kexinit: &'a [u8],
    pub(crate) host_key: &'a [u8],
    pub(crate) client_public: &'a [u8],
    pub(crate) server_public: &'a [u8],
}

pub(crate) fn exchange_hash(
    inputs: &ExchangeInputs<'_>,
    secret: &SharedSecret,
) -> Result<[u8; HASH_BYTES], WireError> {
    let mut hasher = Sha256::new();
    for field in [
        inputs.client_id,
        inputs.server_id,
        inputs.client_kexinit,
        inputs.server_kexinit,
        inputs.host_key,
        inputs.client_public,
        inputs.server_public,
    ] {
        let length = u32::try_from(field.len()).map_err(|_| WireError::TooLong)?;
        hasher.update(length.to_be_bytes());
        hasher.update(field);
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(40));
    secret.put(&mut encoded)?;
    hasher.update(encoded.as_slice());
    Ok(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyUse {
    IvClientToServer,
    IvServerToClient,
    KeyClientToServer,
    KeyServerToClient,
}

impl KeyUse {
    fn letter(self) -> u8 {
        match self {
            Self::IvClientToServer => b'A',
            Self::IvServerToClient => b'B',
            Self::KeyClientToServer => b'C',
            Self::KeyServerToClient => b'D',
        }
    }
}

pub(crate) fn derive_key(
    secret: &SharedSecret,
    hash: &[u8; HASH_BYTES],
    session_id: &[u8; HASH_BYTES],
    key_use: KeyUse,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(40));
    secret.put(&mut encoded)?;
    let mut key = Zeroizing::new(Vec::with_capacity(length.next_multiple_of(HASH_BYTES)));
    let mut first = Sha256::new();
    first.update(encoded.as_slice());
    first.update(hash);
    first.update([key_use.letter()]);
    first.update(session_id);
    key.extend_from_slice(&first.finalize());
    while key.len() < length {
        let mut next = Sha256::new();
        next.update(encoded.as_slice());
        next.update(hash);
        next.update(key.as_slice());
        key.extend_from_slice(&next.finalize());
    }
    key.truncate(length);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn list(text: &str) -> NameList<'_> {
        NameList::parse(text.as_bytes()).unwrap()
    }

    fn init<'a>(
        kex: &'a str,
        host_key: &'a str,
        cipher: &'a str,
        compression: &'a str,
    ) -> KexInit<'a> {
        KexInit {
            cookie: [0; 16],
            kex: list(kex),
            host_key: list(host_key),
            cipher_c2s: list(cipher),
            cipher_s2c: list(cipher),
            mac_c2s: list("hmac-sha1"),
            mac_s2c: list("hmac-sha1"),
            compression_c2s: list(compression),
            compression_s2c: list(compression),
            language_c2s: list(""),
            language_s2c: list(""),
            first_kex_follows: false,
        }
    }

    fn client() -> KexInit<'static> {
        init(
            CLIENT_KEX,
            "ssh-ed25519,ecdsa-sha2-nistp256",
            CLIENT_CIPHERS,
            CLIENT_COMPRESSION,
        )
    }

    fn read_all(bytes: &[u8]) -> Result<Vec<Line>, KexError> {
        let mut identification = Identification::default();
        let mut lines = Vec::new();
        let mut at = 0;
        while let Some(line) = identification.read(&bytes[at..])? {
            at += match &line {
                Line::Other { consumed } | Line::Version { consumed, .. } => *consumed,
            };
            let done = matches!(line, Line::Version { .. });
            lines.push(line);
            if done {
                break;
            }
        }
        Ok(lines)
    }

    #[test]
    fn the_identification_line_is_found_after_other_lines() {
        let lines = read_all(b"hello\r\nworld\nSSH-2.0-OpenSSH_10.0 Debian\r\nrest").unwrap();
        assert_eq!(
            lines,
            [
                Line::Other { consumed: 7 },
                Line::Other { consumed: 6 },
                Line::Version {
                    consumed: 29,
                    id: 0..27
                }
            ]
        );
        assert_eq!(
            read_all(b"SSH-1.99-old\n").unwrap(),
            [Line::Version {
                consumed: 13,
                id: 0..12
            }]
        );
    }

    #[test]
    fn a_partial_line_waits_for_more() {
        let mut identification = Identification::default();
        assert_eq!(identification.read(b""), Ok(None));
        assert_eq!(identification.read(b"SS"), Ok(None));
        assert_eq!(identification.read(b"SSH-2.0-Open"), Ok(None));
        assert_eq!(identification.read(b"banner without end"), Ok(None));
    }

    #[test]
    fn other_protocol_versions_are_refused() {
        assert_eq!(read_all(b"SSH-1.5-old\r\n"), Err(KexError::Version));
        assert_eq!(read_all(b"SSH-3.0-new\r\n"), Err(KexError::Version));
    }

    #[test]
    fn an_identification_line_over_255_bytes_or_with_controls_is_refused() {
        let mut long = b"SSH-2.0-".to_vec();
        long.resize(253, b'x');
        long.extend_from_slice(b"\r\n");
        assert!(read_all(&long).is_ok());
        long.insert(10, b'x');
        assert_eq!(read_all(&long), Err(KexError::Identification));
        let mut endless = b"SSH-2.0-".to_vec();
        endless.resize(255, b'x');
        assert_eq!(read_all(&endless), Err(KexError::Identification));
        assert_eq!(
            read_all(b"SSH-2.0-a\x1b[2Jb\r\n"),
            Err(KexError::Identification)
        );
        assert_eq!(
            read_all(b"SSH-2.0-a\x00b\r\n"),
            Err(KexError::Identification)
        );
    }

    #[test]
    fn at_most_32_lines_and_8_kib_come_before_the_identification() {
        let mut lines = b"x\n".repeat(32);
        lines.extend_from_slice(b"SSH-2.0-ok\n");
        assert!(read_all(&lines).is_ok());
        let mut lines = b"x\n".repeat(33);
        lines.extend_from_slice(b"SSH-2.0-ok\n");
        assert_eq!(read_all(&lines), Err(KexError::TooMuchBeforeIdentification));
        let mut big = vec![b'x'; 8191];
        big.push(b'\n');
        big.extend_from_slice(b"SSH-2.0-ok\n");
        assert!(read_all(&big).is_ok());
        let mut over = vec![b'x'; 8192];
        over.push(b'\n');
        assert_eq!(read_all(&over), Err(KexError::TooMuchBeforeIdentification));
        let endless = vec![b'x'; 9000];
        assert_eq!(
            read_all(&endless),
            Err(KexError::TooMuchBeforeIdentification)
        );
    }

    #[test]
    fn the_8_kib_budget_counts_every_line_before_the_identification() {
        let mut two = [vec![b'x'; 4095], vec![b'\n']].concat().repeat(2);
        two.extend_from_slice(b"SSH-2.0-ok\n");
        assert!(read_all(&two).is_ok());
        let mut over_two = [vec![b'x'; 4096], vec![b'\n']].concat().repeat(2);
        over_two.extend_from_slice(b"SSH-2.0-ok\n");
        assert_eq!(
            read_all(&over_two),
            Err(KexError::TooMuchBeforeIdentification)
        );
    }

    #[test]
    fn an_endless_line_after_other_lines_is_refused_within_the_budget() {
        let mut bytes = [vec![b'x'; 4096], vec![b'\n']].concat();
        bytes.extend_from_slice(&[b'y'; 4096]);
        assert_eq!(read_all(&bytes), Err(KexError::TooMuchBeforeIdentification));
    }

    #[test]
    fn errors_name_what_is_missing() {
        assert_eq!(
            KexError::NoCommon(Category::Cipher).to_string(),
            "the server offers none of the ciphers mahi supports"
        );
        for category in [Category::Kex, Category::HostKey, Category::Compression] {
            assert!(!category.to_string().is_empty());
        }
    }

    #[test]
    fn a_shared_secret_with_a_leading_zero_byte_is_a_shorter_mpint() {
        let client_public = hex("75870ced945b9dc377eb97dcd41637a38ff00e38190f8d0bf9226bae29a05232");
        let server_public = hex("a1d78ddb252c683ffbbda074f242cb77d66a00b1e6905a3e6854e3ddd7869540");
        let secret = SharedSecret::Mpint(secret_of(&hex(
            "00201d273cee20b7b762a7757720825163bccdce3fb4ce4506b495058b809e35",
        )));
        let h = exchange_hash(&inputs(&client_public, &server_public), &secret).unwrap();
        assert_eq!(
            h.to_vec(),
            hex("8b9f2e4ca4c8f1a506d8bae847ce814f07f52e4db7a7193c38f7c5a9926ff455")
        );
        assert_eq!(
            derive_key(&secret, &h, &h, KeyUse::KeyClientToServer, 64)
                .unwrap()
                .to_vec(),
            hex(
                "6c48c51691c31b3816df4bd27d7b906739c8f14c8a83b367cfbd6ec2f5e797d3f422b3476efb58c8654a3e3dc041052159ab7c3d679f6e853c9873852311f653"
            )
        );
    }

    #[test]
    fn secrets_never_appear_in_debug_output() {
        let share = KeyShare::from_randomness(&[0xab; 32], Some(&[0xcd; 64]));
        assert_eq!(format!("{share:?}"), "KeyShare");
        let secret = SharedSecret::String(Zeroizing::new([0xef; 32]));
        assert_eq!(format!("{secret:?}"), "SharedSecret");
    }

    #[test]
    fn the_client_order_wins_and_markers_are_never_chosen() {
        let server = init(
            "kex-strict-s-v00@openssh.com,curve25519-sha256@libssh.org,mlkem768x25519-sha256",
            "ecdsa-sha2-nistp256,ssh-ed25519,ssh-rsa",
            "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
            "zlib,none",
        );
        assert_eq!(
            negotiate(&client(), &server, true),
            Ok(Algorithms {
                kex: KexMethod::MlKem768X25519,
                host_key: HostKeyAlgorithm::Ed25519,
                cipher_c2s: CipherName::Aes256Gcm,
                cipher_s2c: CipherName::Aes256Gcm,
            })
        );
        let only_markers = init(
            "kex-strict-s-v00@openssh.com,kex-strict-c-v00@openssh.com",
            "ssh-ed25519",
            CLIENT_CIPHERS,
            "none",
        );
        assert_eq!(
            negotiate(&client(), &only_markers, true),
            Err(KexError::NoCommon(Category::Kex))
        );
    }

    #[test]
    fn a_server_without_strict_kex_is_refused_only_on_the_first_exchange() {
        let server = init("curve25519-sha256", "ssh-ed25519", CLIENT_CIPHERS, "none");
        assert_eq!(
            negotiate(&client(), &server, true),
            Err(KexError::NoStrictKex)
        );
        assert_eq!(
            negotiate(&client(), &server, false).map(|chosen| chosen.kex),
            Ok(KexMethod::Curve25519)
        );
    }

    #[test]
    fn old_algorithms_compression_and_guesses_are_refused() {
        let strict = "curve25519-sha256,kex-strict-s-v00@openssh.com";
        for (server, error) in [
            (
                init(
                    "diffie-hellman-group14-sha256,kex-strict-s-v00@openssh.com",
                    "ssh-ed25519",
                    CLIENT_CIPHERS,
                    "none",
                ),
                KexError::NoCommon(Category::Kex),
            ),
            (
                init(strict, "ssh-rsa,rsa-sha2-512", CLIENT_CIPHERS, "none"),
                KexError::NoCommon(Category::HostKey),
            ),
            (
                init(strict, "ssh-ed25519", "aes256-ctr,aes128-cbc", "none"),
                KexError::NoCommon(Category::Cipher),
            ),
            (
                init(strict, "ssh-ed25519", CLIENT_CIPHERS, "zlib@openssh.com"),
                KexError::NoCommon(Category::Compression),
            ),
        ] {
            assert_eq!(negotiate(&client(), &server, true), Err(error));
        }
        let mut guessing = init(strict, "ssh-ed25519", CLIENT_CIPHERS, "none");
        guessing.first_kex_follows = true;
        assert_eq!(
            negotiate(&client(), &guessing, true),
            Err(KexError::Guessed)
        );
    }

    #[test]
    fn each_direction_gets_its_own_cipher() {
        let mut server = init(
            "curve25519-sha256,kex-strict-s-v00@openssh.com",
            "ssh-ed25519",
            CLIENT_CIPHERS,
            "none",
        );
        server.cipher_c2s = list("aes128-gcm@openssh.com");
        let chosen = negotiate(&client(), &server, true).unwrap();
        assert_eq!(chosen.cipher_c2s, CipherName::Aes128Gcm);
        assert_eq!(chosen.cipher_s2c, CipherName::ChaCha20Poly1305);
    }

    fn inputs<'a>(client_public: &'a [u8], server_public: &'a [u8]) -> ExchangeInputs<'a> {
        ExchangeInputs {
            client_id: b"SSH-2.0-mahi",
            server_id: b"SSH-2.0-OpenSSH_10.0",
            client_kexinit: b"\x14client-kexinit",
            server_kexinit: b"\x14server-kexinit",
            host_key: b"host-key-blob",
            client_public,
            server_public,
        }
    }

    fn secret_of(bytes: &[u8]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(bytes.try_into().unwrap())
    }

    #[test]
    fn the_exchange_hash_and_keys_match_an_independent_implementation() {
        for (client_public, server_public, shared, hash, iv_c2s, key_c2s, key_s2c, string_hash) in [
            (
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                "96a6eb30fa592e02f5e287949419e37e9fc1c0519b205a4bb24655385f5035b2",
                "939be459862f876a2b979672",
                "6cb27ef2424d153062743f13e72bfe69a8f6bc7852e3600336ba3636bd03b8d25f60a4c52c25af7bda94594fd0b62e6126543420c7c0be94aea07b180095a92e",
                "4ed502de7c26ad61bf394b473a2a288eb527c20ac57f57e8c0e55828c6426e91",
                "96a6eb30fa592e02f5e287949419e37e9fc1c0519b205a4bb24655385f5035b2",
            ),
            (
                "62b7dc7d65c08282480b18084a88a354d2f24eb98eb08c2439c7cfa7c3d41e53",
                "a6bd0f838829b140e3ccaf0ff29fa13bc28f46ede251301d2e63c926d88bc11d",
                "946fef3483ddf9289e82cda41d78c06e27afa72bfdcba19c19fe5fd77fe7a83c",
                "f4ac73ebd01c9c456e4826f07581e250cdc3a16efec71311cd0300e4fe2387a9",
                "a0a9507a727a2cf219e5d4a8",
                "854e613eb5b98bfc758fd98096c4e95ff0c0e501d5f3f38dc17bf8e1e137ed73b878cbb59b923881ff29e1856d40fa771f0f10394f277c5a1c73ec97ddb76d4b",
                "556c184e27aca611456e73403fbc1602567d4fee51f7824a32f5dae1228f5e04",
                "1cabaf4e790977aacdee02e62dec08e7b83b397d40b7afb34bf22d5cd808f917",
            ),
        ] {
            let (client_public, server_public) = (hex(client_public), hex(server_public));
            let exchange = inputs(&client_public, &server_public);
            let secret = SharedSecret::Mpint(secret_of(&hex(shared)));
            let h = exchange_hash(&exchange, &secret).unwrap();
            assert_eq!(h.to_vec(), hex(hash));
            let derive = |key_use, length| {
                derive_key(&secret, &h, &h, key_use, length)
                    .unwrap()
                    .to_vec()
            };
            assert_eq!(derive(KeyUse::IvClientToServer, 12), hex(iv_c2s));
            assert_eq!(derive(KeyUse::KeyClientToServer, 64), hex(key_c2s));
            assert_eq!(derive(KeyUse::KeyServerToClient, 32), hex(key_s2c));
            let as_string = SharedSecret::String(secret_of(&hex(shared)));
            assert_eq!(
                exchange_hash(&exchange, &as_string).unwrap().to_vec(),
                hex(string_hash)
            );
        }
    }

    const ALICE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    fn array<const N: usize>(text: &str) -> [u8; N] {
        hex(text).try_into().unwrap()
    }

    fn secret_bytes(secret: &SharedSecret) -> (bool, [u8; 32]) {
        match secret {
            SharedSecret::Mpint(bytes) => (true, **bytes),
            SharedSecret::String(bytes) => (false, **bytes),
        }
    }

    #[test]
    fn curve25519_matches_rfc_7748() {
        let share = KeyShare::from_randomness(&array(ALICE), None);
        assert_eq!(share.public(), hex(ALICE_PUBLIC));
        let secret = share.agree(&hex(BOB_PUBLIC)).unwrap();
        assert_eq!(secret_bytes(&secret), (true, array(SHARED)));
    }

    #[test]
    fn low_order_points_and_wrong_lengths_are_refused() {
        let share = KeyShare::from_randomness(&array(ALICE), None);
        let mut one = [0; 32];
        one[0] = 1;
        for weak in [[0; 32], one] {
            assert_eq!(share.agree(&weak).err(), Some(KexError::WeakSharedSecret));
        }
        let order_8 = hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        assert_eq!(
            share.agree(&order_8).err(),
            Some(KexError::WeakSharedSecret)
        );
        for length in [0, 31, 33, 64] {
            assert_eq!(
                share.agree(&vec![9; length]).err(),
                Some(KexError::ServerPublic)
            );
        }
    }

    fn server_side(client_public: &[u8], m: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let (encapsulation, classical) = client_public.split_at(MLKEM_PUBLIC_BYTES);
        let key = ml_kem_768::EncapsulationKey::new(encapsulation.try_into().unwrap()).unwrap();
        let (ciphertext, quantum) = key.encapsulate_deterministic(&(*m).into());
        let bob = StaticSecret::from(array::<32>(BOB));
        let classical: [u8; 32] = classical.try_into().unwrap();
        let shared = bob.diffie_hellman(&classical.into());
        let mut reply = ciphertext.to_vec();
        reply.extend_from_slice(x25519_dalek::PublicKey::from(&bob).as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(quantum.as_slice());
        hasher.update(shared.as_bytes());
        (reply, hasher.finalize().into())
    }

    #[test]
    fn the_hybrid_secret_hashes_the_ml_kem_secret_then_the_x25519_one() {
        let share = KeyShare::from_randomness(&array(ALICE), Some(&[3; 64]));
        assert_eq!(share.public().len(), MLKEM_PUBLIC_BYTES + X25519_BYTES);
        assert_eq!(&share.public()[MLKEM_PUBLIC_BYTES..], hex(ALICE_PUBLIC));
        let (reply, expected) = server_side(share.public(), &[4; 32]);
        assert_eq!(reply.len(), MLKEM_CIPHERTEXT_BYTES + X25519_BYTES);
        let secret = share.agree(&reply).unwrap();
        assert_eq!(secret_bytes(&secret), (false, expected));
        let mut tampered = reply.clone();
        tampered[0] ^= 1;
        let tampered = share.agree(&tampered).unwrap();
        assert_ne!(secret_bytes(&tampered).1, expected);
        for length in [0, MLKEM_CIPHERTEXT_BYTES, reply.len() - 1, reply.len() + 1] {
            assert_eq!(
                share
                    .agree(
                        &reply[..length.min(reply.len())]
                            .iter()
                            .copied()
                            .chain(std::iter::repeat_n(0, length.saturating_sub(reply.len())))
                            .collect::<Vec<_>>()
                    )
                    .err(),
                Some(KexError::ServerPublic),
                "{length}"
            );
        }
        let mut weak = reply;
        weak[MLKEM_CIPHERTEXT_BYTES..].fill(0);
        assert_eq!(share.agree(&weak).err(), Some(KexError::WeakSharedSecret));
    }

    #[test]
    fn generated_shares_are_fresh() {
        let first = KeyShare::generate(KexMethod::MlKem768X25519).unwrap();
        let second = KeyShare::generate(KexMethod::MlKem768X25519).unwrap();
        assert_ne!(first.public(), second.public());
        assert_eq!(
            KeyShare::generate(KexMethod::Curve25519)
                .unwrap()
                .public()
                .len(),
            32
        );
    }

    fn host_key(algorithm: HostKeyAlgorithm) -> ssh_key::PrivateKey {
        let algorithm = match algorithm {
            HostKeyAlgorithm::Ed25519 => ssh_key::Algorithm::Ed25519,
            HostKeyAlgorithm::EcdsaP256 => ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
            HostKeyAlgorithm::EcdsaP384 => ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP384,
            },
        };
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, algorithm).unwrap()
    }

    fn signed(key: &ssh_key::PrivateKey, hash: &[u8; 32]) -> Vec<u8> {
        let signature: Signature = signature::Signer::try_sign(key.key_data(), hash).unwrap();
        Vec::try_from(signature).unwrap()
    }

    #[test]
    fn a_host_key_signature_of_the_hash_verifies_for_each_type() {
        let hash = [7; 32];
        for algorithm in HostKeyAlgorithm::ALL {
            let key = host_key(algorithm);
            let blob = key.public_key().to_bytes().unwrap();
            let verified = verify_host_key(algorithm, &blob, &signed(&key, &hash), &hash).unwrap();
            assert_eq!(verified.key_data(), key.public_key().key_data());
            assert_eq!(
                verify_host_key(algorithm, &blob, &signed(&key, &hash), &[8; 32]).err(),
                Some(KexError::Signature),
                "{algorithm:?}"
            );
        }
    }

    #[test]
    fn a_host_key_or_signature_of_another_type_or_with_extra_bytes_is_refused() {
        let hash = [7; 32];
        let ed25519 = host_key(HostKeyAlgorithm::Ed25519);
        let p256 = host_key(HostKeyAlgorithm::EcdsaP256);
        let ed_blob = ed25519.public_key().to_bytes().unwrap();
        let p256_blob = p256.public_key().to_bytes().unwrap();
        let ed_signature = signed(&ed25519, &hash);
        assert_eq!(
            verify_host_key(HostKeyAlgorithm::EcdsaP256, &ed_blob, &ed_signature, &hash).err(),
            Some(KexError::HostKeyType)
        );
        assert_eq!(
            verify_host_key(
                HostKeyAlgorithm::Ed25519,
                &ed_blob,
                &signed(&p256, &hash),
                &hash
            )
            .err(),
            Some(KexError::HostKeyType)
        );
        assert_eq!(
            verify_host_key(
                HostKeyAlgorithm::EcdsaP256,
                &p256_blob,
                &ed_signature,
                &hash
            )
            .err(),
            Some(KexError::HostKeyType)
        );
        let p384 = host_key(HostKeyAlgorithm::EcdsaP384);
        assert_eq!(
            verify_host_key(
                HostKeyAlgorithm::EcdsaP256,
                &p384.public_key().to_bytes().unwrap(),
                &signed(&p384, &hash),
                &hash
            )
            .err(),
            Some(KexError::HostKeyType)
        );
        let mut long_key = ed_blob.clone();
        long_key.push(0);
        assert_eq!(
            verify_host_key(HostKeyAlgorithm::Ed25519, &long_key, &ed_signature, &hash).err(),
            Some(KexError::HostKey)
        );
        let mut long_signature = ed_signature.clone();
        long_signature.push(0);
        assert_eq!(
            verify_host_key(HostKeyAlgorithm::Ed25519, &ed_blob, &long_signature, &hash).err(),
            Some(KexError::Signature)
        );
        let mut short_signature = ed_signature;
        short_signature.truncate(short_signature.len() - 1);
        assert!(
            verify_host_key(HostKeyAlgorithm::Ed25519, &ed_blob, &short_signature, &hash).is_err()
        );
        assert_eq!(
            verify_host_key(HostKeyAlgorithm::Ed25519, b"garbage", b"", &hash).err(),
            Some(KexError::HostKey)
        );
    }

    proptest! {
        #[test]
        fn reading_any_bytes_never_panics_and_consumes_what_it_saw(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let mut identification = Identification::default();
            let mut at = 0;
            while let Ok(Some(line)) = identification.read(&bytes[at..]) {
                let consumed = match line {
                    Line::Other { consumed } | Line::Version { consumed, .. } => consumed,
                };
                prop_assert!(consumed >= 1 && at + consumed <= bytes.len());
                at += consumed;
                if matches!(line, Line::Version { .. }) {
                    break;
                }
            }
        }

        #[test]
        fn verifying_any_host_key_and_signature_never_panics(
            key in proptest::collection::vec(any::<u8>(), 0..120),
            signature in proptest::collection::vec(any::<u8>(), 0..120),
        ) {
            for algorithm in HostKeyAlgorithm::ALL {
                prop_assert!(verify_host_key(algorithm, &key, &signature, &[0; 32]).is_err());
            }
        }

        #[test]
        fn agreeing_on_any_server_value_never_panics(server in proptest::collection::vec(any::<u8>(), 0..1200)) {
            let share = KeyShare::from_randomness(&[1; 32], Some(&[2; 64]));
            let _ = share.agree(&server);
            let classical = KeyShare::from_randomness(&[1; 32], None);
            let _ = classical.agree(&server);
        }

        #[test]
        fn negotiation_picks_the_first_client_name_the_server_has(
            server_kex in proptest::sample::subsequence(vec!["mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org", "sntrup761x25519-sha512"], 0..=4),
            server_ciphers in proptest::sample::subsequence(vec!["aes128-gcm@openssh.com", "aes256-ctr", "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"], 0..=4),
            server_keys in proptest::sample::subsequence(vec!["ecdsa-sha2-nistp384", "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"], 0..=4),
            shuffle in any::<bool>(),
        ) {
            let mut server_kex = server_kex;
            if shuffle { server_kex.reverse(); }
            server_kex.push("kex-strict-s-v00@openssh.com");
            let (kex, ciphers, keys) = (server_kex.join(","), server_ciphers.join(","), server_keys.join(","));
            let ours = init(CLIENT_KEX, "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384", CLIENT_CIPHERS, "none");
            let server = init(&kex, &keys, &ciphers, "none");
            let expected_kex = ["mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org"].into_iter().find(|name| server_kex.contains(name));
            let expected_cipher = CLIENT_CIPHERS.split(',').find(|name| server_ciphers.contains(name));
            let expected_key = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"].into_iter().find(|name| server_keys.contains(name));
            match (negotiate(&ours, &server, true), expected_kex, expected_key, expected_cipher) {
                (Ok(chosen), Some(kex), Some(key), Some(cipher)) => {
                    prop_assert_eq!(Some(chosen.kex), KexMethod::from_name(kex));
                    prop_assert_eq!(chosen.host_key.name(), key);
                    prop_assert_eq!(chosen.cipher_c2s.name(), cipher);
                }
                (Err(KexError::NoCommon(Category::Kex)), None, _, _)
                | (Err(KexError::NoCommon(Category::HostKey)), Some(_), None, _)
                | (Err(KexError::NoCommon(Category::Cipher)), Some(_), Some(_), None) => {}
                (outcome, kex, key, cipher) => prop_assert!(false, "{outcome:?} for {kex:?} {key:?} {cipher:?}"),
            }
        }
    }
}
