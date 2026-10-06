//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`: each takes
//! untrusted bytes as ssh-agent could answer them, or as a key file could hold them, and must
//! neither panic nor use more than its bounds allow.

use std::sync::LazyLock;

use age::secrecy::SecretString;
use zeroize::Zeroizing;

use crate::{
    Credential,
    LocalIdentity,
    NodeKey,
    PublicIdentity,
    SigningKey,
    ssh_agent,
};

/// Reads `data` as ssh-agent's answer to a sign request and to a key listing.
pub fn agent_answer(data: &[u8]) {
    let _ = ssh_agent::parse_signature(data);
    let _ = ssh_agent::parse_identities(data);
    let _ = ssh_agent::parse_login_keys(data);
}

/// Reads `data` as each of the key files mahi keeps in plaintext: the public identity, the
/// signing key, the node key and a stored credential. What one of them accepts reads back the
/// same once written again.
pub fn key_files(data: &[u8]) {
    if let Ok(public) = PublicIdentity::parse(data) {
        let written = format!("{}\n", public.recipient());
        let again = PublicIdentity::parse(written.as_bytes()).expect("a written identity parses");
        assert_eq!(
            again.recipient().to_string(),
            public.recipient().to_string()
        );
    }
    if let Ok(signing) = SigningKey::parse(data) {
        let line = signing
            .public_key()
            .to_openssh()
            .expect("a parsed key encodes");
        assert!(data == line.as_bytes() || data == format!("{line}\n").as_bytes());
    }
    assert_eq!(NodeKey::parse(data).is_ok(), data.len() == 32);
    if let Ok(credential) = Credential::new(Zeroizing::new(data.to_vec())) {
        let again = Credential::new(Zeroizing::new(credential.expose().to_vec()))
            .expect("a stored credential stores again");
        assert_eq!(again.expose(), credential.expose());
    }
}

const PASSPHRASE: &str = "fuzz";

static ENCRYPTED: LazyLock<Vec<u8>> = LazyLock::new(|| {
    LocalIdentity::generate()
        .encrypt(&SecretString::from(PASSPHRASE.to_owned()), 2)
        .expect("an identity encrypts")
});

/// Reads `data` as the encrypted identity file, opened with a fixed passphrase, or, when its
/// first byte is odd, flips the bits it names in a real identity file encrypted with that
/// passphrase at a low work factor, which opens when no bit is flipped.
pub fn identity_file(data: &[u8]) {
    let passphrase = SecretString::from(PASSPHRASE.to_owned());
    let Some((&choice, rest)) = data.split_first() else {
        return;
    };
    if choice % 2 == 0 {
        let _ = LocalIdentity::decrypt(rest, &passphrase);
        return;
    }
    let mut file = ENCRYPTED.clone();
    let Some((at, flips)) = rest.split_first_chunk::<2>() else {
        assert!(LocalIdentity::decrypt(&file, &passphrase).is_ok());
        return;
    };
    let at = usize::from(u16::from_be_bytes(*at)) % file.len();
    for (byte, flip) in file.iter_mut().skip(at).zip(flips) {
        *byte ^= flip;
    }
    let opened = LocalIdentity::decrypt(&file, &passphrase);
    if file == *ENCRYPTED {
        assert!(opened.is_ok(), "an untouched identity file opens");
    }
}
