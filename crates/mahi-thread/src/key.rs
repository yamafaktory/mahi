use std::fmt;

use ed25519_dalek::VerifyingKey;
use ssh_key::{
    Algorithm,
    PublicKey,
    SshSig,
};
use thiserror::Error;

/// A participant's public key: an SSH ed25519 key, the only kind mahi accepts.
///
/// Every other SSH key type is refused, `ssh-rsa` included, and so are ed25519 points of small
/// order, for which anyone can forge signatures. The key's comment is dropped,
/// so two keys are equal exactly when their key material is.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ParticipantKey {
    key: PublicKey,
    line: String,
}

/// A string or key that is not a usable SSH ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyError {
    /// The input is not an OpenSSH public key.
    #[error("not an OpenSSH public key")]
    Malformed,
    /// The key is of a type other than ed25519.
    #[error("{0} keys are not supported; use an ed25519 key")]
    Unsupported(String),
    /// The key is not a valid ed25519 point, or is a point of small order.
    #[error("ed25519 key is invalid or weak")]
    Weak,
}

impl ParticipantKey {
    /// Parses an OpenSSH public key line such as `ssh-ed25519 AAAA… alice@laptop`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] if `line` is not an OpenSSH public key, is not ed25519, or is weak.
    pub fn from_openssh(line: &str) -> Result<Self, KeyError> {
        let key = PublicKey::from_openssh(line.trim()).map_err(|_| KeyError::Malformed)?;
        Self::from_public_key(&key)
    }

    /// Accepts `key` if it is a usable ed25519 key.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] if `key` is not ed25519 or is weak.
    pub fn from_public_key(key: &PublicKey) -> Result<Self, KeyError> {
        let Some(ed25519) = key.key_data().ed25519() else {
            return Err(KeyError::Unsupported(key.algorithm().to_string()));
        };
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(KeyError::Unsupported(key.algorithm().to_string()));
        }
        let point = VerifyingKey::from_bytes(&ed25519.0).map_err(|_| KeyError::Weak)?;
        if point.is_weak() || point.to_edwards().compress().to_bytes() != ed25519.0 {
            return Err(KeyError::Weak);
        }
        let key = PublicKey::new(key.key_data().clone(), "");
        let line = key.to_openssh().map_err(|_| KeyError::Malformed)?;
        Ok(Self { key, line })
    }

    /// Returns the key as an OpenSSH public key line, without a comment.
    #[must_use]
    pub fn to_openssh(&self) -> &str {
        &self.line
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.key
    }

    pub(crate) fn verifies(&self, namespace: &str, message: &[u8], signature: &SshSig) -> bool {
        self.key.verify(namespace, message, signature).is_ok()
    }
}

impl fmt::Debug for ParticipantKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParticipantKey({})", self.line)
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::{
        PrivateKey,
        public::{
            Ed25519PublicKey,
            KeyData,
        },
        rand_core::OsRng,
    };

    use super::*;

    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDU88jp0gZG1pnbk45/jquMkXECFQjH4lB40SRDQBOd6sYfqqaLt1gdu0tK8jApiV/sbirg4lAgTEWOfYCkXegaBgE51266E3LYEwRcgp/KosX0sw0AACaLV5wQtlNUegIaNEmXGxCK4tKcdoYj+kNKnk9r33GLXcbL3yeIyGRGvw==";
    const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKxItRL4q2DjzWigIE3unPUBDOIUbsg9ghqSKSzh/wodSN26U616UdMicR7839NkHTS3vuYqav1s4X4/Zm7KfgM=";

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    fn raw_ed25519(bytes: [u8; 32]) -> PublicKey {
        PublicKey::new(KeyData::Ed25519(Ed25519PublicKey(bytes)), "")
    }

    #[test]
    fn accepts_ed25519_and_drops_the_comment() {
        let private = ed25519();
        let line = format!(
            "{} alice@laptop\n",
            private.public_key().to_openssh().unwrap()
        );
        let key = ParticipantKey::from_openssh(&line).unwrap();
        assert!(key.to_openssh().starts_with("ssh-ed25519 "));
        assert!(!key.to_openssh().contains("alice"));
        assert_eq!(
            key,
            ParticipantKey::from_public_key(private.public_key()).unwrap()
        );
    }

    #[test]
    fn refuses_rsa_and_ecdsa() {
        for line in [RSA, ECDSA] {
            assert!(matches!(
                ParticipantKey::from_openssh(line),
                Err(KeyError::Unsupported(_) | KeyError::Malformed)
            ));
        }
    }

    #[test]
    fn refuses_small_order_points() {
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut order_two = [0; 32];
        order_two[0] = 0xec;
        order_two[1..31].fill(0xff);
        order_two[31] = 0x7f;
        for bytes in [identity, order_two, [0; 32]] {
            assert_eq!(
                ParticipantKey::from_public_key(&raw_ed25519(bytes)),
                Err(KeyError::Weak),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn refuses_garbage() {
        for line in ["", "ssh-ed25519", "ssh-ed25519 !!!", "hello world"] {
            assert_eq!(
                ParticipantKey::from_openssh(line),
                Err(KeyError::Malformed),
                "{line:?}"
            );
        }
    }

    #[test]
    fn verifies_only_its_own_signatures() {
        let alice = ed25519();
        let bob = ed25519();
        let key = ParticipantKey::from_public_key(alice.public_key()).unwrap();
        let signature = alice
            .sign("ns", ssh_key::HashAlg::Sha512, b"message")
            .unwrap();
        assert!(key.verifies("ns", b"message", &signature));
        assert!(!key.verifies("other", b"message", &signature));
        assert!(!key.verifies("ns", b"messagE", &signature));
        let forged = bob
            .sign("ns", ssh_key::HashAlg::Sha512, b"message")
            .unwrap();
        assert!(!key.verifies("ns", b"message", &forged));
    }
}
