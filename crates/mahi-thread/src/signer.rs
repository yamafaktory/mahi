use mahi_identity::{
    AgentError,
    AgentSigner,
};
use ssh_key::{
    HashAlg,
    PrivateKey,
    PublicKey,
    SshSig,
};
use thiserror::Error;

/// Why an [`SshSigner`] could not sign.
#[derive(Debug, Error)]
pub enum SignError {
    /// Signing with an in-memory key failed.
    #[error("cannot sign with the key")]
    Key(#[from] ssh_key::Error),
    /// ssh-agent could not sign.
    #[error(transparent)]
    Agent(#[from] AgentError),
}

/// Something that makes SSHSIG signatures with one SSH key: ssh-agent in normal use, or a key
/// held in memory.
pub trait SshSigner {
    /// Returns the key this signer signs with.
    fn public_key(&self) -> &PublicKey;

    /// Signs `message` in `namespace` with `hash`.
    ///
    /// # Errors
    ///
    /// Returns a [`SignError`] if the signature cannot be made.
    fn sign_sshsig(
        &self,
        namespace: &str,
        hash: HashAlg,
        message: &[u8],
    ) -> Result<SshSig, SignError>;
}

impl SshSigner for PrivateKey {
    fn public_key(&self) -> &PublicKey {
        PrivateKey::public_key(self)
    }

    fn sign_sshsig(
        &self,
        namespace: &str,
        hash: HashAlg,
        message: &[u8],
    ) -> Result<SshSig, SignError> {
        Ok(self.sign(namespace, hash, message)?)
    }
}

impl SshSigner for AgentSigner {
    fn public_key(&self) -> &PublicKey {
        AgentSigner::public_key(self)
    }

    fn sign_sshsig(
        &self,
        namespace: &str,
        hash: HashAlg,
        message: &[u8],
    ) -> Result<SshSig, SignError> {
        Ok(self.sign(namespace, hash, message)?)
    }
}
