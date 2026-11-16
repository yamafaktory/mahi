use std::io;

use mahi_core::ThreadId;
use mahi_crypto::ThreadKey;
use mahi_identity::{
    ConfigDir,
    IdentityError,
    LocalIdentity,
};
use mahi_store::Store;
use mahi_thread::{
    ParticipantKey,
    load_meta,
};
use thiserror::Error;

use crate::{
    prompt::{
        Prompt as _,
        TerminalPrompt,
    },
    session,
    unlocked,
};

/// Unlocking the user's mahi key failed, so no thread can be opened.
#[derive(Debug, Error)]
pub(crate) enum UnlockError {
    #[error("cannot ask for the passphrase")]
    Terminal(#[source] io::Error),
    #[error("cannot unlock your mahi key")]
    Unlock(#[source] IdentityError),
}

/// Where the user's mahi key comes from: their identity file, unlocked with the passphrase at
/// the first thread that lists them, or a key already unlocked.
pub(crate) enum MahiKey<'env> {
    /// Locked in the identity file of this configuration.
    Locked(&'env ConfigDir),
    /// Already unlocked, so the passphrase is never asked.
    Unlocked(LocalIdentity),
}

/// Opens the keys of the repository's threads that list the user.
pub(crate) struct ThreadKeys<'env> {
    store: &'env Store,
    own: &'env ParticipantKey,
    key: MahiKey<'env>,
}

impl<'env> ThreadKeys<'env> {
    /// Returns the opener of the threads in `store` for the user whose key is `own`, with their
    /// mahi key from `key`.
    pub(crate) fn new(store: &'env Store, own: &'env ParticipantKey, key: MahiKey<'env>) -> Self {
        Self { store, own, key }
    }

    /// Opens `thread`'s key; the inner error says why this thread cannot be read, such as a
    /// `meta` that does not check out or does not list the user.
    ///
    /// # Errors
    ///
    /// Returns an [`UnlockError`] when the passphrase cannot be asked or does not unlock the key.
    pub(crate) fn open(
        &mut self,
        thread: ThreadId,
    ) -> Result<Result<ThreadKey, String>, UnlockError> {
        let meta = session::thread_owner(self.store, thread, self.own.clone())
            .map_err(|error| crate::describe(&error))
            .and_then(|owner| {
                load_meta(self.store, thread, &owner, 0).map_err(|error| crate::describe(&error))
            });
        let listed = meta.and_then(|meta| {
            let me = meta
                .participants()
                .find(|participant| participant.key() == self.own)
                .map(|participant| participant.name().clone())
                .ok_or_else(|| "it does not list you".to_owned())?;
            Ok((meta, me))
        });
        let (meta, me) = match listed {
            Ok(listed) => listed,
            Err(error) => return Ok(Err(error)),
        };
        if let MahiKey::Locked(config) = self.key {
            self.key = MahiKey::Unlocked(unlocked::identity(
                &config.identity_file(),
                ask_passphrase,
                UnlockError::Unlock,
            )?);
        }
        let MahiKey::Unlocked(identity) = &self.key else {
            return Ok(Err("your mahi key is locked".to_owned()));
        };
        Ok(meta
            .thread_key(&me, identity.as_age())
            .map_err(|error| crate::describe(&error)))
    }
}

fn ask_passphrase() -> Result<age::secrecy::SecretString, UnlockError> {
    TerminalPrompt::open()
        .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
        .map_err(UnlockError::Terminal)
}
