use std::{
    collections::HashSet,
    fmt,
};

use age::x25519;
use gix_hash::ObjectId;
use mahi_core::{
    NameError,
    ParticipantName,
    ThreadId,
};
use mahi_crypto::{
    OpenError,
    SealError,
    ThreadKey,
    WrapError,
    WrappedKeyError,
};
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest,
    Sha256,
};
use ssh_key::{
    HashAlg,
    LineEnding,
    SshSig,
};
use thiserror::Error;

use crate::{
    KeyError,
    ParticipantKey,
    SignError,
    SshSigner,
};

/// The largest encoded meta document mahi reads, in bytes.
pub const MAX_META_BYTES: usize = 256 * 1024;
/// The most participants a thread can have.
pub const MAX_PARTICIPANTS: usize = 256;

const VERSION: u16 = 1;
const NAMESPACE: &str = "mahi-meta";
const HASH: HashAlg = HashAlg::Sha512;
const MAX_TITLE_BYTES: usize = 256;
const MAX_BRANCH_BYTES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 4096;
const MAX_PRIVATE_BYTES: usize = 4096;
const LOW_ORDER_PROBE: [u8; 32] = [0x5a; 32];

/// A person in a thread: their name, the SSH key they sign with, and the mahi key that the
/// thread key is wrapped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    name: ParticipantName,
    key: ParticipantKey,
    recipient: x25519::Recipient,
}

/// The encrypted part of a thread's meta document.
///
/// Its fields never appear in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateMeta {
    title: String,
    landing_branch: String,
}

/// A thread's meta document before it is signed.
#[derive(Clone)]
pub struct MetaDraft {
    thread: ThreadId,
    generation: u64,
    base: ObjectId,
    owner: ParticipantName,
    participants: Vec<Participant>,
    private: PrivateMeta,
}

/// A meta document whose signature was checked against a trusted owner key.
#[derive(Clone)]
pub struct VerifiedMeta {
    thread: ThreadId,
    generation: u64,
    body_hash: [u8; 32],
    base: ObjectId,
    owner: ParticipantName,
    recipient: x25519::Recipient,
    participants: Vec<(Participant, Vec<u8>)>,
    private: Vec<u8>,
}

/// A rule of the meta document format that was broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InvalidMeta {
    /// There are no participants.
    #[error("a thread needs a participant")]
    NoParticipants,
    /// There are more than [`MAX_PARTICIPANTS`] participants.
    #[error("more than {MAX_PARTICIPANTS} participants")]
    TooManyParticipants,
    /// Two participants share a name.
    #[error("two participants share a name")]
    DuplicateName,
    /// Two participants share a key.
    #[error("two participants share a key")]
    DuplicateKey,
    /// Two participants share a mahi key.
    #[error("two participants share a mahi key")]
    DuplicateRecipient,
    /// A participant's mahi key is not an age X25519 recipient.
    #[error("a participant's mahi key is not an age X25519 recipient")]
    ParticipantRecipient,
    /// A participant's mahi key is a point of small order, which no one can safely encrypt to.
    #[error("a participant's mahi key is a weak X25519 point")]
    WeakRecipient,
    /// The owner is not a participant.
    #[error("the owner is not a participant")]
    OwnerNotListed,
    /// The owner is listed with a key other than the trusted one.
    #[error("the owner's key is not the trusted owner key")]
    OwnerKeyUntrusted,
    /// The signing key is not the owner's.
    #[error("the signing key is not the owner's key")]
    SigningKeyNotOwner,
    /// The base is not a git object id.
    #[error("base is not an object id")]
    Base,
    /// The recipient is not an age X25519 recipient.
    #[error("recipient is not an age X25519 recipient")]
    Recipient,
    /// The sealed private part is larger than allowed.
    #[error("private part is too large")]
    PrivateTooLarge,
    /// The title is longer than 256 bytes.
    #[error("title is longer than {MAX_TITLE_BYTES} bytes")]
    TitleTooLong,
    /// The title contains a control, format, bidirectional or blank-looking character.
    ///
    /// Zero-width joiners are among them, so emoji built from joined sequences are refused.
    #[error("title contains a control or invisible character")]
    TitleCharacter,
    /// The landing branch is not a valid git branch name.
    #[error("landing branch is not a valid branch name")]
    Branch,
}

/// Building, signing or reading a meta document failed.
#[derive(Debug, Error)]
pub enum MetaError {
    /// The encoded document is larger than [`MAX_META_BYTES`].
    #[error("meta document is larger than {MAX_META_BYTES} bytes")]
    TooLarge,
    /// The document is not valid postcard of the expected shape.
    #[error("meta document is malformed")]
    Malformed,
    /// Encoding the document failed.
    #[error("cannot encode meta document")]
    Encode(#[source] postcard::Error),
    /// The document has a format version this build does not read.
    #[error("meta document version {0} is not supported")]
    UnsupportedVersion(u16),
    /// The signature is missing, malformed, not SHA-512, or not made by the trusted owner key.
    #[error("meta document is not signed by the thread owner")]
    BadSignature,
    /// The document describes another thread than the one it was read for.
    #[error("meta document belongs to another thread")]
    ThreadMismatch,
    /// The content breaks a rule of the format.
    #[error("invalid meta document: {0}")]
    Invalid(#[from] InvalidMeta),
    /// A participant name is invalid.
    #[error("invalid participant name")]
    Name(#[from] NameError),
    /// A participant key is invalid.
    #[error("invalid participant key")]
    Key(#[from] KeyError),
    /// Signing failed.
    #[error("cannot sign meta document")]
    Sign(#[source] SignError),
    /// The signer returned a signature that the owner's key does not verify.
    #[error("the signer returned a signature the owner's key does not verify")]
    InvalidSignature,
    /// Sealing the private part failed.
    #[error("cannot seal meta document")]
    Seal(#[from] SealError),
    /// Opening the private part failed.
    #[error("cannot open meta document")]
    Open(#[from] OpenError),
    /// Wrapping the thread key failed.
    #[error("cannot wrap thread key")]
    Wrap(#[from] WrapError),
    /// Recovering the thread key failed.
    #[error("cannot recover thread key")]
    WrappedKey(#[from] WrappedKeyError),
    /// The named participant is not in the thread.
    #[error("not a participant in this thread")]
    NotAParticipant,
    /// A wrapped key does not match the thread's recipient.
    #[error("wrapped thread key does not match the thread")]
    KeyMismatch,
}

#[derive(Serialize, Deserialize)]
struct WireEnvelope<'a> {
    version: u16,
    body: &'a [u8],
    signature: &'a str,
}

#[derive(Serialize, Deserialize)]
struct WireBody<'a> {
    thread: [u8; 16],
    generation: u64,
    base: &'a [u8],
    owner: &'a str,
    recipient: &'a str,
    #[serde(borrow)]
    participants: Vec<WireParticipant<'a>>,
    private: &'a [u8],
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct WireParticipant<'a> {
    name: &'a str,
    key: &'a str,
    recipient: &'a str,
    wrapped: &'a [u8],
}

#[derive(Serialize, Deserialize)]
struct WirePrivate<'a> {
    title: &'a str,
    landing_branch: &'a str,
}

impl Participant {
    /// Creates a participant who signs with `key` and receives the thread key at `recipient`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMeta::WeakRecipient`] if `recipient` is an X25519 point of small order:
    /// wrapping to one would give a shared secret of zero.
    pub fn new(
        name: ParticipantName,
        key: ParticipantKey,
        recipient: x25519::Recipient,
    ) -> Result<Self, InvalidMeta> {
        if is_low_order(&recipient) {
            return Err(InvalidMeta::WeakRecipient);
        }
        Ok(Self {
            name,
            key,
            recipient,
        })
    }

    /// Returns the participant's name.
    #[must_use]
    pub fn name(&self) -> &ParticipantName {
        &self.name
    }

    /// Returns the participant's SSH signing key.
    #[must_use]
    pub fn key(&self) -> &ParticipantKey {
        &self.key
    }

    /// Returns the participant's mahi key, which the thread key is wrapped to.
    #[must_use]
    pub fn recipient(&self) -> &x25519::Recipient {
        &self.recipient
    }
}

impl PrivateMeta {
    /// Creates the private part of a meta document.
    ///
    /// # Errors
    ///
    /// Returns [`MetaError::Invalid`] if the title is longer than 256 bytes or contains a
    /// control, format or bidirectional character, or the landing branch is not a valid git
    /// branch name.
    pub fn new(title: &str, landing_branch: &str) -> Result<Self, MetaError> {
        validate_title(title)?;
        validate_branch(landing_branch)?;
        Ok(Self {
            title: title.to_owned(),
            landing_branch: landing_branch.to_owned(),
        })
    }

    /// Returns the thread's title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the branch the thread lands on, without `refs/heads/`.
    #[must_use]
    pub fn landing_branch(&self) -> &str {
        &self.landing_branch
    }
}

impl fmt::Debug for PrivateMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateMeta").finish_non_exhaustive()
    }
}

impl MetaDraft {
    /// Creates a draft of generation `generation` for `thread`, started from `base` by `owner`.
    ///
    /// A thread's first meta document is generation 0, and every later one is one higher.
    ///
    /// # Errors
    ///
    /// Returns [`MetaError::Invalid`] if there are no or too many participants, two share a
    /// name or a key, or `owner` is not one of them.
    pub fn new(
        thread: ThreadId,
        generation: u64,
        base: ObjectId,
        owner: ParticipantName,
        participants: Vec<Participant>,
        private: PrivateMeta,
    ) -> Result<Self, MetaError> {
        validate_participants(&owner, participants.iter())?;
        Ok(Self {
            thread,
            generation,
            base,
            owner,
            participants,
            private,
        })
    }

    /// Returns the thread the draft describes.
    #[must_use]
    pub fn thread(&self) -> ThreadId {
        self.thread
    }

    /// Returns the draft's generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the owner's participant entry.
    #[must_use]
    pub fn owner(&self) -> Option<&Participant> {
        self.participants.iter().find(|p| p.name == self.owner)
    }

    /// Seals the private part to `thread_key`, wraps `thread_key` for every participant, and
    /// signs the result with `owner_key`.
    ///
    /// # Errors
    ///
    /// Returns [`MetaError::Invalid`] if `owner_key` is not the owner's key, or another
    /// [`MetaError`] if sealing, wrapping, encoding or signing fails.
    pub fn sign(
        &self,
        thread_key: &ThreadKey,
        owner_key: &dyn SshSigner,
    ) -> Result<Vec<u8>, MetaError> {
        let owner = self.owner().ok_or(InvalidMeta::OwnerNotListed)?;
        if owner.key.public_key().key_data() != owner_key.public_key().key_data() {
            return Err(InvalidMeta::SigningKeyNotOwner.into());
        }

        let private = postcard::to_allocvec(&WirePrivate {
            title: &self.private.title,
            landing_branch: &self.private.landing_branch,
        })
        .map_err(MetaError::Encode)?;
        let private = thread_key.seal(&private)?;

        let mut wrapped = Vec::with_capacity(self.participants.len());
        for participant in &self.participants {
            wrapped.push(thread_key.wrap(&[&participant.recipient])?);
        }
        let names: Vec<String> = self
            .participants
            .iter()
            .map(|p| p.name.to_string())
            .collect();
        let recipients: Vec<String> = self
            .participants
            .iter()
            .map(|p| p.recipient.to_string())
            .collect();
        let owner_name = self.owner.to_string();
        let recipient = thread_key.recipient().to_string();

        let body = postcard::to_allocvec(&WireBody {
            thread: *self.thread.as_bytes(),
            generation: self.generation,
            base: self.base.as_bytes(),
            owner: &owner_name,
            recipient: &recipient,
            participants: self
                .participants
                .iter()
                .zip(&names)
                .zip(&recipients)
                .zip(&wrapped)
                .map(
                    |(((participant, name), recipient), wrapped)| WireParticipant {
                        name,
                        key: participant.key.to_openssh(),
                        recipient,
                        wrapped,
                    },
                )
                .collect(),
            private: &private,
        })
        .map_err(MetaError::Encode)?;

        let signature = owner_key
            .sign_sshsig(NAMESPACE, HASH, &body)
            .map_err(MetaError::Sign)?;
        if owner
            .key
            .public_key()
            .verify(NAMESPACE, &body, &signature)
            .is_err()
        {
            return Err(MetaError::InvalidSignature);
        }
        let signature = signature
            .to_pem(LineEnding::LF)
            .map_err(|error| MetaError::Sign(error.into()))?;
        let encoded = postcard::to_allocvec(&WireEnvelope {
            version: VERSION,
            body: &body,
            signature: &signature,
        })
        .map_err(MetaError::Encode)?;
        if encoded.len() > MAX_META_BYTES {
            return Err(MetaError::TooLarge);
        }
        Ok(encoded)
    }
}

impl fmt::Debug for MetaDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetaDraft")
            .field("thread", &self.thread)
            .field("generation", &self.generation)
            .field("base", &self.base)
            .field("owner", &self.owner)
            .field("participants", &self.participants)
            .finish_non_exhaustive()
    }
}

impl VerifiedMeta {
    /// Decodes the meta document read for `thread` and checks that `trusted_owner` signed it.
    ///
    /// `trusted_owner` must come from outside the document, such as the invite ticket or the
    /// user's own key: a document is never trusted on the strength of a key it names itself.
    /// The caller must still check [`VerifiedMeta::generation`] against the highest generation
    /// it has seen for the thread, so that an older signed document cannot be put back.
    ///
    /// # Errors
    ///
    /// Returns [`MetaError::BadSignature`] if `trusted_owner` did not sign it with SHA-512,
    /// [`MetaError::ThreadMismatch`] if it describes another thread, or another [`MetaError`]
    /// if it is too large, malformed, or breaks a rule of the format.
    pub fn decode(
        encoded: &[u8],
        thread: ThreadId,
        trusted_owner: &ParticipantKey,
    ) -> Result<Self, MetaError> {
        if encoded.len() > MAX_META_BYTES {
            return Err(MetaError::TooLarge);
        }
        let envelope: WireEnvelope<'_> = decode_exact(encoded)?;
        if envelope.version != VERSION {
            return Err(MetaError::UnsupportedVersion(envelope.version));
        }
        if envelope.signature.len() > MAX_SIGNATURE_BYTES {
            return Err(MetaError::BadSignature);
        }
        let signature =
            SshSig::from_pem(envelope.signature).map_err(|_| MetaError::BadSignature)?;
        if signature.hash_alg() != HASH
            || !trusted_owner.verifies(NAMESPACE, envelope.body, &signature)
        {
            return Err(MetaError::BadSignature);
        }

        let body: WireBody<'_> = decode_exact(envelope.body)?;
        if ThreadId::from_bytes(body.thread) != thread {
            return Err(MetaError::ThreadMismatch);
        }
        let owner = ParticipantName::new(body.owner)?;
        let base = ObjectId::try_from(body.base).map_err(|_| InvalidMeta::Base)?;
        let recipient = body.recipient.parse().map_err(|_| InvalidMeta::Recipient)?;
        if body.participants.len() > MAX_PARTICIPANTS {
            return Err(InvalidMeta::TooManyParticipants.into());
        }
        if body.private.len() > MAX_PRIVATE_BYTES {
            return Err(InvalidMeta::PrivateTooLarge.into());
        }
        let mut participants = Vec::with_capacity(body.participants.len());
        for wire in &body.participants {
            let participant = Participant::new(
                ParticipantName::new(wire.name)?,
                ParticipantKey::from_openssh(wire.key)?,
                wire.recipient
                    .parse()
                    .map_err(|_| InvalidMeta::ParticipantRecipient)?,
            )?;
            participants.push((participant, wire.wrapped.to_vec()));
        }
        validate_participants(&owner, participants.iter().map(|(p, _)| p))?;
        let owner_trusted = participants
            .iter()
            .any(|(p, _)| p.name == owner && &p.key == trusted_owner);
        if !owner_trusted {
            return Err(InvalidMeta::OwnerKeyUntrusted.into());
        }

        Ok(Self {
            thread,
            generation: body.generation,
            body_hash: Sha256::digest(envelope.body).into(),
            base,
            owner,
            recipient,
            participants,
            private: body.private.to_vec(),
        })
    }

    /// Returns the thread the document describes.
    #[must_use]
    pub fn thread(&self) -> ThreadId {
        self.thread
    }

    /// Returns the document's generation: 0 for a new thread, one higher for each later one.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the SHA-256 hash of the signed body, which identifies the document.
    #[must_use]
    pub fn body_hash(&self) -> [u8; 32] {
        self.body_hash
    }

    /// Returns the commit the thread started from.
    #[must_use]
    pub fn base(&self) -> ObjectId {
        self.base
    }

    /// Returns the thread's owner.
    #[must_use]
    pub fn owner(&self) -> &ParticipantName {
        &self.owner
    }

    /// Returns the thread's participants.
    pub fn participants(&self) -> impl Iterator<Item = &Participant> {
        self.participants.iter().map(|(participant, _)| participant)
    }

    /// Recovers the thread key wrapped for participant `name`, using their `identity`.
    ///
    /// # Errors
    ///
    /// Returns [`MetaError::NotAParticipant`] if `name` is not in the thread,
    /// [`MetaError::WrappedKey`] if `identity` cannot unwrap it, or [`MetaError::KeyMismatch`]
    /// if the unwrapped key is not the thread's.
    pub fn thread_key(
        &self,
        name: &ParticipantName,
        identity: &dyn age::Identity,
    ) -> Result<ThreadKey, MetaError> {
        let (_, wrapped) = self
            .participants
            .iter()
            .find(|(participant, _)| &participant.name == name)
            .ok_or(MetaError::NotAParticipant)?;
        let key = ThreadKey::from_wrapped(wrapped, identity)?;
        if key.recipient().to_string() != self.recipient.to_string() {
            return Err(MetaError::KeyMismatch);
        }
        Ok(key)
    }

    /// Opens the private part with the thread key.
    ///
    /// # Errors
    ///
    /// Returns [`MetaError::Open`] if `thread_key` cannot open it, or another [`MetaError`] if
    /// its content is invalid.
    pub fn private(&self, thread_key: &ThreadKey) -> Result<PrivateMeta, MetaError> {
        let plaintext = thread_key.open(&self.private, MAX_PRIVATE_BYTES)?;
        let wire: WirePrivate<'_> = decode_exact(&plaintext)?;
        PrivateMeta::new(wire.title, wire.landing_branch)
    }
}

impl fmt::Debug for VerifiedMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedMeta")
            .field("thread", &self.thread)
            .field("generation", &self.generation)
            .field("base", &self.base)
            .field("owner", &self.owner)
            .field(
                "participants",
                &self
                    .participants()
                    .map(Participant::name)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

fn is_low_order(recipient: &x25519::Recipient) -> bool {
    let Ok((_, data)) = bech32::decode(&recipient.to_string()) else {
        return true;
    };
    let Ok(point) = <[u8; 32]>::try_from(data.as_slice()) else {
        return true;
    };
    x25519_dalek::x25519(LOW_ORDER_PROBE, point) == [0; 32]
}

fn decode_exact<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, MetaError> {
    match postcard::take_from_bytes(bytes) {
        Ok((value, [])) => Ok(value),
        _ => Err(MetaError::Malformed),
    }
}

fn validate_participants<'a>(
    owner: &ParticipantName,
    participants: impl ExactSizeIterator<Item = &'a Participant>,
) -> Result<(), InvalidMeta> {
    if participants.len() == 0 {
        return Err(InvalidMeta::NoParticipants);
    }
    if participants.len() > MAX_PARTICIPANTS {
        return Err(InvalidMeta::TooManyParticipants);
    }
    let mut names = HashSet::new();
    let mut keys = HashSet::new();
    let mut recipients = HashSet::new();
    let mut has_owner = false;
    for participant in participants {
        if !names.insert(&participant.name) {
            return Err(InvalidMeta::DuplicateName);
        }
        if !keys.insert(&participant.key) {
            return Err(InvalidMeta::DuplicateKey);
        }
        if !recipients.insert(&participant.recipient) {
            return Err(InvalidMeta::DuplicateRecipient);
        }
        has_owner |= &participant.name == owner;
    }
    if !has_owner {
        return Err(InvalidMeta::OwnerNotListed);
    }
    Ok(())
}

fn validate_title(title: &str) -> Result<(), InvalidMeta> {
    if title.len() > MAX_TITLE_BYTES {
        return Err(InvalidMeta::TitleTooLong);
    }
    if title.chars().any(|c| c.is_control() || is_invisible(c)) {
        return Err(InvalidMeta::TitleCharacter);
    }
    Ok(())
}

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{180B}'..='\u{180F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{3164}'
            | '\u{FFA0}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

fn validate_branch(branch: &str) -> Result<(), InvalidMeta> {
    let full = format!("refs/heads/{branch}");
    let valid = !branch.is_empty()
        && !branch.starts_with('-')
        && branch.len() <= MAX_BRANCH_BYTES
        && gix_validate::reference::branch_name(full.as_str().into()).is_ok();
    if valid {
        Ok(())
    } else {
        Err(InvalidMeta::Branch)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;

    struct Person {
        name: ParticipantName,
        private: PrivateKey,
        mahi: x25519::Identity,
    }

    impl Person {
        fn new(name: &str) -> Self {
            Self {
                name: ParticipantName::new(name).unwrap(),
                private: PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
                mahi: x25519::Identity::generate(),
            }
        }

        fn key(&self) -> ParticipantKey {
            ParticipantKey::from_public_key(self.private.public_key()).unwrap()
        }

        fn participant(&self) -> Participant {
            Participant::new(self.name.clone(), self.key(), self.mahi.to_public()).unwrap()
        }

        fn identity(&self) -> &x25519::Identity {
            &self.mahi
        }
    }

    fn base() -> ObjectId {
        ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap()
    }

    fn draft(owner: &Person, others: &[&Person]) -> MetaDraft {
        let mut participants = vec![owner.participant()];
        participants.extend(others.iter().map(|p| p.participant()));
        MetaDraft::new(
            ThreadId::random().unwrap(),
            0,
            base(),
            owner.name.clone(),
            participants,
            PrivateMeta::new("Fix the parser", "feature/parser").unwrap(),
        )
        .unwrap()
    }

    fn signed_envelope(
        signer: &PrivateKey,
        body: &[u8],
        hash: HashAlg,
        namespace: &str,
        version: u16,
    ) -> Vec<u8> {
        let signature = signer
            .sign(namespace, hash, body)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        postcard::to_allocvec(&WireEnvelope {
            version,
            body,
            signature: &signature,
        })
        .unwrap()
    }

    fn resign(signer: &PrivateKey, body: &[u8]) -> Vec<u8> {
        signed_envelope(signer, body, HASH, NAMESPACE, VERSION)
    }

    fn body_of(encoded: &[u8]) -> Vec<u8> {
        let envelope: WireEnvelope<'_> = postcard::from_bytes(encoded).unwrap();
        envelope.body.to_vec()
    }

    #[test]
    fn a_participant_reads_back_everything() {
        let (alice, bob) = (Person::new("alice"), Person::new("bob"));
        let draft = draft(&alice, &[&bob]);
        let thread_key = ThreadKey::generate();
        let encoded = draft.sign(&thread_key, &alice.private).unwrap();

        let meta = VerifiedMeta::decode(&encoded, draft.thread, &alice.key()).unwrap();
        assert_eq!(meta.thread(), draft.thread);
        assert_eq!(meta.generation(), 0);
        assert_eq!(meta.base(), base());
        assert_eq!(meta.owner(), &alice.name);
        assert_eq!(
            meta.participants().cloned().collect::<Vec<_>>(),
            [alice.participant(), bob.participant()]
        );

        let key = meta.thread_key(&bob.name, bob.identity()).unwrap();
        let private = meta.private(&key).unwrap();
        assert_eq!(private.title(), "Fix the parser");
        assert_eq!(private.landing_branch(), "feature/parser");
    }

    #[test]
    fn the_body_hash_ignores_the_envelope_but_not_the_body() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        let body = body_of(&encoded);
        let a = VerifiedMeta::decode(&encoded, draft.thread, &alice.key()).unwrap();
        let rewrapped = resign(&alice.private, &body);
        let b = VerifiedMeta::decode(&rewrapped, draft.thread, &alice.key()).unwrap();
        assert_eq!(a.body_hash(), b.body_hash());
        assert_eq!(a.body_hash(), <[u8; 32]>::from(Sha256::digest(&body)));

        let other = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        let c = VerifiedMeta::decode(&other, draft.thread, &alice.key()).unwrap();
        assert_ne!(a.body_hash(), c.body_hash());
    }

    #[test]
    fn the_generation_is_signed_and_read_back() {
        let alice = Person::new("alice");
        let mut draft = draft(&alice, &[]);
        draft.generation = 7;
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        let meta = VerifiedMeta::decode(&encoded, draft.thread, &alice.key()).unwrap();
        assert_eq!(meta.generation(), 7);
    }

    #[test]
    fn the_private_part_stays_out_of_the_document_and_debug() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        assert!(
            !encoded
                .windows(b"parser".len())
                .any(|window| window == b"parser")
        );
        assert!(!format!("{draft:?}").contains("parser"));
        assert!(!format!("{:?}", draft.private).contains("parser"));
    }

    #[test]
    fn a_document_for_another_thread_is_refused() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        assert!(matches!(
            VerifiedMeta::decode(&encoded, ThreadId::random().unwrap(), &alice.key()),
            Err(MetaError::ThreadMismatch)
        ));
    }

    #[test]
    fn only_the_trusted_owner_key_is_accepted() {
        let (alice, mallory) = (Person::new("alice"), Person::new("mallory"));
        let draft = draft(&alice, &[]);
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        assert!(matches!(
            VerifiedMeta::decode(&encoded, draft.thread, &mallory.key()),
            Err(MetaError::BadSignature)
        ));
    }

    #[test]
    fn a_substituted_document_is_refused() {
        let (alice, bob, mallory) = (
            Person::new("alice"),
            Person::new("bob"),
            Person::new("mallory"),
        );
        let forged_owner = Person {
            name: alice.name.clone(),
            private: mallory.private.clone(),
            mahi: x25519::Identity::generate(),
        };
        let forged = draft(&forged_owner, &[&bob]);
        let encoded = forged
            .sign(&ThreadKey::generate(), &mallory.private)
            .unwrap();
        assert!(matches!(
            VerifiedMeta::decode(&encoded, forged.thread, &alice.key()),
            Err(MetaError::BadSignature)
        ));
    }

    #[test]
    fn the_owner_signing_a_listing_with_another_owner_is_refused() {
        let (alice, bob) = (Person::new("alice"), Person::new("bob"));
        let as_bob = draft(&bob, &[&alice]);
        let encoded = as_bob.sign(&ThreadKey::generate(), &bob.private).unwrap();
        let resigned = resign(&alice.private, &body_of(&encoded));
        assert!(matches!(
            VerifiedMeta::decode(&resigned, as_bob.thread, &alice.key()),
            Err(MetaError::Invalid(InvalidMeta::OwnerKeyUntrusted))
        ));
    }

    #[test]
    fn any_change_to_the_body_breaks_the_signature() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        let envelope: WireEnvelope<'_> = postcard::from_bytes(&encoded).unwrap();
        for index in [0, envelope.body.len() / 2, envelope.body.len() - 1] {
            let mut tampered = envelope.body.to_vec();
            tampered[index] ^= 1;
            let reencoded = postcard::to_allocvec(&WireEnvelope {
                version: VERSION,
                body: &tampered,
                signature: envelope.signature,
            })
            .unwrap();
            assert!(matches!(
                VerifiedMeta::decode(&reencoded, draft.thread, &alice.key()),
                Err(MetaError::BadSignature)
            ));
        }
    }

    #[test]
    fn signatures_need_the_namespace_and_sha512() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let body = body_of(&draft.sign(&ThreadKey::generate(), &alice.private).unwrap());
        for encoded in [
            signed_envelope(&alice.private, &body, HASH, "git", VERSION),
            signed_envelope(&alice.private, &body, HashAlg::Sha256, NAMESPACE, VERSION),
        ] {
            assert!(matches!(
                VerifiedMeta::decode(&encoded, draft.thread, &alice.key()),
                Err(MetaError::BadSignature)
            ));
        }
    }

    #[test]
    fn oversized_or_garbled_signatures_are_refused() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let body = body_of(&draft.sign(&ThreadKey::generate(), &alice.private).unwrap());
        let long = "x".repeat(MAX_SIGNATURE_BYTES + 1);
        for signature in [long.as_str(), "", "-----BEGIN SSH SIGNATURE-----\n!!\n"] {
            let encoded = postcard::to_allocvec(&WireEnvelope {
                version: VERSION,
                body: &body,
                signature,
            })
            .unwrap();
            assert!(matches!(
                VerifiedMeta::decode(&encoded, draft.thread, &alice.key()),
                Err(MetaError::BadSignature)
            ));
        }
    }

    #[test]
    fn unknown_versions_trailing_bytes_and_huge_input_are_refused() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        let v2 = signed_envelope(&alice.private, &body_of(&encoded), HASH, NAMESPACE, 2);
        assert!(matches!(
            VerifiedMeta::decode(&v2, draft.thread, &alice.key()),
            Err(MetaError::UnsupportedVersion(2))
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            VerifiedMeta::decode(&trailing, draft.thread, &alice.key()),
            Err(MetaError::Malformed)
        ));
        assert!(matches!(
            VerifiedMeta::decode(&vec![0; MAX_META_BYTES + 1], draft.thread, &alice.key()),
            Err(MetaError::TooLarge)
        ));
    }

    #[test]
    fn a_signed_body_with_bad_content_is_refused_for_the_right_reason() {
        let alice = Person::new("alice");
        let key = alice.key();
        let recipient = ThreadKey::generate().recipient().to_string();
        let base = base();
        let big_private = vec![0; MAX_PRIVATE_BYTES + 1];
        let mahi = alice.mahi.to_public().to_string();
        let good = WireParticipant {
            name: "alice",
            key: key.to_openssh(),
            recipient: &mahi,
            wrapped: b"",
        };
        let fresh = || WireBody {
            thread: [0; 16],
            generation: 0,
            base: base.as_bytes(),
            owner: "alice",
            recipient: &recipient,
            participants: vec![good],
            private: b"",
        };
        let decode = |body: &WireBody<'_>| {
            let encoded = resign(&alice.private, &postcard::to_allocvec(body).unwrap());
            VerifiedMeta::decode(&encoded, ThreadId::from_bytes([0; 16]), &key)
        };

        assert!(decode(&fresh()).is_ok());
        let mut body = fresh();
        body.base = &[1; 5];
        assert!(matches!(
            decode(&body),
            Err(MetaError::Invalid(InvalidMeta::Base))
        ));
        let mut body = fresh();
        body.recipient = "age1nope";
        assert!(matches!(
            decode(&body),
            Err(MetaError::Invalid(InvalidMeta::Recipient))
        ));
        let mut body = fresh();
        body.owner = "Alice";
        assert!(matches!(decode(&body), Err(MetaError::Name(_))));
        let mut body = fresh();
        body.participants = vec![good, good];
        assert!(matches!(
            decode(&body),
            Err(MetaError::Invalid(InvalidMeta::DuplicateName))
        ));
        let mut body = fresh();
        body.participants = vec![good; MAX_PARTICIPANTS + 1];
        assert!(matches!(
            decode(&body),
            Err(MetaError::Invalid(InvalidMeta::TooManyParticipants))
        ));
        let mut body = fresh();
        body.participants = vec![];
        assert!(matches!(
            decode(&body),
            Err(MetaError::Invalid(InvalidMeta::NoParticipants))
        ));
        let mut body = fresh();
        body.private = &big_private;
        assert!(matches!(
            decode(&body),
            Err(MetaError::Invalid(InvalidMeta::PrivateTooLarge))
        ));
        let mut body = fresh();
        body.participants[0].recipient = "age1nope";
        assert!(matches!(
            decode(&body),
            Err(MetaError::Invalid(InvalidMeta::ParticipantRecipient))
        ));
        let mut body = fresh();
        body.participants[0].key = "ssh-ed25519 AAAA";
        assert!(matches!(decode(&body), Err(MetaError::Key(_))));
    }

    #[test]
    fn the_private_part_is_validated_when_opened() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let thread_key = ThreadKey::generate();
        let encoded = draft.sign(&thread_key, &alice.private).unwrap();
        let envelope: WireEnvelope<'_> = postcard::from_bytes(&encoded).unwrap();
        let mut body: WireBody<'_> = postcard::from_bytes(envelope.body).unwrap();
        let bad = thread_key
            .seal(
                &postcard::to_allocvec(&WirePrivate {
                    title: "\u{202E}evil",
                    landing_branch: "main",
                })
                .unwrap(),
            )
            .unwrap();
        body.private = &bad;
        let resigned = resign(&alice.private, &postcard::to_allocvec(&body).unwrap());
        let meta = VerifiedMeta::decode(&resigned, draft.thread, &alice.key()).unwrap();
        assert!(matches!(
            meta.private(&thread_key),
            Err(MetaError::Invalid(InvalidMeta::TitleCharacter))
        ));
    }

    #[test]
    fn thread_key_needs_a_listed_participant_and_a_matching_key() {
        let (alice, bob, carol) = (
            Person::new("alice"),
            Person::new("bob"),
            Person::new("carol"),
        );
        let draft = draft(&alice, &[&bob]);
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        let meta = VerifiedMeta::decode(&encoded, draft.thread, &alice.key()).unwrap();
        assert!(matches!(
            meta.thread_key(&carol.name, carol.identity()),
            Err(MetaError::NotAParticipant)
        ));
        assert!(matches!(
            meta.thread_key(&bob.name, carol.identity()),
            Err(MetaError::WrappedKey(_))
        ));
    }

    #[test]
    fn a_wrapped_key_for_another_thread_is_detected() {
        let alice = Person::new("alice");
        let draft = draft(&alice, &[]);
        let encoded = draft.sign(&ThreadKey::generate(), &alice.private).unwrap();
        let envelope: WireEnvelope<'_> = postcard::from_bytes(&encoded).unwrap();
        let mut body: WireBody<'_> = postcard::from_bytes(envelope.body).unwrap();
        let other = ThreadKey::generate()
            .wrap(&[&alice.mahi.to_public()])
            .unwrap();
        body.participants[0].wrapped = &other;
        let resigned = resign(&alice.private, &postcard::to_allocvec(&body).unwrap());
        let meta = VerifiedMeta::decode(&resigned, draft.thread, &alice.key()).unwrap();
        assert!(matches!(
            meta.thread_key(&alice.name, alice.identity()),
            Err(MetaError::KeyMismatch)
        ));
    }

    struct LyingSigner {
        claims: PrivateKey,
        signs_with: PrivateKey,
    }

    impl SshSigner for LyingSigner {
        fn public_key(&self) -> &ssh_key::PublicKey {
            self.claims.public_key()
        }

        fn sign_sshsig(
            &self,
            namespace: &str,
            hash: HashAlg,
            message: &[u8],
        ) -> Result<SshSig, SignError> {
            Ok(self.signs_with.sign(namespace, hash, message)?)
        }
    }

    #[test]
    fn a_signer_returning_another_key_signature_is_refused() {
        let (alice, mallory) = (Person::new("alice"), Person::new("mallory"));
        let lying = LyingSigner {
            claims: alice.private.clone(),
            signs_with: mallory.private.clone(),
        };
        assert!(matches!(
            draft(&alice, &[]).sign(&ThreadKey::generate(), &lying),
            Err(MetaError::InvalidSignature)
        ));
    }

    #[test]
    fn signing_needs_the_owner_key() {
        let (alice, bob) = (Person::new("alice"), Person::new("bob"));
        assert!(matches!(
            draft(&alice, &[&bob]).sign(&ThreadKey::generate(), &bob.private),
            Err(MetaError::Invalid(InvalidMeta::SigningKeyNotOwner))
        ));
    }

    #[test]
    fn drafts_check_their_participants() {
        let (alice, bob) = (Person::new("alice"), Person::new("bob"));
        let private = PrivateMeta::new("t", "main").unwrap();
        let make = |participants: Vec<Participant>| {
            MetaDraft::new(
                ThreadId::random().unwrap(),
                0,
                base(),
                alice.name.clone(),
                participants,
                private.clone(),
            )
            .map(|_| ())
            .map_err(|error| match error {
                MetaError::Invalid(reason) => reason,
                other => panic!("{other:?}"),
            })
        };
        assert_eq!(make(vec![]), Err(InvalidMeta::NoParticipants));
        assert_eq!(
            make(vec![bob.participant()]),
            Err(InvalidMeta::OwnerNotListed)
        );
        assert_eq!(
            make(vec![alice.participant(), alice.participant()]),
            Err(InvalidMeta::DuplicateName)
        );
        let same_key =
            Participant::new(bob.name.clone(), alice.key(), bob.mahi.to_public()).unwrap();
        let same_recipient =
            Participant::new(bob.name.clone(), bob.key(), alice.mahi.to_public()).unwrap();
        assert_eq!(
            make(vec![alice.participant(), same_key]),
            Err(InvalidMeta::DuplicateKey)
        );
        assert_eq!(
            make(vec![alice.participant(), same_recipient]),
            Err(InvalidMeta::DuplicateRecipient)
        );
        assert_eq!(make(vec![alice.participant(), bob.participant()]), Ok(()));
    }

    fn recipient_from_bytes(bytes: [u8; 32]) -> x25519::Recipient {
        let hrp = bech32::Hrp::parse("age").unwrap();
        bech32::encode::<bech32::Bech32>(hrp, &bytes)
            .unwrap()
            .parse()
            .unwrap()
    }

    fn low_order_points() -> Vec<[u8; 32]> {
        let mut minus_one = [0xff; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        let mut one = [0; 32];
        one[0] = 1;
        let mut high_bit_zero = [0; 32];
        high_bit_zero[31] = 0x80;
        let order_eight = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        vec![[0; 32], one, minus_one, high_bit_zero, order_eight]
    }

    #[test]
    fn low_order_mahi_keys_are_refused() {
        let alice = Person::new("alice");
        for point in low_order_points() {
            assert_eq!(
                Participant::new(alice.name.clone(), alice.key(), recipient_from_bytes(point)),
                Err(InvalidMeta::WeakRecipient),
                "{point:02x?}"
            );
        }
        assert!(Participant::new(alice.name.clone(), alice.key(), alice.mahi.to_public()).is_ok());
    }

    #[test]
    fn a_signed_body_with_a_low_order_mahi_key_is_refused() {
        let alice = Person::new("alice");
        let key = alice.key();
        let weak = recipient_from_bytes([0; 32]).to_string();
        let recipient = ThreadKey::generate().recipient().to_string();
        let base = base();
        let body = WireBody {
            thread: [0; 16],
            generation: 0,
            base: base.as_bytes(),
            owner: "alice",
            recipient: &recipient,
            participants: vec![WireParticipant {
                name: "alice",
                key: key.to_openssh(),
                recipient: &weak,
                wrapped: b"",
            }],
            private: b"",
        };
        let encoded = resign(&alice.private, &postcard::to_allocvec(&body).unwrap());
        assert!(matches!(
            VerifiedMeta::decode(&encoded, ThreadId::from_bytes([0; 16]), &key),
            Err(MetaError::Invalid(InvalidMeta::WeakRecipient))
        ));
    }

    #[test]
    fn differently_encoded_copies_of_a_mahi_key_are_duplicates() {
        let (alice, bob) = (Person::new("alice"), Person::new("bob"));
        let upper: x25519::Recipient = alice
            .mahi
            .to_public()
            .to_string()
            .to_uppercase()
            .parse()
            .unwrap();
        let copy = Participant::new(bob.name.clone(), bob.key(), upper).unwrap();
        assert!(matches!(
            MetaDraft::new(
                ThreadId::random().unwrap(),
                0,
                base(),
                alice.name.clone(),
                vec![alice.participant(), copy],
                PrivateMeta::new("t", "main").unwrap(),
            ),
            Err(MetaError::Invalid(InvalidMeta::DuplicateRecipient))
        ));
    }

    #[test]
    fn private_meta_checks_title_and_branch() {
        let reason = |title: &str, branch: &str| match PrivateMeta::new(title, branch) {
            Ok(_) => None,
            Err(MetaError::Invalid(reason)) => Some(reason),
            Err(other) => panic!("{other:?}"),
        };
        assert_eq!(reason("Fix the parser: step 2", "main"), None);
        assert_eq!(reason("ok", "feature/x-1"), None);
        assert_eq!(reason("日本語のタイトル", "main"), None);
        assert_eq!(
            reason(&"t".repeat(MAX_TITLE_BYTES + 1), "main"),
            Some(InvalidMeta::TitleTooLong)
        );
        for title in [
            "line\nbreak",
            "bell\u{7}",
            "\u{202E}gnp.exe",
            "zero\u{200B}width",
            "\u{2066}isolate",
            "line\u{2028}separator",
            "blank\u{3164}filler",
            "joined\u{200D}emoji",
        ] {
            assert_eq!(
                reason(title, "main"),
                Some(InvalidMeta::TitleCharacter),
                "{title:?}"
            );
        }
        for branch in [
            "", "a..b", "a b", "a~b", "-", "-x", "HEAD", "x.lock", "a/", "@{", "HEAD^",
        ] {
            assert_eq!(reason("t", branch), Some(InvalidMeta::Branch), "{branch:?}");
        }
    }

    proptest! {
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let alice = Person::new("alice");
            let _ = VerifiedMeta::decode(&bytes, ThreadId::from_bytes([0; 16]), &alice.key());
        }
    }
}
