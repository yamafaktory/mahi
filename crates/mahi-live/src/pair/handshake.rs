use chacha20poly1305::{
    KeyInit,
    XChaCha20Poly1305,
    XNonce,
    aead::{
        Aead,
        Payload,
    },
};
use hkdf::Hkdf;
use hmac::{
    Hmac,
    Mac,
};
use sha2::{
    Digest,
    Sha256,
};
use spake2::{
    Ed25519Group,
    Identity,
    Password,
    Spake2,
};
use thiserror::Error;
use zeroize::Zeroizing;

use super::PairingCode;

/// The most a sealed pairing message carries.
pub const MAX_MESSAGE_BYTES: usize = 4096;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
/// The most a sealed message takes on the wire: its nonce, its ciphertext and its tag.
pub const MAX_SEALED_BYTES: usize = NONCE_BYTES + MAX_MESSAGE_BYTES + TAG_BYTES;
const KEY_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Which side of a pairing this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The thread's owner, who drew the code and waits.
    Owner,
    /// The teammate who typed the code.
    Joiner,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Self::Owner => b'O',
            Self::Joiner => b'J',
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Owner => Self::Joiner,
            Self::Joiner => Self::Owner,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Joiner => "joiner",
        }
    }
}

/// A pairing went wrong; none of these says anything about the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PairError {
    /// The other side's key exchange message is not one.
    #[error("the other side's pairing message is not valid")]
    Exchange,
    /// The other side does not know the same code.
    #[error("the pairing code did not match")]
    Mismatch,
    /// A sealed message is too short, too long, or not sealed for this pairing in this order.
    #[error("a pairing message cannot be opened")]
    Sealed,
    /// The system gave no random bytes.
    #[error("cannot draw random bytes for the pairing")]
    Random,
}

/// The first step of a pairing: this side's SPAKE2 message is sent, the other's awaited.
#[derive(Debug)]
pub struct Handshake {
    role: Role,
    slot: u16,
    spake: Spake2<Ed25519Group>,
    sent: Vec<u8>,
}

impl Handshake {
    /// Starts a pairing as `role` with `code`, and returns the message to send first.
    #[must_use]
    pub fn start(role: Role, code: &PairingCode) -> (Self, Vec<u8>) {
        let slot = code.slot();
        let password = code.password();
        let owner = identity(Role::Owner, slot);
        let joiner = identity(Role::Joiner, slot);
        let password = Password::new(password.as_bytes());
        let (spake, sent) = match role {
            Role::Owner => Spake2::<Ed25519Group>::start_a(
                &password,
                &Identity::new(&owner),
                &Identity::new(&joiner),
            ),
            Role::Joiner => Spake2::<Ed25519Group>::start_b(
                &password,
                &Identity::new(&owner),
                &Identity::new(&joiner),
            ),
        };
        let message = sent.clone();
        (
            Self {
                role,
                slot,
                spake,
                sent,
            },
            message,
        )
    }

    /// Takes the other side's SPAKE2 message and derives the keys; both sides must then
    /// confirm them before anything else is sent.
    ///
    /// # Errors
    ///
    /// Returns [`PairError::Exchange`] if the message is not a SPAKE2 message of the other side.
    pub fn finish(self, received: &[u8]) -> Result<Confirming, PairError> {
        let key = Zeroizing::new(
            self.spake
                .finish(received)
                .map_err(|_| PairError::Exchange)?,
        );
        let (owner_message, joiner_message) = match self.role {
            Role::Owner => (self.sent.as_slice(), received),
            Role::Joiner => (received, self.sent.as_slice()),
        };
        let mut transcript = Sha256::new();
        for message in [owner_message, joiner_message] {
            transcript.update(
                u32::try_from(message.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            transcript.update(message);
        }
        let salt = format!("mahi-pair-v1 {}", self.slot);
        let expander = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &key);
        let derive = |info: &str| {
            let mut out = Zeroizing::new([0_u8; KEY_BYTES]);
            expander
                .expand(info.as_bytes(), out.as_mut())
                .map(|()| out)
                .map_err(|_| PairError::Exchange)
        };
        let own = self.role.name();
        let their = self.role.other().name();
        Ok(Confirming {
            role: self.role,
            transcript: transcript.finalize().into(),
            confirm_own: derive(&format!("confirm {own}"))?,
            confirm_their: derive(&format!("confirm {their}"))?,
            seal_own: derive(&format!("seal {own}"))?,
            seal_their: derive(&format!("seal {their}"))?,
        })
    }
}

fn identity(role: Role, slot: u16) -> Vec<u8> {
    format!("mahi-pair-v1 {} {slot}", role.name()).into_bytes()
}

/// The keys both sides derived, not yet confirmed: the joiner sends its confirmation first,
/// and nothing else is sent until each has checked the other's.
pub struct Confirming {
    role: Role,
    transcript: [u8; 32],
    confirm_own: Zeroizing<[u8; KEY_BYTES]>,
    confirm_their: Zeroizing<[u8; KEY_BYTES]>,
    seal_own: Zeroizing<[u8; KEY_BYTES]>,
    seal_their: Zeroizing<[u8; KEY_BYTES]>,
}

impl std::fmt::Debug for Confirming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Confirming")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl Confirming {
    /// Returns this side's confirmation, to send to the other.
    #[must_use]
    pub fn confirmation(&self) -> [u8; 32] {
        mac(&self.confirm_own, &self.transcript)
            .finalize()
            .into_bytes()
            .into()
    }

    /// Checks the other side's confirmation, in constant time, and opens the sealed channel.
    ///
    /// # Errors
    ///
    /// Returns [`PairError::Mismatch`] if it does not match, which means the two sides did not
    /// use the same code.
    pub fn check(self, theirs: &[u8]) -> Result<Channel, PairError> {
        mac(&self.confirm_their, &self.transcript)
            .verify_slice(theirs)
            .map_err(|_| PairError::Mismatch)?;
        Ok(Channel {
            role: self.role,
            seal_own: self.seal_own,
            seal_their: self.seal_their,
            sent: 0,
            received: 0,
            failed: false,
        })
    }
}

fn mac(key: &[u8; KEY_BYTES], transcript: &[u8; 32]) -> HmacSha256 {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(transcript);
    mac
}

/// The confirmed pairing: messages each way, sealed under that way's key with the sender's
/// role and a counter as associated data, so none can be replayed, reflected or reordered.
/// After any failure it seals and opens nothing more, since a failure ends the pairing.
pub struct Channel {
    role: Role,
    seal_own: Zeroizing<[u8; KEY_BYTES]>,
    seal_their: Zeroizing<[u8; KEY_BYTES]>,
    sent: u64,
    received: u64,
    failed: bool,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("role", &self.role)
            .field("sent", &self.sent)
            .field("received", &self.received)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// Seals `message` for the other side: a random nonce, then the ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`PairError::Sealed`] if the message is larger than [`MAX_MESSAGE_BYTES`], or
    /// [`PairError::Random`] when the system gives no random bytes.
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>, PairError> {
        let sealed = self.seal_next(message);
        self.failed |= sealed.is_err();
        sealed
    }

    fn seal_next(&mut self, message: &[u8]) -> Result<Vec<u8>, PairError> {
        let next = self.sent.checked_add(1).ok_or(PairError::Sealed)?;
        if self.failed || message.len() > MAX_MESSAGE_BYTES {
            return Err(PairError::Sealed);
        }
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| PairError::Random)?;
        let aad = associated_data(self.role, self.sent);
        let sealed = XChaCha20Poly1305::new((&*self.seal_own).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: message,
                    aad: &aad,
                },
            )
            .map_err(|_| PairError::Sealed)?;
        self.sent = next;
        let mut out = Vec::with_capacity(NONCE_BYTES + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Opens the other side's next sealed message.
    ///
    /// # Errors
    ///
    /// Returns [`PairError::Sealed`] if it is too short or too long, or was not sealed by the
    /// other side of this pairing as its next message.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, PairError> {
        let opened = self.open_next(sealed);
        self.failed |= opened.is_err();
        opened
    }

    fn open_next(&mut self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, PairError> {
        let next = self.received.checked_add(1).ok_or(PairError::Sealed)?;
        if self.failed || sealed.len() < NONCE_BYTES + TAG_BYTES || sealed.len() > MAX_SEALED_BYTES
        {
            return Err(PairError::Sealed);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        let aad = associated_data(self.role.other(), self.received);
        let opened = XChaCha20Poly1305::new((&*self.seal_their).into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| PairError::Sealed)?;
        self.received = next;
        Ok(Zeroizing::new(opened))
    }
}

fn associated_data(sender: Role, counter: u64) -> [u8; 21] {
    let mut aad = [0_u8; 21];
    aad[..12].copy_from_slice(b"mahi-pair-v1");
    aad[12] = sender.byte();
    aad[13..].copy_from_slice(&counter.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(text: &str) -> PairingCode {
        text.parse().unwrap()
    }

    fn paired(owner_code: &str, joiner_code: &str) -> Result<(Channel, Channel), PairError> {
        let (owner, to_joiner) = Handshake::start(Role::Owner, &code(owner_code));
        let (joiner, to_owner) = Handshake::start(Role::Joiner, &code(joiner_code));
        let owner = owner.finish(&to_owner)?;
        let joiner = joiner.finish(&to_joiner)?;
        let from_joiner = joiner.confirmation();
        let from_owner = owner.confirmation();
        let owner = owner.check(&from_joiner)?;
        let joiner = joiner.check(&from_owner)?;
        Ok((owner, joiner))
    }

    #[test]
    fn the_same_code_pairs_and_messages_go_both_ways() {
        let (mut owner, mut joiner) =
            paired("412-aardvark-adroitness", "412-aardvark-adroitness").unwrap();
        let card = joiner.seal(b"mahi-participant bob").unwrap();
        assert_eq!(&*owner.open(&card).unwrap(), b"mahi-participant bob");
        let ticket = owner.seal(b"ticket").unwrap();
        assert_eq!(&*joiner.open(&ticket).unwrap(), b"ticket");
        let second = joiner.seal(b"again").unwrap();
        assert_eq!(&*owner.open(&second).unwrap(), b"again");
    }

    #[test]
    fn a_different_word_or_slot_fails_the_confirmation() {
        for other in [
            "412-aardvark-adviser",
            "412-absurd-adroitness",
            "413-aardvark-adroitness",
        ] {
            assert_eq!(
                paired("412-aardvark-adroitness", other).unwrap_err(),
                PairError::Mismatch,
                "{other}"
            );
        }
    }

    #[test]
    fn a_reflected_replayed_reordered_or_tampered_message_is_refused_and_ends_the_channel() {
        let (mut owner, mut joiner) = paired("1-zulu-yucatan", "1-zulu-yucatan").unwrap();
        let first = joiner.seal(b"one").unwrap();
        assert_eq!(joiner.open(&first).unwrap_err(), PairError::Sealed);
        assert_eq!(joiner.seal(b"more").unwrap_err(), PairError::Sealed);
        assert_eq!(&*owner.open(&first).unwrap(), b"one");
        assert_eq!(owner.open(&first).unwrap_err(), PairError::Sealed);
        assert_eq!(owner.seal(b"x").unwrap_err(), PairError::Sealed);

        let (mut owner, mut joiner) = paired("1-zulu-yucatan", "1-zulu-yucatan").unwrap();
        let _skipped = joiner.seal(b"one").unwrap();
        let second = joiner.seal(b"two").unwrap();
        assert_eq!(owner.open(&second).unwrap_err(), PairError::Sealed);

        let (mut owner, mut joiner) = paired("1-zulu-yucatan", "1-zulu-yucatan").unwrap();
        let mut tampered = owner.seal(b"x").unwrap();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert_eq!(joiner.open(&tampered).unwrap_err(), PairError::Sealed);
        assert!(format!("{joiner:?}").contains("failed: true"));
    }

    #[test]
    fn the_joiner_refuses_a_wrong_reflected_or_cut_confirmation() {
        let start = |owner_code: &str, joiner_code: &str| {
            let (owner, to_joiner) = Handshake::start(Role::Owner, &code(owner_code));
            let (joiner, to_owner) = Handshake::start(Role::Joiner, &code(joiner_code));
            (
                owner.finish(&to_owner).unwrap(),
                joiner.finish(&to_joiner).unwrap(),
            )
        };
        let (owner, joiner) = start("8-ahead-amusement", "8-ahead-antenna");
        assert_eq!(
            joiner.check(&owner.confirmation()).unwrap_err(),
            PairError::Mismatch
        );
        let (_owner, joiner) = start("8-ahead-amusement", "8-ahead-amusement");
        let own = joiner.confirmation();
        assert_eq!(joiner.check(&own).unwrap_err(), PairError::Mismatch);
        let (owner, joiner) = start("8-ahead-amusement", "8-ahead-amusement");
        let cut = owner.confirmation();
        assert_eq!(
            joiner.check(cut.get(..31).unwrap()).unwrap_err(),
            PairError::Mismatch
        );
    }

    #[test]
    fn a_message_from_the_same_role_or_of_the_wrong_size_is_refused() {
        let (owner, to_joiner) = Handshake::start(Role::Owner, &code("5-acme-aggregate"));
        let (other_owner, _) = Handshake::start(Role::Owner, &code("5-acme-aggregate"));
        assert_eq!(
            other_owner.finish(&to_joiner).unwrap_err(),
            PairError::Exchange
        );
        assert_eq!(owner.finish(&[0x42; 3]).unwrap_err(), PairError::Exchange);
        let fresh = || paired("5-acme-aggregate", "5-acme-aggregate").unwrap();
        let (mut owner, _) = fresh();
        assert_eq!(owner.open(&[0; 39]).unwrap_err(), PairError::Sealed);
        let (mut owner, _) = fresh();
        assert_eq!(
            owner.open(&vec![0; MAX_SEALED_BYTES + 1]).unwrap_err(),
            PairError::Sealed
        );
        let (mut owner, _) = fresh();
        assert_eq!(
            owner.seal(&[0; MAX_MESSAGE_BYTES + 1]).unwrap_err(),
            PairError::Sealed
        );
        let (mut owner, mut joiner) = fresh();
        let largest = joiner.seal(&[7; MAX_MESSAGE_BYTES]).unwrap();
        assert_eq!(largest.len(), MAX_SEALED_BYTES);
        assert_eq!(owner.open(&largest).unwrap().len(), MAX_MESSAGE_BYTES);
    }

    #[test]
    fn debug_output_shows_no_key() {
        let (owner, _) = Handshake::start(Role::Owner, &code("5-acme-aggregate"));
        let (joiner, to_owner) = Handshake::start(Role::Joiner, &code("5-acme-aggregate"));
        let _ = joiner;
        let confirming = owner.finish(&to_owner).unwrap();
        assert_eq!(format!("{confirming:?}"), "Confirming { role: Owner, .. }");
        let (channel, _) = paired("5-acme-aggregate", "5-acme-aggregate").unwrap();
        assert_eq!(
            format!("{channel:?}"),
            "Channel { role: Owner, sent: 0, received: 0, failed: false, .. }"
        );
    }
}
