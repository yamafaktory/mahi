use std::{
    fmt,
    str::FromStr,
};

use mahi_core::{
    NameError,
    ParticipantName,
};
use thiserror::Error;

use crate::{
    InvalidMeta,
    KeyError,
    NodeId,
    NodeIdError,
    Participant,
    ParticipantKey,
};

const PREFIX: &str = "mahi-participant";
const MAX_CARD_BYTES: usize = 1024;

/// A participant's public keys on one line, which they send to a thread's owner to be invited:
/// `mahi-participant <name> <mahi key> <node id> ssh-ed25519 <key>`.
///
/// Fields are separated by ASCII whitespace; anything after the SSH key is its comment and is
/// dropped. A card is one line: control characters, line breaks included, are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantCard(Participant);

/// A line that is not a usable participant card.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CardError {
    /// The line is longer than 1 KiB, does not start with `mahi-participant`, or misses a field.
    #[error(
        "not a participant card; it looks like `{PREFIX} <name> <mahi key> <node id> ssh-ed25519 <key>`"
    )]
    Malformed,
    /// The participant name is invalid.
    #[error("invalid participant name")]
    Name(#[from] NameError),
    /// The mahi key is not an age X25519 recipient.
    #[error("the mahi key is not an age X25519 recipient")]
    Recipient,
    /// The node id is not usable.
    #[error("invalid node id")]
    Node(#[from] NodeIdError),
    /// The SSH key is not a usable ed25519 key.
    #[error("invalid SSH key")]
    Key(#[from] KeyError),
    /// The keys break a rule of the meta document, such as a weak mahi key.
    #[error("invalid participant: {0}")]
    Invalid(#[from] InvalidMeta),
}

impl ParticipantCard {
    /// Makes the card of `participant`.
    #[must_use]
    pub fn new(participant: Participant) -> Self {
        Self(participant)
    }

    /// Returns the participant the card describes.
    #[must_use]
    pub fn participant(&self) -> &Participant {
        &self.0
    }

    /// Returns the participant the card describes.
    #[must_use]
    pub fn into_participant(self) -> Participant {
        self.0
    }
}

impl fmt::Display for ParticipantCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{PREFIX} {} {} {} {}",
            self.0.name(),
            self.0.recipient(),
            self.0.node(),
            self.0.key().to_openssh()
        )
    }
}

impl FromStr for ParticipantCard {
    type Err = CardError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.len() > MAX_CARD_BYTES {
            return Err(CardError::Malformed);
        }
        if text.trim().chars().any(char::is_control) {
            return Err(CardError::Malformed);
        }
        let mut words = text.split_ascii_whitespace();
        let mut word = || words.next().ok_or(CardError::Malformed);
        if word()? != PREFIX {
            return Err(CardError::Malformed);
        }
        let name = ParticipantName::new(word()?)?;
        let recipient = word()?.parse().map_err(|_| CardError::Recipient)?;
        let node = word()?.parse::<NodeId>()?;
        let algorithm = word()?;
        let key = ParticipantKey::from_openssh(&format!("{algorithm} {}", word()?))?;
        Ok(Self(Participant::new(name, key, recipient, node)?))
    }
}

#[cfg(test)]
mod tests {
    use age::x25519;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;
    use crate::node::tests::random_node;

    fn participant() -> Participant {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        Participant::new(
            ParticipantName::new("bob").unwrap(),
            ParticipantKey::from_public_key(key.public_key()).unwrap(),
            x25519::Identity::generate().to_public(),
            random_node(),
        )
        .unwrap()
    }

    #[test]
    fn a_card_round_trips_and_tolerates_spacing_and_a_key_comment() {
        let card = ParticipantCard::new(participant());
        let line = card.to_string();
        assert!(line.starts_with("mahi-participant bob age1"));
        assert_eq!(line.parse::<ParticipantCard>().unwrap(), card);
        let spaced = format!("  {}  bob@laptop\n", line.replacen(' ', "   ", 3));
        assert_eq!(spaced.parse::<ParticipantCard>().unwrap(), card);
        assert_eq!(
            card.clone().into_participant().node(),
            card.participant().node()
        );
    }

    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDU88jp0gZG1pnbk45/jquMkXECFQjH4lB40SRDQBOd6sYfqqaLt1gdu0tK8jApiV/sbirg4lAgTEWOfYCkXegaBgE51266E3LYEwRcgp/KosX0sw0AACaLV5wQtlNUegIaNEmXGxCK4tKcdoYj+kNKnk9r33GLXcbL3yeIyGRGvw==";

    #[test]
    fn a_card_is_one_line_without_control_characters() {
        let first = ParticipantCard::new(participant()).to_string();
        let second = ParticipantCard::new(participant()).to_string();
        for bad in [
            format!("{first} bob@laptop\n{second} carol@x"),
            format!("{first}\n{second}"),
            format!("{first} c\n\0garbage"),
            format!("{first} x\x1b[2Jy"),
            format!("{first}\tcomment\r"),
        ] {
            assert_eq!(
                bad.parse::<ParticipantCard>(),
                Err(CardError::Malformed),
                "{bad:?}"
            );
        }
        let tabbed = first.replace(' ', "\t");
        assert!(matches!(
            tabbed.parse::<ParticipantCard>(),
            Err(CardError::Malformed)
        ));
        let spaced = first.replacen(' ', "  ", 5);
        assert!(spaced.parse::<ParticipantCard>().is_ok());
        assert!(format!("{first}\r\n").parse::<ParticipantCard>().is_ok());
    }

    #[test]
    fn each_broken_field_is_named() {
        let line = ParticipantCard::new(participant()).to_string();
        let fields: Vec<&str> = line.splitn(5, ' ').collect();
        let with = |index: usize, value: &str| {
            let mut changed = fields.clone();
            changed[index] = value;
            changed.join(" ").parse::<ParticipantCard>()
        };
        assert_eq!(with(0, "mahi-person"), Err(CardError::Malformed));
        assert!(matches!(with(1, "Bob"), Err(CardError::Name(_))));
        assert_eq!(with(2, "age1nope"), Err(CardError::Recipient));
        assert!(matches!(with(3, "00"), Err(CardError::Node(_))));
        assert!(matches!(
            with(4, RSA),
            Err(CardError::Key(KeyError::Unsupported(_)))
        ));
        assert_eq!(
            fields[..4].join(" ").parse::<ParticipantCard>(),
            Err(CardError::Malformed)
        );
        assert_eq!(
            format!("{line}{}", " ".repeat(MAX_CARD_BYTES)).parse::<ParticipantCard>(),
            Err(CardError::Malformed)
        );
    }
}
