use std::{
    fmt,
    str::FromStr,
};

use thiserror::Error;

const MAX_LEN: usize = 32;
const SLOT_SEPARATOR: char = '.';

/// A string that is not a valid participant or agent name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NameError {
    /// The name is empty.
    #[error("name is empty")]
    Empty,
    /// The name is longer than 32 bytes.
    #[error("name is longer than {MAX_LEN} bytes")]
    TooLong,
    /// The name contains a character other than `a`–`z`, `0`–`9` and `-`.
    #[error("name contains {0:?}; only a-z, 0-9 and - are allowed")]
    InvalidChar(char),
    /// The name starts or ends with `-`.
    #[error("name starts or ends with -")]
    EdgeHyphen,
    /// The name is reserved, because it would make an invalid git ref name.
    #[error("name is reserved")]
    Reserved,
}

fn validate(s: &str, reserved: &[&str]) -> Result<(), NameError> {
    if s.is_empty() {
        return Err(NameError::Empty);
    }
    if s.len() > MAX_LEN {
        return Err(NameError::TooLong);
    }
    if let Some(bad) = s
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(NameError::InvalidChar(bad));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(NameError::EdgeHyphen);
    }
    if reserved.contains(&s) {
        return Err(NameError::Reserved);
    }
    Ok(())
}

macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident, reserved: $reserved:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Box<str>);

        impl $name {
            /// Validates `s` as a name.
            ///
            /// A name is 1 to 32 bytes of `a`–`z`, `0`–`9` and `-`, and does not start or end
            /// with `-`, and is not one of the type's reserved names. That keeps it safe inside a
            /// git ref name.
            ///
            /// # Errors
            ///
            /// Returns [`NameError`] if `s` is not a valid name or is reserved.
            pub fn new(s: &str) -> Result<Self, NameError> {
                validate(s, $reserved)?;
                Ok(Self(s.into()))
            }

            /// Returns the name as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = NameError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }
    };
}

name_type! {
    /// The name of a person taking part in a thread, such as `alice`.
    ParticipantName, reserved: &[]
}

name_type! {
    /// The name of an agent, such as `claude-code`.
    ///
    /// `lock` is reserved: git refuses a ref component ending in `.lock`, and the agent is the
    /// last part of `<participant>.<agent>`.
    AgentName, reserved: &["lock"]
}

/// One participant's agent in a thread, written `<participant>.<agent>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentSlot {
    participant: ParticipantName,
    agent: AgentName,
}

/// A string that is not a valid `<participant>.<agent>` slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SlotError {
    /// There is no `.` between the participant and the agent.
    #[error("agent slot has no . between participant and agent")]
    MissingSeparator,
    /// The participant part is not a valid name.
    #[error("invalid participant: {0}")]
    Participant(NameError),
    /// The agent part is not a valid name.
    #[error("invalid agent: {0}")]
    Agent(NameError),
}

impl AgentSlot {
    /// Creates the slot for `participant`'s `agent`.
    #[must_use]
    pub fn new(participant: ParticipantName, agent: AgentName) -> Self {
        Self { participant, agent }
    }

    /// Returns the participant who runs the agent.
    #[must_use]
    pub fn participant(&self) -> &ParticipantName {
        &self.participant
    }

    /// Returns the agent.
    #[must_use]
    pub fn agent(&self) -> &AgentName {
        &self.agent
    }
}

impl fmt::Display for AgentSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{SLOT_SEPARATOR}{}", self.participant, self.agent)
    }
}

impl FromStr for AgentSlot {
    type Err = SlotError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (participant, agent) = s
            .split_once(SLOT_SEPARATOR)
            .ok_or(SlotError::MissingSeparator)?;
        Ok(Self {
            participant: participant.parse().map_err(SlotError::Participant)?,
            agent: agent.parse().map_err(SlotError::Agent)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn accepts_simple_names() {
        for s in [
            "a",
            "alice",
            "claude-code",
            "gpt5",
            "0",
            &"x".repeat(MAX_LEN),
        ] {
            assert_eq!(AgentName::new(s).unwrap().as_str(), s);
        }
    }

    #[test]
    fn rejects_empty_and_long_names() {
        assert_eq!(AgentName::new(""), Err(NameError::Empty));
        assert_eq!(
            AgentName::new(&"x".repeat(MAX_LEN + 1)),
            Err(NameError::TooLong)
        );
    }

    #[test]
    fn rejects_characters_unsafe_in_ref_names() {
        for (s, bad) in [
            ("Alice", 'A'),
            ("a.b", '.'),
            ("a/b", '/'),
            ("a b", ' '),
            ("a_b", '_'),
            ("a~b", '~'),
            ("a:b", ':'),
            ("a@b", '@'),
            ("a\\b", '\\'),
            ("é", 'é'),
            ("a\u{0}", '\u{0}'),
        ] {
            assert_eq!(
                ParticipantName::new(s),
                Err(NameError::InvalidChar(bad)),
                "{s:?}"
            );
        }
    }

    #[test]
    fn rejects_edge_hyphens() {
        assert_eq!(AgentName::new("-a"), Err(NameError::EdgeHyphen));
        assert_eq!(AgentName::new("a-"), Err(NameError::EdgeHyphen));
        assert_eq!(AgentName::new("-"), Err(NameError::EdgeHyphen));
    }

    #[test]
    fn agent_named_lock_is_reserved() {
        assert_eq!(AgentName::new("lock"), Err(NameError::Reserved));
        assert_eq!(
            "alice.lock".parse::<AgentSlot>(),
            Err(SlotError::Agent(NameError::Reserved))
        );
        assert!(AgentName::new("locker").is_ok());
        assert!(ParticipantName::new("lock").is_ok());
    }

    #[test]
    fn slot_displays_participant_dot_agent() {
        let slot = AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("claude-code").unwrap(),
        );
        assert_eq!(slot.to_string(), "alice.claude-code");
        assert_eq!(slot.participant().as_str(), "alice");
        assert_eq!(slot.agent().as_str(), "claude-code");
    }

    #[test]
    fn slot_parse_reports_which_half_is_wrong() {
        assert_eq!(
            "alice".parse::<AgentSlot>(),
            Err(SlotError::MissingSeparator)
        );
        assert_eq!(
            ".codex".parse::<AgentSlot>(),
            Err(SlotError::Participant(NameError::Empty))
        );
        assert_eq!(
            "alice.".parse::<AgentSlot>(),
            Err(SlotError::Agent(NameError::Empty))
        );
        assert_eq!(
            "alice.claude.code".parse::<AgentSlot>(),
            Err(SlotError::Agent(NameError::InvalidChar('.')))
        );
    }

    fn name() -> impl Strategy<Value = String> {
        "[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?"
    }

    proptest! {
        #[test]
        fn valid_names_round_trip(s in name()) {
            prop_assert_eq!(ParticipantName::new(&s).unwrap().to_string(), s);
        }

        #[test]
        fn slot_round_trips(p in name(), a in name().prop_filter("reserved", |a| a != "lock")) {
            let slot: AgentSlot = format!("{p}.{a}").parse().unwrap();
            prop_assert_eq!(slot.to_string(), format!("{p}.{a}"));
        }

        #[test]
        fn accepted_names_are_ref_safe(s in ".*") {
            if let Ok(name) = AgentName::new(&s) {
                let n = name.as_str();
                prop_assert!(!n.is_empty() && n.len() <= MAX_LEN);
                prop_assert!(n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
                prop_assert!(!n.starts_with('-') && !n.ends_with('-'));
            }
        }
    }
}
