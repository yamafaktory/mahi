use std::{
    fmt,
    str::FromStr,
};

use mahi_core::{
    AgentSlot,
    is_invisible,
};
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
    de,
};

const LANDING: &str = "landing:";

/// Where a merge into an agent's worktree comes from: a teammate's agent, or the landing branch
/// a landing on its tip brought.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Source {
    Agent(AgentSlot),
    Landing(LandingBranch),
}

/// The landing branch a landing was built on, and the remote it was fetched from, both names
/// without whitespace, control or invisible characters, or `:`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct LandingBranch {
    remote: String,
    branch: String,
}

impl LandingBranch {
    /// Returns the landing branch `branch` on `remote`, or `None` when either name is empty or
    /// holds whitespace, a control or invisible character, or `:`.
    pub(crate) fn new(remote: &str, branch: &str) -> Option<Self> {
        let plain = |name: &str| {
            !name.is_empty()
                && !name.chars().any(|character| {
                    character.is_whitespace()
                        || character.is_control()
                        || is_invisible(character)
                        || character == ':'
                })
        };
        (plain(remote) && plain(branch)).then(|| Self {
            remote: remote.to_owned(),
            branch: branch.to_owned(),
        })
    }
}

impl Source {
    /// Returns the label of conflict markers on this source's side: `mahi bob.claude` for a
    /// teammate's agent, `mahi main` for the landing branch.
    pub(crate) fn label(&self) -> String {
        format!("mahi {}", self.shown())
    }

    /// Returns how the note and the status line name this source: `bob.claude`, or
    /// `main on up`.
    pub(crate) fn named(&self) -> String {
        match self {
            Self::Agent(slot) => slot.to_string(),
            Self::Landing(landing) => format!("{} on {}", landing.branch, landing.remote),
        }
    }

    /// Returns how the palette names this source: `bob.claude`, or `main`.
    pub(crate) fn shown(&self) -> String {
        match self {
            Self::Agent(slot) => slot.to_string(),
            Self::Landing(landing) => landing.branch.clone(),
        }
    }

    /// Returns the teammate's agent, when this source is one.
    pub(crate) fn agent(&self) -> Option<&AgentSlot> {
        match self {
            Self::Agent(slot) => Some(slot),
            Self::Landing(_) => None,
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent(slot) => write!(formatter, "{slot}"),
            Self::Landing(landing) => {
                write!(formatter, "{LANDING}{}:{}", landing.remote, landing.branch)
            }
        }
    }
}

impl FromStr for Source {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let Some(landing) = text.strip_prefix(LANDING) else {
            return text.parse().map(Self::Agent).map_err(|_| ());
        };
        let (remote, branch) = landing.split_once(':').ok_or(())?;
        LandingBranch::new(remote, branch)
            .map(Self::Landing)
            .ok_or(())
    }
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse()
            .map_err(|()| de::Error::custom("not a merge source"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_reads_back_as_written_and_names_itself_as_the_note_does() {
        let bob = Source::Agent("bob.claude".parse().unwrap());
        let main = Source::Landing(LandingBranch::new("up", "release/main").unwrap());
        for source in [&bob, &main] {
            assert_eq!(source.to_string().parse::<Source>(), Ok(source.clone()));
        }
        assert_eq!(main.to_string(), "landing:up:release/main");
        assert_eq!(
            [bob.label(), bob.named(), main.label(), main.named()],
            [
                "mahi bob.claude",
                "bob.claude",
                "mahi release/main",
                "release/main on up"
            ]
        );
        assert_eq!(
            bob.agent().map(ToString::to_string).as_deref(),
            Some("bob.claude")
        );
        assert_eq!(main.agent(), None);
        for refused in [
            "landing:up",
            "landing::main",
            "landing:up:a b",
            "landing:u\u{1b}:m",
            "bob",
        ] {
            assert_eq!(refused.parse::<Source>(), Err(()), "{refused:?}");
        }
        assert_eq!(LandingBranch::new("up", "a:b"), None);
        assert_eq!(LandingBranch::new("up", "ma\u{202e}in"), None);
    }
}
