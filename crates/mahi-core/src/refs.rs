use std::{
    fmt,
    str::FromStr,
};

use thiserror::Error;

use crate::{
    AgentSlot,
    ParseThreadIdError,
    SlotError,
    ThreadId,
};

/// The prefix of every thread ref.
pub const THREADS_PREFIX: &str = "refs/threads/";

const META: &str = "meta";
const STATE: &str = "state";
const AGENTS: &str = "agents";
const SNAPSHOTS: &str = "snapshots";
const TRANSCRIPT: &str = "transcript";
const SESSION: &str = "session";

/// What a thread ref holds.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefKind {
    /// Title, base, participants, wrapped keys and landing branch.
    Meta,
    /// The encrypted shared CRDT state.
    State,
    /// One commit per edit of an agent's worktree.
    Snapshots(AgentSlot),
    /// One encrypted commit per agent turn.
    Transcript(AgentSlot),
    /// The agent's encrypted native session files.
    Session(AgentSlot),
}

/// A ref in a thread's namespace, such as `refs/threads/<id>/agents/alice.codex/snapshots`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadRef {
    thread: ThreadId,
    kind: RefKind,
}

/// A ref name that is not in the thread ref layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParseRefError {
    /// The name does not start with `refs/threads/`.
    #[error("not a thread ref")]
    NotThreadRef,
    /// The thread ID segment is invalid.
    #[error(transparent)]
    ThreadId(#[from] ParseThreadIdError),
    /// The agent slot segment is invalid.
    #[error(transparent)]
    Slot(#[from] SlotError),
    /// The segments after the thread ID are not a known layout.
    #[error("unknown thread ref layout")]
    UnknownLayout,
}

impl ThreadRef {
    /// Creates the ref of `kind` in `thread`.
    #[must_use]
    pub fn new(thread: ThreadId, kind: RefKind) -> Self {
        Self { thread, kind }
    }

    /// Returns the thread the ref belongs to.
    #[must_use]
    pub fn thread(&self) -> ThreadId {
        self.thread
    }

    /// Returns what the ref holds.
    #[must_use]
    pub fn kind(&self) -> &RefKind {
        &self.kind
    }
}

impl fmt::Display for ThreadRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{THREADS_PREFIX}{}/", self.thread)?;
        match &self.kind {
            RefKind::Meta => f.write_str(META),
            RefKind::State => f.write_str(STATE),
            RefKind::Snapshots(slot) => write!(f, "{AGENTS}/{slot}/{SNAPSHOTS}"),
            RefKind::Transcript(slot) => write!(f, "{AGENTS}/{slot}/{TRANSCRIPT}"),
            RefKind::Session(slot) => write!(f, "{AGENTS}/{slot}/{SESSION}"),
        }
    }
}

impl FromStr for ThreadRef {
    type Err = ParseRefError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix(THREADS_PREFIX)
            .ok_or(ParseRefError::NotThreadRef)?;
        let (thread, rest) = rest.split_once('/').ok_or(ParseRefError::UnknownLayout)?;
        let thread = thread.parse()?;
        let mut parts = rest.splitn(4, '/');
        let kind = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(META), None, None, None) => RefKind::Meta,
            (Some(STATE), None, None, None) => RefKind::State,
            (Some(AGENTS), Some(slot), Some(leaf), None) => {
                let slot = slot.parse()?;
                match leaf {
                    SNAPSHOTS => RefKind::Snapshots(slot),
                    TRANSCRIPT => RefKind::Transcript(slot),
                    SESSION => RefKind::Session(slot),
                    _ => return Err(ParseRefError::UnknownLayout),
                }
            }
            _ => return Err(ParseRefError::UnknownLayout),
        };
        Ok(Self { thread, kind })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        AgentName,
        ParticipantName,
    };

    const ID: &str = "7f3a9c2e00010203040506070809abff";

    fn slot() -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("claude-code").unwrap(),
        )
    }

    fn all_kinds() -> Vec<RefKind> {
        vec![
            RefKind::Meta,
            RefKind::State,
            RefKind::Snapshots(slot()),
            RefKind::Transcript(slot()),
            RefKind::Session(slot()),
        ]
    }

    #[test]
    fn follows_the_design_layout() {
        let id: ThreadId = ID.parse().unwrap();
        let names: Vec<String> = all_kinds()
            .into_iter()
            .map(|kind| ThreadRef::new(id, kind).to_string())
            .collect();
        assert_eq!(
            names,
            [
                format!("refs/threads/{ID}/meta"),
                format!("refs/threads/{ID}/state"),
                format!("refs/threads/{ID}/agents/alice.claude-code/snapshots"),
                format!("refs/threads/{ID}/agents/alice.claude-code/transcript"),
                format!("refs/threads/{ID}/agents/alice.claude-code/session"),
            ]
        );
    }

    #[test]
    fn every_kind_round_trips() {
        let id: ThreadId = ID.parse().unwrap();
        for kind in all_kinds() {
            let r = ThreadRef::new(id, kind);
            assert_eq!(r.to_string().parse::<ThreadRef>(), Ok(r.clone()));
        }
    }

    #[test]
    fn rejects_refs_outside_the_namespace() {
        for s in ["refs/heads/main", "refs/threads", "refs/thread/x/meta", ""] {
            assert_eq!(
                s.parse::<ThreadRef>(),
                Err(ParseRefError::NotThreadRef),
                "{s}"
            );
        }
    }

    #[test]
    fn rejects_malformed_layouts() {
        for suffix in [
            "",
            "/",
            "/meta/",
            "/meta/x",
            "/Meta",
            "/agents",
            "/agents/alice.codex",
            "/agents/alice.codex/",
            "/agents/alice.codex/snapshots/x",
            "/agents/alice.codex/other",
            "/agents/alice.codex//snapshots",
            "/alice.codex/snapshots",
            "//meta",
        ] {
            let s = format!("refs/threads/{ID}{suffix}");
            assert!(s.parse::<ThreadRef>().is_err(), "{s}");
        }
    }

    #[test]
    fn rejects_bad_ids_and_slots() {
        assert_eq!(
            "refs/threads/nothex/meta".parse::<ThreadRef>(),
            Err(ParseRefError::ThreadId(ParseThreadIdError))
        );
        assert_eq!(
            format!("refs/threads/{ID}/agents/alice/snapshots").parse::<ThreadRef>(),
            Err(ParseRefError::Slot(SlotError::MissingSeparator))
        );
        assert!(
            format!("refs/threads/{ID}/agents/../snapshots")
                .parse::<ThreadRef>()
                .is_err()
        );
    }

    fn is_valid_git_ref(name: &str) -> bool {
        gix_validate::reference::name(name.into()).is_ok()
    }

    #[test]
    fn every_kind_is_a_valid_git_ref() {
        let id: ThreadId = ID.parse().unwrap();
        for kind in all_kinds() {
            let name = ThreadRef::new(id, kind).to_string();
            assert!(is_valid_git_ref(&name), "{name}");
        }
    }

    fn segment() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("lock".to_owned()),
            "[a-z0-9]([a-z0-9-]{0,6}[a-z0-9])?",
            "[a-z0-9.-]{0,8}",
        ]
    }

    fn near_valid_ref() -> impl Strategy<Value = String> {
        let id = prop_oneof![
            4 => "[0-9a-f]{32}",
            1 => "[0-9a-fA-G.]{30,34}",
        ];
        let slot = prop_oneof![
            4 => (segment(), segment()).prop_map(|(p, a)| format!("{p}.{a}")),
            1 => "[a-z0-9./-]{0,12}",
        ];
        let leaf = prop_oneof![
            Just(SNAPSHOTS.to_owned()),
            Just(TRANSCRIPT.to_owned()),
            Just(SESSION.to_owned()),
            "[a-z/.]{0,10}",
        ];
        let tail = prop_oneof![
            Just(META.to_owned()),
            Just(STATE.to_owned()),
            (slot, leaf).prop_map(|(slot, leaf)| format!("{AGENTS}/{slot}/{leaf}")),
            "[a-z0-9./-]{0,20}",
        ];
        (id, tail).prop_map(|(id, tail)| format!("{THREADS_PREFIX}{id}/{tail}"))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn accepted_refs_display_back_and_are_valid_git_refs(s in near_valid_ref()) {
            if let Ok(r) = s.parse::<ThreadRef>() {
                prop_assert_eq!(r.to_string(), s.clone());
                prop_assert!(is_valid_git_ref(&s), "{}", s);
            }
        }

        #[test]
        fn parsing_arbitrary_strings_never_panics(s in ".{0,200}") {
            let _ = s.parse::<ThreadRef>();
        }
    }
}
