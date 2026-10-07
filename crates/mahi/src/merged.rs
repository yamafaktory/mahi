use std::{
    collections::BTreeMap,
    fmt::Write as _,
};

use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_store::{
    MAX_HISTORY_WALK,
    ObjectId,
    Store,
    StoreError,
};

use crate::session::SNAPSHOT_MESSAGE;

const TRAILER: &str = "Mahi-Merged: ";
const MOST_SOURCES: usize = 256;
const MOST_ABSORBED: usize = MOST_SOURCES / 2;

/// The latest snapshot of each agent whose work was merged into an agent, as the `Mahi-Merged`
/// trailers of the agent's snapshots record it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct MergedFrom(BTreeMap<AgentSlot, ObjectId>);

impl MergedFrom {
    /// Reads the trailers of a snapshot's `message`, leaving out lines that do not parse and
    /// keeping at most 256 sources.
    pub(crate) fn parse(message: &[u8]) -> Self {
        let mut merged = BTreeMap::new();
        for line in message.split(|byte| *byte == b'\n') {
            let Some(rest) = line.strip_prefix(TRAILER.as_bytes()) else {
                continue;
            };
            let Ok(rest) = std::str::from_utf8(rest) else {
                continue;
            };
            let Some((slot, commit)) = rest.split_once(' ') else {
                continue;
            };
            let (Ok(slot), Ok(commit)) = (
                slot.parse::<AgentSlot>(),
                ObjectId::from_hex(commit.as_bytes()),
            ) else {
                continue;
            };
            if merged.len() < MOST_SOURCES || merged.contains_key(&slot) {
                merged.insert(slot, commit);
            }
        }
        Self(merged)
    }

    /// Returns the agents whose work was merged.
    pub(crate) fn sources(&self) -> impl Iterator<Item = &AgentSlot> {
        self.0.keys()
    }

    /// Returns the snapshot of `source` last merged, if any.
    pub(crate) fn of(&self, source: &AgentSlot) -> Option<ObjectId> {
        self.0.get(source).copied()
    }

    /// Records that `commit`, a snapshot of `source`, was merged; returns `false`, recording
    /// nothing, when 256 other sources are already recorded.
    pub(crate) fn record(&mut self, source: AgentSlot, commit: ObjectId) -> bool {
        if self.0.len() >= MOST_SOURCES && !self.0.contains_key(&source) {
            return false;
        }
        self.0.insert(source, commit);
        true
    }

    /// Takes in what a source just merged had itself merged, `theirs`: each agent other than
    /// `except` with snapshots in `thread` whose snapshot there is the one this record holds or
    /// a newer one, while the record holds fewer than half of the sources it may, so that
    /// direct merges always have room. What cannot be decided within the shared walking budget
    /// is left as it is.
    pub(crate) fn absorb(
        &mut self,
        store: &Store,
        (theirs, thread): (&Self, ThreadId),
        except: Option<&AgentSlot>,
    ) {
        let mut budget = MAX_HISTORY_WALK;
        for (source, &commit) in &theirs.0 {
            if Some(source) == except {
                continue;
            }
            let held = self.of(source);
            if held.is_none() && self.0.len() >= MOST_ABSORBED {
                continue;
            }
            let snapshots = ThreadRef::new(thread, RefKind::Snapshots(source.clone()));
            if !matches!(store.head(&snapshots), Ok(Some(_))) {
                continue;
            }
            let newer = match held {
                None => true,
                Some(held) => {
                    held != commit
                        && matches!(store.descends_within(commit, held, &mut budget), Ok(true))
                }
            };
            if newer {
                let _ = self.record(source.clone(), commit);
            }
        }
    }

    /// Returns a snapshot that both a source, which merged `theirs`, and a target holding this
    /// record, or its own snapshots at `own` when it is one of the agents named, contain: the
    /// one each holds of an agent, whichever of the two is older. An agent whose snapshots
    /// cannot be read is passed over; `None` when there is none, or when the shared walking
    /// budget runs out first.
    pub(crate) fn shared_with(
        &self,
        store: &Store,
        theirs: &Self,
        own: Option<(&AgentSlot, ObjectId)>,
    ) -> Option<ObjectId> {
        let mut budget = MAX_HISTORY_WALK;
        for (source, &shared) in &theirs.0 {
            let ours = match own {
                Some((slot, head)) if slot == source => Some(head),
                _ => self.of(source),
            };
            let Some(ours) = ours else {
                continue;
            };
            for (newer, older) in [(ours, shared), (shared, ours)] {
                match store.descends_within(newer, older, &mut budget) {
                    Ok(true) => return Some(older),
                    Err(StoreError::HistoryTooLong(_)) => return None,
                    Ok(false) | Err(_) => {}
                }
            }
        }
        None
    }

    /// Returns the message of a snapshot that carries these trailers.
    pub(crate) fn message(&self) -> String {
        let mut message = String::from(SNAPSHOT_MESSAGE);
        if !self.0.is_empty() {
            message.push('\n');
        }
        for (slot, commit) in &self.0 {
            let _ = write!(message, "\n{TRAILER}{slot} {commit}");
        }
        message.push('\n');
        message
    }

    /// Reads what the agent whose snapshots are `snapshots` merged so far: the trailers of its
    /// newest snapshot that carries any, found by walking back from the newest, at most
    /// [`MAX_HISTORY_WALK`] snapshots.
    pub(crate) fn read(store: &Store, snapshots: &ThreadRef) -> Result<Self, StoreError> {
        Self::read_from(store, store.head(snapshots)?)
    }

    /// Reads what the snapshot history ending at `newest` merged so far, as [`Self::read`]
    /// does for a ref.
    pub(crate) fn read_from(store: &Store, newest: Option<ObjectId>) -> Result<Self, StoreError> {
        let mut next = newest;
        let mut walked = 0;
        while let Some(commit) = next {
            if walked >= MAX_HISTORY_WALK {
                return Err(StoreError::HistoryTooLong(commit));
            }
            walked += 1;
            let found = Self::parse(&store.commit_message(commit)?);
            if !found.0.is_empty() {
                return Ok(found);
            }
            next = store.parent(commit)?;
        }
        Ok(Self::default())
    }
}

#[cfg(test)]
mod tests {
    use mahi_core::{
        RefKind,
        ThreadId,
    };

    use super::*;

    fn slot(name: &str) -> AgentSlot {
        name.parse().unwrap()
    }

    fn id(byte: u8) -> ObjectId {
        ObjectId::from_bytes_or_panic(&[byte; 20])
    }

    #[test]
    fn trailers_round_trip_through_a_snapshot_message() {
        let mut merged = MergedFrom::default();
        assert_eq!(merged.message(), "snapshot\n");
        assert!(merged.record(slot("bob.codex"), id(2)));
        assert!(merged.record(slot("alice.claude"), id(1)));
        assert!(merged.record(slot("bob.codex"), id(3)));
        let message = merged.message();
        assert_eq!(
            message,
            format!(
                "snapshot\n\nMahi-Merged: alice.claude {}\nMahi-Merged: bob.codex {}\n",
                id(1),
                id(3)
            )
        );
        let parsed = MergedFrom::parse(message.as_bytes());
        assert_eq!(parsed, merged);
        assert_eq!(parsed.of(&slot("bob.codex")), Some(id(3)));
        assert_eq!(parsed.of(&slot("carol.aider")), None);
    }

    #[test]
    fn malformed_trailers_are_left_out_and_at_most_256_sources_are_kept() {
        let message = format!(
            "snapshot\n\nMahi-Merged: no-dot {}\nMahi-Merged: alice.claude nothex\nMahi-Merged: alice.claude\nMahi-Merged:  alice.claude {}\nMahi-Merged: bob.codex {}\n",
            id(1),
            id(1),
            id(2)
        );
        let parsed = MergedFrom::parse(message.as_bytes());
        assert_eq!(parsed.0.len(), 1);
        assert_eq!(parsed.of(&slot("bob.codex")), Some(id(2)));

        let mut many = MergedFrom::default();
        for index in 0..MOST_SOURCES {
            assert!(many.record(slot(&format!("alice.agent{index}")), id(1)));
        }
        assert!(!many.record(slot("bob.codex"), id(1)));
        assert!(many.record(slot("alice.agent0"), id(2)));
        let mut text = many.message();
        let _ = writeln!(text, "{TRAILER}bob.codex {}", id(3));
        let parsed = MergedFrom::parse(text.as_bytes());
        assert_eq!(parsed.0.len(), MOST_SOURCES);
        assert_eq!(parsed.of(&slot("bob.codex")), None);
    }

    #[test]
    fn the_newest_snapshot_with_trailers_is_read() {
        let (_repo, store) = crate::session::tests::repository_on_main();
        let snapshots = ThreadRef::new(
            ThreadId::random().unwrap(),
            RefKind::Snapshots(slot("alice.claude")),
        );
        assert_eq!(
            MergedFrom::read(&store, &snapshots).unwrap(),
            MergedFrom::default()
        );
        let tree = store.write_tree(&[]).unwrap();
        let mut older = MergedFrom::default();
        older.record(slot("bob.codex"), id(1));
        let first = store
            .append(&snapshots, None, tree, &older.message())
            .unwrap();
        let mut newer = older.clone();
        newer.record(slot("bob.codex"), id(2));
        let second = store
            .append(&snapshots, Some(first), tree, &newer.message())
            .unwrap();
        let third = store
            .append(&snapshots, Some(second), tree, SNAPSHOT_MESSAGE)
            .unwrap();
        store
            .append(&snapshots, Some(third), tree, SNAPSHOT_MESSAGE)
            .unwrap();
        assert_eq!(MergedFrom::read(&store, &snapshots).unwrap(), newer);
    }

    #[test]
    fn records_take_in_newer_snapshots_and_share_the_older_of_two() {
        let (_repo, store) = crate::session::tests::repository_on_main();
        let snapshots = ThreadRef::new(
            ThreadId::random().unwrap(),
            RefKind::Snapshots(slot("alice.claude")),
        );
        let tree = store.write_tree(&[]).unwrap();
        let first = store
            .append(&snapshots, None, tree, SNAPSHOT_MESSAGE)
            .unwrap();
        let second = store
            .append(&snapshots, Some(first), tree, SNAPSHOT_MESSAGE)
            .unwrap();
        let third = store
            .append(&snapshots, Some(second), tree, SNAPSHOT_MESSAGE)
            .unwrap();
        let held = |commit| {
            let mut record = MergedFrom::default();
            record.record(slot("alice.claude"), commit);
            record
        };

        let thread = snapshots.thread();
        let bob = ThreadRef::new(thread, RefKind::Snapshots(slot("bob.codex")));
        let bobs = store.append(&bob, None, tree, SNAPSHOT_MESSAGE).unwrap();

        let mut ours = held(second);
        ours.absorb(&store, (&held(first), thread), None);
        assert_eq!(ours.of(&slot("alice.claude")), Some(second));
        ours.absorb(&store, (&held(third), thread), Some(&slot("alice.claude")));
        assert_eq!(ours.of(&slot("alice.claude")), Some(second));
        let mut theirs = held(third);
        theirs.record(slot("bob.codex"), bobs);
        theirs.record(slot("eve.forged"), id(9));
        ours.absorb(&store, (&theirs, thread), None);
        assert_eq!(ours.of(&slot("alice.claude")), Some(third));
        assert_eq!(ours.of(&slot("bob.codex")), Some(bobs));
        assert_eq!(ours.of(&slot("eve.forged")), None);

        let mut full = MergedFrom::default();
        for index in 0..MOST_ABSORBED {
            full.record(slot(&format!("p{index}.agent")), id(1));
        }
        full.absorb(&store, (&held(third), thread), None);
        assert_eq!(full.of(&slot("alice.claude")), None);

        assert_eq!(
            held(first).shared_with(&store, &held(third), None),
            Some(first)
        );
        assert_eq!(
            held(third).shared_with(&store, &held(first), None),
            Some(first)
        );
        let own = (&slot("alice.claude"), second);
        assert_eq!(
            MergedFrom::default().shared_with(&store, &held(first), Some(own)),
            Some(first)
        );
        let elsewhere = ThreadRef::new(
            ThreadId::random().unwrap(),
            RefKind::Snapshots(slot("alice.claude")),
        );
        let unrelated = store.append(&elsewhere, None, tree, "unrelated").unwrap();
        assert_eq!(
            held(unrelated).shared_with(&store, &held(third), None),
            None
        );
        assert_eq!(
            MergedFrom::default().shared_with(&store, &held(third), None),
            None
        );
    }
}
