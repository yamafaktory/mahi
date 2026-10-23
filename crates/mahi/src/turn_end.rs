use std::collections::HashMap;

use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_live::{
    COMMIT_BYTES,
    TurnEnd,
};
use mahi_store::{
    ObjectId,
    Store,
    StoreError,
};

use crate::session::SNAPSHOT_MESSAGE;

const TRAILER: &str = "Mahi-Turn-End: ";
const MAX_WALK: usize = 4096;

/// Returns the message of the snapshot that ends a turn of `slot`.
pub(crate) fn message(slot: &AgentSlot) -> String {
    format!("{SNAPSHOT_MESSAGE}\n\n{TRAILER}{slot}\n")
}

/// Says whether a snapshot's `message` ends a turn of the slot written `slot`: a line of its
/// trailers names that slot.
pub(crate) fn ends_turn_of(message: &[u8], slot: &str) -> bool {
    message
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(TRAILER.as_bytes()))
        .any(|named| named == slot.as_bytes())
}

/// The latest turn-end snapshot of each agent a host serves, read from its snapshots ref.
#[derive(Debug)]
pub(crate) struct LatestTurnEnds {
    thread: ThreadId,
    seen: HashMap<AgentSlot, Seen>,
}

#[derive(Debug, Clone, Copy)]
struct Seen {
    head: ObjectId,
    ended: Option<ObjectId>,
}

impl LatestTurnEnds {
    pub(crate) fn new(thread: ThreadId) -> Self {
        Self {
            thread,
            seen: HashMap::new(),
        }
    }

    /// Reads the snapshots of `slots` again, forgetting other agents and agents whose
    /// snapshots ref is gone, and returns the turn ends that are new since the last call.
    /// Each agent's snapshots are walked back from their newest to the newest seen before or
    /// to a turn end, at most 4,096 of them. When the ref no longer descends from the newest
    /// snapshot seen before, as after it was moved back, the latest turn end of its new
    /// history is taken without announcing it, so older work is never announced and the
    /// turn ends after it are. An agent whose snapshots cannot be read is read again next
    /// time.
    pub(crate) fn refresh(&mut self, store: &Store, slots: &[AgentSlot]) -> Vec<TurnEnd> {
        self.seen.retain(|slot, _| slots.contains(slot));
        let mut new = Vec::new();
        for slot in slots {
            let snapshots = ThreadRef::new(self.thread, RefKind::Snapshots(slot.clone()));
            let head = match store.head(&snapshots) {
                Ok(Some(head)) => head,
                Ok(None) => {
                    self.seen.remove(slot);
                    continue;
                }
                Err(_) => continue,
            };
            let before = self.seen.get(slot).copied();
            if before.is_some_and(|before| before.head == head) {
                continue;
            }
            let known = before.and_then(|before| before.ended);
            let mut budget = MAX_WALK;
            let moved_on = match before {
                None => true,
                Some(before) => match store.descends_within(head, before.head, &mut budget) {
                    Ok(moved_on) => moved_on,
                    Err(StoreError::HistoryTooLong(_)) => false,
                    Err(_) => continue,
                },
            };
            let text = slot.to_string();
            let stop_at = before.filter(|_| moved_on).map(|before| before.head);
            let ended = match latest_ended(store, &text, head, stop_at) {
                Walked::Failed => continue,
                Walked::Found(found) => Some(found),
                Walked::Nothing if moved_on => known,
                Walked::Nothing => None,
            };
            if moved_on && ended != known {
                new.extend(ended.and_then(|commit| announced(slot, commit)));
            }
            self.seen.insert(slot.clone(), Seen { head, ended });
        }
        new
    }

    /// Returns the latest turn end known of each agent.
    pub(crate) fn known(&self) -> Vec<TurnEnd> {
        self.seen
            .iter()
            .filter_map(|(slot, seen)| announced(slot, seen.ended?))
            .collect()
    }
}

/// What a walk back through an agent's snapshots found: a turn end, none new (it met the
/// snapshot seen before, the first snapshot or its limit), or a snapshot it could not read.
enum Walked {
    Found(ObjectId),
    Nothing,
    Failed,
}

fn latest_ended(store: &Store, slot: &str, head: ObjectId, stop_at: Option<ObjectId>) -> Walked {
    let mut next = Some(head);
    for _ in 0..MAX_WALK {
        let Some(commit) = next else {
            return Walked::Nothing;
        };
        if Some(commit) == stop_at {
            return Walked::Nothing;
        }
        let Ok(message) = store.commit_message(commit) else {
            return Walked::Failed;
        };
        if ends_turn_of(&message, slot) {
            return Walked::Found(commit);
        }
        let Ok(parent) = store.parent(commit) else {
            return Walked::Failed;
        };
        next = parent;
    }
    Walked::Nothing
}

fn announced(slot: &AgentSlot, commit: ObjectId) -> Option<TurnEnd> {
    let commit = <[u8; COMMIT_BYTES]>::try_from(commit.as_bytes()).ok()?;
    Some(TurnEnd {
        slot: slot.clone(),
        commit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::tests::repository_on_main;

    fn slot(name: &str) -> AgentSlot {
        name.parse().unwrap()
    }

    fn bytes(commit: ObjectId) -> [u8; COMMIT_BYTES] {
        commit.as_bytes().try_into().unwrap()
    }

    #[test]
    fn only_a_trailer_that_names_the_slot_ends_its_turn() {
        let alice = slot("alice.claude");
        assert!(ends_turn_of(message(&alice).as_bytes(), "alice.claude"));
        assert!(!ends_turn_of(message(&alice).as_bytes(), "bob.claude"));
        assert!(!ends_turn_of(SNAPSHOT_MESSAGE.as_bytes(), "alice.claude"));
        assert!(!ends_turn_of(
            b"snapshot\n\nMahi-Turn-End: alice.claude2\n",
            "alice.claude"
        ));
        assert!(!ends_turn_of(
            b"snapshot\n\nMahi-Turn-End:  alice.claude\n",
            "alice.claude"
        ));
    }

    #[test]
    fn a_host_learns_each_new_turn_end_once_and_keeps_the_latest() {
        let (_dir, store) = repository_on_main();
        let thread = ThreadId::random().unwrap();
        let alice = slot("alice.claude");
        let snapshots = ThreadRef::new(thread, RefKind::Snapshots(alice.clone()));
        let tree = store.write_tree(&[]).unwrap();
        let first = store
            .append(&snapshots, None, tree, SNAPSHOT_MESSAGE)
            .unwrap();
        let mut latest = LatestTurnEnds::new(thread);
        let slots = [alice.clone()];
        assert_eq!(latest.refresh(&store, &slots), []);

        let ended = store
            .append(&snapshots, Some(first), tree, &message(&alice))
            .unwrap();
        let after = store
            .append(&snapshots, Some(ended), tree, SNAPSHOT_MESSAGE)
            .unwrap();
        let expected = TurnEnd {
            slot: alice.clone(),
            commit: bytes(ended),
        };
        assert_eq!(
            latest.refresh(&store, &slots),
            std::slice::from_ref(&expected)
        );
        assert_eq!(latest.refresh(&store, &slots), []);

        let other = store
            .append(&snapshots, Some(after), tree, &message(&slot("bob.claude")))
            .unwrap();
        store
            .append(&snapshots, Some(other), tree, SNAPSHOT_MESSAGE)
            .unwrap();
        assert_eq!(latest.refresh(&store, &slots), []);
        assert_eq!(latest.known(), [expected]);

        assert_eq!(latest.refresh(&store, &[]), []);
        assert_eq!(latest.known(), []);
    }

    #[test]
    fn a_ref_moved_back_announces_only_the_turn_ends_after_it_and_a_removed_one_is_forgotten() {
        let (_dir, store) = repository_on_main();
        let thread = ThreadId::random().unwrap();
        let alice = slot("alice.claude");
        let snapshots = ThreadRef::new(thread, RefKind::Snapshots(alice.clone()));
        let tree = store.write_tree(&[]).unwrap();
        let older = store
            .append(&snapshots, None, tree, &message(&alice))
            .unwrap();
        let newer = store
            .append(&snapshots, Some(older), tree, &message(&alice))
            .unwrap();
        let mut latest = LatestTurnEnds::new(thread);
        let slots = [alice.clone()];
        let newest = TurnEnd {
            slot: alice.clone(),
            commit: bytes(newer),
        };
        assert_eq!(
            latest.refresh(&store, &slots),
            std::slice::from_ref(&newest)
        );

        let repo = gix::open(store.common_dir()).unwrap();
        repo.reference(
            snapshots.to_string(),
            older,
            gix::refs::transaction::PreviousValue::Any,
            "moved back",
        )
        .unwrap();
        assert_eq!(latest.refresh(&store, &slots), []);
        let rewound = TurnEnd {
            slot: alice.clone(),
            commit: bytes(older),
        };
        assert_eq!(latest.known(), std::slice::from_ref(&rewound));
        let next = store
            .append(&snapshots, Some(older), tree, &message(&alice))
            .unwrap();
        assert_eq!(
            latest.refresh(&store, &slots),
            [TurnEnd {
                slot: alice.clone(),
                commit: bytes(next),
            }]
        );

        repo.find_reference(snapshots.to_string().as_str())
            .unwrap()
            .delete()
            .unwrap();
        assert_eq!(latest.refresh(&store, &slots), []);
        assert_eq!(latest.known(), []);
    }
}
