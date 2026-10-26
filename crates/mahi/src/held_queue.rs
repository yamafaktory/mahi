use std::{
    collections::{
        HashMap,
        VecDeque,
    },
    sync::Mutex,
    time::Instant,
};

use mahi_core::AgentSlot;
use mahi_store::ObjectId;

use crate::held::HeldSettings;

/// The teammates' snapshots that wait for the user because they change agent settings, as the
/// run's palette shows them, and what the user chose for each.
#[derive(Debug, Default)]
pub(crate) struct HeldQueue {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    waiting: Vec<Waiting>,
    choices: VecDeque<(AgentSlot, HeldSettings, Choice)>,
    seen: HashMap<(AgentSlot, ObjectId), Instant>,
    open: bool,
}

/// A snapshot that waits for the user: its teammate, the record of it, and when this run
/// first saw it.
#[derive(Debug, Clone)]
pub(crate) struct Waiting {
    pub(crate) from: AgentSlot,
    pub(crate) held: HeldSettings,
    pub(crate) since: Instant,
}

/// What the user chose for a snapshot that waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choice {
    /// Merge it, agent settings and all.
    Take,
    /// Leave its change out, and merge the teammate's next turns from it.
    Skip,
}

impl HeldQueue {
    fn lock(&self) -> Option<std::sync::MutexGuard<'_, State>> {
        self.state.lock().ok()
    }

    /// Shows the snapshots in `held` as the ones that wait, but those the user already chose
    /// for, and asks for the palette to open when one comes that this run had not shown.
    pub(crate) fn show(&self, held: Vec<(AgentSlot, HeldSettings)>) {
        let Some(mut state) = self.lock() else {
            return;
        };
        let now = Instant::now();
        let mut waiting = Vec::with_capacity(held.len());
        for (from, record) in held {
            let chosen = state
                .choices
                .iter()
                .any(|(slot, chosen, _)| *slot == from && chosen.commit == record.commit);
            if chosen {
                continue;
            }
            let key = (from.clone(), record.commit);
            let since = if let Some(since) = state.seen.get(&key) {
                *since
            } else {
                state.seen.insert(key, now);
                state.open = true;
                now
            };
            waiting.push(Waiting {
                from,
                held: record,
                since,
            });
        }
        state.waiting = waiting;
    }

    /// Calls `each` with every snapshot that waits, in order.
    pub(crate) fn each(&self, mut each: impl FnMut(&Waiting)) {
        let Some(state) = self.lock() else {
            return;
        };
        for waiting in &state.waiting {
            each(waiting);
        }
    }

    /// Returns the snapshot of `from` that waits, if one does.
    pub(crate) fn waiting(&self, from: &AgentSlot) -> Option<Waiting> {
        let state = self.lock()?;
        state
            .waiting
            .iter()
            .find(|waiting| waiting.from == *from)
            .cloned()
    }

    /// Records the user's `choice` for the snapshot `commit` of `from`, and says whether it
    /// still waited.
    pub(crate) fn choose(&self, (from, commit): (&AgentSlot, ObjectId), choice: Choice) -> bool {
        let Some(mut state) = self.lock() else {
            return false;
        };
        let Some(index) = state
            .waiting
            .iter()
            .position(|waiting| waiting.from == *from && waiting.held.commit == commit)
        else {
            return false;
        };
        let chosen = state.waiting.remove(index);
        state.choices.push_back((chosen.from, chosen.held, choice));
        true
    }

    /// Takes the choices the user made, oldest first.
    pub(crate) fn take_choices(&self) -> Vec<(AgentSlot, HeldSettings, Choice)> {
        self.lock()
            .map(|mut state| state.choices.drain(..).collect())
            .unwrap_or_default()
    }

    /// Asks for the palette to open again, since taking a snapshot failed and it waits once
    /// more.
    pub(crate) fn failed(&self) {
        if let Some(mut state) = self.lock() {
            state.open = true;
        }
    }

    /// Says, once, whether a snapshot came that the palette should open for.
    pub(crate) fn wants_open(&self) -> bool {
        self.lock()
            .is_some_and(|mut state| std::mem::take(&mut state.open))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(byte: u8) -> HeldSettings {
        HeldSettings::new(
            ObjectId::from_bytes_or_panic(&[byte; 20]),
            &["CLAUDE.md".to_owned()],
        )
    }

    #[test]
    fn a_new_held_snapshot_asks_once_for_the_palette_and_a_choice_takes_it_off() {
        let queue = HeldQueue::default();
        let bob: AgentSlot = "bob.claude".parse().unwrap();
        assert!(!queue.wants_open());
        queue.show(vec![(bob.clone(), record(1))]);
        assert!(queue.wants_open());
        assert!(!queue.wants_open());
        let since = queue.waiting(&bob).unwrap().since;
        queue.show(vec![(bob.clone(), record(1))]);
        assert!(!queue.wants_open());
        assert_eq!(queue.waiting(&bob).unwrap().since, since);
        assert!(queue.choose((&bob, record(1).commit), Choice::Skip));
        assert!(!queue.choose((&bob, record(1).commit), Choice::Skip));
        queue.show(vec![(bob.clone(), record(1))]);
        assert!(queue.waiting(&bob).is_none());
        let choices = queue.take_choices();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].2, Choice::Skip);
        assert!(queue.take_choices().is_empty());
        queue.show(vec![(bob.clone(), record(2))]);
        assert!(queue.wants_open());
        assert_eq!(queue.waiting(&bob).unwrap().held.commit, record(2).commit);
        queue.show(Vec::new());
        assert!(queue.waiting(&bob).is_none());
    }
}
