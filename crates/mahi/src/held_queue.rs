use std::{
    collections::{
        HashMap,
        VecDeque,
    },
    sync::Mutex,
    time::Instant,
};

use mahi_store::ObjectId;

use crate::{
    held::HeldSettings,
    source::Source,
    when::Since,
};

/// The teammates' snapshots that wait for the user because they change agent settings, as the
/// run's palette shows them, and what the user chose for each.
#[derive(Debug, Default)]
pub(crate) struct HeldQueue {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    waiting: Vec<Waiting>,
    choices: VecDeque<(Source, HeldSettings, Choice)>,
    seen: HashMap<(Source, ObjectId), (Since, Option<String>)>,
    open: bool,
}

/// A snapshot that waits for the user: its teammate, the record of it, and when its turn ended,
/// or else when this run first saw it.
#[derive(Debug, Clone)]
pub(crate) struct Waiting {
    pub(crate) from: Source,
    pub(crate) held: HeldSettings,
    pub(crate) since: Instant,
    pub(crate) failure: Option<String>,
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
    /// for, and asks for the palette to open when one comes that this run had not shown. A
    /// snapshot waits since the instant `dated` gives it, asked until it gives one, and since
    /// this run first saw it meanwhile.
    pub(crate) fn show(
        &self,
        held: Vec<(Source, HeldSettings)>,
        dated: impl Fn(&Source, ObjectId) -> Option<Instant>,
    ) {
        let undated: Vec<((Source, ObjectId), Option<Since>)> = {
            let Some(state) = self.lock() else {
                return;
            };
            held.iter()
                .map(|(from, record)| {
                    let key = (from.clone(), record.commit);
                    let known = state.seen.get(&key).map(|(since, _)| *since);
                    (key, known)
                })
                .filter(|(_, known)| !matches!(known, Some(Since::TurnEnded(_))))
                .collect()
        };
        let now = Instant::now();
        let settled: HashMap<(Source, ObjectId), Since> = undated
            .into_iter()
            .map(|(key, known)| {
                let since = Since::settle(known, || dated(&key.0, key.1), now);
                (key, since)
            })
            .collect();
        let Some(mut state) = self.lock() else {
            return;
        };
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
            let settled = settled.get(&key).copied();
            state.open |= !state.seen.contains_key(&key);
            let entry = state
                .seen
                .entry(key)
                .or_insert((Since::FirstSeen(now), None));
            if let Some(since) = settled {
                entry.0 = since;
            }
            let (since, failure) = (entry.0.instant(), entry.1.clone());
            waiting.push(Waiting {
                from,
                held: record,
                since,
                failure,
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
    pub(crate) fn waiting(&self, from: &Source) -> Option<Waiting> {
        let state = self.lock()?;
        state
            .waiting
            .iter()
            .find(|waiting| waiting.from == *from)
            .cloned()
    }

    /// Records the user's `choice` for the snapshot `commit` of `from`, and says whether it
    /// still waited.
    pub(crate) fn choose(&self, (from, commit): (&Source, ObjectId), choice: Choice) -> bool {
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
        if let Some((_, failure)) = state.seen.get_mut(&(chosen.from.clone(), commit)) {
            *failure = None;
        }
        state.choices.push_back((chosen.from, chosen.held, choice));
        true
    }

    /// Takes the choices the user made, oldest first.
    pub(crate) fn take_choices(&self) -> Vec<(Source, HeldSettings, Choice)> {
        self.lock()
            .map(|mut state| state.choices.drain(..).collect())
            .unwrap_or_default()
    }

    pub(crate) fn failed(&self, (from, commit): (&Source, ObjectId), reason: String) {
        if let Some(mut state) = self.lock() {
            state.open = true;
            if let Some((_, failure)) = state.seen.get_mut(&(from.clone(), commit)) {
                *failure = Some(reason);
            }
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
    use std::time::Duration;

    use super::*;

    fn undated(_: &Source, _: ObjectId) -> Option<Instant> {
        None
    }

    fn record(byte: u8) -> HeldSettings {
        HeldSettings::new(
            ObjectId::from_bytes_or_panic(&[byte; 20]),
            &["CLAUDE.md".to_owned()],
        )
    }

    #[test]
    fn a_new_held_snapshot_asks_once_for_the_palette_and_a_choice_takes_it_off() {
        let queue = HeldQueue::default();
        let bob: Source = "bob.claude".parse().unwrap();
        assert!(!queue.wants_open());
        queue.show(vec![(bob.clone(), record(1))], undated);
        assert!(queue.wants_open());
        assert!(!queue.wants_open());
        let since = queue.waiting(&bob).unwrap().since;
        queue.show(vec![(bob.clone(), record(1))], undated);
        assert!(!queue.wants_open());
        assert_eq!(queue.waiting(&bob).unwrap().since, since);
        assert!(queue.choose((&bob, record(1).commit), Choice::Skip));
        assert!(!queue.choose((&bob, record(1).commit), Choice::Skip));
        queue.show(vec![(bob.clone(), record(1))], undated);
        assert!(queue.waiting(&bob).is_none());
        let choices = queue.take_choices();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].2, Choice::Skip);
        assert!(queue.take_choices().is_empty());
        queue.show(vec![(bob.clone(), record(2))], undated);
        assert!(queue.wants_open());
        assert_eq!(queue.waiting(&bob).unwrap().held.commit, record(2).commit);
        queue.show(Vec::new(), undated);
        assert!(queue.waiting(&bob).is_none());
    }

    #[test]
    fn a_held_snapshot_waits_since_its_turn_ended_once_that_time_arrives_and_is_not_dated_again() {
        let queue = HeldQueue::default();
        let bob: Source = "bob.claude".parse().unwrap();
        let ended = Instant::now()
            .checked_sub(Duration::from_secs(600))
            .unwrap();
        let asked = std::cell::Cell::new(0);
        let arrived = std::cell::Cell::new(false);
        let dated = |_: &Source, _: ObjectId| {
            asked.set(asked.get() + 1);
            arrived.get().then_some(ended)
        };
        queue.show(vec![(bob.clone(), record(1))], dated);
        let first_seen = queue.waiting(&bob).unwrap().since;
        assert!(first_seen > ended);
        assert!(queue.wants_open());
        queue.show(vec![(bob.clone(), record(1))], dated);
        assert_eq!(queue.waiting(&bob).unwrap().since, first_seen);
        arrived.set(true);
        queue.show(vec![(bob.clone(), record(1))], dated);
        assert_eq!(queue.waiting(&bob).unwrap().since, ended);
        assert!(!queue.wants_open());
        let asked_before = asked.get();
        queue.show(vec![(bob.clone(), record(1))], dated);
        assert_eq!(asked.get(), asked_before);
        assert_eq!(queue.waiting(&bob).unwrap().since, ended);
    }

    #[test]
    fn a_failed_take_keeps_its_reason_until_the_user_chooses_again() {
        let queue = HeldQueue::default();
        let bob: Source = "bob.claude".parse().unwrap();
        queue.show(vec![(bob.clone(), record(1))], undated);
        assert!(queue.waiting(&bob).unwrap().failure.is_none());
        assert!(queue.choose((&bob, record(1).commit), Choice::Take));
        queue.take_choices();
        queue.wants_open();
        queue.failed((&bob, record(1).commit), "the merge failed".to_owned());
        assert!(queue.wants_open());
        queue.show(vec![(bob.clone(), record(1))], undated);
        assert_eq!(
            queue.waiting(&bob).unwrap().failure.as_deref(),
            Some("the merge failed")
        );
        queue.show(vec![(bob.clone(), record(2))], undated);
        assert!(queue.waiting(&bob).unwrap().failure.is_none());
        queue.show(vec![(bob.clone(), record(1))], undated);
        assert!(queue.choose((&bob, record(1).commit), Choice::Take));
        queue.show(vec![(bob.clone(), record(1))], undated);
        assert!(queue.waiting(&bob).is_none());
        queue.take_choices();
        queue.show(vec![(bob.clone(), record(1))], undated);
        assert!(queue.waiting(&bob).unwrap().failure.is_none());
    }
}
