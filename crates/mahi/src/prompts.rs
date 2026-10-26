use std::{
    collections::{
        HashSet,
        VecDeque,
    },
    sync::Mutex,
    time::Instant,
};

use mahi_core::ParticipantName;
use mahi_live::{
    PROMPT_ID_BYTES,
    PromptOutcome,
    PromptText,
};
use mahi_term::Report;

use crate::roles::Watchers;

const MAX_WAITING: usize = 32;
const MAX_WAITING_FROM_ONE: usize = 8;
const MAX_ANSWERS: usize = 256;
const MAX_ACCEPTED: usize = 32;
const MAX_ARRIVALS: usize = 8;
const ARRIVAL_CHARS: usize = 80;

/// The prompts teammates sent the host's agent, waiting for the host user, and the answers
/// their senders are owed.
#[derive(Debug, Default)]
pub(crate) struct Prompts {
    state: Mutex<State>,
    watchers: Option<Box<dyn Watchers>>,
    own: Option<ParticipantName>,
}

#[derive(Debug, Default)]
struct State {
    waiting: VecDeque<Waiting>,
    accepted: VecDeque<Accepted>,
    trusted: HashSet<ParticipantName>,
    answers: VecDeque<Answer>,
    arrivals: VecDeque<Arrival>,
    closed: bool,
    reported: usize,
}

/// A prompt that just came, for the host user to be told of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Arrival {
    pub(crate) from: ParticipantName,
    pub(crate) first_words: String,
    pub(crate) accepted: bool,
}

/// A prompt the host user accepted, waiting for the agent to be idle: its text and its
/// teammate.
#[derive(Debug)]
pub(crate) struct Accepted {
    pub(crate) id: [u8; PROMPT_ID_BYTES],
    pub(crate) text: PromptText,
    /// The teammate who sent it, when it is a prompt of someone other than the host user.
    pub(crate) from: Option<ParticipantName>,
}

/// What the host user does with a waiting prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Give it to the agent.
    Accept,
    /// Give it to the agent, and every prompt from the same teammate for the rest of the run.
    AlwaysAccept,
    /// Do not give it to the agent.
    Reject,
}

/// A prompt waiting for the host user.
#[derive(Debug)]
pub(crate) struct Waiting {
    pub(crate) id: [u8; PROMPT_ID_BYTES],
    pub(crate) from: ParticipantName,
    pub(crate) text: PromptText,
    pub(crate) at: Instant,
}

/// What became of a prompt, for its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) id: [u8; PROMPT_ID_BYTES],
    pub(crate) outcome: PromptOutcome,
}

impl Prompts {
    /// Returns no prompts yet, for the host of `own`'s agent, whose teammates who only watch
    /// `watchers` tells, asked again with each prompt, so a role changed while the agent runs
    /// counts at once; `own`'s own prompts are asked about as before.
    pub(crate) fn with_watchers(watchers: Box<dyn Watchers>, own: ParticipantName) -> Self {
        Self {
            state: Mutex::default(),
            watchers: Some(watchers),
            own: Some(own),
        }
    }

    /// Takes a prompt `from` a teammate: it is refused when they only watch, and accepted at
    /// once when the host user always accepts them; otherwise it waits, unless too many do, in
    /// all or from that teammate, or the run is ending. Either way its sender is answered.
    pub(crate) fn offer(
        &self,
        from: ParticipantName,
        id: [u8; PROMPT_ID_BYTES],
        text: PromptText,
    ) -> PromptOutcome {
        let watches = self
            .watchers
            .as_ref()
            .filter(|_| self.own.as_ref() != Some(&from))
            .is_some_and(|watchers| watchers.is_watcher(&from));
        let teammate = self.teammate(&from);
        let Ok(mut state) = self.state.lock() else {
            return PromptOutcome::Dropped;
        };
        if watches {
            state.answer(id, PromptOutcome::Rejected);
            return PromptOutcome::Rejected;
        }
        let trusted = state.trusted.contains(&from);
        if !state.closed && trusted {
            let first_words: String = text.as_str().chars().take(ARRIVAL_CHARS).collect();
            let outcome = state.accept(id, text, teammate);
            if outcome == PromptOutcome::Accepted {
                state.arrived(&from, &first_words, true);
            }
            state.answer(id, outcome);
            return outcome;
        }
        let from_them = state
            .waiting
            .iter()
            .filter(|waiting| waiting.from == from)
            .count();
        let outcome = if state.closed
            || state.waiting.len() >= MAX_WAITING
            || from_them >= MAX_WAITING_FROM_ONE
        {
            PromptOutcome::Dropped
        } else {
            state.arrived(&from, text.as_str(), false);
            state.waiting.push_back(Waiting {
                id,
                from,
                text,
                at: Instant::now(),
            });
            state.report_waiting();
            PromptOutcome::Queued
        };
        state.answer(id, outcome);
        outcome
    }

    /// Returns `from` when they are a teammate of the host user, once the host user is known,
    /// so their accepted prompts name them.
    fn teammate(&self, from: &ParticipantName) -> Option<ParticipantName> {
        self.own
            .as_ref()
            .filter(|own| *own != from)
            .map(|_| from.clone())
    }

    /// Applies the host user's `decision` to the waiting prompt `id`, and returns whether it
    /// was still waiting.
    pub(crate) fn decide(&self, id: [u8; PROMPT_ID_BYTES], decision: Decision) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let Some(position) = state.waiting.iter().position(|waiting| waiting.id == id) else {
            return false;
        };
        let Some(waiting) = state.waiting.remove(position) else {
            return false;
        };
        let teammate = self.teammate(&waiting.from);
        let outcome = match decision {
            Decision::Reject => PromptOutcome::Rejected,
            Decision::Accept => state.accept(waiting.id, waiting.text, teammate),
            Decision::AlwaysAccept => {
                let outcome = state.accept(waiting.id, waiting.text, teammate.clone());
                let from = waiting.from;
                while let Some(position) = state.waiting.iter().position(|other| other.from == from)
                {
                    if let Some(other) = state.waiting.remove(position) {
                        let outcome = state.accept(other.id, other.text, teammate.clone());
                        state.answer(other.id, outcome);
                    }
                }
                state.trusted.insert(from);
                outcome
            }
        };
        state.report_waiting();
        state.answer(id, outcome);
        true
    }

    /// Returns the text of the waiting prompt `id`.
    pub(crate) fn text_of(&self, id: [u8; PROMPT_ID_BYTES]) -> Option<String> {
        let state = self.state.lock().ok()?;
        let waiting = state.waiting.iter().find(|waiting| waiting.id == id)?;
        Some(waiting.text.as_str().to_owned())
    }

    /// Takes the oldest accepted prompt, for the agent.
    pub(crate) fn next_accepted(&self) -> Option<Accepted> {
        self.state.lock().ok()?.accepted.pop_front()
    }

    /// Moves the prompts that came since the last call into `into`, oldest first.
    pub(crate) fn take_arrivals(&self, into: &mut Vec<Arrival>) {
        if let Ok(mut state) = self.state.lock() {
            into.extend(state.arrivals.drain(..));
        }
    }

    /// Moves the answers owed into `into`, oldest first.
    pub(crate) fn take_answers(&self, into: &mut Vec<Answer>) {
        if let Ok(mut state) = self.state.lock() {
            into.extend(state.answers.drain(..));
        }
    }

    /// Drops every waiting prompt, as the run ends, and takes no more.
    pub(crate) fn close(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.closed = true;
        while let Some(waiting) = state.waiting.pop_front() {
            state.answer(waiting.id, PromptOutcome::Dropped);
        }
        state.report_waiting();
        while let Some(accepted) = state.accepted.pop_front() {
            state.answer(accepted.id, PromptOutcome::Dropped);
        }
    }

    /// Calls `visit` with each waiting prompt, oldest first.
    pub(crate) fn each_waiting(&self, mut visit: impl FnMut(&Waiting)) {
        if let Ok(state) = self.state.lock() {
            for waiting in &state.waiting {
                visit(waiting);
            }
        }
    }
}

impl State {
    fn arrived(&mut self, from: &ParticipantName, text: &str, accepted: bool) {
        if self.arrivals.len() == MAX_ARRIVALS {
            self.arrivals.pop_front();
        }
        self.arrivals.push_back(Arrival {
            from: from.clone(),
            first_words: text.chars().take(ARRIVAL_CHARS).collect(),
            accepted,
        });
    }

    /// Queues `text` for the agent, naming `from`, the teammate who sent it.
    fn accept(
        &mut self,
        id: [u8; PROMPT_ID_BYTES],
        text: PromptText,
        from: Option<ParticipantName>,
    ) -> PromptOutcome {
        if self.accepted.len() >= MAX_ACCEPTED {
            return PromptOutcome::Dropped;
        }
        self.accepted.push_back(Accepted { id, text, from });
        PromptOutcome::Accepted
    }

    fn report_waiting(&mut self) {
        let count = self.waiting.len();
        if count != self.reported {
            self.reported = count;
            crate::report::send(&Report::Prompts(u16::try_from(count).unwrap_or(u16::MAX)));
        }
    }

    fn answer(&mut self, id: [u8; PROMPT_ID_BYTES], outcome: PromptOutcome) {
        if self.answers.len() == MAX_ANSWERS {
            self.answers.pop_front();
        }
        self.answers.push_back(Answer { id, outcome });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(name: &str) -> ParticipantName {
        ParticipantName::new(name).unwrap()
    }

    fn text() -> PromptText {
        PromptText::new("fix the test".to_owned()).unwrap()
    }

    fn waiting(prompts: &Prompts) -> usize {
        let mut count = 0;
        prompts.each_waiting(|_| count += 1);
        count
    }

    fn answers(prompts: &Prompts) -> Vec<Answer> {
        let mut answers = Vec::new();
        prompts.take_answers(&mut answers);
        answers
    }

    #[test]
    fn the_workspace_hears_how_many_prompts_wait_each_time_it_changes() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        crate::report::connect(std::os::fd::IntoRawFd::into_raw_fd(writer));
        let prompts = Prompts::default();
        for id in 1..=3 {
            prompts.offer(name("bob"), [id; 16], text());
        }
        prompts.offer(name("carol"), [4; 16], text());
        prompts.decide([9; 16], Decision::Reject);
        prompts.decide([1; 16], Decision::AlwaysAccept);
        prompts.offer(name("bob"), [7; 16], text());
        prompts.close();
        let mut read = [0_u8; 256];
        let length = rustix::io::read(&reader, &mut read).unwrap();
        let mut reports = Vec::new();
        mahi_term::ReportReader::default().feed(&read[..length], |report| reports.push(report));
        let counts: Vec<u16> = reports
            .into_iter()
            .map(|report| match report {
                Report::Prompts(count) => count,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(counts, [1, 2, 3, 4, 1, 0]);
    }

    #[derive(Debug, Default)]
    struct Listed(std::sync::Arc<Mutex<HashSet<ParticipantName>>>);

    impl Watchers for Listed {
        fn is_watcher(&self, participant: &ParticipantName) -> bool {
            self.0.lock().unwrap().contains(participant)
        }
    }

    #[test]
    fn a_watchers_prompt_is_refused_and_anyone_elses_waits_for_the_host_user() {
        let watching =
            std::sync::Arc::new(Mutex::new(HashSet::from([name("carol"), name("alice")])));
        let prompts = Prompts::with_watchers(
            Box::new(Listed(std::sync::Arc::clone(&watching))),
            name("alice"),
        );
        assert_eq!(
            prompts.offer(name("bob"), [1; 16], text()),
            PromptOutcome::Queued
        );
        assert_eq!(
            prompts.offer(name("carol"), [2; 16], text()),
            PromptOutcome::Rejected
        );
        assert_eq!(
            prompts.offer(name("dave"), [3; 16], text()),
            PromptOutcome::Queued
        );
        assert_eq!(waiting(&prompts), 2);
        let mut arrivals = Vec::new();
        prompts.take_arrivals(&mut arrivals);
        assert_eq!(
            arrivals
                .iter()
                .map(|arrival| (arrival.from.as_str(), arrival.accepted))
                .collect::<Vec<_>>(),
            [("bob", false), ("dave", false)]
        );
        prompts.decide([3; 16], Decision::AlwaysAccept);
        watching.lock().unwrap().insert(name("dave"));
        assert_eq!(
            prompts.offer(name("dave"), [4; 16], text()),
            PromptOutcome::Rejected
        );
        assert_eq!(
            prompts.offer(name("alice"), [5; 16], text()),
            PromptOutcome::Queued
        );
        assert_eq!(waiting(&prompts), 2);
        prompts.close();
        assert_eq!(
            prompts.offer(name("bob"), [7; 16], text()),
            PromptOutcome::Dropped
        );
    }

    #[test]
    fn an_accepted_prompt_names_its_teammate_but_not_the_host_user() {
        let prompts = Prompts::with_watchers(Box::new(Listed::default()), name("alice"));
        prompts.offer(name("bob"), [1; 16], text());
        prompts.decide([1; 16], Decision::Accept);
        prompts.offer(name("alice"), [2; 16], text());
        prompts.offer(name("carol"), [3; 16], text());
        prompts.offer(name("carol"), [8; 16], text());
        prompts.decide([2; 16], Decision::Accept);
        prompts.decide([3; 16], Decision::AlwaysAccept);
        prompts.offer(name("carol"), [9; 16], text());
        let senders: Vec<Option<String>> = std::iter::from_fn(|| prompts.next_accepted())
            .map(|accepted| accepted.from.map(|from| from.to_string()))
            .collect();
        assert_eq!(
            senders,
            [
                Some("bob".to_owned()),
                None,
                Some("carol".to_owned()),
                Some("carol".to_owned()),
                Some("carol".to_owned()),
            ]
        );
        let unknown = Prompts::default();
        unknown.offer(name("bob"), [5; 16], text());
        unknown.decide([5; 16], Decision::Accept);
        assert_eq!(
            unknown.next_accepted().map(|accepted| accepted.from),
            Some(None)
        );
    }

    #[test]
    fn a_prompt_waits_and_its_sender_is_told_so() {
        let prompts = Prompts::default();
        assert_eq!(
            prompts.offer(name("bob"), [1; 16], text()),
            PromptOutcome::Queued
        );
        assert_eq!(waiting(&prompts), 1);
        assert_eq!(
            answers(&prompts),
            [Answer {
                id: [1; 16],
                outcome: PromptOutcome::Queued,
            }]
        );
        assert!(answers(&prompts).is_empty());
    }

    #[test]
    fn one_teammate_cannot_fill_the_queue_nor_can_all_of_them_overflow_it() {
        let prompts = Prompts::default();
        for id in 0..MAX_WAITING_FROM_ONE {
            let id = [u8::try_from(id).unwrap(); 16];
            assert_eq!(
                prompts.offer(name("bob"), id, text()),
                PromptOutcome::Queued
            );
        }
        assert_eq!(
            prompts.offer(name("bob"), [99; 16], text()),
            PromptOutcome::Dropped
        );
        let mut id = 100_u8;
        for sender in ["carol", "dave", "erin"] {
            for _ in 0..MAX_WAITING_FROM_ONE {
                prompts.offer(name(sender), [id; 16], text());
                id += 1;
            }
        }
        assert_eq!(waiting(&prompts), MAX_WAITING);
        assert_eq!(
            prompts.offer(name("frank"), [200; 16], text()),
            PromptOutcome::Dropped
        );
    }

    #[test]
    fn closing_drops_what_waits_and_everything_after() {
        let prompts = Prompts::default();
        prompts.offer(name("bob"), [1; 16], text());
        prompts.offer(name("carol"), [2; 16], text());
        answers(&prompts);
        prompts.close();
        assert_eq!(waiting(&prompts), 0);
        let dropped = |id| Answer {
            id,
            outcome: PromptOutcome::Dropped,
        };
        assert_eq!(answers(&prompts), [dropped([1; 16]), dropped([2; 16])]);
        assert_eq!(
            prompts.offer(name("bob"), [3; 16], text()),
            PromptOutcome::Dropped
        );
        assert_eq!(answers(&prompts), [dropped([3; 16])]);
    }

    #[test]
    fn answers_owed_are_bounded_and_the_oldest_go_first() {
        let prompts = Prompts::default();
        prompts.close();
        for id in 0..=MAX_ANSWERS {
            let id = u16::try_from(id).unwrap().to_le_bytes();
            let mut full = [0; 16];
            full[..2].copy_from_slice(&id);
            prompts.offer(name("bob"), full, text());
        }
        let owed = answers(&prompts);
        assert_eq!(owed.len(), MAX_ANSWERS);
        assert_eq!(owed[0].id[..2], [1, 0]);
    }

    #[test]
    fn accepted_prompts_go_to_the_agent_in_order_and_rejected_ones_never() {
        let prompts = Prompts::default();
        prompts.offer(name("bob"), [1; 16], text());
        prompts.offer(name("carol"), [2; 16], text());
        prompts.offer(name("bob"), [3; 16], text());
        answers(&prompts);
        assert!(prompts.decide([3; 16], Decision::Accept));
        assert!(prompts.decide([2; 16], Decision::Reject));
        assert!(!prompts.decide([2; 16], Decision::Accept));
        assert!(prompts.decide([1; 16], Decision::Accept));
        let outcome = |id, outcome| Answer { id, outcome };
        assert_eq!(
            answers(&prompts),
            [
                outcome([3; 16], PromptOutcome::Accepted),
                outcome([2; 16], PromptOutcome::Rejected),
                outcome([1; 16], PromptOutcome::Accepted),
            ]
        );
        assert_eq!(prompts.next_accepted().unwrap().id, [3; 16]);
        assert_eq!(prompts.next_accepted().unwrap().id, [1; 16]);
        assert!(prompts.next_accepted().is_none());
        assert_eq!(waiting(&prompts), 0);
    }

    #[test]
    fn always_accepting_a_teammate_takes_their_waiting_and_later_prompts() {
        let prompts = Prompts::default();
        prompts.offer(name("bob"), [1; 16], text());
        prompts.offer(name("carol"), [2; 16], text());
        prompts.offer(name("bob"), [3; 16], text());
        assert!(prompts.decide([1; 16], Decision::AlwaysAccept));
        assert_eq!(waiting(&prompts), 1);
        assert_eq!(
            prompts.offer(name("bob"), [4; 16], text()),
            PromptOutcome::Accepted
        );
        assert_eq!(
            prompts.offer(name("carol"), [5; 16], text()),
            PromptOutcome::Queued
        );
        let ids: Vec<[u8; 16]> = std::iter::from_fn(|| prompts.next_accepted())
            .map(|accepted| accepted.id)
            .collect();
        assert_eq!(ids, [[1; 16], [3; 16], [4; 16]]);
    }

    #[test]
    fn accepted_prompts_not_yet_given_are_dropped_when_the_run_ends() {
        let prompts = Prompts::default();
        prompts.offer(name("bob"), [1; 16], text());
        prompts.decide([1; 16], Decision::Accept);
        answers(&prompts);
        prompts.close();
        assert_eq!(
            answers(&prompts),
            [Answer {
                id: [1; 16],
                outcome: PromptOutcome::Dropped,
            }]
        );
        assert!(prompts.next_accepted().is_none());
        prompts.decide([1; 16], Decision::AlwaysAccept);
        assert_eq!(
            prompts.offer(name("bob"), [2; 16], text()),
            PromptOutcome::Dropped
        );
    }

    #[test]
    fn arrivals_are_noted_for_the_host_user_and_bounded() {
        let prompts = Prompts::default();
        prompts.offer(name("bob"), [1; 16], text());
        prompts.decide([1; 16], Decision::AlwaysAccept);
        prompts.offer(name("bob"), [2; 16], text());
        prompts.close();
        prompts.offer(name("carol"), [3; 16], text());
        let mut arrivals = Vec::new();
        prompts.take_arrivals(&mut arrivals);
        assert_eq!(
            arrivals
                .iter()
                .map(|arrival| (arrival.from.as_str(), arrival.accepted))
                .collect::<Vec<_>>(),
            [("bob", false), ("bob", true)]
        );
        assert_eq!(arrivals[0].first_words, "fix the test");
        let full = Prompts::default();
        full.offer(name("bob"), [0; 16], text());
        full.decide([0; 16], Decision::AlwaysAccept);
        for id in 1..=MAX_ACCEPTED {
            full.offer(name("bob"), [u8::try_from(id).unwrap(); 16], text());
        }
        arrivals.clear();
        full.take_arrivals(&mut arrivals);
        assert_eq!(arrivals.len(), MAX_ARRIVALS);
        assert!(full.next_accepted().is_some());
        let mut owed = Vec::new();
        full.take_answers(&mut owed);
        assert_eq!(owed.last().unwrap().outcome, PromptOutcome::Dropped);
        let many = Prompts::default();
        for id in 0..12 {
            many.offer(name(&format!("p{id}")), [id; 16], text());
        }
        arrivals.clear();
        many.take_arrivals(&mut arrivals);
        assert_eq!(arrivals.len(), MAX_ARRIVALS);
        assert_eq!(arrivals[0].from.as_str(), "p4");
    }
}
