use std::{
    collections::VecDeque,
    sync::Mutex,
    time::Instant,
};

use mahi_core::ParticipantName;
use mahi_live::{
    PROMPT_ID_BYTES,
    PromptOutcome,
    PromptText,
};

const MAX_WAITING: usize = 32;
const MAX_WAITING_FROM_ONE: usize = 8;
const MAX_ANSWERS: usize = 256;

/// The prompts teammates sent the host's agent, waiting for the host user, and the answers
/// their senders are owed.
#[derive(Debug, Default)]
pub(crate) struct Prompts {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    waiting: VecDeque<Waiting>,
    answers: VecDeque<Answer>,
    closed: bool,
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
    /// Takes a prompt `from` a teammate: it waits, unless too many do, in all or from that
    /// teammate, or the run is ending; either way its sender is answered.
    pub(crate) fn offer(
        &self,
        from: ParticipantName,
        id: [u8; PROMPT_ID_BYTES],
        text: PromptText,
    ) -> PromptOutcome {
        let Ok(mut state) = self.state.lock() else {
            return PromptOutcome::Dropped;
        };
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
            state.waiting.push_back(Waiting {
                id,
                from,
                text,
                at: Instant::now(),
            });
            PromptOutcome::Queued
        };
        state.answer(id, outcome);
        outcome
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
    }

    /// Calls `visit` with each waiting prompt, oldest first.
    pub(crate) fn each_waiting(&self, mut visit: impl FnMut(&Waiting)) {
        if let Ok(state) = self.state.lock() {
            state.waiting.iter().for_each(&mut visit);
        }
    }
}

impl State {
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
}
