use std::{
    mem,
    path::PathBuf,
    sync::mpsc::Receiver,
};

use mahi_core::{
    AgentSlot,
    ThreadId,
};
use mahi_crypto::ThreadKey;
use mahi_schedule::Poker;
use mahi_store::{
    Store,
    StoreError,
};
use mahi_thread::{
    Event,
    MAX_EVENTS_PER_TURN,
    MAX_TURN_BYTES,
    TranscriptError,
    TranscriptTip,
    TurnRecord,
    append_turn,
};
use thiserror::Error;

use crate::hook::{
    Delivery,
    HookKind,
    HookMessage,
};

const EVENT_OVERHEAD: usize = 64;

/// Where the transcript goes and what seals it.
#[derive(Debug)]
pub(crate) struct Transcript {
    pub(crate) git_dir: PathBuf,
    pub(crate) key: ThreadKey,
    pub(crate) thread: ThreadId,
    pub(crate) slot: AgentSlot,
}

/// How recording the transcript went, and the first error it met.
#[derive(Debug, Default)]
pub(crate) struct Summary {
    pub(crate) turns: u64,
    pub(crate) dropped: u64,
    pub(crate) error: Option<TurnError>,
}

#[derive(Debug, Error)]
pub(crate) enum TurnError {
    #[error("cannot open the repository")]
    Store(#[from] StoreError),
    #[error("cannot record a turn")]
    Transcript(#[from] TranscriptError),
}

/// Collects hook messages into turns until [`Delivery::End`], seals each turn when its
/// `turn-end` arrives, and pokes `poker` whenever the worktree may have changed.
pub(crate) fn record(
    transcript: &Transcript,
    inputs: &Receiver<Delivery>,
    poker: Option<&Poker>,
) -> Summary {
    let store = match Store::open(&transcript.git_dir) {
        Ok(store) => store,
        Err(error) => {
            return Summary {
                error: Some(error.into()),
                ..Summary::default()
            };
        }
    };
    let mut turns = Turns::default();
    while let Ok(delivery) = inputs.recv() {
        let message = match delivery {
            Delivery::Message(message) => message,
            Delivery::End { dropped } => {
                turns.summary.dropped += dropped;
                break;
            }
        };
        if let Some(poker) = poker
            && matches!(message.kind, HookKind::Tool | HookKind::TurnEnd)
        {
            poker.poke();
        }
        let ends = message.kind == HookKind::TurnEnd;
        turns.push(&message);
        if ends {
            turns.seal_or_note(&store, transcript);
        }
    }
    turns.seal_or_note(&store, transcript);
    turns.summary
}

#[derive(Debug, Default)]
struct Turns {
    tip: Option<TranscriptTip>,
    next_turn: u64,
    next_seq: u64,
    events: Vec<Event>,
    bytes: usize,
    summary: Summary,
}

impl Turns {
    fn push(&mut self, message: &HookMessage) {
        let name = message.kind.as_str().as_bytes();
        let size = name.len() + 1 + message.payload.len() + EVENT_OVERHEAD;
        if self.events.len() >= MAX_EVENTS_PER_TURN || self.bytes + size > MAX_TURN_BYTES {
            self.summary.dropped += 1;
            return;
        }
        let mut payload = Vec::with_capacity(name.len() + 1 + message.payload.len());
        payload.extend_from_slice(name);
        payload.push(b'\n');
        payload.extend_from_slice(&message.payload);
        match Event::new(self.next_seq, payload) {
            Ok(event) => {
                self.next_seq += 1;
                self.bytes += size;
                self.events.push(event);
            }
            Err(_) => self.summary.dropped += 1,
        }
    }

    fn seal_or_note(&mut self, store: &Store, transcript: &Transcript) {
        if let Err(error) = self.seal(store, transcript) {
            self.summary.error.get_or_insert(error);
        }
    }

    fn seal(&mut self, store: &Store, transcript: &Transcript) -> Result<(), TurnError> {
        if self.events.is_empty() {
            return Ok(());
        }
        self.bytes = 0;
        let record = TurnRecord::new(self.next_turn, mem::take(&mut self.events))?;
        let tip = append_turn(
            store,
            &transcript.key,
            transcript.thread,
            &transcript.slot,
            self.tip.as_ref(),
            &record,
        )?;
        self.tip = Some(tip);
        self.next_turn += 1;
        self.summary.turns += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use mahi_schedule::{
        Schedule,
        Scheduler,
        Trigger,
    };
    use mahi_thread::read_turns;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;
    use crate::session::tests::{
        repository_on_main,
        start_with,
    };

    fn hook(kind: HookKind, payload: &[u8]) -> Delivery {
        Delivery::Message(HookMessage {
            kind,
            payload: payload.to_vec(),
        })
    }

    fn texts(record: &TurnRecord) -> Vec<String> {
        record
            .events()
            .iter()
            .map(|event| String::from_utf8(event.payload().to_vec()).unwrap())
            .collect()
    }

    #[test]
    fn turns_end_at_turn_end_and_the_last_one_at_the_end_of_the_agent() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let transcript = Transcript {
            git_dir: store.common_dir().to_path_buf(),
            key: started.key.take().unwrap(),
            thread: started.thread,
            slot: started.slot.clone(),
        };
        let (sender, inputs) = mpsc::channel();
        for input in [
            hook(HookKind::Prompt, b"fix it"),
            hook(HookKind::Tool, b"edit"),
            hook(HookKind::TurnEnd, b""),
            hook(HookKind::Prompt, b"and again"),
            Delivery::End { dropped: 1 },
            hook(HookKind::Tool, b"after the end"),
        ] {
            sender.send(input).unwrap();
        }
        let summary = record(&transcript, &inputs, None);
        assert!(summary.error.is_none(), "{:?}", summary.error);
        assert_eq!((summary.turns, summary.dropped), (2, 1));
        let turns = read_turns(
            &store,
            &transcript.key,
            transcript.thread,
            &transcript.slot,
            10,
        )
        .unwrap();
        assert_eq!(turns.len(), 2);
        assert_eq!(
            texts(&turns[0]),
            ["prompt\nfix it", "tool\nedit", "turn-end\n"]
        );
        assert_eq!(texts(&turns[1]), ["prompt\nand again"]);
        assert_eq!(turns[1].events()[0].seq(), 3);
    }

    #[test]
    fn tools_and_turn_ends_poke_the_snapshot_scheduler() {
        let (_dir, store) = repository_on_main();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut started = start_with(&store, &signer).unwrap();
        let transcript = Transcript {
            git_dir: store.common_dir().to_path_buf(),
            key: started.key.take().unwrap(),
            thread: started.thread,
            slot: started.slot.clone(),
        };
        let (mut scheduler, poker) = Scheduler::new(
            Schedule::new(
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(3600),
                std::time::Duration::from_millis(1),
            )
            .unwrap(),
        );
        assert_eq!(scheduler.wait(), Trigger::Timer);
        let (sender, inputs) = mpsc::channel();
        sender.send(hook(HookKind::Tool, b"")).unwrap();
        sender.send(Delivery::End { dropped: 0 }).unwrap();
        assert!(record(&transcript, &inputs, Some(&poker)).error.is_none());
        assert_eq!(scheduler.wait(), Trigger::Poked);
    }

    #[test]
    fn events_beyond_a_turns_limits_are_dropped_and_counted() {
        let mut turns = Turns::default();
        let large = vec![b'x'; crate::hook::MAX_PAYLOAD_BYTES];
        let fits = MAX_TURN_BYTES / ("tool\n".len() + large.len() + EVENT_OVERHEAD);
        for _ in 0..=fits {
            turns.push(&HookMessage {
                kind: HookKind::Tool,
                payload: large.clone(),
            });
        }
        assert_eq!(turns.events.len(), fits);
        assert_eq!(turns.summary.dropped, 1);
    }
}
