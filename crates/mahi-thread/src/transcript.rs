use std::{
    fmt,
    marker::PhantomData,
};

use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_crypto::{
    OpenError,
    SealError,
    ThreadKey,
};
use mahi_store::{
    CommitSigner,
    EntryKind,
    ObjectId,
    Store,
    StoreError,
};
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    de::{
        self,
        SeqAccess,
        Visitor,
    },
};
use thiserror::Error;

/// The name of the file holding the sealed turn in each transcript commit's tree.
pub const TURN_ENTRY: &str = "turn";
/// The largest single event payload, in bytes.
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
/// The most events one turn may hold.
pub const MAX_EVENTS_PER_TURN: usize = 100_000;
/// The largest encoded turn, before sealing, in bytes.
pub const MAX_TURN_BYTES: usize = 64 * 1024 * 1024;

const MAX_SEALED_TURN_BYTES: u64 = (MAX_TURN_BYTES + MAX_TURN_BYTES / 255 + 64 * 1024) as u64;
const VERSION: u16 = 1;
const TURN_MESSAGE: &str = "turn";

/// One event of an agent's session, as the adapter recorded it.
///
/// Its payload never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct Event {
    seq: u64,
    payload: Vec<u8>,
}

/// One agent turn: its number, counted from 0, and its events in order.
///
/// Its events' payloads never appear in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnRecord {
    turn: u64,
    events: Vec<Event>,
}

/// The newest turn of a transcript: its commit, its number, and the last event sequence number
/// of the whole transcript so far.
///
/// The host keeps it after each [`append_turn`], and [`read_tip`] recovers it after a restart,
/// so appending never has to open earlier turns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptTip {
    commit: ObjectId,
    turn: u64,
    last_seq: Option<u64>,
}

/// Recording or reading a transcript failed.
///
/// Neither messages nor `Debug` output include turn or sequence numbers, which come from
/// sealed content.
#[derive(Debug, Error)]
pub enum TranscriptError {
    /// An event payload is larger than [`MAX_EVENT_BYTES`].
    #[error("event payload is larger than {MAX_EVENT_BYTES} bytes")]
    EventTooLarge,
    /// A turn has more than [`MAX_EVENTS_PER_TURN`] events.
    #[error("a turn has more than {MAX_EVENTS_PER_TURN} events")]
    TooManyEvents,
    /// A turn is larger than [`MAX_TURN_BYTES`].
    #[error("a turn is larger than {MAX_TURN_BYTES} bytes")]
    TurnTooLarge,
    /// Event sequence numbers do not strictly increase, within a turn or across turns.
    #[error("event sequence numbers do not strictly increase")]
    SequenceNotIncreasing,
    /// A turn's number is not one more than the previous turn's, or the first turn is not 0.
    #[error("turn numbers do not follow on")]
    TurnOrder,
    /// A transcript commit holds no turn, or a turn that does not decode or is inconsistent.
    #[error("transcript commit {0} is malformed")]
    Malformed(ObjectId),
    /// The turn uses a format version this build does not read.
    #[error("turn format version {0} is not supported")]
    UnsupportedVersion(u16),
    /// Encoding the turn failed.
    #[error("cannot encode turn")]
    Encode(#[source] postcard::Error),
    /// Sealing the turn failed.
    #[error("cannot seal turn")]
    Seal(#[from] SealError),
    /// Opening the turn failed: it is not sealed to this thread's key, or was tampered with.
    #[error("cannot open turn")]
    Open(#[from] OpenError),
    /// Reading or writing the repository failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Serialize, Deserialize)]
struct WireBody<'a> {
    turn: u64,
    last_seq: Option<u64>,
    #[serde(borrow)]
    events: WireEvents<'a>,
}

#[derive(Serialize)]
#[serde(transparent)]
struct WireEvents<'a>(Vec<WireEvent<'a>>);

#[derive(Serialize, Deserialize)]
struct WireEvent<'a> {
    seq: u64,
    payload: &'a [u8],
}

struct BoundedEvents<'a>(PhantomData<&'a ()>);

impl<'de: 'a, 'a> Visitor<'de> for BoundedEvents<'a> {
    type Value = WireEvents<'a>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at most {MAX_EVENTS_PER_TURN} events")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut events = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1024));
        while let Some(event) = seq.next_element::<WireEvent<'de>>()? {
            if events.len() == MAX_EVENTS_PER_TURN {
                return Err(de::Error::custom("too many events"));
            }
            events.push(event);
        }
        Ok(WireEvents(events))
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for WireEvents<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(BoundedEvents(PhantomData))
    }
}

impl Event {
    /// Creates an event with sequence number `seq`.
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptError::EventTooLarge`] if `payload` is larger than
    /// [`MAX_EVENT_BYTES`].
    pub fn new(seq: u64, payload: Vec<u8>) -> Result<Self, TranscriptError> {
        if payload.len() > MAX_EVENT_BYTES {
            return Err(TranscriptError::EventTooLarge);
        }
        Ok(Self { seq, payload })
    }

    /// Returns the event's sequence number, assigned by the host.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the event's payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl TurnRecord {
    /// Creates turn number `turn` from `events`.
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptError::TooManyEvents`] if there are more than
    /// [`MAX_EVENTS_PER_TURN`] events, or [`TranscriptError::SequenceNotIncreasing`] if their
    /// sequence numbers do not strictly increase.
    pub fn new(turn: u64, events: Vec<Event>) -> Result<Self, TranscriptError> {
        if events.len() > MAX_EVENTS_PER_TURN {
            return Err(TranscriptError::TooManyEvents);
        }
        if events
            .iter()
            .zip(events.iter().skip(1))
            .any(|(earlier, later)| earlier.seq >= later.seq)
        {
            return Err(TranscriptError::SequenceNotIncreasing);
        }
        Ok(Self { turn, events })
    }

    /// Returns the turn's number.
    #[must_use]
    pub fn turn(&self) -> u64 {
        self.turn
    }

    /// Returns the turn's events.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    fn first_seq(&self) -> Option<u64> {
        self.events.first().map(Event::seq)
    }

    fn encode(&self, last_seq: Option<u64>) -> Result<Vec<u8>, TranscriptError> {
        let body = WireBody {
            turn: self.turn,
            last_seq,
            events: WireEvents(
                self.events
                    .iter()
                    .map(|event| WireEvent {
                        seq: event.seq,
                        payload: &event.payload,
                    })
                    .collect(),
            ),
        };
        let bytes = postcard::to_allocvec(&(VERSION, body)).map_err(TranscriptError::Encode)?;
        if bytes.len() > MAX_TURN_BYTES {
            return Err(TranscriptError::TurnTooLarge);
        }
        Ok(bytes)
    }
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Event")
            .field("seq", &self.seq)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl fmt::Debug for TurnRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnRecord")
            .field("turn", &self.turn)
            .field("events", &self.events)
            .finish()
    }
}

impl TranscriptTip {
    /// Returns the newest transcript commit.
    #[must_use]
    pub fn commit(&self) -> ObjectId {
        self.commit
    }

    /// Returns the newest turn's number.
    #[must_use]
    pub fn turn(&self) -> u64 {
        self.turn
    }

    /// Returns the last event sequence number of the whole transcript, if it has any events.
    #[must_use]
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }
}

struct Decoded {
    record: TurnRecord,
    last_seq: Option<u64>,
}

fn decode(bytes: &[u8], commit: ObjectId) -> Result<Decoded, TranscriptError> {
    let malformed = || TranscriptError::Malformed(commit);
    let (version, rest): (u16, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| malformed())?;
    if version != VERSION {
        return Err(TranscriptError::UnsupportedVersion(version));
    }
    let (body, rest): (WireBody<'_>, &[u8]) =
        postcard::take_from_bytes(rest).map_err(|_| malformed())?;
    if !rest.is_empty() {
        return Err(malformed());
    }
    let events = body
        .events
        .0
        .into_iter()
        .map(|event| Event::new(event.seq, event.payload.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let record = TurnRecord::new(body.turn, events)?;
    if let Some(last) = record.events.last()
        && body.last_seq != Some(last.seq)
    {
        return Err(malformed());
    }
    Ok(Decoded {
        record,
        last_seq: body.last_seq,
    })
}

/// Seals `record` to `thread_key` and commits it on top of `slot`'s transcript in `thread`,
/// signed by `signer`, the participant's key.
///
/// `tip` is the transcript's newest turn, from the previous [`append_turn`] or [`read_tip`], or
/// `None` for the first turn. The turn must be numbered one more than `tip`'s, or 0 for the
/// first, and its events must come after every earlier event.
///
/// Returns the new tip.
///
/// # Errors
///
/// Returns [`TranscriptError::TurnOrder`] or [`TranscriptError::SequenceNotIncreasing`] if the
/// turn does not follow `tip`, or another [`TranscriptError`] if the turn is too large, cannot
/// be sealed, or the transcript moved since `tip`.
pub fn append_turn(
    store: &Store,
    thread_key: &ThreadKey,
    thread: ThreadId,
    slot: &AgentSlot,
    tip: Option<&TranscriptTip>,
    record: &TurnRecord,
    signer: &dyn CommitSigner,
) -> Result<TranscriptTip, TranscriptError> {
    let follows = match tip {
        Some(tip) => tip.turn.checked_add(1) == Some(record.turn),
        None => record.turn == 0,
    };
    if !follows {
        return Err(TranscriptError::TurnOrder);
    }
    let previous_seq = tip.and_then(|tip| tip.last_seq);
    if let (Some(previous), Some(first)) = (previous_seq, record.first_seq())
        && first <= previous
    {
        return Err(TranscriptError::SequenceNotIncreasing);
    }
    let last_seq = record.events.last().map(Event::seq).or(previous_seq);
    let blob = store.write_sealed(thread_key, &record.encode(last_seq)?)?;
    let tree = store.write_tree(&[(TURN_ENTRY, EntryKind::Blob, blob)])?;
    let transcript = ThreadRef::new(thread, RefKind::Transcript(slot.clone()));
    let commit = store.append_signed(
        &transcript,
        tip.map(|tip| tip.commit),
        tree,
        TURN_MESSAGE,
        signer,
    )?;
    Ok(TranscriptTip {
        commit,
        turn: record.turn,
        last_seq,
    })
}

/// Reads the newest turn of `slot`'s transcript in `thread`, or `None` if it has none.
///
/// Only the newest commit is opened.
///
/// # Errors
///
/// Returns a [`TranscriptError`] if the newest commit is malformed or cannot be opened.
pub fn read_tip(
    store: &Store,
    thread_key: &ThreadKey,
    thread: ThreadId,
    slot: &AgentSlot,
) -> Result<Option<TranscriptTip>, TranscriptError> {
    let transcript = ThreadRef::new(thread, RefKind::Transcript(slot.clone()));
    let Some(commit) = store.head(&transcript)? else {
        return Ok(None);
    };
    let decoded = read_turn(store, thread_key, commit)?;
    if store.parent(commit)?.is_none() {
        check_first(&decoded, commit)?;
    }
    Ok(Some(TranscriptTip {
        commit,
        turn: decoded.record.turn,
        last_seq: decoded.last_seq,
    }))
}

/// Visits the newest `limit` turns of `slot`'s transcript in `thread`, newest first.
///
/// Each commit is checked before its turn is visited: it has at most one parent, holds a
/// sealed turn that opens with `thread_key`, and its turn number and event sequence numbers
/// fit with the turn visited before it. Only one turn is held at a time.
///
/// # Errors
///
/// Returns a [`TranscriptError`] if a commit is malformed, cannot be opened, or breaks the
/// order of turns or events. Turns visited before the error were valid.
pub fn walk_turns(
    store: &Store,
    thread_key: &ThreadKey,
    thread: ThreadId,
    slot: &AgentSlot,
    limit: usize,
    mut visit: impl FnMut(TurnRecord),
) -> Result<(), TranscriptError> {
    let transcript = ThreadRef::new(thread, RefKind::Transcript(slot.clone()));
    let mut next = store.head(&transcript)?;
    let mut newer: Option<Link> = None;
    for _ in 0..limit {
        let Some(commit) = next else {
            break;
        };
        let decoded = read_turn(store, thread_key, commit)?;
        next = store.parent(commit)?;
        if let Some(newer) = newer {
            check_pair(&decoded, newer, commit)?;
        }
        if next.is_none() {
            check_first(&decoded, commit)?;
        }
        newer = Some(Link {
            turn: decoded.record.turn,
            first_seq: decoded.record.first_seq(),
            last_seq: decoded.last_seq,
        });
        visit(decoded.record);
    }
    Ok(())
}

/// Reads the newest `limit` turns of `slot`'s transcript in `thread`, oldest first.
///
/// This holds every turn read in memory; [`walk_turns`] visits them one at a time instead.
///
/// # Errors
///
/// Returns a [`TranscriptError`] if a commit is malformed, cannot be opened, or breaks the
/// order of turns or events.
pub fn read_turns(
    store: &Store,
    thread_key: &ThreadKey,
    thread: ThreadId,
    slot: &AgentSlot,
    limit: usize,
) -> Result<Vec<TurnRecord>, TranscriptError> {
    let mut turns = Vec::new();
    walk_turns(store, thread_key, thread, slot, limit, |turn| {
        turns.push(turn);
    })?;
    turns.reverse();
    Ok(turns)
}

#[derive(Clone, Copy)]
struct Link {
    turn: u64,
    first_seq: Option<u64>,
    last_seq: Option<u64>,
}

fn check_pair(older: &Decoded, newer: Link, commit: ObjectId) -> Result<(), TranscriptError> {
    if older.record.turn.checked_add(1) != Some(newer.turn) {
        return Err(TranscriptError::TurnOrder);
    }
    if let (Some(older_last), Some(first)) = (older.last_seq, newer.first_seq)
        && first <= older_last
    {
        return Err(TranscriptError::SequenceNotIncreasing);
    }
    let carried = newer.first_seq.is_none() && newer.last_seq != older.last_seq;
    let lost = newer.last_seq.is_none() && older.last_seq.is_some();
    if carried || lost {
        return Err(TranscriptError::Malformed(commit));
    }
    Ok(())
}

fn check_first(first: &Decoded, commit: ObjectId) -> Result<(), TranscriptError> {
    if first.record.turn != 0 {
        return Err(TranscriptError::TurnOrder);
    }
    if first.record.events.is_empty() && first.last_seq.is_some() {
        return Err(TranscriptError::Malformed(commit));
    }
    Ok(())
}

fn read_turn(
    store: &Store,
    thread_key: &ThreadKey,
    commit: ObjectId,
) -> Result<Decoded, TranscriptError> {
    let sealed = store
        .read_entry(commit, TURN_ENTRY, MAX_SEALED_TURN_BYTES)?
        .ok_or(TranscriptError::Malformed(commit))?;
    let plaintext = thread_key.open(&sealed, MAX_TURN_BYTES)?;
    decode(&plaintext, commit)
}

#[cfg(test)]
mod tests {
    use gix::objs::Write as _;
    use mahi_core::{
        AgentName,
        ParticipantName,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        GitSigner,
        ParticipantKey,
        signed_by,
    };

    struct Setup {
        dir: TempDir,
        store: Store,
        key: ThreadKey,
        thread: ThreadId,
        slot: AgentSlot,
        signer: GitSigner<PrivateKey>,
    }

    fn setup() -> Setup {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path()).unwrap();
        Setup {
            store: Store::open(dir.path()).unwrap(),
            dir,
            key: ThreadKey::generate(),
            thread: ThreadId::random().unwrap(),
            slot: AgentSlot::new(
                ParticipantName::new("alice").unwrap(),
                AgentName::new("claude-code").unwrap(),
            ),
            signer: GitSigner(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()),
        }
    }

    fn turn(number: u64, seqs: &[u64]) -> TurnRecord {
        let events = seqs
            .iter()
            .map(|seq| Event::new(*seq, format!("{{\"seq\":{seq}}}").into_bytes()).unwrap())
            .collect();
        TurnRecord::new(number, events).unwrap()
    }

    fn try_append(
        setup: &Setup,
        tip: Option<&TranscriptTip>,
        record: &TurnRecord,
    ) -> Result<TranscriptTip, TranscriptError> {
        append_turn(
            &setup.store,
            &setup.key,
            setup.thread,
            &setup.slot,
            tip,
            record,
            &setup.signer,
        )
    }

    fn append(setup: &Setup, tip: Option<&TranscriptTip>, record: &TurnRecord) -> TranscriptTip {
        try_append(setup, tip, record).unwrap()
    }

    fn read(setup: &Setup, limit: usize) -> Result<Vec<TurnRecord>, TranscriptError> {
        read_turns(&setup.store, &setup.key, setup.thread, &setup.slot, limit)
    }

    fn transcript_ref(setup: &Setup) -> ThreadRef {
        ThreadRef::new(setup.thread, RefKind::Transcript(setup.slot.clone()))
    }

    fn put_raw(setup: &Setup, parent: Option<ObjectId>, plaintext: &[u8]) -> ObjectId {
        let blob = setup.store.write_sealed(&setup.key, plaintext).unwrap();
        let tree = setup
            .store
            .write_tree(&[(TURN_ENTRY, EntryKind::Blob, blob)])
            .unwrap();
        setup
            .store
            .append(&transcript_ref(setup), parent, tree, "turn")
            .unwrap()
    }

    #[test]
    fn turns_read_back_in_order() {
        let setup = setup();
        let turns = [turn(0, &[1, 2, 3]), turn(1, &[]), turn(2, &[4, 9])];
        let mut tip = None;
        for record in &turns {
            tip = Some(append(&setup, tip.as_ref(), record));
        }
        assert_eq!(read(&setup, 10).unwrap(), turns);
        assert_eq!(read(&setup, 2).unwrap(), turns[1..]);
        assert!(read(&setup, 0).unwrap().is_empty());
    }

    #[test]
    fn every_turn_is_signed_by_the_participant() {
        let setup = setup();
        let key = ParticipantKey::from_public_key(setup.signer.0.public_key()).unwrap();
        let first = append(&setup, None, &turn(0, &[1]));
        let second = append(&setup, Some(&first), &turn(1, &[2]));
        for tip in [first, second] {
            assert!(signed_by(&setup.store, tip.commit, &key).unwrap());
        }
    }

    #[test]
    fn the_tip_is_recovered_from_the_newest_commit() {
        let setup = setup();
        assert_eq!(
            read_tip(&setup.store, &setup.key, setup.thread, &setup.slot).unwrap(),
            None
        );
        let tip = append(&setup, None, &turn(0, &[4]));
        let tip = append(&setup, Some(&tip), &turn(1, &[]));
        let read = read_tip(&setup.store, &setup.key, setup.thread, &setup.slot)
            .unwrap()
            .unwrap();
        assert_eq!(read, tip);
        assert_eq!(read.turn(), 1);
        assert_eq!(read.last_seq(), Some(4));
    }

    #[test]
    fn an_empty_turn_does_not_reset_the_sequence_check() {
        let setup = setup();
        let tip = append(&setup, None, &turn(0, &[5]));
        let tip = append(&setup, Some(&tip), &turn(1, &[]));
        assert!(matches!(
            try_append(&setup, Some(&tip), &turn(2, &[3])),
            Err(TranscriptError::SequenceNotIncreasing)
        ));
        let tip = append(&setup, Some(&tip), &turn(2, &[6]));
        assert_eq!(tip.last_seq(), Some(6));
        assert_eq!(read(&setup, 10).unwrap().len(), 3);
    }

    #[test]
    fn an_empty_transcript_reads_as_nothing() {
        assert!(read(&setup(), 10).unwrap().is_empty());
    }

    #[test]
    fn turns_are_sealed() {
        let setup = setup();
        let tip = append(&setup, None, &turn(0, &[1]));
        let sealed = setup
            .store
            .read_entry(tip.commit(), TURN_ENTRY, MAX_SEALED_TURN_BYTES)
            .unwrap()
            .unwrap();
        assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
        assert!(!sealed.windows(5).any(|window| window == b"\"seq\""));
    }

    #[test]
    fn a_turn_at_the_size_limit_reads_back() {
        let setup = setup();
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut noise = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[0]
                })
                .collect()
        };
        let events: Vec<Event> = (0..63)
            .map(|seq| Event::new(seq, noise(MAX_EVENT_BYTES - 64)).unwrap())
            .collect();
        let record = TurnRecord::new(0, events).unwrap();
        assert!(record.encode(Some(62)).unwrap().len() > MAX_TURN_BYTES - 2 * MAX_EVENT_BYTES);
        append(&setup, None, &record);
        assert_eq!(read(&setup, 1).unwrap(), [record]);
    }

    #[test]
    fn turn_numbers_must_follow_on() {
        let setup = setup();
        assert!(matches!(
            try_append(&setup, None, &turn(1, &[1])),
            Err(TranscriptError::TurnOrder)
        ));
        let tip = append(&setup, None, &turn(0, &[1]));
        for wrong in [0, 2, 5] {
            assert!(
                matches!(
                    try_append(&setup, Some(&tip), &turn(wrong, &[10])),
                    Err(TranscriptError::TurnOrder)
                ),
                "{wrong}"
            );
        }
    }

    #[test]
    fn a_stale_tip_is_a_conflict() {
        let setup = setup();
        let first = append(&setup, None, &turn(0, &[1]));
        append(&setup, Some(&first), &turn(1, &[2]));
        assert!(matches!(
            try_append(&setup, Some(&first), &turn(1, &[3])),
            Err(TranscriptError::Store(StoreError::Conflict { .. }))
        ));
    }

    #[test]
    fn sequence_numbers_must_increase_within_and_across_turns() {
        let events = vec![
            Event::new(5, Vec::new()).unwrap(),
            Event::new(5, Vec::new()).unwrap(),
        ];
        assert!(matches!(
            TurnRecord::new(0, events),
            Err(TranscriptError::SequenceNotIncreasing)
        ));
        let setup = setup();
        let tip = append(&setup, None, &turn(0, &[1, 7]));
        assert!(matches!(
            try_append(&setup, Some(&tip), &turn(1, &[7])),
            Err(TranscriptError::SequenceNotIncreasing)
        ));
    }

    #[test]
    fn size_limits_are_enforced() {
        assert!(matches!(
            Event::new(0, vec![0; MAX_EVENT_BYTES + 1]),
            Err(TranscriptError::EventTooLarge)
        ));
        let events = (0..=MAX_EVENTS_PER_TURN as u64)
            .map(|seq| Event::new(seq, Vec::new()).unwrap())
            .collect();
        assert!(matches!(
            TurnRecord::new(0, events),
            Err(TranscriptError::TooManyEvents)
        ));
    }

    #[test]
    fn a_hostile_turn_with_too_many_events_stops_decoding() {
        let setup = setup();
        let events: Vec<WireEvent<'_>> = (0..=MAX_EVENTS_PER_TURN as u64)
            .map(|seq| WireEvent { seq, payload: b"" })
            .collect();
        let body = WireBody {
            turn: 0,
            last_seq: Some(MAX_EVENTS_PER_TURN as u64),
            events: WireEvents(events),
        };
        put_raw(
            &setup,
            None,
            &postcard::to_allocvec(&(VERSION, body)).unwrap(),
        );
        assert!(matches!(
            read(&setup, 10),
            Err(TranscriptError::Malformed(_))
        ));
    }

    #[test]
    fn another_thread_key_cannot_read_the_transcript() {
        let setup = setup();
        append(&setup, None, &turn(0, &[1]));
        let other = ThreadKey::generate();
        assert!(matches!(
            read_turns(&setup.store, &other, setup.thread, &setup.slot, 10),
            Err(TranscriptError::Open(_))
        ));
    }

    #[test]
    fn a_forged_history_is_refused() {
        let setup = setup();
        let first = put_raw(&setup, None, &turn(0, &[1]).encode(Some(1)).unwrap());
        put_raw(&setup, Some(first), &turn(5, &[2]).encode(Some(2)).unwrap());
        assert!(matches!(read(&setup, 10), Err(TranscriptError::TurnOrder)));
    }

    #[test]
    fn an_inconsistent_running_sequence_is_refused() {
        let setup = setup();
        let first = put_raw(&setup, None, &turn(0, &[4]).encode(Some(4)).unwrap());
        put_raw(&setup, Some(first), &turn(1, &[]).encode(Some(9)).unwrap());
        assert!(matches!(
            read(&setup, 10),
            Err(TranscriptError::Malformed(_))
        ));

        let setup = self::setup();
        put_raw(&setup, None, &turn(0, &[4]).encode(Some(5)).unwrap());
        assert!(matches!(
            read(&setup, 10),
            Err(TranscriptError::Malformed(_))
        ));
    }

    #[test]
    fn a_bad_turn_beyond_the_limit_is_not_read() {
        let setup = setup();
        let first = put_raw(&setup, None, &turn(3, &[1]).encode(Some(1)).unwrap());
        let second = put_raw(&setup, Some(first), &turn(4, &[2]).encode(Some(2)).unwrap());
        put_raw(
            &setup,
            Some(second),
            &turn(5, &[3]).encode(Some(3)).unwrap(),
        );
        assert_eq!(read(&setup, 2).unwrap(), [turn(4, &[2]), turn(5, &[3])]);
        assert!(matches!(read(&setup, 3), Err(TranscriptError::TurnOrder)));
    }

    #[test]
    fn a_merge_in_the_history_is_refused() {
        let setup = setup();
        let tip = append(&setup, None, &turn(0, &[1]));
        let side = put_raw(
            &setup,
            Some(tip.commit()),
            &turn(1, &[2]).encode(Some(2)).unwrap(),
        );
        let blob = setup
            .store
            .write_sealed(&setup.key, &turn(2, &[3]).encode(Some(3)).unwrap())
            .unwrap();
        let tree = setup
            .store
            .write_tree(&[(TURN_ENTRY, EntryKind::Blob, blob)])
            .unwrap();
        let merge_commit = gix::objs::Commit {
            tree,
            parents: [side, tip.commit()].into_iter().collect(),
            author: gix::actor::Signature::default(),
            committer: gix::actor::Signature::default(),
            encoding: None,
            message: "merge".into(),
            extra_headers: Vec::new(),
        };
        let repo = gix::open(setup.dir.path()).unwrap();
        let merge = repo.objects.write(&merge_commit).unwrap();
        let r = transcript_ref(&setup);
        let head = setup.store.head(&r).unwrap();
        repo.reference(
            r.to_string(),
            merge,
            gix::refs::transaction::PreviousValue::MustExistAndMatch(head.unwrap().into()),
            "test",
        )
        .unwrap();
        assert!(matches!(
            read(&setup, 10),
            Err(TranscriptError::Store(StoreError::NotLinear(_)))
        ));
    }

    #[test]
    fn malformed_commits_are_refused() {
        let setup = setup();
        let r = transcript_ref(&setup);
        let empty = setup.store.write_tree(&[]).unwrap();
        let head = setup.store.append(&r, None, empty, "turn").unwrap();
        assert!(matches!(
            read(&setup, 10),
            Err(TranscriptError::Malformed(commit)) if commit == head
        ));

        let garbage = |plaintext: &[u8]| {
            let setup = self::setup();
            put_raw(&setup, None, plaintext);
            read(&setup, 10)
        };
        assert!(matches!(
            garbage(b"not postcard at all, too long"),
            Err(TranscriptError::Malformed(_) | TranscriptError::UnsupportedVersion(_))
        ));
        let mut v2 = turn(0, &[1]).encode(Some(1)).unwrap();
        v2[0] = 2;
        assert!(matches!(
            garbage(&v2),
            Err(TranscriptError::UnsupportedVersion(2))
        ));
        let mut trailing = turn(0, &[1]).encode(Some(1)).unwrap();
        trailing.push(0);
        assert!(matches!(
            garbage(&trailing),
            Err(TranscriptError::Malformed(_))
        ));
    }

    #[test]
    fn debug_output_carries_no_payloads() {
        let record = TurnRecord::new(
            7,
            vec![Event::new(3, b"secret prompt text".to_vec()).unwrap()],
        )
        .unwrap();
        let debug = format!("{record:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("115"));
        assert!(debug.contains("payload_len: 18"));
    }

    #[test]
    fn read_tip_refuses_a_root_that_is_not_turn_zero() {
        let setup = setup();
        put_raw(&setup, None, &turn(3, &[1]).encode(Some(1)).unwrap());
        assert!(matches!(
            read_tip(&setup.store, &setup.key, setup.thread, &setup.slot),
            Err(TranscriptError::TurnOrder)
        ));
    }
}
