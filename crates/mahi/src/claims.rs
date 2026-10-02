use std::{
    collections::HashMap,
    sync::Mutex,
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    AgentSlot,
    is_invisible,
};
use mahi_live::{
    ClaimEntry,
    MAX_CLAIM_BYTES,
    MAX_CLAIM_NOTE_BYTES,
    MAX_FRAME_CLAIMS,
    MAX_LOCAL_CLAIMS,
};
use mahi_thread::NodeId;
use thiserror::Error;

/// The longest a claimed path or task may be, in bytes.
pub(crate) const MAX_WHAT_BYTES: usize = MAX_CLAIM_BYTES;
/// The longest a claim's note may be, in bytes.
pub(crate) const MAX_NOTE_BYTES: usize = MAX_CLAIM_NOTE_BYTES;
/// The most claims one agent holds.
pub(crate) const MAX_PER_SLOT: usize = 32;
/// How long another host's claims are kept without being heard again.
const THEIRS_KEPT: Duration = Duration::from_secs(30);

/// An advisory claim on a path or a task: the agent that holds it, what it claims, an optional
/// note, and how long ago it was taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Claim {
    pub(crate) slot: AgentSlot,
    pub(crate) what: String,
    pub(crate) note: Option<String>,
    pub(crate) age: Duration,
}

/// Why a claim was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ClaimError {
    #[error("what is claimed must be text of 1 to 256 bytes without control characters")]
    BadWhat,
    #[error("a note must be text of at most 200 bytes without control characters")]
    BadNote,
    #[error("an agent holds at most 32 claims; release some first")]
    TooMany,
    #[error("the claims cannot be read")]
    Unavailable,
}

/// The claims this mahi knows: those its agent holds, those of the agents of the user's other
/// mahis it hosts, the latest list each other host sent, and, when another mahi of the user
/// hosts, the whole list that one sent.
#[derive(Debug, Default)]
pub(crate) struct Claims {
    state: Mutex<Board>,
}

#[derive(Debug, Default)]
struct Board {
    held: Vec<Held>,
    guests: HashMap<AgentSlot, Vec<ClaimEntry>>,
    theirs: HashMap<NodeId, (Instant, Vec<ClaimEntry>)>,
    from_host: Option<(Instant, Vec<ClaimEntry>)>,
    hosted_changed: bool,
    version: u64,
    held_version: u64,
}

#[derive(Debug)]
struct Held {
    what: String,
    note: Option<String>,
    at: Instant,
}

impl Board {
    fn changed(&mut self, held: bool) {
        self.version = self.version.wrapping_add(1);
        self.hosted_changed = true;
        if held {
            self.held_version = self.held_version.wrapping_add(1);
        }
    }

    fn others(&self, me: &AgentSlot) -> impl Iterator<Item = (&ClaimEntry, Duration)> {
        let fresh = |heard: &Instant| heard.elapsed() <= THEIRS_KEPT;
        let guests = self
            .guests
            .values()
            .flatten()
            .map(|entry| (entry, Duration::ZERO));
        let theirs = self
            .theirs
            .values()
            .filter(move |(heard, _)| fresh(heard))
            .flat_map(|(heard, entries)| entries.iter().map(|entry| (entry, heard.elapsed())));
        let from_host = self
            .from_host
            .iter()
            .flat_map(|(heard, entries)| entries.iter().map(|entry| (entry, heard.elapsed())));
        guests
            .chain(theirs)
            .chain(from_host)
            .filter(move |(entry, _)| &entry.slot != me)
    }
}

impl Claims {
    /// Claims `what` for this mahi's agent `me`, with `note`, renewing its claim on it;
    /// returns the other agents that claim it too.
    pub(crate) fn claim(
        &self,
        me: &AgentSlot,
        what: &str,
        note: Option<&str>,
    ) -> Result<Vec<AgentSlot>, ClaimError> {
        if !fits(what, MAX_WHAT_BYTES) || what.trim() != what {
            return Err(ClaimError::BadWhat);
        }
        if note.is_some_and(|note| !fits(note, MAX_NOTE_BYTES)) {
            return Err(ClaimError::BadNote);
        }
        let Ok(mut board) = self.state.lock() else {
            return Err(ClaimError::Unavailable);
        };
        let mut others: Vec<AgentSlot> = board
            .others(me)
            .filter(|(entry, _)| entry.what == what)
            .map(|(entry, _)| entry.slot.clone())
            .collect();
        others.sort();
        others.dedup();
        if let Some(held) = board.held.iter_mut().find(|held| held.what == what) {
            held.note = note.map(str::to_owned);
        } else {
            if board.held.len() >= MAX_PER_SLOT {
                return Err(ClaimError::TooMany);
            }
            board.held.push(Held {
                what: what.to_owned(),
                note: note.map(str::to_owned),
                at: Instant::now(),
            });
        }
        board.changed(true);
        Ok(others)
    }

    /// Releases this mahi's agent's claim on `what`, and returns whether it held one.
    pub(crate) fn release(&self, what: &str) -> bool {
        let Ok(mut board) = self.state.lock() else {
            return false;
        };
        let before = board.held.len();
        board.held.retain(|held| held.what != what);
        let released = board.held.len() != before;
        if released {
            board.changed(true);
        }
        released
    }

    /// Takes the latest claims the host `node` sent, which replace the ones before; lists not
    /// heard again for 30 s are dropped.
    pub(crate) fn hear(&self, node: NodeId, entries: Vec<ClaimEntry>) {
        self.hear_at(node, entries, Instant::now());
    }

    fn hear_at(&self, node: NodeId, entries: Vec<ClaimEntry>, heard: Instant) {
        if let Ok(mut board) = self.state.lock() {
            board
                .theirs
                .retain(|_, (at, _)| at.elapsed() <= THEIRS_KEPT);
            board.theirs.insert(node, (heard, entries));
            board.version = board.version.wrapping_add(1);
        }
    }

    /// Forgets the list the mahi of the user that hosted sent, as this mahi stops being its
    /// guest.
    pub(crate) fn host_lost(&self) {
        if let Ok(mut board) = self.state.lock()
            && board.from_host.take().is_some()
        {
            board.version = board.version.wrapping_add(1);
        }
    }

    /// Takes the claims the agent `guest` of another mahi of the user holds, which this mahi
    /// hosts; entries for any other agent are left out.
    pub(crate) fn hear_guest(&self, guest: &AgentSlot, mut entries: Vec<ClaimEntry>) {
        entries.retain(|entry| &entry.slot == guest);
        entries.truncate(MAX_PER_SLOT);
        if let Ok(mut board) = self.state.lock() {
            board.guests.insert(guest.clone(), entries);
            board.changed(false);
        }
    }

    /// Forgets the claims of the agent `guest`, as its mahi leaves.
    pub(crate) fn forget_guest(&self, guest: &AgentSlot) {
        if let Ok(mut board) = self.state.lock()
            && board.guests.remove(guest).is_some()
        {
            board.changed(false);
        }
    }

    /// Takes the whole list the mahi of the user that hosts sent.
    pub(crate) fn hear_host(&self, entries: Vec<ClaimEntry>) {
        if let Ok(mut board) = self.state.lock() {
            board.from_host = Some((Instant::now(), entries));
            board.version = board.version.wrapping_add(1);
        }
    }

    /// Returns every claim known, those of `me`, this mahi's agent, first.
    pub(crate) fn all(&self, me: &AgentSlot) -> Vec<Claim> {
        let Ok(board) = self.state.lock() else {
            return Vec::new();
        };
        let mut all: Vec<Claim> = board.held.iter().map(|held| held.claim(me)).collect();
        all.extend(board.others(me).map(|(entry, since)| Claim {
            slot: entry.slot.clone(),
            what: entry.what.clone(),
            note: entry.note.clone(),
            age: Duration::from_secs(u64::from(entry.age_secs)) + since,
        }));
        all
    }

    /// Returns what this mahi broadcasts as host: the claims of its agent `me` and of the
    /// agents it hosts for the user's other mahis, at most as many as a frame carries.
    pub(crate) fn hosted(&self, me: &AgentSlot) -> Vec<ClaimEntry> {
        let Ok(board) = self.state.lock() else {
            return Vec::new();
        };
        board
            .held
            .iter()
            .map(|held| held.entry(me))
            .chain(board.guests.values().flatten().cloned())
            .take(MAX_FRAME_CLAIMS)
            .collect()
    }

    /// Returns every claim known, as the host sends them to the user's other mahis.
    pub(crate) fn known(&self, me: &AgentSlot) -> Vec<ClaimEntry> {
        self.all(me)
            .into_iter()
            .take(MAX_LOCAL_CLAIMS)
            .map(|claim| ClaimEntry {
                slot: claim.slot,
                what: claim.what,
                note: claim.note,
                age_secs: u32::try_from(claim.age.as_secs()).unwrap_or(u32::MAX),
            })
            .collect()
    }

    /// Returns the claims of this mahi's agent `me`, as it sends them to the mahi that hosts.
    pub(crate) fn held(&self, me: &AgentSlot) -> Vec<ClaimEntry> {
        self.state
            .lock()
            .map(|board| board.held.iter().map(|held| held.entry(me)).collect())
            .unwrap_or_default()
    }

    /// Returns whether what this mahi broadcasts as host changed since the last call.
    pub(crate) fn take_hosted_changed(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|mut board| std::mem::take(&mut board.hosted_changed))
    }

    /// Returns a number that changes whenever any claim known changes.
    pub(crate) fn version(&self) -> u64 {
        self.state.lock().map_or(0, |board| board.version)
    }

    /// Returns a number that changes whenever this mahi's agent's claims change.
    pub(crate) fn held_version(&self) -> u64 {
        self.state.lock().map_or(0, |board| board.held_version)
    }
}

impl Held {
    fn claim(&self, me: &AgentSlot) -> Claim {
        Claim {
            slot: me.clone(),
            what: self.what.clone(),
            note: self.note.clone(),
            age: self.at.elapsed(),
        }
    }

    fn entry(&self, me: &AgentSlot) -> ClaimEntry {
        ClaimEntry {
            slot: me.clone(),
            what: self.what.clone(),
            note: self.note.clone(),
            age_secs: u32::try_from(self.at.elapsed().as_secs()).unwrap_or(u32::MAX),
        }
    }
}

fn fits(text: &str, most: usize) -> bool {
    !text.is_empty()
        && text.len() <= most
        && !text
            .chars()
            .any(|character| character.is_control() || is_invisible(character))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(name: &str) -> AgentSlot {
        name.parse().unwrap()
    }

    fn entry(slot_name: &str, what: &str) -> ClaimEntry {
        ClaimEntry {
            slot: slot(slot_name),
            what: what.to_owned(),
            note: None,
            age_secs: 60,
        }
    }

    #[test]
    fn a_claim_is_held_renewed_and_released() {
        let claims = Claims::default();
        let claude = slot("alice.claude");
        assert_eq!(claims.claim(&claude, "src/parser.rs", None), Ok(Vec::new()));
        assert!(claims.take_hosted_changed());
        assert!(!claims.take_hosted_changed());
        let version = claims.held_version();
        claims
            .claim(&claude, "src/parser.rs", Some("adding tests"))
            .unwrap();
        assert_ne!(claims.held_version(), version);
        let all = claims.all(&claude);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].note.as_deref(), Some("adding tests"));
        assert_eq!(claims.held(&claude)[0].slot, claude);
        assert!(claims.release("src/parser.rs"));
        assert!(!claims.release("src/parser.rs"));
        assert!(claims.all(&claude).is_empty());
    }

    #[test]
    fn odd_or_oversized_claims_are_refused_and_an_agent_holds_at_most_32() {
        let claims = Claims::default();
        let claude = slot("alice.claude");
        for bad in [
            "",
            " padded",
            "line\nbreak",
            "\u{202e}flip",
            &"x".repeat(257),
        ] {
            assert_eq!(
                claims.claim(&claude, bad, None),
                Err(ClaimError::BadWhat),
                "{bad:?}"
            );
        }
        assert_eq!(
            claims.claim(&claude, "ok", Some(&"n".repeat(201))),
            Err(ClaimError::BadNote)
        );
        for index in 0..MAX_PER_SLOT {
            claims
                .claim(&claude, &format!("file{index}"), None)
                .unwrap();
        }
        assert_eq!(
            claims.claim(&claude, "one more", None),
            Err(ClaimError::TooMany)
        );
    }

    #[test]
    fn guests_hosts_and_other_hosts_claims_are_known_without_echoing_ones_own() {
        let claims = Claims::default();
        let claude = slot("alice.claude");
        let codex = slot("alice.codex");
        claims.claim(&claude, "src/parser.rs", None).unwrap();
        claims.take_hosted_changed();
        claims.hear_guest(
            &codex,
            vec![entry("alice.codex", "docs"), entry("bob.x", "forged")],
        );
        assert!(claims.take_hosted_changed());
        let hosted = claims.hosted(&claude);
        assert_eq!(hosted.len(), 2);
        assert!(hosted.iter().all(|entry| entry.slot != slot("bob.x")));
        let node =
            NodeId::from_bytes(mahi_identity::NodeKey::generate().unwrap().public()).unwrap();
        claims.hear(node, vec![entry("bob.codex", "src/parser.rs")]);
        assert_eq!(
            claims.claim(&claude, "src/parser.rs", None),
            Ok(vec![slot("bob.codex")])
        );
        assert_eq!(claims.all(&claude).len(), 3);
        claims.forget_guest(&codex);
        assert_eq!(claims.hosted(&claude).len(), 1);

        let guest = Claims::default();
        guest.claim(&codex, "docs", None).unwrap();
        guest.hear_host(vec![
            entry("alice.codex", "docs"),
            entry("alice.claude", "x"),
        ]);
        let known = guest.all(&codex);
        assert_eq!(known.len(), 2);
        assert_eq!(guest.known(&codex).len(), 2);
    }

    #[test]
    fn other_hosts_lists_not_heard_for_30_s_and_a_lost_hosts_list_are_forgotten() {
        let claims = Claims::default();
        let me = slot("alice.claude");
        let long_ago = Instant::now()
            .checked_sub(THEIRS_KEPT + Duration::from_secs(1))
            .unwrap();
        let node =
            NodeId::from_bytes(mahi_identity::NodeKey::generate().unwrap().public()).unwrap();
        claims.hear_at(node, vec![entry("bob.codex", "old")], long_ago);
        assert!(claims.all(&me).is_empty());
        claims.hear(node, vec![entry("bob.codex", "new")]);
        assert_eq!(claims.all(&me).len(), 1);
        claims.hear_host(vec![entry("alice.codex", "docs")]);
        assert_eq!(claims.all(&me).len(), 2);
        if let Ok(mut board) = claims.state.lock()
            && let Some((heard, _)) = board.from_host.as_mut()
        {
            *heard = long_ago;
        }
        assert_eq!(claims.all(&me).len(), 2);
        let version = claims.version();
        claims.host_lost();
        assert_ne!(claims.version(), version);
        assert_eq!(claims.all(&me).len(), 1);
    }
}
