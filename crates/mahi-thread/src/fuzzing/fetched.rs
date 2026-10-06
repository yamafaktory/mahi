use std::collections::HashMap;

use age::x25519;
use ed25519_dalek::SigningKey;
use mahi_core::{
    AgentName,
    AgentSlot,
    ParticipantName,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_crypto::ThreadKey;
use mahi_store::{
    EntryKind,
    FETCHED_PREFIX,
    ObjectId,
    Store,
    fuzzing::{
        scratch_store,
        set_ref,
    },
};
use ssh_key::{
    PrivateKey,
    private::Ed25519Keypair,
};

use crate::{
    GitSigner,
    MetaDraft,
    NodeId,
    Participant,
    ParticipantKey,
    PrivateMeta,
    accept_fetched,
    create_thread,
    thread::META_ENTRY,
};

const THREAD: [u8; 16] = [9; 16];
const NAMES: [&str; 3] = ["owner", "bob", "eve"];
const LISTED: usize = 2;

struct People {
    keys: [PrivateKey; 3],
    participants: [Participant; 3],
}

fn person(seed: u8, name: &str) -> (PrivateKey, Participant) {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]));
    let public = ParticipantKey::from_public_key(key.public_key()).expect("an ed25519 key");
    let node = NodeId::from_bytes(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .expect("a valid node id");
    let recipient = x25519::Identity::generate().to_public();
    let participant = Participant::new(
        ParticipantName::new(name).expect("a valid name"),
        public,
        recipient,
        node,
    )
    .expect("a valid participant");
    (key, participant)
}

fn people() -> People {
    let (owner_key, owner) = person(1, NAMES[0]);
    let (bob_key, bob) = person(2, NAMES[1]);
    let (eve_key, eve) = person(3, NAMES[2]);
    People {
        keys: [owner_key, bob_key, eve_key],
        participants: [owner, bob, eve],
    }
}

fn draft(people: &People, generation: u64, listed: usize) -> MetaDraft {
    MetaDraft::new(
        ThreadId::from_bytes(THREAD),
        generation,
        ObjectId::null(gix_hash::Kind::Sha1),
        ParticipantName::new(NAMES[0]).expect("a valid name"),
        people.participants[..listed].to_vec(),
        PrivateMeta::new("fuzz", "main").expect("a valid title"),
    )
    .expect("a valid draft")
}

struct History<'a> {
    store: &'a Store,
    made: usize,
    signed_by: HashMap<ObjectId, Option<usize>>,
    parent: HashMap<ObjectId, ObjectId>,
}

impl History<'_> {
    fn scratch(&mut self) -> ThreadRef {
        self.made += 1;
        let mut id = [0_u8; 16];
        id[..8].copy_from_slice(&(self.made as u64).to_be_bytes());
        ThreadRef::new(ThreadId::from_bytes(id), RefKind::Meta)
    }

    fn commit(
        &mut self,
        people: &People,
        signer: Option<usize>,
        parent: Option<ObjectId>,
    ) -> ObjectId {
        let scratch = self.scratch();
        if let Some(parent) = parent {
            set_ref(self.store, &scratch.to_string(), parent);
        }
        let blob = self
            .store
            .write_blob(&self.made.to_be_bytes())
            .expect("a blob is written");
        let tree = self
            .store
            .write_tree(&[("f", EntryKind::Blob, blob)])
            .expect("a tree is written");
        let commit = match signer {
            Some(who) => self.store.append_signed(
                &scratch,
                parent,
                tree,
                "m",
                &GitSigner(people.keys[who].clone()),
            ),
            None => self.store.append(&scratch, parent, tree, "m"),
        }
        .expect("a commit is written");
        self.signed_by.insert(commit, signer);
        if let Some(parent) = parent {
            self.parent.insert(commit, parent);
        }
        commit
    }

    fn chain(
        &mut self,
        people: &People,
        signer: Option<usize>,
        mut tip: Option<ObjectId>,
        length: usize,
    ) -> Option<ObjectId> {
        for _ in 0..length {
            tip = Some(self.commit(people, signer, tip));
        }
        tip
    }

    fn meta(&mut self, encoded: &[u8], parent: ObjectId) -> ObjectId {
        let scratch = self.scratch();
        set_ref(self.store, &scratch.to_string(), parent);
        let blob = self.store.write_blob(encoded).expect("a blob is written");
        let tree = self
            .store
            .write_tree(&[(META_ENTRY, EntryKind::Blob, blob)])
            .expect("a tree is written");
        self.store
            .append(&scratch, Some(parent), tree, "meta")
            .expect("a commit is written")
    }
}

fn fetched_name(thread_ref: &ThreadRef) -> String {
    thread_ref
        .to_string()
        .replacen("refs/threads/", FETCHED_PREFIX, 1)
}

struct Slot {
    who: usize,
    thread_ref: ThreadRef,
    local: Option<ObjectId>,
    fetched: Option<ObjectId>,
}

fn fetched_meta(
    history: &mut History<'_>,
    people: &People,
    (key, local_meta): (&ThreadKey, ObjectId),
    choice: u8,
) -> Option<ObjectId> {
    let signed = match choice {
        0 => return Some(local_meta),
        1 => draft(people, 1, 3)
            .sign(key, &people.keys[0])
            .expect("the owner signs"),
        2 => MetaDraft::new(
            ThreadId::from_bytes(THREAD),
            1,
            ObjectId::null(gix_hash::Kind::Sha1),
            ParticipantName::new(NAMES[2]).expect("a valid name"),
            people.participants.to_vec(),
            PrivateMeta::new("fuzz", "main").expect("a valid title"),
        )
        .expect("a valid draft")
        .sign(key, &people.keys[2])
        .expect("eve signs her own draft"),
        _ => return None,
    };
    Some(history.meta(&signed, local_meta))
}

fn slots(
    store: &Store,
    history: &mut History<'_>,
    people: &People,
    next: &mut impl FnMut() -> u8,
) -> Vec<Slot> {
    let thread = ThreadId::from_bytes(THREAD);
    let agent = AgentName::new("claude").expect("a valid agent");
    let mut slots = Vec::new();
    for (who, name) in NAMES.iter().enumerate() {
        let shape = next();
        let more = next();
        let kind: fn(AgentSlot) -> RefKind = match more % 3 {
            0 => RefKind::Snapshots,
            1 => RefKind::Transcript,
            _ => RefKind::Session,
        };
        let slot = AgentSlot::new(
            ParticipantName::new(name).expect("a valid name"),
            agent.clone(),
        );
        let thread_ref = ThreadRef::new(thread, kind(slot));
        let signer = match (more / 3) % 5 {
            0 | 1 => Some(who),
            2 => Some(2),
            3 => Some(0),
            _ => None,
        };
        let local = history.chain(people, Some(who), None, usize::from(shape % 3));
        let extra = usize::from(shape / 3 % 3) + 1;
        let fetched = match shape / 9 % 5 {
            0 => None,
            1 => local,
            2 => history.chain(people, signer, local, extra),
            3 => local.and_then(|tip| history.parent.get(&tip).copied()),
            _ => {
                let from = local.and_then(|tip| history.parent.get(&tip).copied());
                history.chain(people, signer, from, extra)
            }
        };
        if let Some(local) = local {
            set_ref(store, &thread_ref.to_string(), local);
        }
        if let Some(fetched) = fetched {
            set_ref(store, &fetched_name(&thread_ref), fetched);
        }
        slots.push(Slot {
            who,
            thread_ref,
            local,
            fetched,
        });
    }
    slots
}

fn assert_moved_forward_by_its_participant(history: &History<'_>, slot: &Slot) {
    let mut at = slot.fetched;
    while at != slot.local {
        assert!(
            at.is_some(),
            "a ref moved to a history that does not hold where it was"
        );
        let Some(commit) = at else {
            return;
        };
        assert_eq!(
            history.signed_by.get(&commit).copied().flatten(),
            Some(slot.who),
            "a ref gained a commit its participant did not sign"
        );
        at = history.parent.get(&commit).copied();
    }
}

/// Builds a thread whose `meta` lists its owner and bob, with agent histories for them and
/// for eve, whom it does not list, then local and fetched versions of each ref related as
/// `data` says (the same, ahead, behind, apart, signed by anyone or no one) and a fetched
/// `meta` that is the same, a newer one that also lists eve, one eve signed, or none, and
/// accepts what was fetched on behalf of the owner or of no one. It checks what accepting
/// promises: when it fails no ref moved; a ref of the local participant, or of one the
/// resulting `meta` does not list, never moves; and a ref that moves goes to the fetched
/// commit, forward from where it was, through commits its participant signed.
///
/// # Panics
///
/// Panics if accepting breaks one of these promises, the bug looked for, or if the scratch
/// repository cannot be set up.
pub fn fetched(data: &[u8]) {
    let mut input = data.iter().copied();
    let mut next = || input.next().unwrap_or(0);
    let store = scratch_store();
    let people = people();
    let thread = ThreadId::from_bytes(THREAD);
    let key = ThreadKey::generate();
    let first = draft(&people, 0, LISTED);
    let local_meta = create_thread(&store, &first, &key, &people.keys[0]).expect("a thread");
    let mut history = History {
        store: &store,
        made: 0,
        signed_by: HashMap::new(),
        parent: HashMap::new(),
    };
    let meta_ref = ThreadRef::new(thread, RefKind::Meta);
    let meta_choice = next() % 4;
    if let Some(fetched) = fetched_meta(&mut history, &people, (&key, local_meta), meta_choice) {
        set_ref(&store, &fetched_name(&meta_ref), fetched);
    }
    let slots = slots(&store, &mut history, &people, &mut next);

    let owner = ParticipantName::new(NAMES[0]).expect("a valid name");
    let local_participant = (next() % 2 == 0).then_some(&owner);
    let result = accept_fetched(
        &store,
        thread,
        people.participants[0].key(),
        local_participant,
    );
    let head = |thread_ref: &ThreadRef| store.head(thread_ref).expect("a ref reads");
    let Ok(accepted) = result else {
        assert_eq!(
            head(&meta_ref),
            Some(local_meta),
            "a refused fetch left meta alone"
        );
        for slot in &slots {
            assert_eq!(
                head(&slot.thread_ref),
                slot.local,
                "a refused fetch moved a ref"
            );
        }
        return;
    };
    assert!(meta_choice < 2, "a forged or missing meta was accepted");
    let eve_listed = meta_choice == 1 && accepted.updated.contains(&meta_ref);
    for slot in &slots {
        let now = head(&slot.thread_ref);
        if now == slot.local {
            continue;
        }
        assert!(
            local_participant.is_none() || slot.who != 0,
            "the local participant's ref moved"
        );
        assert!(
            slot.who < LISTED || eve_listed,
            "an unlisted participant's ref moved"
        );
        assert_eq!(
            now, slot.fetched,
            "a ref moved somewhere other than the fetched commit"
        );
        assert_moved_forward_by_its_participant(&history, slot);
    }
}
