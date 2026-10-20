use std::{
    fs::File,
    io::{
        self,
        Read,
    },
    os::fd::OwnedFd,
    str::FromStr,
    sync::{
        Arc,
        atomic::AtomicBool,
    },
    time::{
        Duration,
        Instant,
    },
};

use age::secrecy::ExposeSecret;
use mahi_core::{
    ReadBudget,
    ThreadId,
};
use mahi_identity::{
    ConfigDir,
    ConfigError,
    IdentityError,
    NodeKey,
};
use mahi_live::{
    CodeError,
    Handshake,
    HostAddress,
    LiveError,
    LiveNode,
    MAX_SLOT,
    PairError,
    PairLink,
    PairListener,
    PairingCode,
    Relays,
    Role,
    STEP_WAIT,
    Ticket,
    TicketError,
    parse_place,
    place_bytes,
};
use mahi_sandbox::TerminationSignals;
use mahi_store::{
    ObjectId,
    Pushed,
    Store,
    StoreError,
};
use mahi_thread::{
    CardError,
    ParticipantCard,
};
use rustix::fs::{
    AtFlags,
    Mode,
    OFlags,
};
use thiserror::Error;

use crate::{
    environment::Environment,
    id::{
        self,
        IdError,
    },
    invite::{
        self,
        InviteError,
        Inviter,
    },
    profile,
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    sync::{
        self,
        PairRemoteError,
    },
    ui::StopOnSignal,
};

const PAIRING_WAIT: Duration = Duration::from_mins(10);
const RELAY_WAIT: Duration = Duration::from_secs(5);
const ACCEPT_SLICE: Duration = Duration::from_millis(250);
const FETCH_BUDGET: u64 = 64 * 1024;
const SLOT_TRIES: usize = 8;
const RECORD: &str = "pairing";
const LOCK: &str = "pairing.lock";
const MAX_RECORD_BYTES: u64 = 128;
const TICKET_PREFIX: &str = "ticket ";
const REFUSED: &[u8] = b"refused";

#[derive(Debug, Error)]
pub(crate) enum PairingError {
    #[error(transparent)]
    Invite(#[from] InviteError),
    #[error("cannot find mahi's configuration directory")]
    Config(#[from] ConfigError),
    #[error("mahi is not set up; run mahi init first")]
    NotInitialised(#[source] IdentityError),
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error(
        "pairing needs a remote to meet through: choose one with mahi remote <name> --private or --public"
    )]
    NoRemote,
    #[error(
        "this clone has no remote to find the owner through; add origin or choose one with mahi remote"
    )]
    NoFetchSource,
    #[error(transparent)]
    Remote(#[from] PairRemoteError),
    #[error("every pairing slot tried on the remote was taken; try again")]
    NoSlot,
    #[error("the remote refused the pairing: {0}")]
    Refused(String),
    #[error("cannot draw a pairing code")]
    Code(#[from] CodeError),
    #[error("the live layer failed")]
    Live(#[from] LiveError),
    #[error("the pairing place cannot be written or read")]
    Place(#[source] TicketError),
    #[error("no one is waiting with pairing code slot {0} on the remote")]
    NoPairing(u16),
    #[error(transparent)]
    Exchange(#[from] PairError),
    #[error("no one paired within 10 minutes")]
    NoOneCame,
    #[error("stopped")]
    Stopped,
    #[error("the teammate's card is not valid")]
    Card(#[from] CardError),
    #[error("the card names another node than the one that connected")]
    CardNode,
    #[error("the owner did not add you")]
    NotAdded,
    #[error(
        "the pairing ended at the code check: the code did not match, the owner stopped, or the network failed"
    )]
    CodeRefused,
    #[error(
        "the pairing ended before the owner added you: they stopped, took longer than 10 minutes, or the network failed"
    )]
    OwnerEnded,
    #[error(
        "the ref refs/mahi/pair/{0} an earlier pairing in this clone left on the remote cannot be removed; try again, or remove it there by hand and delete mahi/pairing in the repository's git directory"
    )]
    Leftover(u16),
    #[error("the pairing took longer than 10 minutes, so no one was added")]
    TooLate,
    #[error("{0} left before being added, so no one was added")]
    JoinerLeft(String),
    #[error("another pairing is running in this clone; wait for it to end")]
    Busy,
    #[error("added {name}, but the ticket did not reach them; give them this ticket: {ticket}")]
    Undelivered { name: String, ticket: Box<Ticket> },
    #[error("you did not add {0}")]
    Declined(String),
    #[error("the owner sent a reply mahi cannot read")]
    Reply,
    #[error("the ticket is for another node than yours")]
    NotForThisNode,
    #[error("cannot ask the user")]
    Prompt(#[source] io::Error),
    #[error("cannot describe you to the owner")]
    Id(#[from] IdError),
    #[error("cannot keep the pending pairing in the git directory")]
    Record(#[source] io::Error),
}

/// Pairs the thread's owner with a teammate through a code: publishes where this mahi waits
/// on the chosen remote, shows the code, and adds the teammate who proves they know it, then
/// removes what it published. Returns what to print.
pub(crate) fn invite_by_code(
    thread: ThreadId,
    environment: &Environment,
) -> Result<String, PairingError> {
    invite::with_inviter(environment, |store, inviter| {
        if crate::remote::sync_remote(store)
            .map_err(|error| PairingError::Remote(PairRemoteError::Setup(error.into())))?
            .is_none()
        {
            return Err(PairingError::NoRemote);
        }
        let _lock = lock_pairing(store)?;
        clear_leftover(store, environment)?;
        let listener = PairListener::bind(inviter.relays)?;
        let found = listener.address(RELAY_WAIT)?;
        let host = place_of(&found, inviter.relays)?;
        let place = place_bytes(&host, inviter.relays).map_err(PairingError::Place)?;
        let commit = store.write_pairing(&place)?;
        let slot = publish(store, environment, commit)?;
        let deadline = Instant::now() + PAIRING_WAIT;
        let paired = PairingCode::random(slot)
            .map_err(PairingError::from)
            .and_then(|code| {
                let mut prompt = TerminalPrompt::open().map_err(PairingError::Prompt)?;
                show_code(&mut prompt, &code)?;
                drop(prompt);
                owner_pairs(&listener, &code, deadline, (store, thread, inviter))
            });
        crate::ui::show_working();
        unpublish(store, environment, slot, commit);
        paired.map(|name| {
            format!("added {name} to thread {thread}; they join with the ticket mahi sent them\n")
        })
    })
}

fn show_code(prompt: &mut TerminalPrompt, code: &PairingCode) -> Result<(), PairingError> {
    let say =
        |prompt: &mut TerminalPrompt, line: &str| prompt.say(line).map_err(PairingError::Prompt);
    say(prompt, &format!("Pairing code: {code}"))?;
    say(
        prompt,
        "Tell it to your teammate, who runs mahi join (or presses c on mahi's home screen) in a \
         clone of this project and types it. Waiting up to 10 minutes; Ctrl-C stops.",
    )
}

fn place_of(found: &HostAddress, relays: Relays) -> Result<HostAddress, PairingError> {
    let place = match relays {
        Relays::Public => HostAddress::new(*found.node(), found.relay().cloned(), Vec::new()),
        Relays::Disabled => HostAddress::new(*found.node(), None, found.direct().to_vec()),
    };
    place.map_err(|error| PairingError::Place(error.into()))
}

/// Pushes the pairing ref to a free slot on the chosen remote, and returns the slot. The
/// record is written before each attempt, so a ref that lands is always recorded; it is
/// removed when no attempt lands.
fn publish(
    store: &Store,
    environment: &Environment,
    commit: ObjectId,
) -> Result<u16, PairingError> {
    let never = Arc::new(AtomicBool::new(false));
    let limit = sync::transfer_limits(environment).fetch_limit;
    let connect = || {
        sync::connect_chosen(store, environment, ReadBudget::new(limit), &never)?
            .map(|(_, transport)| transport)
            .ok_or(PairingError::NoRemote)
    };
    let mut taken: Vec<u16> = store
        .remote_pairings(connect()?)?
        .into_iter()
        .map(|(slot, _)| slot)
        .collect();
    let mut refused = None;
    for _ in 0..SLOT_TRIES {
        let slot = random_slot(&taken)?;
        write_record(store, slot, commit).map_err(PairingError::Record)?;
        let pushed = connect().and_then(|transport| {
            store
                .push_pairing(transport, slot, commit, &never)
                .map_err(PairingError::from)
        });
        match pushed {
            Ok(Pushed::Updated | Pushed::UpToDate) => return Ok(slot),
            Ok(Pushed::Behind) => {}
            Ok(Pushed::Refused(reason)) => refused = Some(reason),
            Ok(other) => {
                unpublish(store, environment, slot, commit);
                return Err(PairingError::Refused(format!("{other:?}")));
            }
            Err(error) => {
                unpublish(store, environment, slot, commit);
                return Err(error);
            }
        }
        taken.push(slot);
    }
    let _ = remove_record(store);
    Err(refused.map_or(PairingError::NoSlot, PairingError::Refused))
}

fn random_slot(taken: &[u16]) -> Result<u16, PairingError> {
    let mut bytes = [0_u8; 2];
    getrandom::fill(&mut bytes).map_err(|_| CodeError::Random)?;
    let start = u16::from_be_bytes(bytes) % MAX_SLOT;
    (0..MAX_SLOT)
        .map(|offset| (start + offset) % MAX_SLOT + 1)
        .find(|slot| !taken.contains(slot))
        .ok_or(PairingError::NoSlot)
}

/// Removes the pairing ref, only while it still points at `commit`, and the local record, and
/// says whether it is gone; a failure is reported and the record kept, so the next pairing
/// removes it.
fn unpublish(store: &Store, environment: &Environment, slot: u16, commit: ObjectId) -> bool {
    let never = Arc::new(AtomicBool::new(false));
    let limit = sync::transfer_limits(environment).fetch_limit;
    let removed = sync::connect_chosen(store, environment, ReadBudget::new(limit), &never)
        .map_err(PairingError::from)
        .and_then(|connected| connected.ok_or(PairingError::NoRemote))
        .and_then(|(_, transport)| {
            store
                .delete_pairing(transport, slot, commit, &never)
                .map_err(PairingError::from)
        });
    match removed {
        Ok(Pushed::Updated | Pushed::UpToDate | Pushed::Behind) => {
            let _ = remove_record(store);
            true
        }
        Ok(other) => {
            eprintln!("mahi: the pairing ref was left on the remote: {other:?}");
            false
        }
        Err(error) => {
            crate::report_with("the pairing ref was left on the remote", &error);
            false
        }
    }
}

/// Removes a pairing ref an earlier pairing in this clone left behind, as its record says; a
/// new pairing does not start while that ref cannot be removed, so its record is never lost.
fn clear_leftover(store: &Store, environment: &Environment) -> Result<(), PairingError> {
    match read_record(store) {
        Some((slot, commit)) if !unpublish(store, environment, slot, commit) => {
            Err(PairingError::Leftover(slot))
        }
        _ => Ok(()),
    }
}

/// Waits for the teammate, runs the exchange, asks the user, adds the teammate and sends them
/// their ticket, all before `deadline`; returns their name.
fn owner_pairs(
    listener: &PairListener,
    code: &PairingCode,
    deadline: Instant,
    (store, thread, inviter): (&Store, ThreadId, &Inviter<'_>),
) -> Result<String, PairingError> {
    let mut link = accept_until_stopped(listener, deadline)?;
    let stop = StopOnSignal::start();
    let (handshake, mine) = Handshake::start(Role::Owner, code);
    let theirs = link.receive(STEP_WAIT)?;
    link.send(&mine)?;
    let confirming = handshake.finish(&theirs)?;
    let own = confirming.confirmation();
    let mut channel = confirming.check(&link.receive(STEP_WAIT)?)?;
    link.send(&own)?;
    let card = channel.open(&link.receive(STEP_WAIT)?)?;
    let card =
        ParticipantCard::from_str(std::str::from_utf8(&card).map_err(|_| CardError::Malformed)?)?;
    if card.participant().node() != link.peer() {
        return Err(PairingError::CardNode);
    }
    let name = card.participant().name().to_string();
    let question = format!(
        "Add {name} ({}) to thread {thread}? [y/N] ",
        card.participant().key().fingerprint()
    );
    drop(stop);
    let answer = TerminalPrompt::open()
        .and_then(|mut prompt| prompt.answer(&question))
        .map_err(PairingError::Prompt)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        if let Ok(sealed) = channel.seal(REFUSED)
            && link.send(&sealed).is_ok()
        {
            let _ = link.finish();
        }
        return Err(PairingError::Declined(name));
    }
    if Instant::now() >= deadline {
        return Err(PairingError::TooLate);
    }
    if !link.is_open() {
        return Err(PairingError::JoinerLeft(name));
    }
    let added = invite::invite_to(store, thread, card, inviter, &mut || TerminalPrompt::open());
    let ticket = match added {
        Ok(ticket) => ticket,
        Err(error) => {
            if let Ok(sealed) = channel.seal(REFUSED)
                && link.send(&sealed).is_ok()
            {
                let _ = link.finish();
            }
            return Err(error.into());
        }
    };
    let _stop = StopOnSignal::start();
    let delivered = channel
        .seal(format!("{TICKET_PREFIX}{ticket}").as_bytes())
        .map_err(PairingError::from)
        .and_then(|sealed| link.send(&sealed).map_err(PairingError::from));
    if delivered.is_err() || !link.finish() {
        return Err(PairingError::Undelivered {
            name,
            ticket: Box::new(ticket),
        });
    }
    Ok(name)
}

fn accept_until_stopped(
    listener: &PairListener,
    deadline: Instant,
) -> Result<PairLink<'_>, PairingError> {
    let signals = TerminationSignals::listen().ok();
    while Instant::now() < deadline {
        match listener.accept(ACCEPT_SLICE) {
            Ok(link) => return Ok(link),
            Err(LiveError::TimedOut) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(signals) = &signals
            && matches!(signals.wait_timeout(Duration::ZERO), Ok(Some(_)))
        {
            return Err(PairingError::Stopped);
        }
    }
    Err(PairingError::NoOneCame)
}

/// Asks for a pairing code, finds the owner through the remote, proves the code, sends the
/// user's card and returns the ticket the owner sends back.
pub(crate) fn join_by_code(environment: &Environment) -> Result<Ticket, PairingError> {
    let relays = invite::relays_for(environment.live)?;
    let cwd = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(InviteError::CurrentDirectory)?;
    let store = Store::discover(&cwd)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let node_key = NodeKey::load(&config.node_key_file()).map_err(PairingError::NotInitialised)?;
    let card = id::id(environment)?;
    let mut prompt = TerminalPrompt::open().map_err(PairingError::Prompt)?;
    let typed = prompt
        .secret("Pairing code: ")
        .map_err(PairingError::Prompt)?;
    let code: PairingCode = typed.expose_secret().parse()?;
    drop(typed);
    let never = Arc::new(AtomicBool::new(false));
    let (_, transport) =
        sync::connect_fetch_source(&store, environment, ReadBudget::new(FETCH_BUDGET), &never)?
            .ok_or(PairingError::NoFetchSource)?;
    let place = store
        .fetch_pairing(transport, code.slot(), &never)?
        .ok_or(PairingError::NoPairing(code.slot()))?;
    let owner = parse_place(&place, relays).map_err(PairingError::Place)?;
    let node = LiveNode::bind(node_key.secret(), relays)?;
    let own = node.node()?;
    let stop = StopOnSignal::start();
    let ticket = joiner_pairs(&node, &owner, &code, card.trim_end(), &mut prompt)?;
    drop(stop);
    node.close()?;
    if ticket.invitee() != &own {
        return Err(PairingError::NotForThisNode);
    }
    Ok(ticket)
}

fn joiner_pairs(
    node: &LiveNode,
    owner: &HostAddress,
    code: &PairingCode,
    card: &str,
    prompt: &mut TerminalPrompt,
) -> Result<Ticket, PairingError> {
    let mut link = node.connect_pairing(owner)?;
    let (handshake, mine) = Handshake::start(Role::Joiner, code);
    link.send(&mine)?;
    let confirming = handshake.finish(&link.receive(STEP_WAIT)?)?;
    link.send(&confirming.confirmation())?;
    let theirs = link
        .receive(STEP_WAIT)
        .map_err(|_| PairingError::CodeRefused)?;
    let mut channel = confirming.check(&theirs)?;
    link.send(&channel.seal(card.as_bytes())?)?;
    prompt
        .say("The code matched; waiting for the owner to add you.")
        .map_err(PairingError::Prompt)?;
    let reply = link
        .receive(PAIRING_WAIT)
        .map_err(|_| PairingError::OwnerEnded)?;
    let reply = channel.open(&reply)?;
    link.wait_closed(STEP_WAIT);
    if reply.as_slice() == REFUSED {
        return Err(PairingError::NotAdded);
    }
    std::str::from_utf8(&reply)
        .ok()
        .and_then(|text| text.strip_prefix(TICKET_PREFIX))
        .and_then(|ticket| ticket.parse::<Ticket>().ok())
        .ok_or(PairingError::Reply)
}

fn record_dir(store: &Store) -> io::Result<OwnedFd> {
    let parent = store.common_dir().join("mahi");
    profile::create_private_dir(&parent)?;
    let parent = rustix::fs::open(
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(parent)
}

/// Holds the clone's pairing lock while it lives, so only one pairing at a time writes the
/// record; the system releases it when mahi ends, however it ends.
fn lock_pairing(store: &Store) -> Result<OwnedFd, PairingError> {
    let file = rustix::fs::openat(
        record_dir(store).map_err(PairingError::Record)?,
        LOCK,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| PairingError::Record(error.into()))?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(PairingError::Busy),
        Err(error) => Err(PairingError::Record(error.into())),
    }
}

fn write_record(store: &Store, slot: u16, commit: ObjectId) -> io::Result<()> {
    profile::replace(
        &record_dir(store)?,
        RECORD,
        format!("{slot} {commit}\n").as_bytes(),
    )
}

fn read_record(store: &Store) -> Option<(u16, ObjectId)> {
    let file = rustix::fs::openat(
        record_dir(store).ok()?,
        RECORD,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let mut text = String::new();
    File::from(file)
        .take(MAX_RECORD_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    let (slot, commit) = text.strip_suffix('\n')?.split_once(' ')?;
    let slot: u16 = slot
        .parse()
        .ok()
        .filter(|slot| (1..=MAX_SLOT).contains(slot))?;
    Some((slot, ObjectId::from_hex(commit.as_bytes()).ok()?))
}

fn remove_record(store: &Store) -> io::Result<()> {
    match rustix::fs::unlinkat(record_dir(store)?, RECORD, AtFlags::empty()) {
        Err(error) if error != rustix::io::Errno::NOENT => Err(error.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn a_pending_pairing_is_recorded_read_back_and_removed() {
        let (_dir, store) = store();
        assert_eq!(read_record(&store), None);
        let commit = store.write_pairing(b"place").unwrap();
        write_record(&store, 412, commit).unwrap();
        assert_eq!(read_record(&store), Some((412, commit)));
        remove_record(&store).unwrap();
        remove_record(&store).unwrap();
        assert_eq!(read_record(&store), None);
    }

    #[test]
    fn only_one_pairing_at_a_time_holds_the_clone() {
        let (_dir, store) = store();
        let held = lock_pairing(&store).unwrap();
        assert!(matches!(lock_pairing(&store), Err(PairingError::Busy)));
        drop(held);
        lock_pairing(&store).unwrap();
    }

    #[test]
    fn a_record_mahi_did_not_write_is_ignored() {
        let (dir, store) = store();
        record_dir(&store).unwrap();
        let path = dir.path().join(".git/mahi").join(RECORD);
        for text in [
            "",
            "0 abc\n",
            "1000 abc\n",
            "412\n",
            "412 nothex\n",
            "412 abc",
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(read_record(&store), None, "{text:?}");
        }
    }

    #[test]
    fn a_random_slot_avoids_the_taken_ones() {
        let taken: Vec<u16> = (1..=MAX_SLOT).filter(|slot| *slot != 7).collect();
        assert_eq!(random_slot(&taken).ok(), Some(7));
        for _ in 0..32 {
            let slot = random_slot(&[]).unwrap();
            assert!((1..=MAX_SLOT).contains(&slot));
        }
        let all: Vec<u16> = (1..=MAX_SLOT).collect();
        assert!(matches!(random_slot(&all), Err(PairingError::NoSlot)));
    }

    #[test]
    fn a_public_place_drops_direct_addresses_and_a_local_one_keeps_them() {
        let node = mahi_thread::NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap();
        let found = HostAddress::new(
            node,
            Some("https://relay.example.org".parse().unwrap()),
            vec!["192.168.1.2:4000".parse().unwrap()],
        )
        .unwrap();
        let public = place_of(&found, Relays::Public).unwrap();
        assert!(public.direct().is_empty() && public.relay().is_some());
        let local = place_of(&found, Relays::Disabled).unwrap();
        assert!(local.relay().is_none() && local.direct().len() == 1);
    }
}
