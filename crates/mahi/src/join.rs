use std::{
    collections::HashSet,
    env,
    fs,
    io::{
        self,
        Read,
        Write,
    },
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    AgentSlot,
    ParticipantName,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_crypto::ThreadKey;
use mahi_identity::{
    ConfigDir,
    ConfigError,
    IdentityError,
    LocalIdentity,
    NodeKey,
    SigningKey,
};
use mahi_live::{
    Body,
    FrameError,
    FrameReceiver,
    FrameSender,
    LiveError,
    LiveKeys,
    LiveNode,
    LiveTopic,
    Peers,
    Relays,
    Ticket,
};
use mahi_sandbox::{
    SignalError,
    TerminationSignals,
};
use mahi_store::{
    Store,
    StoreError,
};
use mahi_thread::{
    MetaError,
    NodeId,
    OwnerError,
    ParticipantKey,
    ThreadError,
    VerifiedMeta,
    load_meta,
    record_meta,
    remember_owner,
    remembered_owner,
};
use thiserror::Error;

use crate::{
    cli::{
        JoinCommand,
        LaunchOptions,
    },
    environment::{
        Environment,
        LiveMode,
    },
    live,
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    run::{
        self,
        Joined,
        Outcome,
        RunError,
    },
    session::CommitKey,
    sync,
    terminal::RawMode,
    thread_lock::{
        LockError,
        ThreadLock,
    },
};

const META_WAIT: Duration = Duration::from_secs(30);
const RETRY_PAUSE: Duration = Duration::from_secs(1);
const JOIN_WAIT: Duration = Duration::from_secs(15);
const ASK_EVERY: Duration = Duration::from_secs(1);
const RECEIVE_PAUSE: Duration = Duration::from_millis(100);
const ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049h";
const MAIN_SCREEN: &[u8] = b"\x1b[?1049l";
const CLEAR: &[u8] = b"\x1b[H\x1b[2J";
const RESET: &[u8] =
    b"\x1b[0m\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?2004l\x1b[?1l\x1b>";
const STUCK_SCREEN: Duration = Duration::from_secs(3);
const DRAIN: usize = 256;
const HOST_SILENCE: Duration = Duration::from_secs(30);
const QUIT_KEYS: [u8; 3] = [b'q', 0x03, 0x04];

#[derive(Debug, Error)]
pub(crate) enum JoinError {
    #[error("joining needs the live layer: set MAHI_LIVE to local or public, or leave it unset")]
    LiveSetting,
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot find mahi's configuration directory")]
    Config(#[from] ConfigError),
    #[error("mahi is not set up; run mahi init first")]
    NotInitialised(#[source] IdentityError),
    #[error("this ticket was made for another machine's node; ask for a ticket for {0}")]
    NotForThisNode(NodeId),
    #[error("run mahi join in a clone of the project")]
    Store(#[from] StoreError),
    #[error("cannot reach the thread's host")]
    Live(#[from] LiveError),
    #[error(
        "the host did not serve the thread's meta; is the thread running, and did the owner invite you?"
    )]
    NoMeta(#[source] LiveError),
    #[error("the thread's meta is not signed by the owner the ticket names")]
    Meta(#[source] MetaError),
    #[error("the thread's meta is older than the ticket allows")]
    Rollback,
    #[error("the thread's meta does not list this node or the host")]
    NotListed,
    #[error("cannot record the thread's meta")]
    Pin(#[source] ThreadError),
    #[error("cannot remember the thread's owner")]
    Owner(#[source] OwnerError),
    #[error("cannot remember the thread's host")]
    Host(#[source] io::Error),
    #[error("thread {0} was started in this repository, not joined; a ticket cannot claim it")]
    NotInvited(ThreadId),
    #[error("cannot ask for your passphrase")]
    Terminal(#[source] io::Error),
    #[error("cannot unlock your mahi key")]
    Unlock(#[source] IdentityError),
    #[error("cannot recover the thread key")]
    ThreadKey(#[source] MetaError),
    #[error("cannot prepare the live frames")]
    Frame(#[from] FrameError),
    #[error("cannot catch the signals that stop mahi")]
    Signals(#[source] SignalError),
    #[error(transparent)]
    Run(Box<RunError>),
    #[error("--allow-host, --pass-env and the other agent options need an agent after --")]
    OptionsNeedAgent,
    #[error("cannot run your agent in the thread")]
    Busy(#[source] LockError),
    #[error(
        "the thread lists another signing key for you than the one mahi init set up; ask the owner to invite your current card (mahi id)"
    )]
    KeyChanged,
}

/// What a viewer shows: the screen of one agent of the participant it follows, rebuilt in its
/// own `vt100` screen from the frames it accepted and drawn from there, as contents and cursor
/// only: no escape sequence the agent wrote, and none of its input modes, reach the viewer's
/// terminal.
pub(crate) struct View {
    follows: ParticipantName,
    slot: Option<AgentSlot>,
    screen: Option<vt100::Parser>,
    shown: Option<vt100::Screen>,
    changed: bool,
    pending: Option<Pending>,
}

struct Pending {
    slot: AgentSlot,
    challenge: [u8; 16],
    rows: u16,
    columns: u16,
    parts: Vec<Option<Vec<u8>>>,
    since: Instant,
}

impl View {
    /// Starts a view of the agents of `follows`.
    pub(crate) fn new(follows: ParticipantName) -> Self {
        Self {
            follows,
            slot: None,
            screen: None,
            shown: None,
            changed: false,
            pending: None,
        }
    }

    /// Says whether a screen is shown yet.
    pub(crate) fn is_showing(&self) -> bool {
        self.screen.is_some()
    }

    /// Says whether a screen has waited for its missing parts for longer than `wait`.
    pub(crate) fn is_stuck(&self, wait: Duration) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.since.elapsed() > wait)
    }

    /// Applies what `participant` sent to the viewer's screen.
    pub(crate) fn apply(&mut self, participant: &ParticipantName, body: Body) {
        if participant != &self.follows {
            return;
        }
        match body {
            Body::Screen {
                slot,
                rows,
                columns,
                challenge,
                part,
                parts,
                bytes,
            } => {
                if self.slot.as_ref().is_none_or(|followed| followed == &slot) {
                    self.take_part(slot, challenge, (rows, columns), (part, parts), bytes);
                }
            }
            Body::Output { slot, bytes } => {
                if let Some(screen) = self.followed_screen(&slot) {
                    screen.process(&bytes);
                    self.changed = true;
                }
            }
            Body::Resize {
                slot,
                rows,
                columns,
            } => {
                if let Some(screen) = self.followed_screen(&slot) {
                    screen.screen_mut().set_size(rows, columns);
                    self.shown = None;
                    self.changed = true;
                }
            }
            Body::ScreenRequest { .. } | Body::Heartbeat { .. } => {}
        }
    }

    /// Returns the participant whose agent the view follows.
    pub(crate) fn follows(&self) -> &ParticipantName {
        &self.follows
    }

    /// Returns what to write to the viewer's terminal to show the screen as it is now: all of
    /// it after a new screen or a resize, and otherwise what changed since the last call.
    pub(crate) fn render(&mut self) -> Option<Vec<u8>> {
        if !self.changed {
            return None;
        }
        self.changed = false;
        let screen = self.screen.as_ref()?.screen();
        let contents = match &self.shown {
            Some(shown) => screen.contents_diff(shown),
            None => [CLEAR, &screen.contents_formatted()].concat(),
        };
        let drawn = [
            contents,
            screen.cursor_state_formatted(),
            screen.attributes_formatted(),
        ]
        .concat();
        self.shown = Some(screen.clone());
        Some(drawn)
    }

    fn followed_screen(&mut self, slot: &AgentSlot) -> Option<&mut vt100::Parser> {
        if self.slot.as_ref() != Some(slot) {
            return None;
        }
        self.screen.as_mut()
    }

    fn take_part(
        &mut self,
        slot: AgentSlot,
        challenge: [u8; 16],
        (rows, columns): (u16, u16),
        (part, parts): (u16, u16),
        bytes: Vec<u8>,
    ) {
        let same = self.pending.as_ref().is_some_and(|pending| {
            pending.slot == slot
                && pending.challenge == challenge
                && (pending.rows, pending.columns) == (rows, columns)
                && pending.parts.len() == usize::from(parts)
        });
        if !same {
            self.pending = Some(Pending {
                slot,
                challenge,
                rows,
                columns,
                parts: vec![None; usize::from(parts)],
                since: Instant::now(),
            });
        }
        let Some(pending) = self.pending.as_mut() else {
            return;
        };
        let Some(place) = pending.parts.get_mut(usize::from(part)) else {
            return;
        };
        *place = Some(bytes);
        if pending.parts.iter().any(Option::is_none) {
            return;
        }
        let Some(pending) = self.pending.take() else {
            return;
        };
        let mut screen = vt100::Parser::new(pending.rows, pending.columns, 0);
        for bytes in pending.parts.into_iter().flatten() {
            screen.process(&bytes);
        }
        self.slot = Some(pending.slot);
        self.screen = Some(screen);
        self.shown = None;
        self.changed = true;
    }
}

/// Shows the viewer on the terminal's alternate screen, and on the way out, however it goes,
/// resets what the agent's screen may have set and returns to the main screen.
struct AlternateScreen;

impl AlternateScreen {
    fn enter() -> Self {
        let mut output = io::stdout().lock();
        let _ = output.write_all(ALTERNATE_SCREEN);
        let _ = output.flush();
        Self
    }
}

impl Drop for AlternateScreen {
    fn drop(&mut self) {
        let mut output = io::stdout().lock();
        let _ = output.write_all(RESET);
        let _ = output.write_all(MAIN_SCREEN);
        let _ = output.flush();
    }
}

/// The nodes a joiner deals with: the host from the ticket, then the participants its `meta`
/// lists. It serves no `meta`.
#[derive(Debug)]
struct JoinPeers(Mutex<HashSet<NodeId>>);

impl Peers for JoinPeers {
    fn admits(&self, node: &NodeId) -> bool {
        self.0.lock().is_ok_and(|admitted| admitted.contains(node))
    }

    fn meta_for(&self, _thread: ThreadId, _node: &NodeId) -> Option<Vec<u8>> {
        None
    }
}

/// Joins the thread `command`'s ticket invites to and shows its host's agent until the user
/// leaves with `q` or Ctrl-C, or mahi is stopped.
pub(crate) fn join(command: &JoinCommand, environment: &Environment) -> Result<Outcome, JoinError> {
    let relays = match environment.live {
        LiveMode::Public => Relays::Public,
        LiveMode::Local => Relays::Disabled,
        LiveMode::Off | LiveMode::Unknown => return Err(JoinError::LiveSetting),
    };
    let ticket = &command.ticket;
    if command.agent().is_none() && command.options != LaunchOptions::default() {
        return Err(JoinError::OptionsNeedAgent);
    }
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(JoinError::CurrentDirectory)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let node_key = NodeKey::load(&config.node_key_file()).map_err(JoinError::NotInitialised)?;
    let own = NodeId::from_bytes(node_key.public())
        .map_err(|_| JoinError::NotInitialised(IdentityError::Malformed))?;
    if ticket.invitee() != &own {
        return Err(JoinError::NotForThisNode(own));
    }
    let signer = match command.agent() {
        Some(_) => {
            let signing =
                SigningKey::load(&config.signing_key_file()).map_err(JoinError::NotInitialised)?;
            Some(
                run::agent_signer(environment, &signing)
                    .map_err(|error| JoinError::Run(Box::new(error)))?,
            )
        }
        None => None,
    };
    let store = Store::discover(&cwd)?;
    let peers = Arc::new(JoinPeers(Mutex::new(HashSet::from([*ticket
        .host()
        .node()]))));
    let node = LiveNode::bind_live(
        node_key.secret(),
        relays,
        Arc::clone(&peers) as Arc<dyn Peers>,
    )?;
    let joined = joined_meta(&node, ticket, &store, own);
    let meta = match joined {
        Ok(meta) => meta,
        Err(error) => {
            let _ = node.close();
            return Err(error);
        }
    };
    if let Some(signer) = signer {
        let _ = node.close();
        let lock = ThreadLock::acquire(&config, ticket.thread()).map_err(JoinError::Busy)?;
        let me = meta
            .participants()
            .find(|listed| listed.node() == &own)
            .map(|listed| listed.name().clone());
        let meta = match me {
            Some(me) => {
                let stopped = sync::fetch_until_stopped(
                    &store,
                    environment,
                    ticket.thread(),
                    ticket.owner(),
                    Some(&me),
                );
                if let Some(signal) = stopped {
                    return Ok(Outcome::Stopped(signal));
                }
                load_meta(&store, ticket.thread(), ticket.owner(), meta.generation())
                    .map_err(JoinError::Pin)?
            }
            None => meta,
        };
        let signing_key = ParticipantKey::from_public_key(signer.public_key())
            .map_err(|_| JoinError::KeyChanged)?;
        let (participant, key) = unlock(&meta, own, Some(&signing_key), &config)?;
        let joined = Joined {
            thread: ticket.thread(),
            base: meta.base(),
            key,
            participant,
            owner: ticket.owner().clone(),
            host: ticket.host().clone(),
            lock,
            commits: CommitKey::new(signer),
        };
        return run::join_run(command, environment, joined)
            .map_err(|error| JoinError::Run(Box::new(error)));
    }
    if let Ok(mut admitted) = peers.0.lock() {
        admitted.extend(meta.participants().map(|participant| *participant.node()));
    }
    let watched = watch(&node, ticket, &meta, &node_key, &config, own);
    let _ = node.close();
    watched.map(|()| Outcome::Exited(0))
}

/// Checks that this node's participant is listed with `signing_key`, when the user's agent will
/// sign, then asks for the passphrase and recovers the thread key wrapped for them.
fn unlock(
    meta: &VerifiedMeta,
    own: NodeId,
    signing_key: Option<&ParticipantKey>,
    config: &ConfigDir,
) -> Result<(ParticipantName, ThreadKey), JoinError> {
    let me = meta
        .participants()
        .find(|participant| participant.node() == &own)
        .ok_or(JoinError::NotListed)?;
    if signing_key.is_some_and(|key| me.key() != key) {
        return Err(JoinError::KeyChanged);
    }
    let passphrase = TerminalPrompt::open()
        .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
        .map_err(JoinError::Terminal)?;
    let identity =
        LocalIdentity::load(&config.identity_file(), &passphrase).map_err(JoinError::Unlock)?;
    drop(passphrase);
    let key = meta
        .thread_key(me.name(), identity.as_age())
        .map_err(JoinError::ThreadKey)?;
    Ok((me.name().clone(), key))
}

fn joined_meta(
    node: &LiveNode,
    ticket: &Ticket,
    store: &Store,
    own: NodeId,
) -> Result<VerifiedMeta, JoinError> {
    let thread = ticket.thread();
    let deadline = Instant::now() + META_WAIT;
    let mut told = false;
    let document = loop {
        match node.fetch_meta(ticket.host(), thread) {
            Ok(document) => break document,
            Err(error) if Instant::now() >= deadline => return Err(JoinError::NoMeta(error)),
            Err(_) => {
                if !told {
                    eprintln!("mahi: waiting for the thread's host");
                    told = true;
                }
                thread::sleep(RETRY_PAUSE);
            }
        }
    };
    let meta = VerifiedMeta::decode(&document, thread, ticket.owner()).map_err(JoinError::Meta)?;
    if meta.generation() < ticket.min_generation() {
        return Err(JoinError::Rollback);
    }
    let listed = |node: &NodeId| meta.participants().any(|listed| listed.node() == node);
    if !listed(&own) || !listed(ticket.host().node()) {
        return Err(JoinError::NotListed);
    }
    check_joinable(store, thread)?;
    record_meta(store, thread, &document, ticket.owner()).map_err(JoinError::Pin)?;
    remember_owner(store, thread, ticket.owner()).map_err(JoinError::Owner)?;
    live::remember_host(store, thread, ticket.host()).map_err(JoinError::Host)?;
    Ok(meta)
}

/// Refuses a thread this repository started: it has a `meta` ref but no remembered owner, so
/// a ticket naming its id must not replace its owner or pin another document.
fn check_joinable(store: &Store, thread: ThreadId) -> Result<(), JoinError> {
    let known_owner = remembered_owner(store, thread).map_err(JoinError::Owner)?;
    let meta_ref = ThreadRef::new(thread, RefKind::Meta);
    if known_owner.is_none() && store.head(&meta_ref)?.is_some() {
        return Err(JoinError::NotInvited(thread));
    }
    Ok(())
}

fn watch(
    node: &LiveNode,
    ticket: &Ticket,
    meta: &VerifiedMeta,
    node_key: &NodeKey,
    config: &ConfigDir,
    own: NodeId,
) -> Result<(), JoinError> {
    let thread = ticket.thread();
    let follows = meta
        .participants()
        .find(|participant| participant.node() == ticket.host().node())
        .ok_or(JoinError::NotListed)?
        .name()
        .clone();
    let (_, thread_key) = unlock(meta, own, None, config)?;
    let topic = node.join(
        LiveKeys::derive(&thread_key, thread)?.topic(),
        std::slice::from_ref(ticket.host()),
        Some(JOIN_WAIT),
    )?;
    let mut frames = FrameReceiver::new(
        LiveKeys::derive(&thread_key, thread)?,
        meta.participants()
            .map(|participant| (*participant.node(), participant.name().clone())),
    );
    let mut sender = FrameSender::new(LiveKeys::derive(&thread_key, thread)?, node_key.secret())?;
    drop(thread_key);
    eprintln!("mahi: watching {follows}'s agent; press q to leave");
    let leave = Arc::new(AtomicBool::new(false));
    let signals = TerminationSignals::listen().map_err(JoinError::Signals)?;
    {
        let leave = Arc::clone(&leave);
        thread::spawn(move || {
            if signals.wait().is_ok() {
                leave.store(true, Ordering::SeqCst);
            }
        });
    }
    let raw = RawMode::enable().map_err(JoinError::Terminal)?;
    let screen = AlternateScreen::enter();
    watch_leave_keys(&leave);
    let ended = show(&topic, &mut frames, &mut sender, View::new(follows), &leave);
    drop(screen);
    drop(raw);
    match ended {
        Ended::Left => {}
        Ended::Closed => eprintln!("mahi: the thread's live topic closed"),
        Ended::Silent => eprintln!(
            "mahi: no live frame from the host for {} s; it may have stopped",
            HOST_SILENCE.as_secs()
        ),
    }
    eprintln!("mahi: left thread {thread}");
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Left,
    Closed,
    Silent,
}

fn show(
    topic: &LiveTopic,
    frames: &mut FrameReceiver,
    sender: &mut FrameSender,
    mut view: View,
    leave: &AtomicBool,
) -> Ended {
    let mut asked_at: Option<Instant> = None;
    let mut dropped = topic.dropped();
    let mut unanchored = false;
    let mut heard_at = Instant::now();
    while !leave.load(Ordering::SeqCst) {
        let lost = topic.dropped() != dropped;
        dropped = topic.dropped();
        let wants_screen = !view.is_showing() || unanchored || lost || view.is_stuck(STUCK_SCREEN);
        if wants_screen && asked_at.is_none_or(|at| at.elapsed() >= ASK_EVERY) {
            if let Ok(frame) = frames
                .request_screen()
                .and_then(|request| sender.seal(&request))
            {
                let _ = topic.broadcast(frame);
            }
            asked_at = Some(Instant::now());
            unanchored = false;
        }
        let mut wait = RECEIVE_PAUSE;
        for _ in 0..DRAIN {
            let frame = match topic.receive(wait) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => return Ended::Closed,
            };
            wait = Duration::ZERO;
            match frames.open(&frame) {
                Ok(received) => {
                    if &received.participant == view.follows() {
                        heard_at = Instant::now();
                    }
                    view.apply(&received.participant, received.body);
                }
                Err(FrameError::Unanchored) => unanchored = true,
                Err(_) => {}
            }
        }
        if let Some(drawn) = view.render() {
            let mut output = io::stdout().lock();
            let _ = output.write_all(&drawn);
            let _ = output.flush();
        }
        if heard_at.elapsed() > HOST_SILENCE {
            return Ended::Silent;
        }
    }
    Ended::Left
}

fn watch_leave_keys(leave: &Arc<AtomicBool>) {
    let leave = Arc::clone(leave);
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        let mut byte = [0_u8; 1];
        while let Ok(read) = input.read(&mut byte) {
            if read == 0 || QUIT_KEYS.contains(&byte[0]) {
                leave.store(true, Ordering::SeqCst);
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use mahi_core::AgentName;

    use super::*;

    fn name(text: &str) -> ParticipantName {
        ParticipantName::new(text).unwrap()
    }

    fn slot(participant: &str, agent: &str) -> AgentSlot {
        AgentSlot::new(name(participant), AgentName::new(agent).unwrap())
    }

    fn screen_of(text: &[u8]) -> Vec<u8> {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(text);
        parser.screen().state_formatted()
    }

    fn part(slot: &AgentSlot, challenge: u8, part: u16, parts: u16, bytes: &[u8]) -> Body {
        Body::Screen {
            slot: slot.clone(),
            rows: 24,
            columns: 80,
            challenge: [challenge; 16],
            part,
            parts,
            bytes: bytes.to_vec(),
        }
    }

    fn output(slot: &AgentSlot, bytes: &[u8]) -> Body {
        Body::Output {
            slot: slot.clone(),
            bytes: bytes.to_vec(),
        }
    }

    fn shown(view: &View) -> String {
        view.screen.as_ref().unwrap().screen().contents()
    }

    #[test]
    fn a_screen_is_shown_once_all_its_parts_arrived_in_any_order() {
        let alice = name("alice");
        let claude = slot("alice", "claude");
        let screen = screen_of(b"hello from the host");
        let (first, second) = screen.split_at(screen.len() / 2);
        let mut view = View::new(alice.clone());
        view.apply(&alice, part(&claude, 1, 1, 2, second));
        assert!(!view.is_showing());
        assert!(view.render().is_none());
        view.apply(&alice, part(&claude, 1, 0, 2, first));
        assert!(view.is_showing());
        let drawn = view.render().unwrap();
        assert!(drawn.starts_with(CLEAR));
        assert!(String::from_utf8_lossy(&drawn).contains("hello from the host"));
        assert!(view.render().is_none());
        view.apply(&alice, part(&claude, 1, 5, 2, b""));
        assert!(shown(&view).contains("hello from the host"));
    }

    #[test]
    fn a_screen_missing_parts_is_stuck_and_a_newer_one_replaces_it() {
        let alice = name("alice");
        let claude = slot("alice", "claude");
        let mut view = View::new(alice.clone());
        view.apply(&alice, part(&claude, 1, 0, 2, b"half"));
        assert!(view.is_stuck(Duration::ZERO));
        assert!(!view.is_stuck(Duration::from_secs(60)));
        view.apply(&alice, part(&claude, 2, 0, 1, &screen_of(b"newer")));
        assert!(!view.is_stuck(Duration::ZERO));
        assert!(shown(&view).contains("newer"));
    }

    #[test]
    fn output_is_drawn_from_the_viewers_own_screen_without_the_agents_escapes_or_modes() {
        let alice = name("alice");
        let claude = slot("alice", "claude");
        let mut view = View::new(alice.clone());
        view.apply(&alice, output(&claude, b"too early"));
        assert!(view.render().is_none());
        view.apply(&alice, part(&claude, 2, 0, 1, &screen_of(b"")));
        view.render().unwrap();
        view.apply(
            &alice,
            output(
                &claude,
                b"visible\x1b]52;c;c2VjcmV0\x07\x1b]0;title\x07\x1b[?1000h\x1b[?1006h\x1b[?2004h\x1b[?1h",
            ),
        );
        let drawn = view.render().unwrap();
        let text = String::from_utf8_lossy(&drawn);
        assert!(text.contains("visible"));
        for sequence in ["]52", "]0;", "?1000h", "?1006h", "?2004h", "?1h"] {
            assert!(!text.contains(sequence), "{sequence}");
        }
        assert!(shown(&view).contains("visible"));
    }

    #[test]
    fn frames_of_other_participants_and_other_agents_are_ignored_and_resizes_redraw() {
        let alice = name("alice");
        let claude = slot("alice", "claude");
        let mut view = View::new(alice.clone());
        let mallory = name("mallory");
        view.apply(
            &mallory,
            part(&slot("mallory", "claude"), 3, 0, 1, &screen_of(b"x")),
        );
        assert!(!view.is_showing());
        view.apply(&alice, part(&claude, 3, 0, 1, &screen_of(b"mine")));
        view.render().unwrap();
        let other_agent = slot("alice", "codex");
        view.apply(&alice, part(&other_agent, 4, 0, 1, &screen_of(b"other")));
        view.apply(&alice, output(&other_agent, b"other"));
        assert!(view.render().is_none());
        assert!(shown(&view).contains("mine"));
        view.apply(
            &alice,
            Body::Resize {
                slot: claude,
                rows: 10,
                columns: 40,
            },
        );
        assert!(view.render().unwrap().starts_with(CLEAR));
        assert_eq!(view.screen.as_ref().unwrap().screen().size(), (10, 40));
    }

    #[test]
    fn a_thread_started_here_cannot_be_claimed_by_a_ticket() {
        use std::sync::atomic::AtomicBool;

        use mahi_identity::PublicIdentity;
        use mahi_store::GlobalPatterns;
        use ssh_key::{
            Algorithm,
            PrivateKey,
            rand_core::OsRng,
        };

        use crate::session::{
            self,
            CommitKey,
            NewThread,
            agent_from,
            tests::repository_on_main,
        };

        let (_repo, store) = repository_on_main();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let worktrees = tempfile::TempDir::new().unwrap();
        let started = session::start(
            &store,
            NewThread {
                public: &PublicIdentity::from(&LocalIdentity::generate()),
                node: NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap(),
                signer: &key,
                commits: &CommitKey::new(key.clone()),
                participant: name("alice"),
                agent: &agent_from(std::path::Path::new("claude")),
                worktrees: worktrees.path(),
            },
            &GlobalPatterns::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(matches!(
            check_joinable(&store, started.thread),
            Err(JoinError::NotInvited(thread)) if thread == started.thread
        ));
        let unknown = ThreadId::random().unwrap();
        check_joinable(&store, unknown).unwrap();
        let owner = mahi_thread::ParticipantKey::from_public_key(key.public_key()).unwrap();
        mahi_thread::remember_owner(&store, started.thread, &owner).unwrap();
        check_joinable(&store, started.thread).unwrap();
    }
}
