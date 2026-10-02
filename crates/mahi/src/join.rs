use std::{
    collections::HashSet,
    env,
    fs,
    io::{
        self,
        Read,
        Write,
    },
    path::Path,
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicBool,
            Ordering,
        },
        mpsc::{
            self,
            Receiver,
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
    PROMPT_ID_BYTES,
    Peers,
    PromptText,
    Relays,
    Ticket,
    prompt_id,
};
use mahi_sandbox::{
    SignalError,
    TerminationSignals,
    WindowChanges,
};
use mahi_store::{
    Store,
    StoreError,
};
use mahi_thread::{
    KeyError,
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
    compose::Composer,
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
    session::{
        self,
        CommitKey,
    },
    settings::{
        Settings,
        SettingsError,
    },
    sync,
    terminal::{
        self,
        RawMode,
    },
    thread_lock::{
        AgentLock,
        LockError,
    },
};

const META_WAIT: Duration = Duration::from_secs(30);
const RETRY_PAUSE: Duration = Duration::from_secs(1);
const JOIN_WAIT: Duration = Duration::from_secs(15);
const ASK_EVERY: Duration = Duration::from_secs(1);
const MOST_AGENTS: usize = 32;
const SWITCH_WAIT: Duration = Duration::from_secs(10);
const RECEIVE_PAUSE: Duration = Duration::from_millis(100);
const ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049h";
const MAIN_SCREEN: &[u8] = b"\x1b[?1049l";
const CLEAR: &[u8] = b"\x1b[H\x1b[2J";
const RESET: &[u8] =
    b"\x1b[0m\x1b[?25h\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?2004l\x1b[?1l\x1b>";
const STUCK_SCREEN: Duration = Duration::from_secs(3);
const DRAIN: usize = 256;
const HOST_SILENCE: Duration = Duration::from_secs(30);
const KEY_QUEUE: usize = 64;
const TYPING_PAUSE: Duration = Duration::from_millis(10);

#[derive(Debug, Error)]
pub(crate) enum JoinError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
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
    #[error("your signing key cannot sign commits")]
    SigningKey(#[source] KeyError),
}

/// What a viewer shows: the screen of one agent of the participant it follows, rebuilt in its
/// own `vt100` screen from the frames it accepted and drawn from there, as contents and cursor
/// only: no escape sequence the agent wrote, and none of its input modes, reach the viewer's
/// terminal.
pub(crate) struct View {
    follows: ParticipantName,
    agents: Vec<(AgentSlot, Instant)>,
    wanted: Option<(AgentSlot, Instant)>,
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
            agents: Vec::new(),
            wanted: None,
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
        match &body {
            Body::Screen { slot, .. }
            | Body::Output { slot, .. }
            | Body::Resize { slot, .. }
            | Body::Heartbeat { slot } => self.seen(slot),
            Body::ScreenRequest { .. } | Body::Prompt { .. } | Body::PromptAnswer { .. } => {}
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
                let followed = self
                    .wanted
                    .as_ref()
                    .map(|(wanted, _)| wanted)
                    .or(self.slot.as_ref());
                if followed.is_none_or(|followed| followed == &slot) {
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
            Body::ScreenRequest { .. }
            | Body::Heartbeat { .. }
            | Body::Prompt { .. }
            | Body::PromptAnswer { .. } => {}
        }
    }

    /// Returns the agents of the followed participant the view heard from, in name order.
    pub(crate) fn agents(&self) -> impl Iterator<Item = &AgentSlot> + Clone {
        self.agents.iter().map(|(slot, _)| slot)
    }

    /// Shows `slot`'s agent instead, once a screen of it arrives.
    pub(crate) fn switch_to(&mut self, slot: AgentSlot) {
        if self.slot.as_ref() == Some(&slot) {
            self.wanted = None;
            return;
        }
        self.pending = None;
        self.wanted = Some((slot, Instant::now()));
    }

    /// Says whether the view waits for the screen of an agent it was switched to.
    pub(crate) fn is_switching(&self) -> bool {
        self.wanted.is_some()
    }

    /// Forgets the agents not heard from for [`HOST_SILENCE`] at `now`, and gives up a switch
    /// whose screen did not arrive within [`SWITCH_WAIT`].
    pub(crate) fn expire(&mut self, now: Instant) {
        self.agents
            .retain(|(_, heard)| now.saturating_duration_since(*heard) <= HOST_SILENCE);
        if self
            .wanted
            .as_ref()
            .is_some_and(|(_, since)| now.saturating_duration_since(*since) > SWITCH_WAIT)
        {
            self.wanted = None;
        }
    }

    fn seen(&mut self, slot: &AgentSlot) {
        let now = Instant::now();
        match self.agents.binary_search_by(|(heard, _)| heard.cmp(slot)) {
            Ok(index) => {
                if let Some((_, heard)) = self.agents.get_mut(index) {
                    *heard = now;
                }
            }
            Err(index) if self.agents.len() < MOST_AGENTS => {
                self.agents.insert(index, (slot.clone(), now));
            }
            Err(_) => {}
        }
    }

    /// Returns the participant whose agent the view follows.
    pub(crate) fn follows(&self) -> &ParticipantName {
        &self.follows
    }

    /// Returns the agent the view shows, once a screen of it arrived.
    pub(crate) fn slot(&self) -> Option<&AgentSlot> {
        self.slot.as_ref()
    }

    /// Makes the next render draw the whole screen again, as after the palette closed.
    pub(crate) fn redraw_all(&mut self) {
        self.shown = None;
        self.changed = self.screen.is_some();
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
        self.wanted = None;
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
        let agent = command
            .agent()
            .map(|(program, _)| session::agent_from(Path::new(program)))
            .ok_or(JoinError::OptionsNeedAgent)?;
        let lock = AgentLock::acquire(&config, ticket.thread(), &agent).map_err(JoinError::Busy)?;
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
        let commits = CommitKey::new(signer).map_err(JoinError::SigningKey)?;
        let (participant, key) = unlock(&meta, own, Some(commits.key()), &config)?;
        let joined = Joined {
            thread: ticket.thread(),
            base: meta.base(),
            key,
            participant,
            owner: ticket.owner().clone(),
            host: ticket.host().clone(),
            lock,
            commits,
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
    let key = Settings::load(config)?.palette_key;
    eprintln!("mahi: watching {follows}'s agent; press q to leave, {key} to write it a prompt");
    let composer = Composer::new(key, follows.as_str());
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
    let keys = read_keys(&leave);
    let ended = show(
        (&topic, &mut frames, &mut sender),
        (View::new(follows), composer),
        (&keys, &leave),
    );
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
    (topic, frames, sender): (&LiveTopic, &mut FrameReceiver, &mut FrameSender),
    (mut view, mut composer): (View, Composer),
    (keys, leave): (&Receiver<Vec<u8>>, &AtomicBool),
) -> Ended {
    let mut asked_at: Option<Instant> = None;
    let mut dropped = topic.dropped();
    let mut unanchored = false;
    let mut heard_at = Instant::now();
    let mut showing_from: Option<NodeId> = None;
    let resized = watch_resizes();
    while !leave.load(Ordering::SeqCst) {
        let lost = topic.dropped() != dropped;
        dropped = topic.dropped();
        view.expire(Instant::now());
        let wants_screen = !view.is_showing()
            || view.is_switching()
            || unanchored
            || lost
            || view.is_stuck(STUCK_SCREEN);
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
        let mut palette_changed = false;
        if resized.swap(false, Ordering::SeqCst) {
            view.redraw_all();
            palette_changed = true;
        }
        let mut wait = if composer.is_open() {
            TYPING_PAUSE
        } else {
            RECEIVE_PAUSE
        };
        for _ in 0..DRAIN {
            let frame = match topic.receive(wait) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => return Ended::Closed,
            };
            wait = Duration::ZERO;
            match frames.open(&frame) {
                Ok(received) => {
                    if &received.participant != view.follows() {
                        continue;
                    }
                    heard_at = Instant::now();
                    match received.body {
                        Body::PromptAnswer { id, outcome, .. } => {
                            let from_host = showing_from == Some(received.sender);
                            palette_changed |= from_host && composer.answered(id, outcome);
                        }
                        body => {
                            let screen = matches!(body, Body::Screen { .. });
                            view.apply(&received.participant, body);
                            if screen && view.is_showing() {
                                showing_from = Some(received.sender);
                            }
                        }
                    }
                }
                Err(FrameError::Unanchored) => unanchored = true,
                Err(_) => {}
            }
        }
        while let Ok(chunk) = keys.try_recv() {
            let was_open = composer.is_open();
            let typed = composer.typed(&chunk);
            if typed.quit {
                return Ended::Left;
            }
            palette_changed |= typed.changed;
            if let Some(slot) = typed.switch {
                view.switch_to(slot);
                asked_at = None;
            }
            if let Some(text) = typed.send {
                let id = showing_from
                    .and_then(|host| send_prompt(&text, &view, frames, sender, (topic, host)));
                composer.sent(id, &text);
            }
            if was_open && !composer.is_open() {
                view.redraw_all();
            }
        }
        draw(&mut view, &mut composer, palette_changed);
        if heard_at.elapsed() > HOST_SILENCE {
            return Ended::Silent;
        }
    }
    Ended::Left
}

/// Draws what changed of the view, and the palette over it when it is open and either changed.
fn draw(view: &mut View, composer: &mut Composer, mut palette_changed: bool) {
    palette_changed |= composer.set_agents(view.agents(), view.slot());
    let drawn = view.render();
    let mut output = io::stdout().lock();
    if let Some(drawn) = &drawn {
        let _ = output.write_all(drawn);
    }
    if composer.is_open() && (drawn.is_some() || palette_changed) {
        let size = terminal::size();
        let _ = composer.draw(size.rows, size.cols, &mut output);
    }
    let _ = output.flush();
}

/// Sends `text` as a prompt to the agent the view shows, in the run of its host the viewer
/// follows, and returns its id; `None` when no screen of the agent arrived yet or it could not
/// be sent.
fn send_prompt(
    text: &str,
    view: &View,
    frames: &FrameReceiver,
    sender: &mut FrameSender,
    (topic, host): (&LiveTopic, NodeId),
) -> Option<[u8; PROMPT_ID_BYTES]> {
    let slot = view.slot()?.clone();
    let run = frames.run_of(&host)?;
    let text = PromptText::new(text.to_owned()).ok()?;
    let id = prompt_id().ok()?;
    let frame = sender
        .seal(&Body::Prompt {
            slot,
            run,
            id,
            text,
        })
        .ok()?;
    topic.broadcast(frame).ok()?;
    Some(id)
}

/// Notes when the viewer's terminal changes size, so the view and the palette are drawn again.
fn watch_resizes() -> Arc<AtomicBool> {
    let resized = Arc::new(AtomicBool::new(false));
    let noted = Arc::clone(&resized);
    thread::spawn(move || {
        let Ok(changes) = WindowChanges::listen() else {
            return;
        };
        while changes.wait().is_ok() {
            noted.store(true, Ordering::SeqCst);
        }
    });
    resized
}

/// Reads the viewer's keys on a thread of its own and passes them on; the end of the input
/// leaves the thread.
fn read_keys(leave: &Arc<AtomicBool>) -> Receiver<Vec<u8>> {
    let (keys, received) = mpsc::sync_channel(KEY_QUEUE);
    let leave = Arc::clone(leave);
    thread::spawn(move || {
        let mut input = io::stdin().lock();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match input.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => 0,
            };
            let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
                leave.store(true, Ordering::SeqCst);
                return;
            };
            if keys.send(chunk.to_vec()).is_err() {
                return;
            }
        }
    });
    received
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
    fn the_view_lists_the_agents_it_hears_from_and_switches_once_the_new_screen_arrives() {
        let alice = name("alice");
        let (claude, codex) = (slot("alice", "claude"), slot("alice", "codex"));
        let mut view = View::new(alice.clone());
        view.apply(&alice, part(&claude, 1, 0, 1, &screen_of(b"claude here")));
        view.apply(
            &alice,
            Body::Heartbeat {
                slot: codex.clone(),
            },
        );
        view.apply(
            &name("bob"),
            Body::Heartbeat {
                slot: slot("bob", "aider"),
            },
        );
        assert!(view.agents().eq([&claude, &codex]));
        assert_eq!(view.slot(), Some(&claude));
        view.switch_to(codex.clone());
        assert!(view.is_switching());
        view.apply(&alice, part(&claude, 2, 0, 1, &screen_of(b"claude again")));
        assert_eq!(view.slot(), Some(&claude));
        view.apply(&alice, output(&codex, b"ignored before its screen"));
        view.apply(&alice, part(&codex, 3, 0, 1, &screen_of(b"codex here")));
        assert!(!view.is_switching());
        assert_eq!(view.slot(), Some(&codex));
        view.apply(&alice, output(&claude, b" not shown"));
        view.apply(&alice, output(&codex, b" more"));
        let shown = view.screen.as_ref().unwrap().screen().contents();
        assert!(shown.contains("codex here more"), "{shown}");
        assert!(!shown.contains("not shown"), "{shown}");
        view.switch_to(codex.clone());
        assert!(!view.is_switching());
    }

    #[test]
    fn silent_agents_are_forgotten_and_a_switch_to_one_that_never_answers_is_given_up() {
        let alice = name("alice");
        let (claude, codex) = (slot("alice", "claude"), slot("alice", "codex"));
        let mut view = View::new(alice.clone());
        view.apply(&alice, part(&claude, 1, 0, 1, &screen_of(b"claude here")));
        view.apply(
            &alice,
            Body::Heartbeat {
                slot: codex.clone(),
            },
        );
        view.switch_to(codex.clone());
        let now = Instant::now();
        view.expire(now);
        assert!(view.is_switching());
        assert_eq!(view.agents().count(), 2);
        view.expire(now + SWITCH_WAIT + Duration::from_secs(1));
        assert!(!view.is_switching());
        assert_eq!(view.agents().count(), 2);
        view.apply(&alice, part(&claude, 2, 0, 1, &screen_of(b"claude again")));
        assert_eq!(view.slot(), Some(&claude));
        view.expire(now + HOST_SILENCE + Duration::from_secs(1));
        assert_eq!(view.agents().count(), 0);
    }

    #[test]
    fn at_most_32_agents_are_listed() {
        let alice = name("alice");
        let mut view = View::new(alice.clone());
        for index in 0..40 {
            view.apply(
                &alice,
                Body::Heartbeat {
                    slot: slot("alice", &format!("agent{index}")),
                },
            );
        }
        assert_eq!(view.agents().count(), MOST_AGENTS);
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
                commits: &CommitKey::new(key.clone()).unwrap(),
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
