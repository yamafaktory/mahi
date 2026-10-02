use std::{
    collections::HashMap,
    io,
    net::Shutdown,
    os::unix::net::{
        UnixListener,
        UnixStream,
    },
    path::{
        Path,
        PathBuf,
    },
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
            RecvTimeoutError,
            SyncSender,
        },
    },
    thread::{
        self,
        JoinHandle,
    },
    time::Duration,
};

use mahi_core::AgentSlot;
use mahi_live::{
    LiveKeys,
    LocalError,
    LocalMessage,
    MAX_CHUNK_BYTES,
    MAX_COLUMNS,
    MAX_ROWS,
    PromptOutcome,
};
use mahi_sandbox::WindowSize;

use crate::{
    claims::Claims,
    live::{
        Guest,
        HostError,
        HostHandle,
        HostTap,
        LiveHost,
        LiveSetup,
        Offer,
        hub_socket,
    },
    prompts::{
        Answer,
        Prompts,
    },
};

const PAUSE: Duration = Duration::from_millis(200);
const SUPERVISE_EVERY: Duration = Duration::from_secs(1);
const HELLO_WAIT: Duration = Duration::from_secs(5);
const GUEST_QUEUE: usize = 256;
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30);

/// Where the agent's terminal is copied for teammates: either the live layer this mahi hosts,
/// or the connection to the mahi of the user that does, with a copy of the screen this mahi
/// keeps to take over the hosting from. It never blocks.
#[derive(Clone)]
pub(crate) struct OutputTap {
    state: Arc<Mutex<TapState>>,
}

struct TapState {
    mirror: vt100::Parser,
    target: Target,
}

enum Target {
    Nobody,
    Host(HostTap),
    Guest(SyncSender<LocalMessage>, Arc<AtomicBool>),
}

impl std::fmt::Debug for OutputTap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputTap").finish_non_exhaustive()
    }
}

impl OutputTap {
    fn new(size: WindowSize) -> Self {
        let size = bounded(size);
        Self {
            state: Arc::new(Mutex::new(TapState {
                mirror: vt100::Parser::new(size.rows, size.cols, 0),
                target: Target::Nobody,
            })),
        }
    }

    /// Takes a chunk of the agent's output.
    pub(crate) fn output(&self, bytes: &[u8]) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let state = &mut *state;
        if let Target::Host(tap) = &state.target {
            tap.output(bytes);
            return;
        }
        state.mirror.process(bytes);
        match &state.target {
            Target::Nobody | Target::Host(_) => {}
            Target::Guest(queue, resync) => {
                for chunk in bytes.chunks(MAX_CHUNK_BYTES) {
                    if queue
                        .try_send(LocalMessage::Output(chunk.to_vec()))
                        .is_err()
                    {
                        resync.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
    }

    /// Takes a new size of the agent's terminal, which teammates see cut to the largest size
    /// a frame carries.
    pub(crate) fn resize(&self, size: WindowSize) {
        let size = bounded(size);
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.mirror.screen_mut().set_size(size.rows, size.cols);
        match &state.target {
            Target::Nobody => {}
            Target::Host(tap) => tap.resize(size),
            Target::Guest(queue, resync) => {
                let resize = LocalMessage::Resize {
                    rows: size.rows,
                    columns: size.cols,
                };
                if queue.try_send(resize).is_err() {
                    resync.store(true, Ordering::SeqCst);
                }
            }
        }
    }

    fn drawn(&self) -> (WindowSize, Vec<u8>) {
        self.state.lock().map_or_else(
            |_| (WindowSize { rows: 24, cols: 80 }, Vec::new()),
            |state| drawn_from(&state.mirror),
        )
    }

    fn point_at(&self, target: Target) {
        if let Ok(mut state) = self.state.lock() {
            state.target = target;
        }
    }

    /// Points the tap at the live layer this mahi now hosts, whose copy of the screen starts
    /// from the mirror, under the tap's lock, so no output is missed in between.
    fn attach(&self, host: HostTap) {
        if let Ok(mut state) = self.state.lock() {
            let (size, screen) = drawn_from(&state.mirror);
            host.reset(size, &screen);
            state.target = Target::Host(host);
        }
    }

    /// Sends the mirror as a whole screen to the host, dropping the output and resizes still
    /// queued, which it already holds; under the tap's lock, so none comes in between.
    fn resend_screen(
        &self,
        queued: &Receiver<LocalMessage>,
        writer: &mut UnixStream,
    ) -> Result<(), LocalError> {
        let Ok(state) = self.state.lock() else {
            return Ok(());
        };
        while queued.try_recv().is_ok() {}
        let (size, screen) = drawn_from(&state.mirror);
        drop(state);
        LocalMessage::Screen {
            rows: size.rows,
            columns: size.cols,
            screen,
        }
        .write_to(writer)
    }
}

fn bounded(size: WindowSize) -> WindowSize {
    WindowSize {
        rows: size.rows.clamp(1, MAX_ROWS),
        cols: size.cols.clamp(1, MAX_COLUMNS),
    }
}

fn drawn_from(mirror: &vt100::Parser) -> (WindowSize, Vec<u8>) {
    let (rows, cols) = mirror.screen().size();
    (WindowSize { rows, cols }, mirror.screen().state_formatted())
}

/// Serves the agents of the user's other mahis in the thread over a Unix socket in mahi's
/// private live directory, while this mahi hosts the live layer.
struct Hub {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<HashMap<u64, UnixStream>>>,
    acceptor: JoinHandle<()>,
}

impl Hub {
    fn start(path: PathBuf, handle: HostHandle) -> io::Result<Self> {
        match std::fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(HashMap::new()));
        let acceptor = {
            let (stop, connections) = (Arc::clone(&stop), Arc::clone(&connections));
            thread::spawn(move || accept(&listener, &handle, &stop, &connections))
        };
        Ok(Self {
            path,
            stop,
            connections,
            acceptor,
        })
    }

    fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.acceptor.join();
        let _ = std::fs::remove_file(&self.path);
        if let Ok(connections) = self.connections.lock() {
            for connection in connections.values() {
                let _ = connection.shutdown(Shutdown::Both);
            }
        }
    }
}

fn accept(
    listener: &UnixListener,
    handle: &HostHandle,
    stop: &AtomicBool,
    connections: &Arc<Mutex<HashMap<u64, UnixStream>>>,
) {
    let mut next: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        let Ok((stream, _)) = listener.accept() else {
            thread::sleep(PAUSE);
            continue;
        };
        let Ok(kept) = stream.try_clone() else {
            continue;
        };
        let id = next;
        next = next.wrapping_add(1);
        if let Ok(mut connections) = connections.lock() {
            connections.insert(id, kept);
        }
        let (handle, connections) = (handle.clone(), Arc::clone(connections));
        thread::spawn(move || {
            let _ = serve_guest(stream, &handle);
            if let Ok(mut connections) = connections.lock()
                && let Some(connection) = connections.remove(&id)
            {
                let _ = connection.shutdown(Shutdown::Both);
            }
        });
    }
}

fn serve_guest(mut stream: UnixStream, handle: &HostHandle) -> Result<(), LocalError> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(HELLO_WAIT))?;
    let LocalMessage::Hello {
        slot,
        rows,
        columns,
        screen,
    } = LocalMessage::read_from(&mut stream)?
    else {
        return Ok(());
    };
    stream.set_read_timeout(None)?;
    let size = WindowSize {
        rows,
        cols: columns,
    };
    let Ok(mut guest) = handle.serve(slot.clone(), size) else {
        return Ok(());
    };
    guest.tap.reset(size, &screen);
    LocalMessage::Welcome.write_to(&mut stream)?;
    let done = Arc::new(AtomicBool::new(false));
    let forwarder = match guest.take_offers() {
        Some(offers) => {
            let (mut writer, done) = (stream.try_clone()?, Arc::clone(&done));
            let (claims, me) = handle.claims();
            let (claims, me) = (Arc::clone(claims), me.clone());
            Some(thread::spawn(move || {
                forward_offers(&offers, &mut writer, &done, (&claims, &me));
                offers
            }))
        }
        None => None,
    };
    let claims = Arc::clone(handle.claims().0);
    let read = read_guest(&mut stream, &guest, (&claims, &slot));
    claims.forget_guest(&slot);
    done.store(true, Ordering::SeqCst);
    let _ = stream.shutdown(Shutdown::Both);
    if let Some(Ok(offers)) = forwarder.map(JoinHandle::join) {
        for Offer { id, .. } in offers.try_iter() {
            guest.answer(Answer {
                id,
                outcome: PromptOutcome::Dropped,
            });
        }
    }
    read
}

/// Passes the prompts for a guest's agent on to its mahi, and every claim the host knows
/// whenever they change.
fn forward_offers(
    offers: &Receiver<Offer>,
    writer: &mut UnixStream,
    done: &AtomicBool,
    (claims, me): (&Claims, &AgentSlot),
) {
    let mut told = None;
    while !done.load(Ordering::SeqCst) {
        let version = claims.version();
        if told != Some(version) {
            if LocalMessage::Claims(claims.known(me))
                .write_to(writer)
                .is_err()
            {
                return;
            }
            told = Some(version);
        }
        match offers.recv_timeout(PAUSE) {
            Ok(Offer { from, id, text }) => {
                if (LocalMessage::Offer { from, id, text })
                    .write_to(writer)
                    .is_err()
                {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn read_guest(
    stream: &mut UnixStream,
    guest: &Guest,
    (claims, slot): (&Claims, &AgentSlot),
) -> Result<(), LocalError> {
    loop {
        match LocalMessage::read_from(stream)? {
            LocalMessage::Output(bytes) => guest.tap.output(&bytes),
            LocalMessage::Resize { rows, columns } => guest.tap.resize(WindowSize {
                rows,
                cols: columns,
            }),
            LocalMessage::Screen {
                rows,
                columns,
                screen,
            } => guest.tap.reset(
                WindowSize {
                    rows,
                    cols: columns,
                },
                &screen,
            ),
            LocalMessage::Answer { id, outcome } => guest.answer(Answer { id, outcome }),
            LocalMessage::Claims(held) => claims.hear_guest(slot, held),
            LocalMessage::Hello { .. } | LocalMessage::Welcome | LocalMessage::Offer { .. } => {
                return Err(LocalError::Malformed);
            }
        }
    }
}

/// The connection of a mahi whose agent the host of the thread's live layer serves: its
/// output and resizes go out through the tap's queue, the prompts teammates send the agent
/// come in to `prompts`, and their answers go back.
struct GuestLink {
    stream: UnixStream,
    lost: Arc<AtomicBool>,
    closing: Arc<AtomicBool>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl GuestLink {
    fn connect(
        path: &Path,
        slot: &AgentSlot,
        tap: &OutputTap,
        (prompts, claims): (&Arc<Prompts>, &Arc<Claims>),
    ) -> Result<Self, LocalError> {
        let mut stream = UnixStream::connect(path)?;
        let (size, screen) = tap.drawn();
        LocalMessage::Hello {
            slot: slot.clone(),
            rows: size.rows,
            columns: size.cols,
            screen,
        }
        .write_to(&mut stream)?;
        stream.set_read_timeout(Some(HELLO_WAIT))?;
        let LocalMessage::Welcome = LocalMessage::read_from(&mut stream)? else {
            return Err(LocalError::Malformed);
        };
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(Some(HELLO_WAIT))?;
        let lost = Arc::new(AtomicBool::new(false));
        let closing = Arc::new(AtomicBool::new(false));
        let resync = Arc::new(AtomicBool::new(true));
        let (queue, queued) = mpsc::sync_channel(GUEST_QUEUE);
        tap.point_at(Target::Guest(queue, Arc::clone(&resync)));
        let reader = {
            let (mut stream, lost) = (stream.try_clone()?, Arc::clone(&lost));
            let (prompts, claims) = (Arc::clone(prompts), Arc::clone(claims));
            thread::spawn(move || {
                read_offers(&mut stream, &prompts, &claims);
                lost.store(true, Ordering::SeqCst);
            })
        };
        let writer = {
            let (mut stream, lost, closing) =
                (stream.try_clone()?, Arc::clone(&lost), Arc::clone(&closing));
            let (tap, prompts, claims) = (tap.clone(), Arc::clone(prompts), Arc::clone(claims));
            let slot = slot.clone();
            thread::spawn(move || {
                let ends = (&*lost, &*closing);
                let shared = (&*prompts, (&*claims, &slot));
                let _ = write_guest(&mut stream, &queued, (&tap, &resync), shared, ends);
                lost.store(true, Ordering::SeqCst);
            })
        };
        Ok(Self {
            stream,
            lost,
            closing,
            reader,
            writer,
        })
    }

    fn lost(&self) -> bool {
        self.lost.load(Ordering::SeqCst)
    }

    /// Closes the link once the answers already given are written.
    fn close(self) {
        self.closing.store(true, Ordering::SeqCst);
        let _ = self.writer.join();
        let _ = self.stream.shutdown(Shutdown::Both);
        let _ = self.reader.join();
    }
}

fn read_offers(stream: &mut UnixStream, prompts: &Prompts, claims: &Claims) {
    loop {
        match LocalMessage::read_from(stream) {
            Ok(LocalMessage::Offer { from, id, text }) => {
                prompts.offer(from, id, text);
            }
            Ok(LocalMessage::Claims(known)) => claims.hear_host(known),
            _ => return,
        }
    }
}

fn write_guest(
    stream: &mut UnixStream,
    queued: &Receiver<LocalMessage>,
    (tap, resync): (&OutputTap, &AtomicBool),
    (prompts, (claims, slot)): (&Prompts, (&Claims, &AgentSlot)),
    (lost, closing): (&AtomicBool, &AtomicBool),
) -> Result<(), LocalError> {
    let mut answers = Vec::new();
    let mut told = None;
    while !lost.load(Ordering::SeqCst) {
        let final_round = closing.load(Ordering::SeqCst);
        let version = claims.held_version();
        if told != Some(version) {
            LocalMessage::Claims(claims.held(slot)).write_to(stream)?;
            told = Some(version);
        }
        if resync.swap(false, Ordering::SeqCst) {
            tap.resend_screen(queued, stream)?;
        }
        prompts.take_answers(&mut answers);
        for Answer { id, outcome } in answers.drain(..) {
            LocalMessage::Answer { id, outcome }.write_to(stream)?;
        }
        if final_round {
            break;
        }
        match queued.recv_timeout(PAUSE) {
            Ok(message) => message.write_to(stream)?,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
    Ok(())
}

/// What this mahi is to the thread's live layer.
enum Role {
    Alone,
    Host(Box<LiveHost>, Option<Hub>),
    Guest(GuestLink),
}

/// This mahi's part in the thread's live layer: it hosts it, serving the user's other mahis
/// in the thread too, or hands its agent to the mahi that does, and takes over the hosting when
/// that one ends.
pub(crate) struct Link {
    tap: OutputTap,
    prompts: Arc<Prompts>,
    claims: Arc<Claims>,
    stop: Arc<AtomicBool>,
    supervisor: JoinHandle<Role>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

/// What a mahi needs to host the thread's live layer, or reach the mahi that does.
struct Joining {
    setup: LiveSetup,
    git_dir: PathBuf,
    slot: AgentSlot,
    keys: LiveKeys,
    socket: PathBuf,
}

impl Link {
    /// Joins the thread's live layer for `slot`'s agent: hosts it, or hands the agent to the
    /// mahi of the user that does, and reports which.
    pub(crate) fn start(
        setup: LiveSetup,
        git_dir: &Path,
        (slot, keys): (AgentSlot, LiveKeys),
        size: WindowSize,
    ) -> Result<Self, HostError> {
        let socket = hub_socket(&setup.runtime, keys.thread()).map_err(HostError::Hub)?;
        let joining = Joining {
            setup,
            git_dir: git_dir.to_path_buf(),
            slot,
            keys,
            socket,
        };
        let tap = OutputTap::new(size);
        let prompts = Arc::new(Prompts::default());
        let claims = Arc::new(Claims::default());
        let role = joining.settle(&tap, (&prompts, &claims))?;
        match &role {
            Role::Host(..) => {}
            Role::Guest(_) => eprintln!(
                "mahi: teammates watch {} through your other mahi in this thread",
                joining.slot.agent()
            ),
            Role::Alone => eprintln!(
                "mahi: teammates cannot watch {} yet: your other mahi in this thread does not answer",
                joining.slot.agent()
            ),
        }
        let stop = Arc::new(AtomicBool::new(false));
        let supervisor = {
            let (tap, stop) = (tap.clone(), Arc::clone(&stop));
            let (prompts, claims) = (Arc::clone(&prompts), Arc::clone(&claims));
            thread::spawn(move || joining.supervise(role, &tap, (&prompts, &claims), &stop))
        };
        Ok(Self {
            tap,
            prompts,
            claims,
            stop,
            supervisor,
        })
    }

    /// Returns where the agent's terminal is copied.
    pub(crate) fn tap(&self) -> OutputTap {
        self.tap.clone()
    }

    /// Returns the prompts teammates sent the agent.
    pub(crate) fn prompts(&self) -> Arc<Prompts> {
        Arc::clone(&self.prompts)
    }

    /// Returns the claims the agent holds and knows of others.
    pub(crate) fn claims(&self) -> Arc<Claims> {
        Arc::clone(&self.claims)
    }

    /// Leaves the live layer once the agent is gone: a host stops serving, so the next of the
    /// user's mahis takes over, and the prompts still waiting are dropped, their senders told.
    pub(crate) fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let role = self.supervisor.join().unwrap_or(Role::Alone);
        self.tap.point_at(Target::Nobody);
        self.prompts.close();
        match role {
            Role::Host(host, hub) => {
                if let Some(hub) = hub {
                    hub.stop();
                }
                host.stop();
            }
            Role::Guest(link) => link.close(),
            Role::Alone => {}
        }
    }
}

impl Joining {
    fn supervise(
        &self,
        mut role: Role,
        tap: &OutputTap,
        shared: (&Arc<Prompts>, &Arc<Claims>),
        stop: &AtomicBool,
    ) -> Role {
        let mut wait = SUPERVISE_EVERY;
        while !stop.load(Ordering::SeqCst) {
            let deadline = std::time::Instant::now() + wait;
            while !stop.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                thread::sleep(PAUSE);
            }
            if stop.load(Ordering::SeqCst) {
                break;
            }
            wait = SUPERVISE_EVERY;
            role = match role {
                Role::Guest(link) if link.lost() => {
                    tap.point_at(Target::Nobody);
                    link.close();
                    shared.1.host_lost();
                    self.settle(tap, shared).unwrap_or_else(|_| {
                        wait = RETRY_AFTER_FAILURE;
                        Role::Alone
                    })
                }
                Role::Alone => self.settle(tap, shared).unwrap_or_else(|_| {
                    wait = RETRY_AFTER_FAILURE;
                    Role::Alone
                }),
                Role::Host(host, None) => {
                    let hub = Hub::start(self.socket.clone(), host.handle()).ok();
                    Role::Host(host, hub)
                }
                kept => kept,
            };
        }
        role
    }

    /// Hosts the live layer, or else connects to the mahi that does; a failure to reach that
    /// one leaves this mahi alone, to try again, and any other failure is returned.
    fn settle(
        &self,
        tap: &OutputTap,
        (prompts, claims): (&Arc<Prompts>, &Arc<Claims>),
    ) -> Result<Role, HostError> {
        let (size, drawn) = tap.drawn();
        match LiveHost::start(
            &self.setup,
            &self.git_dir,
            (self.slot.clone(), &self.keys),
            (size, &drawn),
            (Arc::clone(prompts), Arc::clone(claims)),
        ) {
            Ok(host) => {
                claims.host_lost();
                tap.attach(host.tap());
                let hub = Hub::start(self.socket.clone(), host.handle()).ok();
                Ok(Role::Host(Box::new(host), hub))
            }
            Err(HostError::AnotherHost) => {
                Ok(
                    GuestLink::connect(&self.socket, &self.slot, tap, (prompts, claims))
                        .map_or(Role::Alone, Role::Guest),
                )
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use mahi_core::{
        AgentName,
        ParticipantName,
    };
    use mahi_live::{
        PromptOutcome,
        PromptText,
    };

    use super::*;
    use crate::prompts::Decision;

    fn slot(participant: &str, agent: &str) -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new(participant).unwrap(),
            AgentName::new(agent).unwrap(),
        )
    }

    fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < deadline, "{what}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn hub() -> (tempfile::TempDir, PathBuf, Hub, HostHandle) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("thread.sock");
        let (handle, _tapped) = HostHandle::for_tests(ParticipantName::new("alice").unwrap());
        let hub = Hub::start(path.clone(), handle.clone()).unwrap();
        (dir, path, hub, handle)
    }

    #[test]
    fn a_guests_screen_output_and_resizes_reach_the_host() {
        let (_dir, path, hub, handle) = hub();
        let codex = slot("alice", "codex");
        let tap = OutputTap::new(WindowSize { rows: 24, cols: 80 });
        tap.output(b"before ");
        let prompts = Arc::new(Prompts::default());
        let link = GuestLink::connect(
            &path,
            &codex,
            &tap,
            (&prompts, &Arc::new(Claims::default())),
        )
        .unwrap();
        eventually("hello", || {
            handle
                .screen_of(&codex)
                .is_some_and(|screen| screen.contains("before"))
        });
        tap.output(b"after");
        eventually("output", || {
            handle
                .screen_of(&codex)
                .is_some_and(|screen| screen.contains("before after"))
        });
        tap.resize(WindowSize { rows: 10, cols: 40 });
        tap.output(b"\r\nresized");
        eventually("resize", || {
            handle
                .screen_of(&codex)
                .is_some_and(|screen| screen.contains("resized"))
        });
        link.close();
        eventually("leaving", || handle.served() == 0);
        hub.stop();
        assert!(!path.exists());
    }

    #[test]
    fn a_terminal_too_large_or_empty_for_a_frame_keeps_the_guest_linked() {
        let (_dir, path, hub, handle) = hub();
        let codex = slot("alice", "codex");
        let tap = OutputTap::new(WindowSize {
            rows: 0,
            cols: 5000,
        });
        let prompts = Arc::new(Prompts::default());
        let link = GuestLink::connect(
            &path,
            &codex,
            &tap,
            (&prompts, &Arc::new(Claims::default())),
        )
        .unwrap();
        tap.resize(WindowSize {
            rows: 2000,
            cols: 0,
        });
        tap.output(b"still here");
        eventually("output", || {
            handle
                .screen_of(&codex)
                .is_some_and(|screen| screen.contains("still here"))
        });
        assert!(!link.lost());
        assert_eq!(
            tap.drawn().0,
            WindowSize {
                rows: MAX_ROWS,
                cols: 1
            }
        );
        link.close();
        hub.stop();
    }

    #[test]
    fn a_teammates_prompt_reaches_the_guests_queue_and_its_answer_comes_back() {
        let (_dir, path, hub, handle) = hub();
        let codex = slot("alice", "codex");
        let tap = OutputTap::new(WindowSize { rows: 24, cols: 80 });
        let prompts = Arc::new(Prompts::default());
        let link = GuestLink::connect(
            &path,
            &codex,
            &tap,
            (&prompts, &Arc::new(Claims::default())),
        )
        .unwrap();
        eventually("served", || handle.served() == 1);
        let id = [3; 16];
        handle.offer(
            &codex,
            ParticipantName::new("bob").unwrap(),
            id,
            PromptText::new("add a test".to_owned()).unwrap(),
        );
        eventually("offered", || prompts.text_of(id).is_some());
        assert_eq!(prompts.text_of(id).as_deref(), Some("add a test"));
        let mut answers = Vec::new();
        eventually("queued answer", || {
            answers.extend(handle.answers_of(&codex));
            answers
                .iter()
                .any(|answer| answer.outcome == PromptOutcome::Queued)
        });
        assert!(prompts.decide(id, Decision::Accept));
        eventually("accepted answer", || {
            answers.extend(handle.answers_of(&codex));
            answers
                .iter()
                .any(|answer| answer.outcome == PromptOutcome::Accepted)
        });
        link.close();
        hub.stop();
    }

    #[test]
    fn a_guest_that_ends_tells_the_host_its_waiting_prompts_were_dropped() {
        let (_dir, path, hub, handle) = hub();
        let codex = slot("alice", "codex");
        let tap = OutputTap::new(WindowSize { rows: 24, cols: 80 });
        let prompts = Arc::new(Prompts::default());
        let link = GuestLink::connect(
            &path,
            &codex,
            &tap,
            (&prompts, &Arc::new(Claims::default())),
        )
        .unwrap();
        eventually("served", || handle.served() == 1);
        let id = [5; 16];
        handle.offer(
            &codex,
            ParticipantName::new("bob").unwrap(),
            id,
            PromptText::new("wait for me".to_owned()).unwrap(),
        );
        eventually("offered", || prompts.text_of(id).is_some());
        prompts.close();
        link.close();
        eventually("left", || handle.served() == 0);
        let answers = handle.answers_of(&codex);
        assert!(
            answers
                .iter()
                .any(|answer| answer.id == id && answer.outcome == PromptOutcome::Dropped),
            "{answers:?}"
        );
        hub.stop();
    }

    #[test]
    fn another_participants_agent_or_one_already_served_is_refused() {
        let (_dir, path, hub, handle) = hub();
        let prompts = Arc::new(Prompts::default());
        let tap = OutputTap::new(WindowSize { rows: 24, cols: 80 });
        assert!(
            GuestLink::connect(
                &path,
                &slot("bob", "codex"),
                &tap,
                (&prompts, &Arc::new(Claims::default()))
            )
            .is_err()
        );
        let first = GuestLink::connect(
            &path,
            &slot("alice", "codex"),
            &tap,
            (&prompts, &Arc::new(Claims::default())),
        )
        .unwrap();
        let other = OutputTap::new(WindowSize { rows: 24, cols: 80 });
        assert!(
            GuestLink::connect(
                &path,
                &slot("alice", "codex"),
                &other,
                (&prompts, &Arc::new(Claims::default()))
            )
            .is_err()
        );
        assert_eq!(handle.served(), 1);
        first.close();
        hub.stop();
    }

    #[test]
    fn a_guest_notices_when_the_host_goes() {
        let (_dir, path, hub, _handle) = hub();
        let tap = OutputTap::new(WindowSize { rows: 24, cols: 80 });
        let prompts = Arc::new(Prompts::default());
        let link = GuestLink::connect(
            &path,
            &slot("alice", "codex"),
            &tap,
            (&prompts, &Arc::new(Claims::default())),
        )
        .unwrap();
        assert!(!link.lost());
        hub.stop();
        eventually("lost", || link.lost());
        link.close();
    }

    #[test]
    fn a_guests_claims_reach_the_host_and_the_hosts_list_reaches_the_guest() {
        let (_dir, path, hub, handle) = hub();
        let codex = slot("alice", "codex");
        let tap = OutputTap::new(WindowSize { rows: 24, cols: 80 });
        let prompts = Arc::new(Prompts::default());
        let guest_claims = Arc::new(Claims::default());
        let link = GuestLink::connect(&path, &codex, &tap, (&prompts, &guest_claims)).unwrap();
        let (host_claims, host) = handle.claims();
        let (host_claims, host) = (Arc::clone(host_claims), host.clone());
        guest_claims
            .claim(&codex, "docs", Some("rewriting"))
            .unwrap();
        eventually("the guest's claim at the host", || {
            host_claims
                .all(&host)
                .iter()
                .any(|claim| claim.slot == codex && claim.what == "docs")
        });
        host_claims.claim(&host, "src/parser.rs", None).unwrap();
        eventually("the host's claim at the guest", || {
            guest_claims
                .all(&codex)
                .iter()
                .any(|claim| claim.slot == host && claim.what == "src/parser.rs")
        });
        assert_eq!(
            guest_claims
                .all(&codex)
                .iter()
                .filter(|claim| claim.what == "docs")
                .count(),
            1
        );
        link.close();
        eventually("the guest's claims forgotten", || {
            !host_claims
                .all(&host)
                .iter()
                .any(|claim| claim.slot == codex)
        });
        hub.stop();
    }
}
