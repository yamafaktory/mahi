use std::{
    collections::{
        HashMap,
        VecDeque,
    },
    io,
    path::Path,
    sync::{
        Arc,
        Mutex,
        OnceLock,
        PoisonError,
        atomic::AtomicBool,
    },
    time::Duration,
};

use bytes::Bytes;
use mahi_core::ReadBudget;
use mahi_identity::{
    AgentError,
    SshAgent,
};
use ssh_key::{
    Algorithm,
    EcdsaCurve,
    HashAlg,
    PublicKey,
};
use thiserror::Error;
use tokio::{
    io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
    net::{
        TcpStream,
        tcp::{
            OwnedReadHalf,
            OwnedWriteHalf,
        },
    },
    runtime,
    sync::{
        mpsc,
        oneshot,
    },
    time::{
        Instant,
        MissedTickBehavior,
        interval_at,
    },
};

use crate::{
    exec::{
        Ending,
        Exec,
        printable,
        until_interrupted,
    },
    known_hosts::{
        HostKeyStatus,
        KnownHosts,
    },
    proto::{
        auth::{
            Auth,
            AuthError,
            Progress,
        },
        channel::{
            ChannelError,
            ChannelId,
            Connection,
            Event,
        },
        kex::HostKeyAlgorithm,
        message::Message,
        transport::{
            Poll,
            Transport,
        },
    },
    remote::SshRemote,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_EARLY_OUTPUT: usize = 64 << 10;
const MAX_ERROR_OUTPUT: usize = 4 << 10;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 4;
const REKEY_INTERVAL: Duration = Duration::from_secs(3600);
const READ_BUFFER: usize = 64 << 10;
const QUEUED_COMMANDS: usize = 64;
const BY_APPLICATION: u32 = 11;
const MAX_QUEUED_OUTPUT: usize = 512 << 10;
const SEND_PIECE: usize = 64 << 10;
const GOODBYE_TIMEOUT: Duration = Duration::from_secs(5);

/// An authenticated SSH connection to a git remote's host.
pub struct SshSession {
    commands: mpsc::Sender<Command>,
    failure: Arc<Mutex<Option<String>>>,
    budget: Arc<OnceLock<ReadBudget>>,
    exec_timeout: Duration,
    interrupt: Option<Arc<AtomicBool>>,
}

/// Why connecting to a remote, or running a command there, failed.
#[derive(Debug, Error)]
pub enum SshError {
    /// The host's key is not in `known_hosts`.
    #[error(
        "the {algorithm} host key of {host} ({fingerprint}) is not in known_hosts; check it and \
         add it, for example by connecting once with ssh"
    )]
    UnknownHostKey {
        /// The host, as `known_hosts` names it.
        host: String,
        /// The key's type.
        algorithm: String,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
    },
    /// The host presented a key other than the one `known_hosts` lists for it.
    #[error(
        "the {algorithm} host key of {host} changed to {fingerprint}, which may be an attack; \
         mahi does not connect"
    )]
    ChangedHostKey {
        /// The host, as `known_hosts` names it.
        host: String,
        /// The key's type.
        algorithm: String,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
    },
    /// The host presented a key marked `@revoked` in `known_hosts`.
    #[error("the host key of {host} ({fingerprint}) is revoked in known_hosts")]
    RevokedHostKey {
        /// The host, as `known_hosts` names it.
        host: String,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
    },
    /// `known_hosts` lists the host only with key types mahi does not support, such as `ssh-rsa`.
    #[error("known_hosts lists {0} only with key types mahi does not support, such as ssh-rsa")]
    UnsupportedHostKey(String),
    /// Reaching ssh-agent failed.
    #[error("cannot use ssh-agent")]
    Agent(#[source] AgentError),
    /// ssh-agent holds no key the host accepted.
    #[error("the host accepted none of the keys in ssh-agent for {user}@{host}")]
    NotAccepted {
        /// The user mahi logged in as.
        user: String,
        /// The host.
        host: String,
    },
    /// Connecting and logging in took too long.
    #[error("connecting to {0} timed out")]
    Timeout(String),
    /// The host refused to run the command.
    #[error("the host refused to run {0}")]
    ExecRefused(String),
    /// The host did not answer whether it runs the command in time.
    #[error("the host did not start {0} in time")]
    ExecTimeout(String),
    /// The host sent more than 64 KiB before saying it runs the command.
    #[error("the host sent too much before starting {0}")]
    EarlyOutput(String),
    /// Commands need a multi-thread runtime, since their output and input block on it.
    #[error("ssh commands need a multi-thread runtime")]
    CurrentThreadRuntime,
    /// The async runtime the connection runs on cannot start.
    #[error("cannot start the ssh runtime")]
    Runtime(#[source] std::io::Error),
    /// The caller asked to stop.
    #[error("interrupted")]
    Interrupted,
    /// Reaching the host, or reading from or writing to it, failed.
    #[error("the ssh connection failed")]
    Io(#[from] io::Error),
    /// The host broke the SSH protocol, or the connection ended.
    #[error("the ssh connection failed: {0}")]
    Protocol(String),
}

fn protocol(error: impl std::fmt::Display) -> SshError {
    SshError::Protocol(error.to_string())
}

impl std::fmt::Debug for SshSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SshSession").finish_non_exhaustive()
    }
}

pub(crate) enum Command {
    Exec {
        command: String,
        env: Vec<(String, String)>,
        reply: oneshot::Sender<Result<Started, SshError>>,
    },
    Write {
        id: ChannelId,
        data: Bytes,
        ack: oneshot::Sender<io::Result<()>>,
    },
    Eof {
        id: ChannelId,
        ack: oneshot::Sender<io::Result<()>>,
    },
    Consumed {
        id: ChannelId,
        count: usize,
    },
    Close {
        id: ChannelId,
    },
    Disconnect {
        ack: oneshot::Sender<()>,
    },
}

pub(crate) struct Started {
    pub(crate) id: ChannelId,
    pub(crate) output: mpsc::UnboundedReceiver<Bytes>,
    pub(crate) ending: Arc<Mutex<Ending>>,
}

impl SshSession {
    /// Connects to `remote`'s host, checks its key against `known_hosts`, and logs in as the
    /// remote's user, or else `default_user`, with the keys of the ssh-agent at `agent`. Once
    /// `interrupt` is set, connecting, and every command's reading and writing, stop within
    /// 100 ms.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] if the host cannot be reached, its key is not trusted, no key is
    /// accepted, this takes longer than 20 s, or `interrupt` is set.
    pub async fn connect(
        remote: &SshRemote,
        known_hosts: &KnownHosts,
        agent: &Path,
        default_user: &str,
        interrupt: Option<Arc<AtomicBool>>,
    ) -> Result<Self, SshError> {
        Self::connect_with(remote, known_hosts, agent, default_user, interrupt, TIMERS).await
    }

    async fn connect_with(
        remote: &SshRemote,
        known_hosts: &KnownHosts,
        agent: &Path,
        default_user: &str,
        interrupt: Option<Arc<AtomicBool>>,
        timers: Timers,
    ) -> Result<Self, SshError> {
        let user = remote.user().unwrap_or(default_user);
        let connecting = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            handshake(remote, known_hosts, agent, user),
        );
        let (wire, connection) = until_interrupted(interrupt.as_deref(), connecting)
            .await
            .ok_or(SshError::Interrupted)?
            .map_err(|_| SshError::Timeout(remote.host().to_owned()))??;
        let (commands, receiver) = mpsc::channel(QUEUED_COMMANDS);
        let failure = Arc::new(Mutex::new(None));
        let budget = Arc::new(OnceLock::new());
        tokio::spawn(
            Driver {
                wire,
                connection,
                slots: HashMap::new(),
                commands: receiver,
                failure: failure.clone(),
                budget: Arc::clone(&budget),
                ids: Vec::new(),
                payload: Vec::new(),
            }
            .run(timers),
        );
        Ok(Self {
            commands,
            failure,
            budget,
            exec_timeout: DEFAULT_EXEC_TIMEOUT,
            interrupt,
        })
    }

    /// Counts every byte the host sends from now on, whatever it carries, against `budget`,
    /// and ends the connection once it is spent; a budget set earlier stays.
    pub fn set_read_budget(&self, budget: ReadBudget) {
        let _ = self.budget.set(budget);
    }

    fn ended(&self) -> SshError {
        let failure = self.failure.lock().unwrap_or_else(PoisonError::into_inner);
        protocol(failure.as_deref().unwrap_or("the connection has ended"))
    }

    /// Sets how long [`SshSession::exec`] waits for the host to start a command; 20 s unless
    /// set.
    pub fn set_exec_timeout(&mut self, timeout: Duration) {
        self.exec_timeout = timeout;
    }

    /// Runs `command` on the host, asking it to set the environment variables `env` first; a
    /// host may ignore them.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] if the runtime is a current-thread one, the channel cannot be
    /// opened, the host refuses the command, or it does not start it within the exec timeout.
    pub async fn exec(&self, command: &str, env: &[(&str, &str)]) -> Result<Exec, SshError> {
        if runtime::Handle::current().runtime_flavor() == runtime::RuntimeFlavor::CurrentThread {
            return Err(SshError::CurrentThreadRuntime);
        }
        let (reply, started) = oneshot::channel();
        let request = Command::Exec {
            command: command.to_owned(),
            env: env
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            reply,
        };
        let starting = tokio::time::timeout(self.exec_timeout, async {
            self.commands
                .send(request)
                .await
                .map_err(|_| self.ended())?;
            started.await.map_err(|_| self.ended())?
        });
        let started = until_interrupted(self.interrupt.as_deref(), starting)
            .await
            .ok_or(SshError::Interrupted)?
            .map_err(|_| SshError::ExecTimeout(command.to_owned()))??;
        Ok(Exec::start(
            runtime::Handle::current(),
            started,
            self.commands.clone(),
            self.interrupt.clone(),
        ))
    }

    /// Closes the connection.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] if the connection has already ended.
    pub async fn close(self) -> Result<(), SshError> {
        let (ack, done) = oneshot::channel();
        self.commands
            .send(Command::Disconnect { ack })
            .await
            .map_err(|_| self.ended())?;
        done.await.map_err(|_| self.ended())
    }
}

struct Wire {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    transport: Transport,
    buffer: Box<[u8]>,
}

impl Wire {
    async fn flush(&mut self) -> Result<(), SshError> {
        let output = self.transport.output();
        if !output.is_empty() {
            self.writer.write_all(output).await?;
            let written = output.len();
            self.transport.advance_output(written);
        }
        Ok(())
    }

    async fn exchange(&mut self) -> Result<(), SshError> {
        self.flush().await?;
        let room = self.transport.room().min(self.buffer.len());
        let read = self.reader.read(&mut self.buffer[..room]).await?;
        if read == 0 {
            return Err(protocol("the host closed the connection"));
        }
        self.transport
            .receive(&self.buffer[..read])
            .map_err(protocol)
    }
}

async fn handshake(
    remote: &SshRemote,
    known_hosts: &KnownHosts,
    agent: &Path,
    user: &str,
) -> Result<(Wire, Connection), SshError> {
    let host = remote.host();
    let port = remote.port();
    let offered = offered_algorithms(&known_hosts.algorithms(host, port))
        .ok_or_else(|| SshError::UnsupportedHostKey(host_name(host, port)))?;
    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true)?;
    let (reader, writer) = stream.into_split();
    let mut wire = Wire {
        reader,
        writer,
        transport: Transport::new(&offered).map_err(protocol)?,
        buffer: vec![0; READ_BUFFER].into_boxed_slice(),
    };
    loop {
        match wire.transport.poll().map_err(protocol)? {
            Poll::HostKey => {
                let key = wire
                    .transport
                    .host_key()
                    .ok_or_else(|| protocol("no host key"))?;
                check_host_key(known_hosts, host, port, key)?;
                wire.transport.accept_host_key().map_err(protocol)?;
            }
            Poll::Message => return Err(protocol("a message came before the key exchange ended")),
            Poll::Pending if wire.transport.ready() => break,
            Poll::Pending => wire.exchange().await?,
        }
    }
    login(&mut wire, agent, user, host).await?;
    Ok((wire, Connection::default()))
}

async fn login(wire: &mut Wire, agent: &Path, user: &str, host: &str) -> Result<(), SshError> {
    let agent = SshAgent::new(agent);
    let listing = agent.clone();
    let keys = tokio::task::spawn_blocking(move || listing.login_keys())
        .await
        .map_err(protocol)?
        .map_err(SshError::Agent)?;
    let not_accepted = || SshError::NotAccepted {
        user: user.to_owned(),
        host: host.to_owned(),
    };
    let refused = |error: AuthError| match error {
        AuthError::NotAccepted | AuthError::MethodNotOffered => not_accepted(),
        other => protocol(other),
    };
    let mut auth = Auth::start(&mut wire.transport, user, keys).map_err(refused)?;
    loop {
        match wire.transport.poll().map_err(protocol)? {
            Poll::Message => {
                let payload = wire.transport.message().to_vec();
                match auth
                    .handle(&mut wire.transport, &payload)
                    .map_err(refused)?
                {
                    Progress::Sign(data) => {
                        let key = auth.key().cloned().ok_or_else(not_accepted)?;
                        let signer = agent.clone();
                        let signature =
                            tokio::task::spawn_blocking(move || signer.sign_blob(&key, &data))
                                .await
                                .map_err(protocol)?;
                        match signature {
                            Ok(signature) => auth.signed(&mut wire.transport, &signature),
                            Err(AgentError::Refused) => auth.sign_refused(&mut wire.transport),
                            Err(error) => return Err(SshError::Agent(error)),
                        }
                        .map_err(refused)?;
                    }
                    Progress::Authenticated => return Ok(()),
                    Progress::Continue => {}
                }
            }
            Poll::Pending => wire.exchange().await?,
            Poll::HostKey => return Err(protocol("a second host key")),
        }
    }
}

struct Slot {
    command: String,
    env: Vec<(String, String)>,
    start: Option<oneshot::Sender<Result<Started, SshError>>>,
    early: Vec<u8>,
    output: Option<mpsc::UnboundedSender<Bytes>>,
    receiver: Option<mpsc::UnboundedReceiver<Bytes>>,
    ending: Arc<Mutex<Ending>>,
    input: VecDeque<(Bytes, oneshot::Sender<io::Result<()>>)>,
    eof: Option<oneshot::Sender<io::Result<()>>>,
}

impl Slot {
    fn record(&self, update: impl FnOnce(&mut Ending)) {
        update(&mut self.ending.lock().unwrap_or_else(PoisonError::into_inner));
    }
}

struct Driver {
    wire: Wire,
    connection: Connection,
    slots: HashMap<ChannelId, Slot>,
    commands: mpsc::Receiver<Command>,
    failure: Arc<Mutex<Option<String>>>,
    budget: Arc<OnceLock<ReadBudget>>,
    ids: Vec<ChannelId>,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Timers {
    keepalive: Duration,
    rekey: Duration,
}

const TIMERS: Timers = Timers {
    keepalive: KEEPALIVE_INTERVAL,
    rekey: REKEY_INTERVAL,
};

enum Step {
    Read(io::Result<usize>),
    Wrote(io::Result<usize>),
    Command(Option<Command>),
    Keepalive,
    Rekey,
}

fn reason(error: impl std::fmt::Display) -> String {
    error.to_string()
}

impl Driver {
    async fn run(mut self, timers: Timers) {
        let mut keepalive = interval_at(Instant::now() + timers.keepalive, timers.keepalive);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut rekey = interval_at(Instant::now() + timers.rekey, timers.rekey);
        rekey.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let failure = loop {
            if let Err(failure) = self.process() {
                break failure;
            }
            let room = self.wire.transport.room().min(self.wire.buffer.len());
            let writing = !self.wire.transport.output().is_empty();
            let step = tokio::select! {
                read = self.wire.reader.read(&mut self.wire.buffer[..room]), if room > 0 => Step::Read(read),
                wrote = self.wire.writer.write(self.wire.transport.output()), if writing => Step::Wrote(wrote),
                command = self.commands.recv() => Step::Command(command),
                _ = keepalive.tick() => Step::Keepalive,
                _ = rekey.tick() => Step::Rekey,
            };
            let outcome = match step {
                Step::Read(Ok(0)) => Err("the host closed the connection".to_owned()),
                Step::Read(Err(error)) | Step::Wrote(Err(error)) => Err(reason(error)),
                Step::Read(Ok(read)) => match self.wire.buffer.get(..read) {
                    Some(bytes) => self
                        .budget
                        .get()
                        .map_or(Ok(()), |budget| budget.charge(read))
                        .map_err(reason)
                        .and_then(|()| self.wire.transport.receive(bytes).map_err(reason)),
                    None => Ok(()),
                },
                Step::Wrote(Ok(written)) => {
                    self.wire.transport.advance_output(written);
                    Ok(())
                }
                Step::Command(None) => return,
                Step::Command(Some(Command::Disconnect { ack })) => {
                    self.disconnect().await;
                    let _ = ack.send(());
                    return;
                }
                Step::Command(Some(command)) => self.command(command),
                Step::Keepalive => self.keepalive(),
                Step::Rekey => self.wire.transport.start_rekey().map_err(reason),
            };
            if let Err(failure) = outcome {
                break failure;
            }
        };
        *self.failure.lock().unwrap_or_else(PoisonError::into_inner) = Some(failure);
    }

    async fn disconnect(&mut self) {
        let mut goodbye = Vec::new();
        if (Message::Disconnect {
            reason: BY_APPLICATION,
            description: b"",
        })
        .encode(&mut goodbye)
        .is_ok()
        {
            let _ = self.wire.transport.send(&goodbye);
        }
        let writer = &mut self.wire.writer;
        let output = self.wire.transport.output();
        let _ = tokio::time::timeout(GOODBYE_TIMEOUT, async {
            let _ = writer.write_all(output).await;
            let _ = writer.shutdown().await;
        })
        .await;
    }

    fn keepalive(&mut self) -> Result<(), String> {
        if self.connection.unanswered_keepalives() >= KEEPALIVE_MAX {
            return Err("the host stopped answering keepalives".to_owned());
        }
        self.connection
            .keepalive(&mut self.wire.transport)
            .map(drop)
            .map_err(reason)
    }

    fn process(&mut self) -> Result<(), String> {
        loop {
            match self.wire.transport.poll().map_err(reason)? {
                Poll::Message => {
                    let mut payload = std::mem::take(&mut self.payload);
                    payload.clear();
                    payload.extend_from_slice(self.wire.transport.message());
                    let handled = self
                        .connection
                        .handle(&mut self.wire.transport, &payload)
                        .map_err(reason)
                        .and_then(|event| self.event(event).map_err(reason));
                    self.payload = payload;
                    handled?;
                }
                Poll::Pending => break,
                Poll::HostKey => return Err("the host presented a second host key".to_owned()),
            }
        }
        let mut ids = std::mem::take(&mut self.ids);
        ids.clear();
        ids.extend(self.slots.keys().copied());
        let pumped = ids.iter().try_for_each(|&id| self.pump(id));
        self.ids = ids;
        pumped
    }

    fn command(&mut self, command: Command) -> Result<(), String> {
        match command {
            Command::Exec {
                command,
                env,
                reply,
            } => match self.connection.open_session(&mut self.wire.transport) {
                Ok(id) => {
                    let (output, receiver) = mpsc::unbounded_channel();
                    self.slots.insert(
                        id,
                        Slot {
                            command,
                            env,
                            start: Some(reply),
                            early: Vec::new(),
                            output: Some(output),
                            receiver: Some(receiver),
                            ending: Arc::new(Mutex::new(Ending::default())),
                            input: VecDeque::new(),
                            eof: None,
                        },
                    );
                }
                Err(error) => {
                    let _ = reply.send(Err(protocol(error)));
                }
            },
            Command::Write { id, data, ack } => match self.slots.get_mut(&id) {
                Some(slot) => slot.input.push_back((data, ack)),
                None => {
                    let _ = ack.send(Err(io::ErrorKind::BrokenPipe.into()));
                }
            },
            Command::Eof { id, ack } => match self.slots.get_mut(&id) {
                Some(slot) => slot.eof = Some(ack),
                None => {
                    let _ = ack.send(Err(io::ErrorKind::BrokenPipe.into()));
                }
            },
            Command::Consumed { id, count } => {
                self.connection
                    .consumed(&mut self.wire.transport, id, count)
                    .map_err(reason)?;
            }
            Command::Close { id } => self.close(id)?,
            Command::Disconnect { .. } => {}
        }
        Ok(())
    }

    fn close(&mut self, id: ChannelId) -> Result<(), String> {
        match self.connection.close(&mut self.wire.transport, id) {
            Ok(()) | Err(ChannelError::UnknownChannel | ChannelError::Closed) => Ok(()),
            Err(error) => Err(reason(error)),
        }
    }

    fn pump(&mut self, id: ChannelId) -> Result<(), String> {
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        if slot.start.is_some() {
            return Ok(());
        }
        while let Some((data, _)) = slot.input.front_mut() {
            if self.wire.transport.output().len() >= MAX_QUEUED_OUTPUT {
                return Ok(());
            }
            let piece = data.get(..data.len().min(SEND_PIECE)).unwrap_or_default();
            match self
                .connection
                .send_data(&mut self.wire.transport, id, piece)
            {
                Ok(sent) => {
                    let whole = sent == piece.len();
                    let _ = data.split_to(sent);
                    if !whole {
                        return Ok(());
                    }
                }
                Err(ChannelError::Closed | ChannelError::UnknownChannel) => {
                    for (_, ack) in slot.input.drain(..) {
                        let _ = ack.send(Err(io::ErrorKind::BrokenPipe.into()));
                    }
                    if let Some(ack) = slot.eof.take() {
                        let _ = ack.send(Err(io::ErrorKind::BrokenPipe.into()));
                    }
                    return Ok(());
                }
                Err(error) => return Err(reason(error)),
            }
            if data.is_empty()
                && let Some((_, ack)) = slot.input.pop_front()
            {
                let _ = ack.send(Ok(()));
            }
        }
        if let Some(ack) = slot.eof.take() {
            match self.connection.send_eof(&mut self.wire.transport, id) {
                Ok(()) => {
                    let _ = ack.send(Ok(()));
                }
                Err(ChannelError::Closed | ChannelError::UnknownChannel) => {
                    let _ = ack.send(Err(io::ErrorKind::BrokenPipe.into()));
                }
                Err(error) => return Err(reason(error)),
            }
        }
        Ok(())
    }

    fn event(&mut self, event: Event<'_>) -> Result<(), ChannelError> {
        let transport = &mut self.wire.transport;
        match event {
            Event::Opened(id) => {
                if let Some(slot) = self.slots.get(&id) {
                    for (name, value) in &slot.env {
                        self.connection.set_env(transport, id, name, value)?;
                    }
                    self.connection.exec(transport, id, &slot.command)?;
                }
            }
            Event::OpenFailed(id) => {
                if let Some(mut slot) = self.slots.remove(&id)
                    && let Some(start) = slot.start.take()
                {
                    let _ = start.send(Err(SshError::ExecRefused(slot.command)));
                }
            }
            Event::Succeeded(id) => self.started(id)?,
            Event::Failed(id) => self.refused(id)?,
            Event::Data(id, data) => self.data(id, data)?,
            Event::Errors(id, data) => {
                if let Some(slot) = self.slots.get(&id) {
                    slot.record(|ending| {
                        let room = MAX_ERROR_OUTPUT.saturating_sub(ending.errors.len());
                        ending.errors.extend_from_slice(
                            data.get(..room.min(data.len())).unwrap_or_default(),
                        );
                    });
                }
                self.connection.consumed(transport, id, data.len())?;
            }
            Event::ExitStatus(id, status) => {
                if let Some(slot) = self.slots.get(&id) {
                    slot.record(|ending| ending.status = Some(status));
                }
            }
            Event::ExitSignal(id, signal, message) => {
                if let Some(slot) = self.slots.get(&id) {
                    let mut said = Vec::with_capacity(MAX_ERROR_OUTPUT);
                    said.extend_from_slice(signal);
                    said.push(b' ');
                    said.extend_from_slice(message);
                    said.truncate(MAX_ERROR_OUTPUT);
                    let said = printable(&said);
                    slot.record(|ending| ending.signal = Some(said));
                }
            }
            Event::Closed(id) => {
                if let Some(mut slot) = self.slots.remove(&id) {
                    slot.record(|ending| ending.closed = true);
                    if let Some(start) = slot.start.take() {
                        let _ = start.send(Err(SshError::ExecRefused(slot.command)));
                    }
                    for (_, ack) in slot.input.drain(..) {
                        let _ = ack.send(Err(io::ErrorKind::BrokenPipe.into()));
                    }
                }
            }
            Event::Eof(_) | Event::WindowOpened(_) | Event::KeepaliveAnswered | Event::Nothing => {}
        }
        Ok(())
    }

    fn started(&mut self, id: ChannelId) -> Result<(), ChannelError> {
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        let (Some(start), Some(output), Some(receiver)) = (
            slot.start.take(),
            slot.output.as_ref(),
            slot.receiver.take(),
        ) else {
            return Ok(());
        };
        if !slot.early.is_empty() {
            let _ = output.send(Bytes::from(std::mem::take(&mut slot.early)));
        }
        let started = Started {
            id,
            output: receiver,
            ending: slot.ending.clone(),
        };
        if start.send(Ok(started)).is_err() {
            slot.output = None;
            self.connection.close(&mut self.wire.transport, id)?;
        }
        Ok(())
    }

    fn refused(&mut self, id: ChannelId) -> Result<(), ChannelError> {
        if let Some(slot) = self.slots.get_mut(&id)
            && let Some(start) = slot.start.take()
        {
            let _ = start.send(Err(SshError::ExecRefused(slot.command.clone())));
            self.connection.close(&mut self.wire.transport, id)?;
        }
        Ok(())
    }

    fn data(&mut self, id: ChannelId, data: &[u8]) -> Result<(), ChannelError> {
        let Some(slot) = self.slots.get_mut(&id) else {
            return Ok(());
        };
        if slot.start.is_some() {
            if slot.early.len() + data.len() > MAX_EARLY_OUTPUT {
                if let Some(start) = slot.start.take() {
                    let _ = start.send(Err(SshError::EarlyOutput(slot.command.clone())));
                }
                return self.connection.close(&mut self.wire.transport, id);
            }
            slot.early.extend_from_slice(data);
            return Ok(());
        }
        let delivered = slot
            .output
            .as_ref()
            .is_some_and(|output| output.send(Bytes::copy_from_slice(data)).is_ok());
        if !delivered {
            slot.output = None;
            match self.connection.close(&mut self.wire.transport, id) {
                Ok(()) | Err(ChannelError::Closed) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn check_host_key(
    known_hosts: &KnownHosts,
    host: &str,
    port: u16,
    key: &PublicKey,
) -> Result<(), SshError> {
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    let algorithm = key.algorithm().to_string();
    match known_hosts.check(host, port, key) {
        HostKeyStatus::Known => Ok(()),
        HostKeyStatus::Unknown => Err(SshError::UnknownHostKey {
            host: host_name(host, port),
            algorithm,
            fingerprint,
        }),
        HostKeyStatus::Changed => Err(SshError::ChangedHostKey {
            host: host_name(host, port),
            algorithm,
            fingerprint,
        }),
        HostKeyStatus::Revoked => Err(SshError::RevokedHostKey {
            host: host_name(host, port),
            fingerprint,
        }),
    }
}

fn host_key_algorithm(algorithm: &Algorithm) -> Option<HostKeyAlgorithm> {
    match algorithm {
        Algorithm::Ed25519 => Some(HostKeyAlgorithm::Ed25519),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => Some(HostKeyAlgorithm::EcdsaP256),
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        } => Some(HostKeyAlgorithm::EcdsaP384),
        _ => None,
    }
}

fn offered_algorithms(known: &[Algorithm]) -> Option<Vec<HostKeyAlgorithm>> {
    if known.is_empty() {
        return Some(HostKeyAlgorithm::ALL.to_vec());
    }
    let offered: Vec<HostKeyAlgorithm> = HostKeyAlgorithm::ALL
        .into_iter()
        .filter(|algorithm| {
            known
                .iter()
                .filter_map(host_key_algorithm)
                .any(|listed| listed == *algorithm)
        })
        .collect();
    (!offered.is_empty()).then_some(offered)
}

fn host_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{
            ErrorKind,
            Read as _,
            Write as _,
        },
        net::SocketAddr,
        os::unix::net::UnixListener,
        path::PathBuf,
        sync::atomic::{
            AtomicUsize,
            Ordering,
        },
    };

    use signature::Verifier as _;
    use ssh_key::{
        PrivateKey,
        Signature,
        rand_core::OsRng,
    };
    use tokio::{
        net::TcpListener,
        runtime::Runtime,
    };

    use super::*;
    use crate::{
        RemoteFailure,
        exec::Interrupted,
        proto::{
            message::AuthMethod,
            test_server::{
                TestServer,
                host_key,
            },
            wire::{
                NameList,
                put_string,
                put_u32,
            },
        },
    };

    const RSA_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCon5LKy0wKilz4XciwFziIQp1K5se6f/fSH7d9re1rFspyRZiiUwgo51S35FCUUwaDULJEiBTb6VDNULuiPeYtAIBmRWyMvvQTchT2UNTSVYj5vOkuMpu/eBtkuzI6EtnVbqwhXeEAjIHn+dHpJNGB6o3d2uHolL+L48qCD4YQhQ==";

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut framed = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(body);
        framed
    }

    fn fake_agent(path: &Path, key: PrivateKey) {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let key = key.clone();
                std::thread::spawn(move || {
                    loop {
                        let mut length = [0; 4];
                        if stream.read_exact(&mut length).is_err() {
                            return;
                        }
                        let mut request = vec![0; u32::from_be_bytes(length) as usize];
                        stream.read_exact(&mut request).unwrap();
                        let mut answer = Vec::new();
                        if request[0] == 11 {
                            answer.push(12);
                            put_u32(&mut answer, 1);
                            put_string(&mut answer, &key.public_key().to_bytes().unwrap()).unwrap();
                            put_string(&mut answer, b"test").unwrap();
                        } else {
                            let mut reader = crate::proto::wire::Reader::new(&request[1..]);
                            reader.string().unwrap();
                            let data = reader.string().unwrap();
                            let signature: Signature =
                                signature::Signer::try_sign(key.key_data(), data).unwrap();
                            answer.push(14);
                            put_string(&mut answer, &Vec::try_from(signature).unwrap()).unwrap();
                        }
                        stream.write_all(&frame(&answer)).unwrap();
                    }
                });
            }
        });
    }

    struct Script {
        accepted: PublicKey,
        logins: Arc<AtomicUsize>,
        kexinits: Arc<AtomicUsize>,
        keepalives: bool,
    }

    #[derive(Default)]
    struct Echo {
        window: u32,
        pending: Vec<u8>,
        eof: bool,
        count: Option<usize>,
    }

    impl Echo {
        fn flush(&mut self, server: &mut TestServer, channel: u32) {
            while !self.pending.is_empty() && self.window > 0 {
                let length = self.pending.len().min(self.window as usize).min(32 << 10);
                let piece: Vec<u8> = self.pending.drain(..length).collect();
                self.window -= u32::try_from(length).unwrap();
                server.send_message(Message::ChannelData {
                    recipient: channel,
                    data: &piece,
                });
            }
            if self.eof && self.pending.is_empty() {
                self.eof = false;
                if let Some(count) = self.count.take() {
                    let said = format!("{count}\n");
                    server.send_message(Message::ChannelData {
                        recipient: channel,
                        data: said.as_bytes(),
                    });
                }
                let mut data = Vec::new();
                put_u32(&mut data, 0);
                server.send_message(Message::ChannelRequest {
                    recipient: channel,
                    kind: b"exit-status",
                    want_reply: false,
                    data: &data,
                });
                server.send_message(Message::ChannelEof { recipient: channel });
                server.send_message(Message::ChannelClose { recipient: channel });
            }
        }
    }

    impl Script {
        fn exec(server: &mut TestServer, channel: u32, command: &[u8]) -> bool {
            let success = Message::ChannelSuccess { recipient: channel };
            let finish = |server: &mut TestServer, status: Option<u32>| {
                if let Some(status) = status {
                    let mut data = Vec::new();
                    put_u32(&mut data, status);
                    server.send_message(Message::ChannelRequest {
                        recipient: channel,
                        kind: b"exit-status",
                        want_reply: false,
                        data: &data,
                    });
                }
                server.send_message(Message::ChannelEof { recipient: channel });
                server.send_message(Message::ChannelClose { recipient: channel });
            };
            if command.starts_with(b"git-upload-pack ") {
                server.send_message(success);
                let said = [b"ran ", command, b"\n"].concat();
                server.send_message(Message::ChannelData {
                    recipient: channel,
                    data: &said,
                });
            } else if command.starts_with(b"git-receive-pack ") {
                server.send_message(Message::ChannelData {
                    recipient: channel,
                    data: b"early\n",
                });
                server.send_message(success);
            } else if command == b"echo" || command == b"count" {
                server.send_message(success);
            } else if command == b"flood" {
                let flood = vec![b'x'; 30 << 10];
                for _ in 0..3 {
                    server.send_message(Message::ChannelData {
                        recipient: channel,
                        data: &flood,
                    });
                }
                server.send_message(success);
            } else if command == b"noise" {
                server.send_message(success);
                let noise = vec![b'n'; 32 << 10];
                for _ in 0..64 {
                    server.send_message(Message::Ignore(&noise));
                }
                server.send_message(Message::ChannelExtendedData {
                    recipient: channel,
                    code: 1,
                    data: &noise,
                });
                return true;
            } else if command == b"eof-cut" {
                server.send_message(success);
                server.send_message(Message::ChannelData {
                    recipient: channel,
                    data: b"partial",
                });
                server.send_message(Message::ChannelEof { recipient: channel });
                return true;
            } else if command == b"hang" {
            } else if command == b"fail" {
                server.send_message(success);
                server.send_message(Message::ChannelExtendedData {
                    recipient: channel,
                    code: 1,
                    data: b"fatal: no such\x1b[2J repository\n",
                });
                finish(server, Some(128));
            } else if command == b"signal" {
                server.send_message(success);
                let mut data = Vec::new();
                put_string(&mut data, b"KILL").unwrap();
                data.push(0);
                put_string(&mut data, "out of \u{202e}memory".as_bytes()).unwrap();
                put_string(&mut data, b"").unwrap();
                server.send_message(Message::ChannelRequest {
                    recipient: channel,
                    kind: b"exit-signal",
                    want_reply: false,
                    data: &data,
                });
                finish(server, None);
            } else if command == b"cut" {
                server.send_message(success);
                server.send_message(Message::ChannelData {
                    recipient: channel,
                    data: b"partial",
                });
                return true;
            } else if command == b"exit 3" {
                server.send_message(success);
                finish(server, Some(3));
            } else {
                server.send_message(Message::ChannelFailure { recipient: channel });
            }
            false
        }

        fn answer(&self, server: &mut TestServer, payload: &[u8], echo: &mut Echo) -> bool {
            match Message::decode(payload).unwrap() {
                Message::ServiceRequest(b"ssh-userauth") => {
                    server.send_message(Message::ServiceAccept(b"ssh-userauth"));
                }
                Message::UserauthRequest {
                    user,
                    method:
                        AuthMethod::PublicKey {
                            algorithm,
                            key,
                            signature,
                        },
                    ..
                } => {
                    self.logins.fetch_add(1, Ordering::SeqCst);
                    let presented = PublicKey::from_bytes(key).unwrap();
                    let accepted =
                        user == b"git" && presented.key_data() == self.accepted.key_data();
                    match (accepted, signature) {
                        (false, _) => server.send_message(Message::UserauthFailure {
                            methods: NameList::parse(b"publickey").unwrap(),
                            partial: false,
                        }),
                        (true, None) => {
                            server.send_message(Message::UserauthPkOk { algorithm, key });
                        }
                        (true, Some(signature)) => {
                            let mut data = Vec::new();
                            put_string(&mut data, server.session_id().unwrap()).unwrap();
                            data.push(50);
                            for field in [&b"git"[..], b"ssh-connection", b"publickey"] {
                                put_string(&mut data, field).unwrap();
                            }
                            data.push(1);
                            put_string(&mut data, algorithm).unwrap();
                            put_string(&mut data, key).unwrap();
                            let signature = Signature::try_from(signature).unwrap();
                            presented.key_data().verify(&data, &signature).unwrap();
                            server.send_message(Message::UserauthSuccess);
                        }
                    }
                }
                Message::ChannelOpen { sender, window, .. } => {
                    echo.window = window;
                    server.send_message(Message::ChannelOpenConfirmation {
                        recipient: sender,
                        sender,
                        window: 1 << 20,
                        max_packet: 32 << 10,
                        data: b"",
                    });
                }
                Message::ChannelRequest {
                    recipient,
                    kind: b"exec",
                    data,
                    ..
                } => {
                    if &data[4..] == b"count" {
                        echo.count = Some(0);
                    }
                    return Self::exec(server, recipient, &data[4..]);
                }
                Message::ChannelData { recipient, data } => {
                    match &mut echo.count {
                        Some(count) => *count += data.len(),
                        None => echo.pending.extend_from_slice(data),
                    }
                    server.send_message(Message::ChannelWindowAdjust {
                        recipient,
                        bytes: u32::try_from(data.len()).unwrap(),
                    });
                    echo.flush(server, recipient);
                }
                Message::ChannelWindowAdjust { recipient, bytes } => {
                    echo.window += bytes;
                    echo.flush(server, recipient);
                }
                Message::ChannelEof { recipient } => {
                    echo.eof = true;
                    echo.flush(server, recipient);
                }
                Message::GlobalRequest {
                    want_reply: true, ..
                } if self.keepalives => {
                    server.send_message(Message::RequestFailure);
                }
                _ => {}
            }
            false
        }
    }

    async fn serve(socket: TcpStream, host: PrivateKey, script: Arc<Script>) {
        let (mut reader, mut writer) = socket.into_split();
        let mut server = TestServer::new(host);
        let mut buffer = vec![0; 64 << 10];
        let mut echo = Echo::default();
        loop {
            let mut cut = false;
            for payload in std::mem::take(&mut server.received) {
                cut |= script.answer(&mut server, &payload, &mut echo);
            }
            script.kexinits.store(server.kexinits, Ordering::SeqCst);
            let output = server.take_output();
            if writer.write_all(&output).await.is_err() || cut {
                return;
            }
            match reader.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => server.receive(&buffer[..read]),
            }
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        runtime: Runtime,
        address: SocketAddr,
        host_key: PublicKey,
        agent: PathBuf,
        logins: Arc<AtomicUsize>,
        kexinits: Arc<AtomicUsize>,
    }

    fn fixture(accepted: &PublicKey, in_agent: PrivateKey) -> Fixture {
        fixture_with(accepted, in_agent, true)
    }

    fn fixture_with(accepted: &PublicKey, in_agent: PrivateKey, keepalives: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let host = host_key(HostKeyAlgorithm::Ed25519);
        let host_key = host.public_key().clone();
        let agent = dir.path().join("agent.sock");
        fake_agent(&agent, in_agent);
        let logins = Arc::new(AtomicUsize::new(0));
        let kexinits = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(Script {
            accepted: accepted.clone(),
            logins: logins.clone(),
            kexinits: kexinits.clone(),
            keepalives,
        });
        let address = runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    tokio::spawn(serve(socket, host.clone(), script.clone()));
                }
            });
            address
        });
        Fixture {
            _dir: dir,
            runtime,
            address,
            host_key,
            agent,
            logins,
            kexinits,
        }
    }

    impl Fixture {
        fn remote(&self) -> SshRemote {
            SshRemote::parse(&format!("ssh://git@127.0.0.1:{}/repo", self.address.port())).unwrap()
        }

        fn known_hosts(&self, key: &PublicKey) -> KnownHosts {
            KnownHosts::parse(&format!(
                "[127.0.0.1]:{} {}\n",
                self.address.port(),
                key.to_openssh().unwrap()
            ))
        }

        fn exec(&self, session: &SshSession, command: &str) -> Result<Exec, SshError> {
            self.runtime.block_on(session.exec(command, &[]))
        }

        fn connect(&self, known_hosts: &KnownHosts, agent: &Path) -> Result<SshSession, SshError> {
            self.runtime.block_on(SshSession::connect(
                &self.remote(),
                known_hosts,
                agent,
                "nobody",
                None,
            ))
        }

        fn session(&self) -> SshSession {
            self.connect(&self.known_hosts(&self.host_key), &self.agent)
                .unwrap()
        }

        fn session_with(&self, timers: Timers) -> SshSession {
            self.runtime
                .block_on(SshSession::connect_with(
                    &self.remote(),
                    &self.known_hosts(&self.host_key),
                    &self.agent,
                    "nobody",
                    None,
                    timers,
                ))
                .unwrap()
        }
    }

    fn user() -> (PrivateKey, PublicKey) {
        let key = ed25519();
        let public = key.public_key().clone();
        (key, public)
    }

    #[test]
    fn a_command_runs_on_a_known_host_logged_in_with_an_agent_key() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session();
        let command = fixture.remote().command(crate::GitService::UploadPack);
        let (mut output, mut input) = fixture.exec(&session, &command).unwrap().split();
        input.write_all(b"want\n").unwrap();
        input.finish().unwrap();
        let mut said = String::new();
        output.read_to_string(&mut said).unwrap();
        assert_eq!(said, "ran git-upload-pack '/repo'\nwant\n");
        let refused = fixture.exec(&session, "rm -rf /");
        assert!(matches!(refused, Err(SshError::ExecRefused(command)) if command == "rm -rf /"));
        fixture.runtime.block_on(session.close()).unwrap();
    }

    #[test]
    fn megabytes_flow_both_ways_through_the_windows() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session();
        let (mut output, mut input) = fixture.exec(&session, "echo").unwrap().split();
        let sent: Vec<u8> = (0..6_000_000u32).map(|i| (i % 251) as u8).collect();
        let writer = {
            let sent = sent.clone();
            std::thread::spawn(move || {
                for piece in sent.chunks(100_000) {
                    input.write_all(piece).unwrap();
                }
                input.finish().unwrap();
            })
        };
        let mut received = Vec::new();
        output.read_to_end(&mut received).unwrap();
        writer.join().unwrap();
        assert_eq!(received.len(), sent.len());
        assert!(received.iter().eq(&sent));
    }

    #[test]
    fn a_large_upload_flows_without_stalling() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session();
        let (mut output, mut input) = fixture.exec(&session, "count").unwrap().split();
        let started = std::time::Instant::now();
        let piece = vec![1; 100_000];
        for _ in 0..50 {
            input.write_all(&piece).unwrap();
        }
        input.finish().unwrap();
        let mut said = String::new();
        output.read_to_string(&mut said).unwrap();
        assert_eq!(said, "5000000\n");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn writing_to_a_finished_or_abandoned_command_fails_only_that_command() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session();
        let (_output, mut input) = fixture.exec(&session, "echo").unwrap().split();
        input.finish().unwrap();
        assert_eq!(
            input.write_all(b"late").unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
        let (output, mut input) = fixture.exec(&session, "echo").unwrap().split();
        drop(output);
        let piece = vec![1; 64 << 10];
        let failed = (0..64).any(|_| input.write_all(&piece).is_err());
        assert!(failed);
        let (mut output, mut input) = fixture.exec(&session, "echo").unwrap().split();
        input.write_all(b"still here").unwrap();
        input.finish().unwrap();
        let mut said = String::new();
        output.read_to_string(&mut said).unwrap();
        assert_eq!(said, "still here");
    }

    #[test]
    fn an_old_command_cannot_reach_a_newer_one() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session();
        let (mut old_output, mut old_input) = fixture.exec(&session, "exit 3").unwrap().split();
        old_output.read_to_end(&mut Vec::new()).unwrap_err();
        let (mut output, mut input) = fixture.exec(&session, "echo").unwrap().split();
        assert!(old_input.write_all(b"stale").is_err());
        input.write_all(b"fresh").unwrap();
        input.finish().unwrap();
        let mut said = String::new();
        output.read_to_string(&mut said).unwrap();
        assert_eq!(said, "fresh");
    }

    #[test]
    fn an_end_of_output_then_a_cut_is_a_cut() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session();
        let (mut output, _input) = fixture.exec(&session, "eof-cut").unwrap().split();
        let error = output.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(
            *error
                .into_inner()
                .unwrap()
                .downcast::<RemoteFailure>()
                .unwrap(),
            RemoteFailure::Cut
        );
    }

    #[test]
    fn more_than_64_kib_before_the_start_is_refused() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session();
        let flooded = fixture.exec(&session, "flood");
        assert!(matches!(flooded, Err(SshError::EarlyOutput(command)) if command == "flood"));
    }

    #[test]
    fn unanswered_keepalives_end_the_connection_with_the_reason() {
        let (key, public) = user();
        let fixture = fixture_with(&public, key, false);
        let session = fixture.session_with(Timers {
            keepalive: Duration::from_millis(30),
            rekey: Duration::from_secs(3600),
        });
        std::thread::sleep(Duration::from_millis(400));
        let ended = fixture.exec(&session, "echo");
        assert!(
            matches!(&ended, Err(SshError::Protocol(why)) if why.contains("keepalives")),
            "{ended:?}"
        );
    }

    #[test]
    fn the_client_rekeys_on_its_timer_and_keeps_working() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session_with(Timers {
            keepalive: Duration::from_secs(15),
            rekey: Duration::from_millis(50),
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while fixture.kexinits.load(Ordering::SeqCst) < 4 {
            assert!(std::time::Instant::now() < deadline, "no rekey");
            std::thread::sleep(Duration::from_millis(20));
        }
        let (mut output, mut input) = fixture.exec(&session, "echo").unwrap().split();
        input.write_all(b"after rekeys").unwrap();
        input.finish().unwrap();
        let mut said = String::new();
        output.read_to_string(&mut said).unwrap();
        assert_eq!(said, "after rekeys");
    }

    #[test]
    fn the_interrupt_flag_stops_a_stalled_handshake() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = silent.local_addr().unwrap().port();
        let _held = std::thread::spawn(move || silent.accept());
        let remote = SshRemote::parse(&format!("ssh://git@127.0.0.1:{port}/repo")).unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let setter = Arc::clone(&flag);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            setter.store(true, Ordering::SeqCst);
        });
        let started = std::time::Instant::now();
        let connected = fixture.runtime.block_on(SshSession::connect(
            &remote,
            &KnownHosts::default(),
            &fixture.agent,
            "nobody",
            Some(flag),
        ));
        assert!(
            matches!(connected, Err(SshError::Interrupted)),
            "{connected:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn output_sent_before_the_host_starts_the_command_is_kept_and_a_silent_host_times_out() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let mut session = fixture.session();
        let command = fixture.remote().command(crate::GitService::ReceivePack);
        let (mut output, mut input) = fixture.exec(&session, &command).unwrap().split();
        let mut early = [0; 6];
        output.read_exact(&mut early).unwrap();
        input.write_all(b"then\n").unwrap();
        input.finish().unwrap();
        let mut rest = String::new();
        output.read_to_string(&mut rest).unwrap();
        assert_eq!((early, rest), (*b"early\n", "then\n".to_owned()));
        session.set_exec_timeout(Duration::from_millis(200));
        let silent = fixture.exec(&session, "hang");
        assert!(matches!(silent, Err(SshError::ExecTimeout(command)) if command == "hang"));
    }

    #[test]
    fn a_failed_command_reports_what_it_said_its_status_its_signal_or_a_cut_connection() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let failure = |command| {
            let session = fixture.session();
            let (mut output, _input) = fixture.exec(&session, command).unwrap().split();
            let error = output.read_to_end(&mut Vec::new()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Other);
            error
                .into_inner()
                .unwrap()
                .downcast::<RemoteFailure>()
                .map(|failure| *failure)
                .unwrap()
        };
        assert_eq!(
            failure("fail"),
            RemoteFailure::Said("fatal: no such?[2J repository".to_owned())
        );
        assert_eq!(failure("exit 3"), RemoteFailure::Status(3));
        assert_eq!(
            failure("signal"),
            RemoteFailure::Signal("KILL out of ?memory".to_owned())
        );
        assert_eq!(failure("cut"), RemoteFailure::Cut);
    }

    #[test]
    fn a_read_budget_counts_what_the_host_sends_besides_the_command_output() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let session = fixture.session();
        let budget = ReadBudget::new(256 << 10);
        session.set_read_budget(budget.clone());
        if let Ok(exec) = fixture.exec(&session, "noise") {
            let (mut output, _input) = exec.split();
            assert!(output.read_to_end(&mut Vec::new()).is_err());
        }
        assert!(budget.exceeded());
        let unlimited = fixture.session();
        let (mut output, _input) = fixture.exec(&unlimited, "exit 3").unwrap().split();
        assert!(output.read_to_end(&mut Vec::new()).is_err());
    }

    #[test]
    fn setting_the_interrupt_flag_stops_connecting_and_a_blocked_read() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let known_hosts = fixture.known_hosts(&fixture.host_key);
        let connect = |flag: &Arc<AtomicBool>| {
            fixture.runtime.block_on(SshSession::connect(
                &fixture.remote(),
                &known_hosts,
                &fixture.agent,
                "nobody",
                Some(Arc::clone(flag)),
            ))
        };
        let stopped = Arc::new(AtomicBool::new(true));
        assert!(matches!(connect(&stopped), Err(SshError::Interrupted)));
        let flag = Arc::new(AtomicBool::new(false));
        let session = connect(&flag).unwrap();
        let command = fixture.remote().command(crate::GitService::ReceivePack);
        let (mut output, _input) = fixture.exec(&session, &command).unwrap().split();
        let mut early = [0; 6];
        output.read_exact(&mut early).unwrap();
        let setter = Arc::clone(&flag);
        let started = std::time::Instant::now();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            setter.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let error = output.read_to_end(&mut Vec::new()).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(error.into_inner().unwrap().is::<Interrupted>());
    }

    #[test]
    fn a_command_needs_a_multi_thread_runtime() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let local = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let session = local
            .block_on(SshSession::connect(
                &fixture.remote(),
                &fixture.known_hosts(&fixture.host_key),
                &fixture.agent,
                "nobody",
                None,
            ))
            .unwrap();
        let refused = local.block_on(session.exec("git-upload-pack 'x'", &[]));
        assert!(
            matches!(refused, Err(SshError::CurrentThreadRuntime)),
            "{refused:?}"
        );
    }

    #[test]
    fn an_unknown_changed_revoked_or_unsupported_host_key_is_refused_before_logging_in() {
        let (key, public) = user();
        let fixture = fixture(&public, key);
        let unknown = fixture.connect(&KnownHosts::default(), &fixture.agent);
        let name = format!("[127.0.0.1]:{}", fixture.address.port());
        assert!(
            matches!(&unknown, Err(SshError::UnknownHostKey { host, .. }) if *host == name),
            "{unknown:?}"
        );
        assert_eq!(fixture.logins.load(Ordering::SeqCst), 0);
        let impostor = ed25519();
        let changed = fixture.connect(&fixture.known_hosts(impostor.public_key()), &fixture.agent);
        assert!(
            matches!(&changed, Err(SshError::ChangedHostKey { host, .. }) if *host == name),
            "{changed:?}"
        );
        let revoked = KnownHosts::parse(&format!(
            "{name} {key}\n@revoked * {key}\n",
            key = fixture.host_key.to_openssh().unwrap()
        ));
        let refused = fixture.connect(&revoked, &fixture.agent);
        assert!(
            matches!(&refused, Err(SshError::RevokedHostKey { host, .. }) if *host == name),
            "{refused:?}"
        );
        let rsa_only = KnownHosts::parse(&format!("{name} {RSA_KEY}\n"));
        let unsupported = fixture.connect(&rsa_only, &fixture.agent);
        assert!(
            matches!(&unsupported, Err(SshError::UnsupportedHostKey(host)) if *host == name),
            "{unsupported:?}"
        );
        assert_eq!(fixture.logins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_host_that_accepts_no_agent_key_is_reported() {
        let (_, public) = user();
        let fixture = fixture(&public, ed25519());
        let refused = fixture.connect(&fixture.known_hosts(&fixture.host_key), &fixture.agent);
        assert!(
            matches!(&refused, Err(SshError::NotAccepted { user, .. }) if user == "git"),
            "{refused:?}"
        );
        let missing = fixture.connect(
            &fixture.known_hosts(&fixture.host_key),
            &fixture.agent.with_file_name("missing.sock"),
        );
        assert!(matches!(missing, Err(SshError::Agent(_))), "{missing:?}");
    }

    #[test]
    fn only_key_types_listed_for_the_host_are_offered_and_rsa_never() {
        let p256 = Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        };
        assert_eq!(
            offered_algorithms(&[p256.clone(), Algorithm::Ed25519]),
            Some(vec![HostKeyAlgorithm::Ed25519, HostKeyAlgorithm::EcdsaP256])
        );
        let rsa = Algorithm::Rsa { hash: None };
        assert_eq!(offered_algorithms(std::slice::from_ref(&rsa)), None);
        assert_eq!(
            offered_algorithms(&[rsa, Algorithm::Ed25519]),
            Some(vec![HostKeyAlgorithm::Ed25519])
        );
        assert_eq!(
            offered_algorithms(&[]),
            Some(HostKeyAlgorithm::ALL.to_vec())
        );
    }
}
