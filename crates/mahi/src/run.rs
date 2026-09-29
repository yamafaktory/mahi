use std::{
    env,
    ffi::{
        OsStr,
        OsString,
    },
    fs::{
        self,
        File,
    },
    io::{
        self,
        Read,
        Write,
    },
    os::unix::{
        ffi::OsStrExt,
        fs::PermissionsExt,
        net::UnixListener,
    },
    path::{
        Path,
        PathBuf,
    },
    process,
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicBool,
            AtomicU64,
            Ordering,
        },
        mpsc::{
            self,
            Receiver,
            RecvTimeoutError,
        },
    },
    thread::{
        self,
        JoinHandle,
    },
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    AgentSlot,
    NameError,
    ParticipantName,
    ThreadId,
};
use mahi_crypto::ThreadKey;
use mahi_identity::{
    AgentError,
    AgentSigner,
    ConfigDir,
    ConfigError,
    Credential,
    CredentialName,
    IdentityError,
    LocalIdentity,
    NodeKey,
    PublicIdentity,
    SigningKey,
    SshAgent,
};
use mahi_live::{
    HostAddress,
    Relays,
};
use mahi_proxy::HostName;
use mahi_sandbox::{
    Access,
    PtyChild,
    PtyCommand,
    PtyError,
    Sandbox,
    SandboxError,
    SignalError,
    Termination,
    TerminationSignals,
    WindowChanges,
    exit_code,
};
use mahi_schedule::Schedule;
use mahi_store::{
    GlobalPatterns,
    ObjectId,
    Store,
    StoreError,
};
use mahi_thread::{
    KeyError,
    OwnerError,
    ParticipantKey,
    load_meta,
};
use rustix::{
    fs::{
        FileType,
        Mode,
        OFlags,
    },
    io::Errno,
    termios::{
        LocalModes,
        SpecialCodeIndex,
    },
};
use tempfile::TempDir;
use thiserror::Error;

use crate::{
    cli::{
        JoinCommand,
        LaunchOptions,
        ResumeCommand,
        RunCommand,
    },
    environment::{
        EnvName,
        Environment,
        HOOK_SOCKET,
        LiveMode,
        MAHI_BIN,
        PASSED_ON,
        PROXY_VARIABLES,
        Passed,
    },
    hook,
    live::{
        self,
        LiveHost,
        LiveSetup,
        OutputTap,
    },
    network::{
        Network,
        NetworkError,
        Running,
    },
    profile::{
        self,
        Profile,
    },
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    recorder::{
        RecordError,
        Recorder,
        Target,
    },
    session::{
        self,
        ResumeError,
        StartError,
        Started,
    },
    terminal::{
        self,
        RawMode,
    },
    thread_lock::{
        LockError,
        ThreadLock,
    },
    turns::{
        self,
        Summary,
        Transcript,
    },
};

#[cfg(target_os = "linux")]
const PROGRAM_HEADERS: [&[u8]; 1] = [b"\x7fELF"];
#[cfg(target_os = "macos")]
const PROGRAM_HEADERS: [&[u8]; 5] = [
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe",
];
const HOOK_SOCKET_NAME: &str = "mahi.sock";
const HOOK_QUEUE: usize = 16;
const HOME: &str = "home";
const TMP: &str = "tmp";
const PRIVATE_IN_HOME: [&str; 9] = [
    ".ssh",
    ".gnupg",
    ".aws",
    ".config",
    ".docker",
    ".kube",
    ".password-store",
    ".local/share/keyrings",
    "Library",
];
const PRIVATE_ON_SYSTEM: [&str; 3] = ["/run", "/private/var/run", "/private/tmp"];
const OUTPUT_GRACE: Duration = Duration::from_millis(500);
const OUTPUT_LIMIT: Duration = Duration::from_secs(5);
const EXIT_POLL: Duration = Duration::from_millis(50);
const STOP_POLL: Duration = Duration::from_millis(50);
const KILL_GRACE: Duration = Duration::from_secs(2);
const BROKEN_PIPE_CODE: i32 = 128 + 13;

#[derive(Debug, Error)]
pub(crate) enum RunError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot find the repository's git directory")]
    GitDirectory(#[source] io::Error),
    #[error("HOME is not set or does not exist, so mahi cannot tell which directories are private")]
    NoHome,
    #[error("refusing to give the agent {}, which holds private files", .0.display())]
    PrivateDirectory(PathBuf),
    #[error("cannot find {0:?} on PATH")]
    AgentNotFound(OsString),
    #[error("cannot find the agent {}", .0.display())]
    Agent(PathBuf, #[source] io::Error),
    #[error("cannot read the agent {}", .0.display())]
    AgentUnreadable(PathBuf, #[source] io::Error),
    #[error("{} is not a program this system can run", .0.display())]
    NotAProgram(PathBuf),
    #[error("cannot create the agent's private directories")]
    Scratch(#[source] io::Error),
    #[error("cannot build the sandbox")]
    Sandbox(#[from] SandboxError),
    #[error("cannot set up the terminal")]
    Terminal(#[source] io::Error),
    #[error("cannot show the agent's output")]
    Output(#[source] io::Error),
    #[error("cannot run the agent")]
    Pty(#[from] PtyError),
    #[error("cannot catch the signals that stop mahi")]
    Signals(#[source] SignalError),
    #[error("cannot find mahi's configuration directory")]
    Config(#[from] ConfigError),
    #[error("mahi is not set up; run mahi init first")]
    NotInitialised(#[source] IdentityError),
    #[error("MAHI_LIVE must be off, local or public")]
    LiveSetting,
    #[error("cannot tell who owns thread {0}")]
    ThreadOwner(ThreadId, #[source] OwnerError),
    #[error("name the agent to run after --, as in mahi join <ticket> -- claude")]
    NoAgent,
    #[error("cannot run your agent in the thread")]
    Enter(#[source] Box<session::EnterError>),
    #[error("SSH_AUTH_SOCK is not set; start ssh-agent and add your signing key (ssh-add)")]
    NoSshAgent,
    #[error("cannot sign with the SSH key")]
    Signer(#[from] AgentError),
    #[error("cannot make a participant name from USER")]
    ParticipantName(#[source] NameError),
    #[error("cannot open the git repository")]
    Store(#[from] StoreError),
    #[error("{0} is not set, so it cannot be passed on to the agent")]
    MissingVariable(EnvName),
    #[error("cannot set up the agent's network")]
    Network(#[from] NetworkError),
    #[error("the {0} profile needs the path of the mahi binary for its hooks, which is unknown")]
    NoMahiBinary(&'static str),
    #[error("{name} is set by the {profile} profile; use --no-profile to set it yourself")]
    SetByProfile {
        name: EnvName,
        profile: &'static str,
    },
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error("the signing key cannot identify thread owners")]
    OwnerKey(#[source] KeyError),
    #[error("cannot unlock your mahi key")]
    Unlock(#[source] IdentityError),
    #[error("cannot resume the thread")]
    Resume(#[from] ResumeError),
    #[error("{} is not a private directory of yours, so it is not reused", .0.display())]
    StateNotPrivate(PathBuf),
    #[error("cannot create the directory for the thread's worktree")]
    Worktrees(#[source] io::Error),
    #[error("there is no credential named {0}; store it with mahi credential add {0}")]
    NoCredential(CredentialName),
    #[error("cannot read the stored credential {0}")]
    Credential(CredentialName, #[source] IdentityError),
    #[error("{0} is given to the agent more than one way")]
    GivenTwice(String),
    #[error("cannot prepare the agent's state directory")]
    State(#[source] io::Error),
    #[error("cannot start the thread")]
    Start(#[from] StartError),
}

#[derive(Debug)]
struct Host {
    holders: Vec<PathBuf>,
    private: Vec<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
struct Agent {
    program: PathBuf,
    canonical: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Exited(i32),
    Stopped(Termination),
}

enum Event {
    Exited(Result<i32, PtyError>),
    OutputEnded(io::Result<()>),
    Stopped(Termination),
}

pub(crate) fn run(command: &RunCommand, environment: &Environment) -> Result<Outcome, RunError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(RunError::CurrentDirectory)?;
    let host = Host::from_environment(environment)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let public =
        PublicIdentity::load(&config.recipient_file()).map_err(RunError::NotInitialised)?;
    let signing = SigningKey::load(&config.signing_key_file()).map_err(RunError::NotInitialised)?;
    let node = session::own_node(&config).map_err(RunError::NotInitialised)?;
    let live = live_setup(environment, &config, own_key(&signing)?, Vec::new())?;
    let socket = environment
        .ssh_auth_sock
        .as_deref()
        .ok_or(RunError::NoSshAgent)?;
    let signer = AgentSigner::new(SshAgent::new(socket), signing.public_key().clone())?;
    let participant = session::participant_from(environment.user.as_deref())
        .map_err(RunError::ParticipantName)?;
    let store = Store::discover(&cwd)?;
    let profile = command.profile();
    let hosts = allowed_hosts(command.options.allow_hosts(), profile);
    let credentials = gather_credentials(&config, &command.options, profile, environment)?;
    let mut prepared = Prepared::new(
        environment,
        host,
        &cwd,
        store,
        &AgentRequest {
            program: command.agent(),
            arguments: command.arguments(),
            profile,
            hosts: &hosts,
        },
        credentials,
    )?;
    prepared.live = live;
    let agent_name = session::agent_from(Path::new(command.agent()));
    let worktrees = worktree_dir(environment, &prepared.host, &prepared.git_dir)?;
    let termination = TerminationSignals::listen().map_err(RunError::Signals)?;
    let (started, caught) = until_stopped(&termination, |interrupt| {
        session::start(
            &prepared.store,
            session::NewThread {
                public: &public,
                node,
                signer: &signer,
                participant,
                agent: &agent_name,
                worktrees: &worktrees,
            },
            &prepared.globals,
            interrupt,
        )
    });
    if let Some(signal) = caught {
        match &started {
            Ok(started) => started.discard_or_report(&prepared.store),
            Err(StartError::Store(StoreError::Interrupted)) => {}
            Err(error) => eprintln!("mahi: {error}"),
        }
        let _ = fs::remove_dir(&worktrees);
        return Ok(Outcome::Stopped(signal));
    }
    let started = started.inspect_err(|_| {
        let _ = fs::remove_dir(&worktrees);
    })?;
    if let Err(error) = keep_private(&worktrees) {
        started.discard_or_report(&prepared.store);
        return Err(error);
    }
    let _lock = match ThreadLock::acquire(&config, started.thread) {
        Ok(lock) => lock,
        Err(error) => {
            started.discard_or_report(&prepared.store);
            return Err(error.into());
        }
    };
    prepared.launch(environment, started, termination)
}

pub(crate) fn resume(
    command: &ResumeCommand,
    environment: &Environment,
) -> Result<Outcome, RunError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(RunError::CurrentDirectory)?;
    let host = Host::from_environment(environment)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let signing = SigningKey::load(&config.signing_key_file()).map_err(RunError::NotInitialised)?;
    let own = ParticipantKey::from_public_key(signing.public_key()).map_err(RunError::OwnerKey)?;
    let participant = session::participant_from(environment.user.as_deref())
        .map_err(RunError::ParticipantName)?;
    let store = Store::discover(&cwd)?;
    let owner = session::thread_owner(&store, command.thread, own)
        .map_err(|error| RunError::ThreadOwner(command.thread, error))?;
    let bootstrap: Vec<HostAddress> = live::remembered_host(&store, command.thread)
        .into_iter()
        .collect();
    let slot = session::pick_slot(&store, command.thread, &participant, command.agent.as_ref())?;
    store
        .worktree_dir(&command.thread.to_string())
        .map_err(|error| ResumeError::NoWorktree(command.thread, error))?;
    let _lock = ThreadLock::acquire(&config, command.thread)?;
    let (program, arguments, profile) = resumed_command(command, &slot);
    let hosts = allowed_hosts(command.options.allow_hosts(), profile);
    let credentials = gather_credentials(&config, &command.options, profile, environment)?;
    let mut prepared = Prepared::new(
        environment,
        host,
        &cwd,
        store,
        &AgentRequest {
            program: &program,
            arguments: &arguments,
            profile,
            hosts: &hosts,
        },
        credentials,
    )?;
    prepared.live = live_setup(environment, &config, owner.clone(), bootstrap)?;
    load_meta(&prepared.store, command.thread, &owner, 0)
        .map_err(|error| ResumeError::Meta(command.thread, Box::new(error)))?;
    let passphrase = TerminalPrompt::open()
        .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
        .map_err(RunError::Terminal)?;
    let identity =
        LocalIdentity::load(&config.identity_file(), &passphrase).map_err(RunError::Unlock)?;
    drop(passphrase);
    let reopen = session::Reopen {
        thread: command.thread,
        owner: &owner,
        identity: &identity,
        participant: &participant,
        agent: Some(slot.agent()),
    };
    let termination = TerminationSignals::listen().map_err(RunError::Signals)?;
    let (started, caught) = until_stopped(&termination, |interrupt| {
        session::resume(&prepared.store, &reopen, &prepared.globals, interrupt)
    });
    drop(identity);
    if let Some(signal) = caught {
        return Ok(Outcome::Stopped(signal));
    }
    prepared.launch(environment, started?, termination)
}

/// Returns what the live layer needs, unless `MAHI_LIVE` turns it off.
fn live_setup(
    environment: &Environment,
    config: &ConfigDir,
    owner: ParticipantKey,
    bootstrap: Vec<HostAddress>,
) -> Result<Option<LiveSetup>, RunError> {
    let relays = match environment.live {
        LiveMode::Off => return Ok(None),
        LiveMode::Local => Relays::Disabled,
        LiveMode::Public => Relays::Public,
        LiveMode::Unknown => return Err(RunError::LiveSetting),
    };
    Ok(Some(LiveSetup {
        config: config.clone(),
        node_key: NodeKey::load(&config.node_key_file()).map_err(RunError::NotInitialised)?,
        owner,
        relays,
        bootstrap,
    }))
}

fn own_key(signing: &SigningKey) -> Result<ParticipantKey, RunError> {
    ParticipantKey::from_public_key(signing.public_key()).map_err(RunError::OwnerKey)
}

/// A thread someone else owns, joined from a ticket: what `mahi join` hands over to run the
/// user's own agent in it.
#[derive(Debug)]
pub(crate) struct Joined {
    pub(crate) thread: ThreadId,
    pub(crate) base: ObjectId,
    pub(crate) key: ThreadKey,
    pub(crate) participant: ParticipantName,
    pub(crate) owner: ParticipantKey,
    pub(crate) host: HostAddress,
    pub(crate) lock: ThreadLock,
}

/// Runs the user's own agent in a thread someone else owns, which `mahi join` checked and
/// recorded, hosting it live on the thread's topic through the owner's host.
pub(crate) fn join_run(
    command: &JoinCommand,
    environment: &Environment,
    joined: Joined,
) -> Result<Outcome, RunError> {
    let (program, arguments) = command.agent().ok_or(RunError::NoAgent)?;
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(RunError::CurrentDirectory)?;
    let host = Host::from_environment(environment)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let store = Store::discover(&cwd)?;
    let profile = command.options.profile_for(program);
    let hosts = allowed_hosts(command.options.allow_hosts(), profile);
    let credentials = gather_credentials(&config, &command.options, profile, environment)?;
    let mut prepared = Prepared::new(
        environment,
        host,
        &cwd,
        store,
        &AgentRequest {
            program,
            arguments,
            profile,
            hosts: &hosts,
        },
        credentials,
    )?;
    prepared.live = live_setup(
        environment,
        &config,
        joined.owner.clone(),
        vec![joined.host.clone()],
    )?;
    let agent_name = session::agent_from(Path::new(program));
    let worktrees = worktree_dir(environment, &prepared.host, &prepared.git_dir)?;
    let _lock = joined.lock;
    let termination = TerminationSignals::listen().map_err(RunError::Signals)?;
    let (started, caught) = until_stopped(&termination, |interrupt| {
        session::enter(
            &prepared.store,
            session::Enter {
                thread: joined.thread,
                base: joined.base,
                key: joined.key,
                participant: joined.participant,
                agent: &agent_name,
                worktrees: &worktrees,
            },
            &prepared.globals,
            interrupt,
        )
    });
    if let Some(signal) = caught {
        return Ok(Outcome::Stopped(signal));
    }
    let started = started.map_err(|error| RunError::Enter(Box::new(error)))?;
    keep_private(&worktrees)?;
    prepared.launch(environment, started, termination)
}

/// Returns what `mahi resume` runs: the command after `--`, or the program named after the
/// thread's agent with its profile's resume arguments.
fn resumed_command(
    command: &ResumeCommand,
    slot: &AgentSlot,
) -> (OsString, Vec<OsString>, Option<&'static Profile>) {
    if let Some((program, arguments)) = command.command.split_first() {
        return (
            program.clone(),
            arguments.to_vec(),
            command.options.profile_for(program),
        );
    }
    let program = OsString::from(slot.agent().as_str());
    let profile = command.options.profile_for(&program);
    let arguments = profile
        .map(|profile| profile.resume_args)
        .unwrap_or_default()
        .iter()
        .map(OsString::from)
        .collect();
    (program, arguments, profile)
}

/// A stored credential handed to the agent, and the variable it becomes.
#[derive(Debug)]
struct Handed {
    variable: String,
    credential: Credential,
}

/// Loads the credentials the agent gets: those named with `--credential`, which must exist, and
/// the profile's, when stored; a variable may be given only one way.
fn gather_credentials(
    config: &ConfigDir,
    options: &LaunchOptions,
    profile: Option<&Profile>,
    environment: &Environment,
) -> Result<Vec<Handed>, RunError> {
    let mut handed: Vec<Handed> = Vec::new();
    let mut hand = |variable: &str, credential: Credential| {
        if handed.iter().any(|earlier| earlier.variable == variable) {
            return Err(RunError::GivenTwice(variable.to_owned()));
        }
        handed.push(Handed {
            variable: variable.to_owned(),
            credential,
        });
        Ok(())
    };
    for binding in options.credentials() {
        let credential = Credential::load(config, &binding.name)
            .map_err(|error| RunError::Credential(binding.name.clone(), error))?
            .ok_or_else(|| RunError::NoCredential(binding.name.clone()))?;
        hand(binding.variable.as_str(), credential)?;
    }
    if let Some((name, variable)) = profile.and_then(|profile| profile.credential)
        && !options
            .credentials()
            .iter()
            .any(|binding| binding.variable.as_str() == variable)
        && let Ok(name) = name.parse::<CredentialName>()
        && let Some(credential) = Credential::load(config, &name)
            .map_err(|error| RunError::Credential(name.clone(), error))?
    {
        hand(variable, credential)?;
    }
    let set_by_profile = profile.map(Profile::set_names).unwrap_or_default();
    for handed in &handed {
        let passed = environment
            .pass_env
            .iter()
            .any(|passed| passed.required && passed.name.as_str() == handed.variable);
        if passed
            || set_by_profile.contains(&handed.variable.as_str())
            || PASSED_ON.contains(&handed.variable.as_str())
        {
            return Err(RunError::GivenTwice(handed.variable.clone()));
        }
    }
    Ok(handed)
}

/// The agent to run and what it may reach.
#[derive(Debug, Clone, Copy)]
struct AgentRequest<'a> {
    program: &'a OsStr,
    arguments: &'a [OsString],
    profile: Option<&'static Profile>,
    hosts: &'a [HostName],
}

/// Everything `mahi run` sets up before the thread exists, so that a failure leaves nothing
/// behind: the agent, its profile, its private directories, the hook socket, the sandbox and
/// the network.
struct Prepared {
    host: Host,
    store: Store,
    git_dir: PathBuf,
    agent: Agent,
    arguments: Vec<OsString>,
    profile: Option<&'static Profile>,
    _scratch: TempDir,
    scratch: PathBuf,
    hook_socket: PathBuf,
    hooks: UnixListener,
    sandbox: Sandbox,
    network: Option<Network>,
    globals: GlobalPatterns,
    credentials: Vec<Handed>,
    live: Option<LiveSetup>,
}

impl Prepared {
    fn new(
        environment: &Environment,
        host: Host,
        cwd: &Path,
        store: Store,
        request: &AgentRequest<'_>,
        credentials: Vec<Handed>,
    ) -> Result<Self, RunError> {
        let AgentRequest {
            program,
            arguments,
            profile,
            hosts,
        } = *request;
        let agent = resolve(program, cwd, environment.path.as_deref())?;
        require_program(&agent.canonical)?;
        check_profile(profile, environment)?;
        require_passed(environment)?;
        let git_dir = fs::canonicalize(store.common_dir()).map_err(RunError::GitDirectory)?;
        if host.is_private(&git_dir) {
            return Err(RunError::PrivateDirectory(git_dir));
        }
        let scratch_dir = tempfile::Builder::new()
            .prefix("mahi-")
            .tempdir_in(&environment.temp_dir)
            .map_err(RunError::Scratch)?;
        let scratch = fs::canonicalize(scratch_dir.path()).map_err(RunError::Scratch)?;
        for directory in [HOME, TMP] {
            fs::create_dir(scratch.join(directory)).map_err(RunError::Scratch)?;
        }
        let hook_socket = scratch.join(HOOK_SOCKET_NAME);
        let hooks = UnixListener::bind(&hook_socket).map_err(RunError::Scratch)?;
        let sandbox = Sandbox::system()?;
        let network = Network::prepare(hosts)?;
        Ok(Self {
            host,
            store,
            git_dir,
            agent,
            arguments: arguments.to_vec(),
            profile,
            _scratch: scratch_dir,
            scratch,
            hook_socket,
            hooks,
            sandbox,
            network,
            globals: environment.git_patterns(),
            credentials,
            live: None,
        })
    }

    fn launch(
        self,
        environment: &Environment,
        mut started: Started,
        termination: TerminationSignals,
    ) -> Result<Outcome, RunError> {
        eprintln!(
            "mahi: thread {} in {}",
            started.thread,
            started.worktree.display()
        );
        if let Some(profile) = self.profile {
            eprintln!(
                "mahi: {} profile (--no-profile runs the agent without it)",
                profile.name
            );
        }
        let launch = Launch {
            arguments: &self.arguments,
            environment,
            agent: &self.agent,
            worktree: &started.worktree,
            git_dir: &self.git_dir,
            scratch: &self.scratch,
            hook_socket: &self.hook_socket,
            host: &self.host,
            profile: self.profile,
            state: self.profile.map(|_| started.state_dir(&self.store)),
            credentials: &self.credentials,
        };
        let (sandbox, network) = (self.sandbox, self.network);
        let live = self
            .live
            .as_ref()
            .zip(started.key.as_ref())
            .and_then(|(setup, key)| {
                LiveHost::start(
                    setup,
                    &self.git_dir,
                    started.thread,
                    started.slot.clone(),
                    key,
                    terminal::size(),
                )
                .inspect_err(|error| eprintln!("mahi: teammates cannot watch this thread: {error}"))
                .ok()
            });
        let launched = started.launch(&self.store, || launch.spawn(sandbox, network));
        let (child, raw, proxy) = match launched {
            Ok(launched) => launched,
            Err(error) => {
                if let Some(live) = live {
                    live.stop();
                }
                return Err(error);
            }
        };
        let (recorder, turns) =
            start_background(&mut started, &self.git_dir, self.globals, self.hooks);
        finish_run(child, raw, termination, recorder, turns, proxy, live)
    }
}

fn start_background(
    started: &mut Started,
    git_dir: &Path,
    globals: GlobalPatterns,
    hooks: UnixListener,
) -> (Option<Recorder>, Option<TurnWorker>) {
    let recorder = started.first_snapshot.take().map(|first| {
        Recorder::start(
            Target {
                git_dir: git_dir.to_path_buf(),
                worktree: started.thread.to_string(),
                snapshots: started.snapshots.clone(),
                globals,
            },
            first,
            Schedule::default(),
        )
    });
    let turns = started.key.take().map(|key| {
        let transcript = Transcript {
            git_dir: git_dir.to_path_buf(),
            key,
            thread: started.thread,
            slot: started.slot.clone(),
            tip: started.tip,
        };
        let poker = recorder.as_ref().map(Recorder::poker);
        let (messages, inputs) = mpsc::sync_channel(HOOK_QUEUE);
        let closing = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&closing);
        thread::spawn(move || hook::serve(&hooks, &flag, &messages));
        let worker = thread::spawn(move || turns::record(&transcript, &inputs, poker.as_ref()));
        (closing, worker)
    });
    (recorder, turns)
}

type TurnWorker = (Arc<AtomicBool>, JoinHandle<Summary>);

fn finish_turns(turns: Option<TurnWorker>) {
    let Some((closing, worker)) = turns else {
        return;
    };
    closing.store(true, Ordering::SeqCst);
    let Ok(summary) = worker.join() else {
        eprintln!("mahi: the transcript stopped unexpectedly");
        return;
    };
    if summary.dropped > 0 {
        eprintln!(
            "mahi: {} agent events were left out of the transcript",
            summary.dropped
        );
    }
    if let Some(error) = summary.error {
        crate::report(&error);
    }
}

fn finish_run(
    child: PtyChild,
    raw: Option<RawMode>,
    termination: TerminationSignals,
    recorder: Option<Recorder>,
    turns: Option<TurnWorker>,
    proxy: Option<Running>,
    live: Option<LiveHost>,
) -> Result<Outcome, RunError> {
    let (code, received) = supervise(child, raw, termination, live.as_ref().map(LiveHost::tap));
    if let Some(live) = live {
        live.stop();
    }
    if matches!(code, Ok(Outcome::Stopped(_))) {
        while received.try_recv().is_ok() {}
    }
    let abandon = recorder.as_ref().map(Recorder::abandon_flag);
    let (caught, stopped) = mpsc::channel();
    thread::spawn(move || stop_on_signal(&received, abandon.as_deref(), &caught));
    finish_turns(turns);
    for error in proxy.into_iter().flat_map(Running::stopped) {
        eprintln!("mahi: the proxy stopped serving the agent: {error}");
    }
    match recorder.map(Recorder::finish) {
        Some(Ok(skipped)) if skipped > 0 => {
            eprintln!("mahi: the last snapshot left out {skipped} paths it could not record");
        }
        Some(Err(RecordError::Store(StoreError::Interrupted))) => {
            eprintln!("mahi: stopped before the last snapshot");
        }
        Some(Err(error)) => crate::report(&error),
        _ => {}
    }
    match stopped.try_recv() {
        Ok(signal) => Ok(Outcome::Stopped(signal)),
        Err(_) => code,
    }
}

fn supervise(
    child: PtyChild,
    raw: Option<RawMode>,
    termination: TerminationSignals,
    tap: Option<OutputTap>,
) -> (Result<Outcome, RunError>, Receiver<Event>) {
    let (events, received) = mpsc::channel();
    let stop_events = events.clone();
    thread::spawn(move || {
        while let Ok(signal) = termination.wait() {
            let _ = stop_events.send(Event::Stopped(signal));
        }
    });
    let code = relay(child, raw.is_some(), events, &received, tap);
    drop(raw);
    (code, received)
}

fn stop_on_signal(
    received: &Receiver<Event>,
    abandon: Option<&AtomicBool>,
    caught: &mpsc::Sender<Termination>,
) {
    let mut stopping = false;
    while let Ok(event) = received.recv() {
        let Event::Stopped(signal) = event else {
            continue;
        };
        let Some(abandon) = abandon.filter(|_| !stopping) else {
            stop_now(signal);
        };
        let _ = caught.send(signal);
        abandon.store(true, Ordering::SeqCst);
        stopping = true;
    }
}

fn check_profile(
    profile: Option<&'static Profile>,
    environment: &Environment,
) -> Result<(), RunError> {
    let Some(profile) = profile else {
        return Ok(());
    };
    if environment.mahi_exe.is_none() {
        return Err(RunError::NoMahiBinary(profile.name));
    }
    let set = profile.set_names();
    match environment
        .pass_env
        .iter()
        .find(|passed| passed.required && set.contains(&passed.name.as_str()))
    {
        Some(passed) => Err(RunError::SetByProfile {
            name: passed.name.clone(),
            profile: profile.name,
        }),
        None => Ok(()),
    }
}

/// Returns the directory that holds this repository's thread worktrees, under the user's
/// worktree root, after checking that it is not a private place and making sure it is a
/// directory of the user's that only the user can use.
fn worktree_dir(
    environment: &Environment,
    host: &Host,
    git_dir: &Path,
) -> Result<PathBuf, RunError> {
    let root = environment.worktree_root().ok_or(RunError::NoHome)?;
    if host.is_private(&root) || host.is_private(&resolve_existing(&root)) {
        return Err(RunError::PrivateDirectory(root));
    }
    profile::create_private_dir(&root).map_err(RunError::Worktrees)?;
    let root = fs::canonicalize(&root).map_err(RunError::Worktrees)?;
    if host.is_private(&root) {
        return Err(RunError::PrivateDirectory(root));
    }
    let name = session::repository_dir(git_dir);
    let root_dir = rustix::fs::open(
        &root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| RunError::Worktrees(error.into()))?;
    let path = root.join(&name);
    profile::open_private_dir(&root_dir, &name)
        .map_err(RunError::Worktrees)?
        .ok_or_else(|| RunError::StateNotPrivate(path.clone()))?;
    Ok(path)
}

/// Resolves the deepest part of `path` that exists and appends the rest unchanged, so a path
/// that does not exist yet can be checked against canonical private directories.
fn resolve_existing(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(resolved) = fs::canonicalize(ancestor) {
            let rest = path.strip_prefix(ancestor).unwrap_or(Path::new(""));
            return resolved.join(rest);
        }
    }
    path.to_path_buf()
}

/// Checks again that the repository's worktree directory is a private directory of the user's,
/// once the worktree is in it, since another mahi may have recreated it in between.
fn keep_private(worktrees: &Path) -> Result<(), RunError> {
    let not_private = || RunError::StateNotPrivate(worktrees.to_path_buf());
    let (Some(root), Some(name)) = (worktrees.parent(), worktrees.file_name()) else {
        return Err(not_private());
    };
    let root = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| RunError::Worktrees(error.into()))?;
    let name = name.to_str().ok_or_else(not_private)?;
    profile::open_private_dir(&root, name)
        .map_err(RunError::Worktrees)?
        .ok_or_else(not_private)?;
    Ok(())
}

fn require_passed(environment: &Environment) -> Result<(), RunError> {
    match environment
        .pass_env
        .iter()
        .find(|passed| passed.required && passed.value.is_none())
    {
        Some(missing) => Err(RunError::MissingVariable(missing.name.clone())),
        None => Ok(()),
    }
}

fn allowed_hosts(allowed: &[HostName], profile: Option<&Profile>) -> Vec<HostName> {
    let from_profile = profile
        .map(|profile| profile.hosts)
        .unwrap_or_default()
        .iter()
        .filter_map(|host| host.parse().ok());
    allowed.iter().cloned().chain(from_profile).collect()
}

fn stop_now(signal: Termination) -> ! {
    signal.reraise();
    process::exit(128 + signal.number())
}

pub(crate) fn until_stopped<T>(
    termination: &TerminationSignals,
    work: impl FnOnce(&AtomicBool) -> T,
) -> (T, Option<Termination>) {
    let interrupt = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let mut caught = None;
            while !finished.load(Ordering::SeqCst) {
                match termination.wait_timeout(STOP_POLL) {
                    Ok(Some(signal)) if caught.is_some() => stop_now(signal),
                    Ok(Some(signal)) => {
                        interrupt.store(true, Ordering::SeqCst);
                        caught = Some(signal);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        eprintln!("mahi: cannot watch for stop signals: {error}");
                        break;
                    }
                }
            }
            caught
        });
        let result = work(&interrupt);
        finished.store(true, Ordering::SeqCst);
        (result, watcher.join().ok().flatten())
    })
}

struct Launch<'a> {
    credentials: &'a [Handed],
    profile: Option<&'static Profile>,
    state: Option<PathBuf>,
    arguments: &'a [OsString],
    environment: &'a Environment,
    agent: &'a Agent,
    worktree: &'a Path,
    git_dir: &'a Path,
    scratch: &'a Path,
    hook_socket: &'a Path,
    host: &'a Host,
}

impl Launch<'_> {
    fn prepare_state(&self) -> Result<Option<PathBuf>, RunError> {
        let (Some(profile), Some(state)) = (self.profile, &self.state) else {
            return Ok(None);
        };
        let not_private = || RunError::StateNotPrivate(state.clone());
        let (Some(parent), Some(name)) = (state.parent(), state.file_name()) else {
            return Err(not_private());
        };
        let name = name.to_str().ok_or_else(not_private)?;
        profile::create_private_dir(parent).map_err(RunError::State)?;
        let parent = fs::canonicalize(parent).map_err(RunError::State)?;
        let parent_dir = rustix::fs::open(
            &parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| RunError::State(error.into()))?;
        let directory = profile::open_private_dir(&parent_dir, name)
            .map_err(RunError::State)?
            .ok_or_else(not_private)?;
        profile.install(&directory).map_err(RunError::State)?;
        Ok(Some(parent.join(name)))
    }

    fn spawn(
        &self,
        mut sandbox: Sandbox,
        network: Option<Network>,
    ) -> Result<(PtyChild, Option<RawMode>, Option<Running>), RunError> {
        let git_file = self.worktree.join(".git");
        for (path, access) in binds(
            self.worktree,
            self.git_dir,
            self.agent,
            self.scratch,
            self.environment.path.as_deref(),
            self.host,
        )? {
            let program_directory =
                access == Access::ReadOnly && path != git_file && path != self.git_dir;
            match sandbox.bind(&path, access) {
                Ok(_) => {}
                Err(SandboxError::Overlaps(_)) if program_directory => {}
                Err(error) => return Err(error.into()),
            }
        }
        if let Some(mahi) = &self.environment.mahi_exe {
            match sandbox.bind(mahi, Access::ReadOnly) {
                Ok(_) | Err(SandboxError::Overlaps(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        sandbox.allow_connect(self.hook_socket)?;
        let state = self.prepare_state()?;
        if let Some(state) = &state {
            sandbox.bind(state, Access::ReadWrite)?;
        }
        if let Some(network) = &network {
            sandbox.open_loopback_port(network.port())?;
        }
        let mut pty = PtyCommand::new(&self.agent.program, self.worktree, terminal::size());
        for argument in self.arguments {
            pty = pty.arg(argument);
        }
        for (name, value) in &self.environment.passed_on {
            pty = pty.env(name, value);
        }
        let mut pty = pty
            .env("HOME", self.scratch.join(HOME))
            .env("TMPDIR", self.scratch.join(TMP))
            .env(HOOK_SOCKET, self.hook_socket);
        if let Some(mahi) = &self.environment.mahi_exe {
            pty = pty.env(MAHI_BIN, mahi);
        }
        let handed = |name: &str| {
            self.credentials
                .iter()
                .any(|handed| handed.variable == name)
        };
        let offered = |passed: &&Passed| {
            passed.required
                || (self
                    .profile
                    .is_some_and(|profile| profile.optional_env.contains(&passed.name.as_str()))
                    && !handed(passed.name.as_str()))
        };
        for passed in self.environment.pass_env.iter().filter(offered) {
            if let Some(value) = &passed.value {
                pty = pty.env(passed.name.as_str(), OsStr::from_bytes(value));
            }
        }
        for handed in self.credentials {
            pty = pty.env(
                &handed.variable,
                OsStr::from_bytes(handed.credential.expose()),
            );
        }
        if let (Some(profile), Some(state)) = (self.profile, &state) {
            pty = pty.env(profile.state_env, state);
            for (name, value) in profile.env {
                pty = pty.env(name, value);
            }
        }
        if let Some(network) = &network {
            for variable in PROXY_VARIABLES {
                pty = pty.env(variable, network.url());
            }
        }
        let pty = pty.sandbox(sandbox);
        let raw = RawMode::enable().map_err(RunError::Terminal)?;
        let mut child = pty.spawn()?;
        let proxy = network
            .map(|network| network.start(child.take_loopback_listener()))
            .transpose()?;
        Ok((child, raw, proxy))
    }
}

impl Host {
    fn from_environment(environment: &Environment) -> Result<Self, RunError> {
        let canonical = |path: Option<&Path>| path.and_then(|path| fs::canonicalize(path).ok());
        let home = canonical(environment.home.as_deref()).ok_or(RunError::NoHome)?;
        let mut holders = vec![home.clone()];
        holders.extend(canonical(Some(&environment.temp_dir)));
        let mut private: Vec<PathBuf> =
            PRIVATE_IN_HOME.iter().map(|name| home.join(name)).collect();
        let resolved: Vec<PathBuf> = private
            .iter()
            .filter_map(|path| fs::canonicalize(path).ok())
            .collect();
        private.extend(resolved);
        private.extend(PRIVATE_ON_SYSTEM.iter().map(PathBuf::from));
        private.extend(canonical(environment.xdg_runtime_dir.as_deref()));
        Ok(Self { holders, private })
    }

    fn is_private(&self, directory: &Path) -> bool {
        self.holders
            .iter()
            .any(|holder| holder.starts_with(directory))
            || self
                .private
                .iter()
                .any(|private| private.starts_with(directory) || directory.starts_with(private))
    }
}

fn relay(
    child: PtyChild,
    interactive: bool,
    events: mpsc::Sender<Event>,
    received: &Receiver<Event>,
    tap: Option<OutputTap>,
) -> Result<Outcome, RunError> {
    let writer = child.writer()?;
    thread::spawn(move || forward_input(writer, interactive));
    let resizer = child.resizer()?;
    let resize_tap = tap.clone();
    thread::spawn(move || {
        let Ok(changes) = WindowChanges::listen() else {
            return;
        };
        while changes.wait().is_ok() {
            let size = terminal::size();
            if resizer.resize(size).is_err() {
                break;
            }
            if let Some(tap) = &resize_tap {
                tap.resize(size);
            }
        }
    });
    let mut reader = child.reader()?;
    let progress = Arc::new(AtomicU64::new(0));
    let output_events = events.clone();
    let output_progress = Arc::clone(&progress);
    thread::spawn(move || {
        let ended = copy_output(&mut reader, &output_progress, tap.as_ref());
        let _ = output_events.send(Event::OutputEnded(ended));
    });
    let child = Arc::new(Mutex::new(child));
    let waited = Arc::clone(&child);
    thread::spawn(move || {
        let _ = events.send(Event::Exited(wait_for(&waited)));
    });
    let mut output_done = false;
    loop {
        match received.recv() {
            Ok(Event::Exited(code)) if output_done => return Ok(Outcome::Exited(code?)),
            Ok(Event::Exited(code)) => {
                return finish_output(received, &progress, code?);
            }
            Ok(Event::OutputEnded(Ok(()))) => output_done = true,
            Ok(Event::OutputEnded(Err(error))) => {
                kill(&child);
                return output_failure(error).map(Outcome::Exited);
            }
            Ok(Event::Stopped(signal)) => {
                kill(&child);
                if !output_done {
                    await_output_end(received);
                }
                return Ok(Outcome::Stopped(signal));
            }
            Err(_) => return Ok(Outcome::Exited(1)),
        }
    }
}

fn kill(child: &Mutex<PtyChild>) {
    if let Ok(mut child) = child.lock() {
        let _ = child.kill();
    }
}

fn await_output_end(received: &Receiver<Event>) {
    let deadline = Instant::now() + KILL_GRACE;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match received.recv_timeout(left) {
            Ok(Event::OutputEnded(_)) | Err(_) => return,
            Ok(Event::Exited(_) | Event::Stopped(_)) => {}
        }
    }
}

fn wait_for(child: &Mutex<PtyChild>) -> Result<i32, PtyError> {
    loop {
        let status = match child.lock() {
            Ok(mut child) => child.try_wait()?,
            Err(_) => return Ok(1),
        };
        if let Some(status) = status {
            return Ok(exit_code(status));
        }
        thread::sleep(EXIT_POLL);
    }
}

fn finish_output(
    received: &Receiver<Event>,
    progress: &AtomicU64,
    code: i32,
) -> Result<Outcome, RunError> {
    let exited = Ok(Outcome::Exited(code));
    let mut seen = progress.load(Ordering::Relaxed);
    let deadline = Instant::now() + OUTPUT_LIMIT;
    loop {
        if Instant::now() > deadline {
            return exited;
        }
        match received.recv_timeout(OUTPUT_GRACE) {
            Ok(Event::OutputEnded(Err(error))) => {
                return output_failure(error).map(|_| Outcome::Exited(code));
            }
            Ok(Event::OutputEnded(Ok(()))) | Err(RecvTimeoutError::Disconnected) => {
                return exited;
            }
            Ok(Event::Stopped(signal)) => return Ok(Outcome::Stopped(signal)),
            Ok(Event::Exited(_)) => {}
            Err(RecvTimeoutError::Timeout) => {
                let now = progress.load(Ordering::Relaxed);
                if now == seen {
                    return exited;
                }
                seen = now;
            }
        }
    }
}

fn output_failure(error: io::Error) -> Result<i32, RunError> {
    if error.kind() == io::ErrorKind::BrokenPipe {
        Ok(BROKEN_PIPE_CODE)
    } else {
        Err(RunError::Output(error))
    }
}

fn copy_output(
    reader: &mut impl Read,
    progress: &AtomicU64,
    tap: Option<&OutputTap>,
) -> io::Result<()> {
    let mut output = io::stdout().lock();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        output.write_all(&buffer[..read])?;
        output.flush()?;
        if let Some(tap) = tap {
            tap.output(&buffer[..read]);
        }
        progress.fetch_add(1, Ordering::Relaxed);
    }
}

fn forward_input(mut writer: File, interactive: bool) {
    let mut input = io::stdin().lock();
    let mut buffer = [0_u8; 4096];
    let mut last = b'\n';
    loop {
        let read = match input.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
            if !interactive {
                end_input(&mut writer, last);
            }
            return;
        };
        if writer.write_all(chunk).is_err() {
            return;
        }
        last = chunk.last().copied().unwrap_or(last);
    }
}

fn end_input(writer: &mut File, last: u8) {
    let Ok(attributes) = rustix::termios::tcgetattr(&*writer) else {
        return;
    };
    if !attributes.local_modes.contains(LocalModes::ICANON) {
        return;
    }
    let end_of_file = attributes.special_codes[SpecialCodeIndex::VEOF];
    if end_of_file == 0 || end_of_file == 0xff {
        return;
    }
    let count = if last == b'\n' { 1 } else { 2 };
    for _ in 0..count {
        if writer.write_all(&[end_of_file]).is_err() {
            return;
        }
    }
}

fn resolve(agent: &OsStr, cwd: &Path, search_path: Option<&OsStr>) -> Result<Agent, RunError> {
    if agent.as_bytes().contains(&b'/') {
        let named = cwd.join(agent);
        let canonical = fs::canonicalize(&named).map_err(|error| RunError::Agent(named, error))?;
        return Ok(Agent {
            program: canonical.clone(),
            canonical,
        });
    }
    let found = absolute_directories(search_path)
        .map(|directory| directory.join(agent))
        .find(|candidate| is_executable(candidate))
        .ok_or_else(|| RunError::AgentNotFound(agent.to_os_string()))?;
    let located = |error| RunError::Agent(found.clone(), error);
    let canonical = fs::canonicalize(&found).map_err(located)?;
    let directory = found
        .parent()
        .map(fs::canonicalize)
        .transpose()
        .map_err(located)?
        .unwrap_or_default();
    Ok(Agent {
        program: directory.join(agent),
        canonical,
    })
}

fn absolute_directories(search_path: Option<&OsStr>) -> impl Iterator<Item = PathBuf> {
    search_path
        .into_iter()
        .flat_map(env::split_paths)
        .filter(|directory| directory.is_absolute())
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn require_program(path: &Path) -> Result<(), RunError> {
    let unreadable = |error: Errno| RunError::AgentUnreadable(path.to_path_buf(), error.into());
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(file) => file,
        Err(Errno::ACCESS) if is_executable(path) => return Ok(()),
        Err(error) => return Err(unreadable(error)),
    };
    let stat = rustix::fs::fstat(&file).map_err(unreadable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(RunError::NotAProgram(path.to_path_buf()));
    }
    let mut header = Vec::with_capacity(4);
    File::from(file)
        .take(4)
        .read_to_end(&mut header)
        .map_err(|error| RunError::AgentUnreadable(path.to_path_buf(), error))?;
    if header.starts_with(b"#!") || PROGRAM_HEADERS.iter().any(|magic| header == *magic) {
        Ok(())
    } else {
        Err(RunError::NotAProgram(path.to_path_buf()))
    }
}

fn binds(
    cwd: &Path,
    git_dir: &Path,
    agent: &Agent,
    scratch: &Path,
    search_path: Option<&OsStr>,
    host: &Host,
) -> Result<Vec<(PathBuf, Access)>, RunError> {
    if host.is_private(cwd) {
        return Err(RunError::PrivateDirectory(cwd.to_path_buf()));
    }
    let mut binds: Vec<(PathBuf, Access)> = Vec::new();
    let covered = |binds: &[(PathBuf, Access)], path: &Path| {
        binds.iter().any(|(bound, _)| path.starts_with(bound))
    };
    for writable in [cwd, scratch] {
        if !covered(&binds, writable) {
            binds.push((writable.to_path_buf(), Access::ReadWrite));
        }
    }
    let git = cwd.join(".git");
    if git
        .symlink_metadata()
        .is_ok_and(|metadata| !metadata.is_symlink())
    {
        binds.push((git, Access::ReadOnly));
    }
    binds.push((git_dir.to_path_buf(), Access::ReadOnly));
    let program_directories = [&agent.program, &agent.canonical]
        .into_iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf));
    for directory in absolute_directories(search_path).chain(program_directories) {
        let Ok(directory) = fs::canonicalize(directory) else {
            continue;
        };
        if !covered(&binds, &directory) && !host.is_private(&directory) {
            binds.push((directory, Access::ReadOnly));
        }
    }
    for program in [&agent.program, &agent.canonical] {
        if !covered(&binds, program) {
            binds.push((program.clone(), Access::ReadOnly));
        }
    }
    Ok(binds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executable(path: &Path) {
        fs::write(path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        (dir, path)
    }

    fn host_with_home(home: &Path) -> Host {
        Host {
            holders: vec![home.to_path_buf()],
            private: PRIVATE_IN_HOME.iter().map(|name| home.join(name)).collect(),
        }
    }

    fn agent_at(path: &Path) -> Agent {
        Agent {
            program: path.to_path_buf(),
            canonical: path.to_path_buf(),
        }
    }

    #[test]
    fn an_agent_on_path_keeps_its_name_in_a_canonical_directory() {
        let (_dir, root) = canonical_tempdir();
        let first = root.join("first");
        let real = root.join("real");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.join("linked")).unwrap();
        fs::write(first.join("agent"), "not executable").unwrap();
        executable(&real.join("agent"));
        executable(&root.join("agent"));
        let search = env::join_paths([Path::new("."), &first, &root.join("linked")]).unwrap();
        let found = resolve(OsStr::new("agent"), &root, Some(&search)).unwrap();
        assert_eq!(found, agent_at(&real.join("agent")));
    }

    #[test]
    fn only_native_programs_and_scripts_are_agents() {
        let (_dir, root) = canonical_tempdir();
        let native = fs::canonicalize("/bin/sh").unwrap();
        require_program(&native).unwrap();
        let script = root.join("script");
        executable(&script);
        require_program(&script).unwrap();
        for (name, content) in [
            ("garbage", b"\x00\x01\x02 not a program".as_slice()),
            ("empty", b"".as_slice()),
            ("text", b"echo no interpreter line".as_slice()),
            ("short", b"\x7fEL".as_slice()),
        ] {
            let path = root.join(name);
            fs::write(&path, content).unwrap();
            assert!(
                matches!(require_program(&path), Err(RunError::NotAProgram(_))),
                "{name}"
            );
        }
        assert!(matches!(
            require_program(&root.join("missing")),
            Err(RunError::AgentUnreadable(..))
        ));
        let socket = root.join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            require_program(&socket),
            Err(RunError::NotAProgram(_) | RunError::AgentUnreadable(..))
        ));
        assert!(matches!(
            require_program(&root),
            Err(RunError::NotAProgram(_) | RunError::AgentUnreadable(..))
        ));
        let hidden = root.join("execute-only");
        fs::copy(&native, &hidden).unwrap();
        fs::set_permissions(&hidden, fs::Permissions::from_mode(0o111)).unwrap();
        if File::open(&hidden).is_err() {
            require_program(&hidden).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_agent_is_refused_without_blocking() {
        let (_dir, root) = canonical_tempdir();
        let fifo = root.join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            FileType::Fifo,
            Mode::from_raw_mode(0o755),
            0,
        )
        .unwrap();
        assert!(matches!(
            require_program(&fifo),
            Err(RunError::NotAProgram(_))
        ));
    }

    #[test]
    fn an_agent_given_with_a_path_is_run_by_its_canonical_path() {
        let (_dir, root) = canonical_tempdir();
        executable(&root.join("agent"));
        let found = resolve(OsStr::new("./agent"), &root, None).unwrap();
        assert_eq!(found, agent_at(&root.join("agent")));
        assert!(matches!(
            resolve(OsStr::new("nothing-here"), &root, None),
            Err(RunError::AgentNotFound(_))
        ));
        assert!(matches!(
            resolve(OsStr::new("/nothing/here"), &root, None),
            Err(RunError::Agent(..))
        ));
    }

    #[test]
    fn private_directories_are_refused_as_the_working_directory() {
        let (_dir, root) = canonical_tempdir();
        let home = root.join("home/user");
        fs::create_dir_all(home.join(".ssh/keys")).unwrap();
        let host = host_with_home(&home);
        let agent = agent_at(Path::new("/usr/bin/true"));
        for cwd in [&home, &root.join("home"), &root, &home.join(".ssh/keys")] {
            assert!(matches!(
                binds(
                    cwd,
                    Path::new("/repo/.git"),
                    &agent,
                    Path::new("/scratch"),
                    None,
                    &host
                ),
                Err(RunError::PrivateDirectory(_))
            ));
        }
        assert!(
            binds(
                &home.join("project"),
                Path::new("/repo/.git"),
                &agent,
                Path::new("/scratch"),
                None,
                &host
            )
            .is_ok()
        );
    }

    #[test]
    fn relative_and_private_path_entries_are_not_bound() {
        let (_dir, root) = canonical_tempdir();
        let home = root.join("home");
        let project = home.join("project");
        let tools = root.join("tools");
        for directory in [
            &project,
            &tools,
            &home.join(".ssh"),
            &home.join(".local/share/keyrings"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        let search = env::join_paths([
            Path::new(".."),
            &home,
            &home.join(".ssh"),
            &home.join(".local"),
            &tools,
        ])
        .unwrap();
        let agent = agent_at(&tools.join("agent"));
        let binds = binds(
            &project,
            Path::new("/repo/.git"),
            &agent,
            &root.join("scratch"),
            Some(&search),
            &host_with_home(&home),
        )
        .unwrap();
        assert_eq!(
            binds,
            [
                (project.clone(), Access::ReadWrite),
                (root.join("scratch"), Access::ReadWrite),
                (PathBuf::from("/repo/.git"), Access::ReadOnly),
                (tools, Access::ReadOnly),
            ]
        );
    }

    #[test]
    fn a_script_agent_gets_its_whole_package_directory() {
        let (_dir, root) = canonical_tempdir();
        let home = root.join("home");
        let package = root.join("lib/agent");
        fs::create_dir_all(&package).unwrap();
        fs::create_dir_all(home.join("project")).unwrap();
        let agent = Agent {
            program: root.join("bin/agent"),
            canonical: package.join("cli.js"),
        };
        let binds = binds(
            &home.join("project"),
            Path::new("/repo/.git"),
            &agent,
            &root.join("scratch"),
            None,
            &host_with_home(&home),
        )
        .unwrap();
        assert!(binds.contains(&(package, Access::ReadOnly)));
    }

    #[test]
    fn an_agent_in_the_home_directory_is_bound_alone() {
        let (_dir, root) = canonical_tempdir();
        let home = root.join("home");
        fs::create_dir_all(home.join("project")).unwrap();
        let agent = agent_at(&home.join("agent.sh"));
        let binds = binds(
            &home.join("project"),
            Path::new("/repo/.git"),
            &agent,
            &root.join("scratch"),
            None,
            &host_with_home(&home),
        )
        .unwrap();
        assert!(binds.contains(&(home.join("agent.sh"), Access::ReadOnly)));
        assert!(!binds.iter().any(|(path, _)| path == &home));
    }

    #[test]
    fn the_git_directory_of_the_working_directory_is_read_only() {
        let (_dir, root) = canonical_tempdir();
        let home = root.join("home");
        let project = home.join("project");
        fs::create_dir_all(project.join(".git")).unwrap();
        let agent = agent_at(Path::new("/usr/bin/true"));
        let binds = binds(
            &project,
            Path::new("/repo/.git"),
            &agent,
            Path::new("/scratch"),
            None,
            &host_with_home(&home),
        )
        .unwrap();
        assert!(binds.contains(&(project.join(".git"), Access::ReadOnly)));
    }
}
