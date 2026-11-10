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
        fs::{
            OpenOptionsExt,
            PermissionsExt,
        },
        io::AsFd,
        net::{
            UnixListener,
            UnixStream,
        },
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

use age::secrecy::{
    ExposeSecret,
    SecretString,
};
use mahi_agent::{
    codex::HookTrust,
    profile::ProfileCredential,
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
    CredentialError,
    CredentialName,
    IdentityError,
    NodeKey,
    PublicIdentity,
    SigningKey,
    SshAgent,
    decline_credential,
    is_credential_declined,
};
use mahi_live::{
    HostAddress,
    LiveKeys,
    Relays,
    TurnState,
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
use mahi_term::{
    KeyScanner,
    Notice,
    PaletteKey,
    Segment,
    TerminalHints,
};
use mahi_thread::{
    KeyError,
    OwnerError,
    Participant,
    ParticipantKey,
    Role,
    VerifiedMeta,
    load_meta,
};
use rustix::{
    event::{
        PollFd,
        PollFlags,
        Timespec,
    },
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
use zeroize::Zeroizing;

use crate::{
    auto_merge::AutoMerge,
    claims::Claims,
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
        MCP_SOCKET,
        PASSED_ON,
        PROXY_VARIABLES,
        Passed,
    },
    held_queue::HeldQueue,
    hook,
    hub::{
        Link,
        OutputTap,
    },
    inject::{
        Activity,
        AgentInput,
        Pace,
    },
    land_desk::{
        self,
        Desk,
        Lander,
    },
    live::{
        self,
        HostError,
        LiveSetup,
        Reports,
    },
    mcp::{
        self,
        ThreadTools,
        Toolbox,
    },
    network::{
        Network,
        NetworkError,
        Running,
    },
    note::{
        self,
        NoteBy,
        NoteContext,
    },
    palette::{
        AgentTerminal,
        Repainter,
        Screen,
    },
    profile::{
        self,
        Profile,
        Tools,
    },
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    recorder::{
        Merger,
        RecordError,
        Recorder,
        Target,
    },
    remote::{
        self,
        RemoteName,
    },
    session::{
        self,
        CommitKey,
        ResumeError,
        StartError,
        Started,
    },
    session_sync::{
        self,
        SessionOf,
        SessionSource,
    },
    settings::{
        AgentApprovals,
        Settings,
        SettingsError,
    },
    sync::{
        self,
        PushPoker,
        Pusher,
        SyncSetup,
    },
    terminal::{
        self,
        RawMode,
    },
    thread_lock::{
        AgentLock,
        LockError,
        ThreadLock,
    },
    turn_end::{
        self,
        Reporting,
    },
    turns::{
        self,
        Summary,
        Transcript,
    },
    unlocked,
};

pub(crate) const THREAD_STOP_WAIT: Duration = Duration::from_secs(2);
const THREAD_POLL: Duration = Duration::from_millis(10);
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
const MCP_SOCKET_NAME: &str = "mcp.sock";
const HOOK_QUEUE: usize = 16;
const HOME: &str = "home";
const GIT_SHARED: [&str; 6] = [
    "objects",
    "refs",
    "packed-refs",
    "info",
    "shallow",
    "reftable",
];
const WORKTREE_CONFIG: &str = "config.worktree";
#[cfg(target_os = "linux")]
const GIT_CONFIG_NAME: &str = "git-config";
#[cfg(not(target_os = "linux"))]
const GIT_STAND_IN: &str = "git";
const GIT_COMMON_DIR: &str = "GIT_COMMON_DIR";
const MAX_GIT_LINK_BYTES: u64 = 4096;
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
const DRAIN_CHUNKS: usize = 16;
const STOP_POLL: Duration = Duration::from_millis(50);
const KILL_GRACE: Duration = Duration::from_secs(2);
const PALETTE_WAIT: Duration = Duration::from_millis(200);
const PALETTE_POLL: Duration = Duration::from_millis(10);
const OUTPUT_READ: usize = 8192;
const PALETTE_TICK: Duration = Duration::from_secs(1);
const BROKEN_PIPE_CODE: i32 = 128 + 13;

#[derive(Debug, Error)]
pub(crate) enum RunError {
    #[error(transparent)]
    UserNamespaces(#[from] mahi_sandbox::UsernsBlocked),
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot find the repository's git directory")]
    GitDirectory(#[source] io::Error),
    #[error("HOME is not set or does not exist, so mahi cannot tell which directories are private")]
    NoHome,
    #[error("refusing to give the agent {}, which holds private files", .0.display())]
    PrivateDirectory(PathBuf),
    #[error("{} is not a worktree of this repository, so its git directory cannot be given to the agent", .0.display())]
    NotLinkedWorktree(PathBuf),
    #[error("refusing to give the agent the worktree's own git settings in {}", .0.display())]
    WorktreeConfig(PathBuf),
    #[error("refusing to run the agent, which would see all of {}, under a system directory it reads", .0.display())]
    GitDirectoryShown(PathBuf),
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
    #[error("the token for {0} cannot be used")]
    UnfitCredential(CredentialName, #[source] CredentialError),
    #[error("cannot keep the credential {0}")]
    KeepCredential(CredentialName, #[source] IdentityError),
    #[error("cannot read whether you chose to go without the credential {0}")]
    DeclinedMark(CredentialName, #[source] IdentityError),
    #[error("{0} is given to the agent more than one way")]
    GivenTwice(String),
    #[error("cannot prepare the agent's state directory")]
    State(#[source] io::Error),
    #[error("cannot start the thread")]
    Start(#[from] StartError),
    #[error(
        "thread {0} does not list your signing key for {1}; resume as the user who started or joined it"
    )]
    NotListed(ThreadId, ParticipantName),
    #[error(
        "this clone has a worktree for thread {0}, whose files would hide what is taken from the remote; record and remove it with mahi end, or resume without --take-remote"
    )]
    WorktreeHere(ThreadId),
    #[error(
        "{0} does not report when its turns end, so your teammates' work could not be kept in sync with it; run Claude Code or Codex, with its profile"
    )]
    NoTurnEnds(String),
    #[error(
        "{owner} made you a watcher in thread {thread}, so you cannot run an agent in it; watch it with mahi join <ticket>, or ask {owner} to invite you as a --collaborator"
    )]
    Watcher {
        owner: ParticipantName,
        thread: ThreadId,
    },
}

#[derive(Debug)]
pub(crate) struct Host {
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
    let signer = agent_signer(environment, &signing)?;
    let commits = CommitKey::new(signer.clone()).map_err(RunError::OwnerKey)?;
    let participant = session::participant_from(environment.user.as_deref())
        .map_err(RunError::ParticipantName)?;
    let store = Store::discover(&cwd)?;
    let profile = command.profile();
    let hosts = allowed_hosts(command.options.allow_hosts(), profile);
    let settings = Settings::load(&config)?;
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
    prepared.apply(&settings);
    prepared.set_thread(live, own_key(&signing)?);
    if let Err(error) =
        remote::offer_origin(&prepared.store, &config, TerminalPrompt::open_interactive)
    {
        crate::report_with("origin was not offered as the remote", &error);
    }
    prepared.sync = SyncSetup::gather(&prepared.store, environment, true);
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
                commits: &commits,
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
    let _lock = match AgentLock::acquire(&config, started.thread, started.slot.agent()) {
        Ok(lock) => lock,
        Err(error) => {
            started.discard_or_report(&prepared.store);
            return Err(error.into());
        }
    };
    prepared.launch((environment, &config), started, termination)
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
    let owner = session::thread_owner(&store, command.thread, own.clone())
        .map_err(|error| RunError::ThreadOwner(command.thread, error))?;
    let owns_meta = owner == own;
    let bootstrap: Vec<HostAddress> = live::bootstrap(&store, command.thread);
    let _whole_thread = command
        .take_remote
        .then(|| ThreadLock::acquire(&config, command.thread))
        .transpose()?;
    let taken = if command.take_remote {
        if session::has_thread_worktree(&store, command.thread)? {
            return Err(RunError::WorktreeHere(command.thread));
        }
        let signer = agent_signer(environment, &signing)?;
        if let Some(signal) =
            sync::fetch_until_stopped(&store, environment, command.thread, &owner, None)
        {
            return Ok(Outcome::Stopped(signal));
        }
        Some(signer)
    } else {
        None
    };
    let slot =
        match session::pick_slot(&store, command.thread, &participant, command.agent.as_ref()) {
            Err(ResumeError::NoAgent(thread)) => {
                return Err(no_agent(&store, thread, &owner, &own));
            }
            picked => picked?,
        };
    let _agent_lock = (!command.take_remote)
        .then(|| AgentLock::acquire(&config, command.thread, slot.agent()))
        .transpose()?;
    let (program, arguments, profile) = resumed_command(command, &slot);
    let hosts = allowed_hosts(command.options.allow_hosts(), profile);
    let settings = Settings::load(&config)?;
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
        Vec::new(),
    )?;
    prepared.apply(&settings);
    prepared.join_thread(environment, &config, owner.clone(), bootstrap)?;
    prepared.sync = SyncSetup::gather(&prepared.store, environment, owns_meta);
    let commits = match listed_and_fetched(
        &prepared.store,
        environment,
        (command.thread, !command.take_remote),
        &owner,
        (&own, &participant),
        (&program, profile),
        (&signing, taken),
    )? {
        Ok(commits) => commits,
        Err(signal) => return Ok(Outcome::Stopped(signal)),
    };
    prepared.credentials = gather_credentials(&config, &command.options, profile, environment)?;
    let identity = unlocked::identity(&config.identity_file(), ask_passphrase, RunError::Unlock)?;
    let worktrees = worktree_dir(environment, &prepared.host, &prepared.git_dir)?;
    let reopen = session::Reopen {
        thread: command.thread,
        owner: &owner,
        identity: &identity,
        participant: &participant,
        agent: Some(slot.agent()),
        worktrees: &worktrees,
        commits: &commits,
    };
    let termination = TerminationSignals::listen().map_err(RunError::Signals)?;
    let (started, caught) = until_stopped(&termination, |interrupt| {
        session::resume(&prepared.store, &reopen, &prepared.globals, interrupt)
    });
    drop(identity);
    if let Some(signal) = caught {
        return Ok(Outcome::Stopped(signal));
    }
    prepared.launch((environment, &config), started?, termination)
}

/// Checks that the thread's `meta` lists the user, fetches the thread as that participant when
/// `fetch` is set, checks with `may_run` that the latest `meta` lets the user run the agent
/// `program`, and returns the key that signs the user's commits: `signer`, or one made from
/// `signing`. The inner `Err` is the signal that stopped the fetch.
fn listed_and_fetched(
    store: &Store,
    environment: &Environment,
    (thread, fetch): (ThreadId, bool),
    owner: &ParticipantKey,
    user: (&ParticipantKey, &ParticipantName),
    agent: (&OsStr, Option<&Profile>),
    (signing, signer): (&SigningKey, Option<AgentSigner>),
) -> Result<Result<CommitKey, Termination>, RunError> {
    let current = load_meta(store, thread, owner, 0)
        .map_err(|error| ResumeError::Meta(thread, Box::new(error)))?;
    listed(&current, thread, user)?;
    let signer = match signer {
        Some(signer) => signer,
        None => agent_signer(environment, signing)?,
    };
    let latest = if fetch {
        let stopped = sync::fetch_until_stopped(store, environment, thread, owner, Some(user.1));
        if let Some(signal) = stopped {
            return Ok(Err(signal));
        }
        load_meta(store, thread, owner, current.generation())
            .map_err(|error| ResumeError::Meta(thread, Box::new(error)))?
    } else {
        current
    };
    may_run(&latest, thread, user, agent)?;
    Ok(Ok(CommitKey::new(signer).map_err(RunError::OwnerKey)?))
}

fn listed<'meta>(
    meta: &'meta VerifiedMeta,
    thread: ThreadId,
    (own, participant): (&ParticipantKey, &ParticipantName),
) -> Result<&'meta Participant, RunError> {
    meta.participants()
        .find(|listed| listed.key() == own)
        .filter(|listed| listed.name() == participant)
        .ok_or_else(|| RunError::NotListed(thread, participant.clone()))
}

fn may_run(
    meta: &VerifiedMeta,
    thread: ThreadId,
    user: (&ParticipantKey, &ParticipantName),
    (program, profile): (&OsStr, Option<&Profile>),
) -> Result<(), RunError> {
    if listed(meta, thread, user)?.role() == Role::Watcher {
        return Err(RunError::Watcher {
            owner: meta.owner().clone(),
            thread,
        });
    }
    let teammates = meta.collaborators().any(|listed| listed.key() != user.0);
    if !teammates {
        return Ok(());
    }
    turn_end::unreported_name(program, profile)
        .map_or(Ok(()), |name| Err(RunError::NoTurnEnds(name)))
}

fn no_agent(
    store: &Store,
    thread: ThreadId,
    owner: &ParticipantKey,
    own: &ParticipantKey,
) -> RunError {
    let meta = load_meta(store, thread, owner, 0).ok();
    let watcher = meta.as_ref().filter(|meta| {
        meta.participants()
            .any(|listed| listed.key() == own && listed.role() == Role::Watcher)
    });
    match watcher {
        Some(meta) => RunError::Watcher {
            owner: meta.owner().clone(),
            thread,
        },
        None => ResumeError::NoAgent(thread).into(),
    }
}

/// Asks for the passphrase of the user's mahi key on the terminal.
fn ask_passphrase() -> Result<SecretString, RunError> {
    TerminalPrompt::open()
        .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
        .map_err(RunError::Terminal)
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
        runtime: environment.runtime_dir(),
        node_key: NodeKey::load(&config.node_key_file()).map_err(RunError::NotInitialised)?,
        owner,
        relays,
        bootstrap,
        reports: Reports::default(),
    }))
}

/// Returns the signer for the user's signing key through ssh-agent, once the agent is found to
/// hold that key.
pub(crate) fn agent_signer(
    environment: &Environment,
    signing: &SigningKey,
) -> Result<AgentSigner, RunError> {
    let socket = environment
        .ssh_auth_sock
        .as_deref()
        .ok_or(RunError::NoSshAgent)?;
    let signer = AgentSigner::new(SshAgent::new(socket), signing.public_key().clone())?;
    signer.require_loaded()?;
    Ok(signer)
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
    pub(crate) lock: AgentLock,
    pub(crate) commits: CommitKey,
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
    let settings = Settings::load(&config)?;
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
    prepared.apply(&settings);
    prepared.join_thread(
        environment,
        &config,
        joined.owner.clone(),
        vec![joined.host.clone()],
    )?;
    prepared.sync = SyncSetup::gather(&prepared.store, environment, false);
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
                commits: &joined.commits,
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
    prepared.launch((environment, &config), started, termination)
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
        .map(|profile| profile.resume_args.as_slice())
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
/// the profile's, when stored, or else asked for on the terminal when the agent would otherwise
/// get no value for it; a variable may be given only one way.
fn gather_credentials(
    config: &ConfigDir,
    options: &LaunchOptions,
    profile: Option<&Profile>,
    environment: &Environment,
) -> Result<Vec<Handed>, RunError> {
    let set_by_profile = profile.map(Profile::set_names).unwrap_or_default();
    let given_otherwise = |variable: &str| {
        let passed = environment
            .pass_env
            .iter()
            .any(|passed| passed.required && passed.name.as_str() == variable);
        if passed || set_by_profile.contains(&variable) || PASSED_ON.contains(&variable) {
            return Err(RunError::GivenTwice(variable.to_owned()));
        }
        Ok(())
    };
    let mut handed: Vec<Handed> = Vec::new();
    for binding in options.credentials() {
        let variable = binding.variable.as_str();
        if handed.iter().any(|earlier| earlier.variable == variable) {
            return Err(RunError::GivenTwice(variable.to_owned()));
        }
        given_otherwise(variable)?;
        let credential = Credential::load(config, &binding.name)
            .map_err(|error| RunError::Credential(binding.name.clone(), error))?
            .ok_or_else(|| RunError::NoCredential(binding.name.clone()))?;
        handed.push(Handed {
            variable: variable.to_owned(),
            credential,
        });
    }
    if let Some(profile) = profile
        && let Some(wanted) = profile.credential.as_ref()
        && !handed
            .iter()
            .any(|earlier| earlier.variable == wanted.variable)
    {
        let stored = Credential::load(config, &wanted.name)
            .map_err(|error| RunError::Credential(wanted.name.clone(), error))?;
        let credential = match stored {
            Some(stored) => Some(stored),
            None if passed_from_environment(wanted, profile, environment) => None,
            None => {
                given_otherwise(&wanted.variable)?;
                ask_for_credential(config, wanted, TerminalPrompt::open_interactive)?
            }
        };
        if let Some(credential) = credential {
            given_otherwise(&wanted.variable)?;
            handed.push(Handed {
                variable: wanted.variable.clone(),
                credential,
            });
        }
    }
    Ok(handed)
}

/// Returns whether the profile's credential variable reaches the agent from mahi's own
/// environment.
fn passed_from_environment(
    wanted: &ProfileCredential,
    profile: &Profile,
    environment: &Environment,
) -> bool {
    environment.pass_env.iter().any(|passed| {
        passed.name.as_str() == wanted.variable
            && (passed.required
                || (passed.value.is_some() && profile.optional_env.contains(&wanted.variable)))
    })
}

/// Asks for the profile's credential, unless the user chose earlier to go without it or there
/// is no terminal, then stores it; an empty answer is remembered as going without it.
fn ask_for_credential<P: Prompt>(
    config: &ConfigDir,
    wanted: &ProfileCredential,
    open: impl FnOnce() -> io::Result<P>,
) -> Result<Option<Credential>, RunError> {
    let name = &wanted.name;
    if is_credential_declined(config, name)
        .map_err(|error| RunError::DeclinedMark(name.clone(), error))?
    {
        return Ok(None);
    }
    let Ok(mut prompt) = open() else {
        return Ok(None);
    };
    let said = |prompt: &mut P, line: &str| prompt.say(line).map_err(RunError::Terminal);
    said(
        &mut prompt,
        &format!("This agent signs in with the credential {name}, which mahi does not have yet."),
    )?;
    if let Some(hint) = &wanted.hint {
        said(&mut prompt, &format!("To make one: {hint}."))?;
    }
    said(
        &mut prompt,
        "Press Enter alone to go without it; mahi will not ask again.",
    )?;
    let answer = prompt
        .secret(&format!("Token for {name}: "))
        .map_err(RunError::Terminal)?;
    if answer.expose_secret().is_empty() {
        decline_credential(config, name)
            .map_err(|error| RunError::KeepCredential(name.clone(), error))?;
        return Ok(None);
    }
    let credential = Credential::new(Zeroizing::new(answer.expose_secret().as_bytes().to_vec()))
        .map_err(|error| RunError::UnfitCredential(name.clone(), error))?;
    drop(answer);
    match credential.save(config, name) {
        Ok(()) => said(&mut prompt, &format!("stored the credential {name}"))?,
        Err(IdentityError::Exists(_)) => {
            said(
                &mut prompt,
                &format!("the credential {name} was stored meanwhile; using that one"),
            )?;
            return Credential::load(config, name)
                .map_err(|error| RunError::Credential(name.clone(), error));
        }
        Err(error) => return Err(RunError::KeepCredential(name.clone(), error)),
    }
    Ok(Some(credential))
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
    mcp_socket: PathBuf,
    mcp: UnixListener,
    owner: Option<ParticipantKey>,
    sandbox: Sandbox,
    network: Option<Network>,
    globals: GlobalPatterns,
    credentials: Vec<Handed>,
    live: Option<LiveSetup>,
    sync: Option<SyncSetup>,
    settings: Settings,
}

impl Prepared {
    /// Takes `settings`: the palette's key, whether the agent asks for permissions and the
    /// transfer limits a landing uses.
    fn apply(&mut self, settings: &Settings) {
        self.settings = settings.clone();
    }

    /// Sets the thread's live layer, if any, and the owner of its `meta`, which the agent's
    /// tools read.
    fn set_thread(&mut self, live: Option<LiveSetup>, owner: ParticipantKey) {
        self.live = live;
        self.owner = Some(owner);
    }

    /// Sets up the live layer of a thread whose `meta` is `owner`'s, reaching its host at
    /// `bootstrap`, as [`Prepared::set_thread`] does.
    fn join_thread(
        &mut self,
        environment: &Environment,
        config: &ConfigDir,
        owner: ParticipantKey,
        bootstrap: Vec<HostAddress>,
    ) -> Result<(), RunError> {
        let live = live_setup(environment, config, owner.clone(), bootstrap)?;
        self.set_thread(live, owner);
        Ok(())
    }

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
        mahi_sandbox::check_user_namespaces(environment.mahi_exe.as_deref())?;
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
        let mcp_socket = scratch.join(MCP_SOCKET_NAME);
        let mcp = UnixListener::bind(&mcp_socket).map_err(RunError::Scratch)?;
        let sandbox = Sandbox::system()?;
        let network = Network::prepare(hosts)?;
        write_git_config(&scratch, &store.agent_config()?, &git_dir).map_err(RunError::Scratch)?;
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
            mcp_socket,
            mcp,
            owner: None,
            sandbox,
            network,
            globals: environment.git_patterns(),
            credentials,
            live: None,
            sync: None,
            settings: Settings::default(),
        })
    }

    /// Returns the agent's state directory, when its profile points the agent at one.
    fn state_dir(&self, started: &Started) -> Option<PathBuf> {
        self.profile
            .filter(|profile| profile.state_env.is_some())
            .map(|_| started.state_dir(&self.store))
    }

    /// Returns where the agent keeps its session, when its profile names a directory for it.
    fn session_source(&self, started: &Started) -> Option<SessionSource> {
        self.profile.and_then(Profile::session_dir).and_then(|dir| {
            let named = fs::canonicalize(&started.worktree).ok().and_then(|worktree| dir(&worktree));
            if named.is_none() {
                eprintln!(
                    "mahi: the agent's session is not kept, since its worktree's path cannot name it"
                );
            }
            Some(SessionSource {
                state: started.state_dir(&self.store),
                dir: named?,
            })
        })
    }

    fn announce(&self, started: &Started) {
        crate::report::send(&mahi_term::Report::Thread(started.thread));
        eprintln!(
            "mahi: thread {} in {}",
            started.thread,
            started.worktree.display()
        );
        if let Some(profile) = self.profile {
            match &profile.source {
                Some(source) => eprintln!(
                    "mahi: {} profile from {} (--no-profile runs the agent without it)",
                    profile.name,
                    source.display()
                ),
                None => eprintln!(
                    "mahi: {} profile (--no-profile runs the agent without it)",
                    profile.name
                ),
            }
        }
        if terminal::is_interactive() {
            eprintln!(
                "mahi: {} opens mahi's palette (palette-key in config.toml changes it)",
                self.settings.palette_key
            );
        }
    }

    /// Returns the state the agent starts in, done and waiting for its first prompt, when its
    /// profile's hooks report its turns.
    fn first_state(&self) -> Option<TurnState> {
        self.profile
            .and_then(Profile::turn_end_agent)
            .map(|_| TurnState::Done)
    }

    fn launch(
        mut self,
        (environment, config): (&Environment, &ConfigDir),
        mut started: Started,
        termination: TerminationSignals,
    ) -> Result<Outcome, RunError> {
        self.announce(&started);
        let session = self.session_source(&started);
        let restore = restore_of(&self.store, session.as_ref(), &started);
        let first = self.first_state();
        let reporting = first.map_or(Reporting::Unreported, |_| Reporting::Reported);
        let (thread, slot) = (started.thread, started.slot.clone());
        let state = self.state_dir(&started);
        let launch = Launch {
            restore,
            arguments: &self.arguments,
            environment,
            agent: &self.agent,
            worktree: &started.worktree,
            git_dir: &self.git_dir,
            scratch: &self.scratch,
            hook_socket: &self.hook_socket,
            mcp_socket: &self.mcp_socket,
            host: &self.host,
            profile: self.profile,
            state: state.clone(),
            config: config.path(),
            credentials: &self.credentials,
            approvals: self.settings.agent_approvals,
        };
        let (sandbox, network) = (self.sandbox, self.network);
        let reports = self
            .live
            .as_ref()
            .map_or_else(Reports::default, |setup| setup.reports.clone());
        reports.hold();
        let live = start_live(self.live.take(), &self.git_dir, &started);
        let store = &self.store;
        let launched = started.launch(store, || {
            turn_end::record_reporting(store, thread, &slot, reporting).map_err(RunError::State)?;
            launch.spawn(sandbox, network)
        });
        let spawned = match launched {
            Ok(launched) => launched,
            Err(error) => {
                if let Some(live) = live {
                    live.stop();
                }
                reports.release();
                return Err(error);
            }
        };
        let pusher = self
            .sync
            .map(|setup| start_pusher(setup, &self.git_dir, &started));
        let activity = Arc::new(Activity::telling(live.as_ref().map(Link::tap), first));
        let key = started.key.take().map(Arc::new);
        let globals = self.globals.clone();
        let (recorder, turns) = start_background(
            &mut started,
            &self.git_dir,
            self.globals,
            (self.hooks, Arc::clone(&activity)),
            pusher.as_ref().map(|(pusher, _)| pusher.poker()),
            session,
            key.clone(),
        );
        let auto_merge = auto_merge(self.profile, self.owner.as_ref(), (&self.git_dir, &started));
        let note_by = self.profile.map_or(NoteBy::ListAgents, Profile::note_by);
        let landing = landing_desk(
            (&self.store, environment, &self.git_dir, &self.settings),
            (self.owner.as_ref(), key.as_deref(), spawned.raw.is_some()),
            (&started, globals),
        );
        let tools = serve_tools(
            self.mcp,
            (self.owner, key, live.as_ref()),
            &self.git_dir,
            (
                &started,
                note_by,
                landing.as_ref().map(|(_, lander)| Arc::clone(lander)),
            ),
        );
        let outcome = finish_run(
            spawned.child,
            spawned.raw,
            &UserSide {
                palette_key: self.settings.palette_key,
                activity,
                desk: landing.map(|(desk, _)| desk),
            },
            termination,
            Background {
                recorder,
                turns,
                pusher,
                auto_merge,
            },
            spawned.proxy,
            live,
        );
        reports.release();
        tools.store(false, Ordering::SeqCst);
        keep_hook_trust(self.profile, spawned.hook_trust.as_ref(), config.path());
        outcome
    }
}

/// Keeps in the user's configuration directory, for their later threads, the approvals of
/// mahi's hooks the agent recorded in its state directory, `hook_trust`'s path, since those
/// it recorded at launch, when it has a profile and one.
fn keep_hook_trust(
    profile: Option<&Profile>,
    hook_trust: Option<&(PathBuf, HookTrust)>,
    config: &Path,
) {
    let (Some(profile), Some((state, launched))) = (profile, hook_trust) else {
        return;
    };
    if let Err(error) = profile.keep_hook_trust(state, config, launched) {
        crate::report_with("the approval of mahi's hooks was not kept", &error);
    }
}

/// Splits the agent's `arguments` before the first `--`, after which the agent takes no
/// options.
fn split_at_separator(arguments: &[OsString]) -> (&[OsString], &[OsString]) {
    let at = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    arguments.split_at(at)
}

/// Serves the tools of `started`'s agent, in the thread whose `meta` is `owner`'s and whose
/// records `key` opens, to its `mahi mcp` at `listener` on a thread of its own. Returns the
/// flag that stops it, and the palette's queue: `live`'s, or else this run's own.
fn serve_tools(
    listener: UnixListener,
    (owner, key, live): (
        Option<ParticipantKey>,
        Option<Arc<ThreadKey>>,
        Option<&Link>,
    ),
    git_dir: &Path,
    (started, note_by, lander): (&Started, NoteBy, Option<Arc<Lander>>),
) -> Arc<AtomicBool> {
    let serving = Arc::new(AtomicBool::new(true));
    let claims = live.map_or_else(|| Arc::new(Claims::default()), Link::claims);
    let Some(owner) = owner else {
        eprintln!("mahi: the agent's tools are off, since the thread's owner is not known");
        return serving;
    };
    let tools = ThreadTools::new(
        git_dir.to_path_buf(),
        (started.thread, owner, key),
        (started.slot.clone(), claims),
    )
    .with_note_by(note_by);
    let tools = match lander {
        Some(lander) => tools.with_lander(lander),
        None => tools,
    };
    let flag = Arc::clone(&serving);
    thread::spawn(move || {
        let toolbox: Arc<dyn Toolbox> = Arc::new(tools);
        mcp::serve(&listener, &flag, &toolbox);
    });
    serving
}

fn landing_desk(
    (store, environment, git_dir, limits): (&Store, &Environment, &Path, &Settings),
    (owner, key, raw): (Option<&ParticipantKey>, Option<&ThreadKey>, bool),
    (started, globals): (&Started, GlobalPatterns),
) -> Option<(Arc<Desk>, Arc<Lander>)> {
    if !(raw && terminal::is_interactive()) {
        return None;
    }
    let owner = owner.filter(|owner| *owner == started.commits.key())?;
    let meta = load_meta(store, started.thread, owner, 0).ok()?;
    let landing = meta.private(key?).ok()?.landing_branch().to_owned();
    let reach = (crate::sync::Reach::gather(environment), limits.clone());
    let (thread, slot) = (started.thread, &started.slot);
    let desk = Arc::new(Desk::new(
        (git_dir.to_path_buf(), thread),
        (slot.participant().clone(), note::file(store, thread, slot)),
        landing,
    ));
    let query = AutoMerge {
        git_dir: git_dir.to_path_buf(),
        thread,
        owner: owner.clone(),
        own: slot.clone(),
        waiting: Arc::default(),
    };
    let lander = Arc::new(Lander::new(
        (thread, slot.clone()),
        (session::worktree_name(thread, slot.agent()), globals),
        (store.user_identity(), reach, started.commits.clone()),
        (Arc::clone(&desk), query),
    ));
    land_desk::watch_turn_ends(&lander);
    Some((desk, lander))
}

/// Starts pushing the refs of `started`'s agent to the remote `setup` names, and returns the
/// pusher with the remote's name.
fn start_pusher(setup: SyncSetup, git_dir: &Path, started: &Started) -> (Pusher, RemoteName) {
    let refs = setup.refs(started.thread, &started.slot);
    let name = setup.name.clone();
    let limit = setup.push_limit;
    let pusher = Pusher::start(git_dir.to_path_buf(), (refs, limit), move |flag| {
        setup.connect(flag)
    });
    (pusher, name)
}

/// Takes the teammates' turn-end snapshots into the agent between its turns, on a thread of
/// its own while `running` is set.
fn spawn_auto_merge<A: AgentInput + Send + Sync + 'static, W: Write + Send + 'static>(
    auto_merge: AutoMerge,
    merger: Merger,
    (activity, agent, writer): (&Arc<Activity>, &Arc<A>, &Arc<Mutex<W>>),
    running: &Arc<AtomicBool>,
) {
    let (activity, agent, writer) = (Arc::clone(activity), Arc::clone(agent), Arc::clone(writer));
    let running = Arc::clone(running);
    thread::spawn(move || {
        auto_merge.run(
            &merger,
            (&activity, &*agent, &writer),
            (&running, Pace::default()),
        );
    });
}

/// Returns where `started`'s agent takes its teammates' work from between its turns, when its
/// profile reports turn ends and the thread's owner is known.
fn auto_merge(
    profile: Option<&Profile>,
    owner: Option<&ParticipantKey>,
    (git_dir, started): (&Path, &Started),
) -> Option<AutoMerge> {
    profile.and_then(Profile::turn_end_agent)?;
    Some(AutoMerge {
        git_dir: git_dir.to_path_buf(),
        thread: started.thread,
        owner: owner?.clone(),
        own: started.slot.clone(),
        waiting: Arc::default(),
    })
}

/// Joins the live layer for `started`'s agent, unless it is off; a failure is reported, and the
/// agent runs without it.
fn start_live(setup: Option<LiveSetup>, git_dir: &Path, started: &Started) -> Option<Link> {
    let (setup, key) = setup.zip(started.key.as_ref())?;
    LiveKeys::derive(key, started.thread)
        .map_err(HostError::from)
        .and_then(|keys| {
            Link::start(
                setup,
                git_dir,
                (started.slot.clone(), keys),
                terminal::size(),
            )
        })
        .inspect_err(|error| eprintln!("mahi: teammates cannot watch this thread: {error}"))
        .ok()
}

fn start_background(
    started: &mut Started,
    git_dir: &Path,
    globals: GlobalPatterns,
    (hooks, activity): (UnixListener, Arc<Activity>),
    pushes: Option<PushPoker>,
    session: Option<SessionSource>,
    key: Option<Arc<ThreadKey>>,
) -> (Option<Recorder>, Option<TurnWorker>) {
    let recorder = started.first_snapshot.take().map(|first| {
        Recorder::start(
            Target {
                git_dir: git_dir.to_path_buf(),
                slot: started.slot.clone(),
                worktree: session::worktree_name(started.thread, started.slot.agent()),
                snapshots: started.snapshots.clone(),
                globals,
                commits: started.commits.clone(),
            },
            first,
            Schedule::default(),
        )
    });
    let turns = key.map(|key| {
        let transcript = Transcript {
            git_dir: git_dir.to_path_buf(),
            key,
            thread: started.thread,
            slot: started.slot.clone(),
            tip: started.tip,
            commits: started.commits.clone(),
            session,
        };
        let events = recorder.as_ref().map(Recorder::events);
        let (messages, inputs) = mpsc::sync_channel(HOOK_QUEUE);
        let closing = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&closing);
        let context = Store::open(git_dir).ok().map(|store| NoteContext {
            file: note::file(&store, started.thread, &started.slot),
        });
        thread::spawn(move || {
            let context = context
                .as_ref()
                .map(|context| context as &dyn hook::Context);
            hook::serve(&hooks, &flag, &messages, (&activity, context));
        });
        let worker = thread::spawn(move || {
            turns::record(&transcript, &inputs, events.as_ref(), pushes.as_ref())
        });
        (closing, worker)
    });
    (recorder, turns)
}

type TurnWorker = (Arc<AtomicBool>, JoinHandle<Summary>);

/// What runs beside the agent and is finished after it: the snapshot recorder, the transcript
/// and the pusher.
struct Background {
    recorder: Option<Recorder>,
    turns: Option<TurnWorker>,
    pusher: Option<(Pusher, RemoteName)>,
    auto_merge: Option<AutoMerge>,
}

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
    if let Some(error) = summary.session_error {
        crate::report_with("the agent's session was not fully recorded", &error);
    }
}

/// What the user's side of a run needs: the key that opens the palette, and what the agent
/// and the user did last, to tell when the agent is idle.
struct UserSide {
    palette_key: PaletteKey,
    activity: Arc<Activity>,
    desk: Option<Arc<Desk>>,
}

fn finish_run(
    child: PtyChild,
    raw: Option<RawMode>,
    user: &UserSide,
    termination: TerminationSignals,
    background: Background,
    proxy: Option<Running>,
    live: Option<Link>,
) -> Result<Outcome, RunError> {
    let Background {
        recorder,
        turns,
        pusher,
        auto_merge,
    } = background;
    let (code, received, _signals) = supervise(
        child,
        raw,
        user,
        termination,
        AgentSide {
            tap: live.as_ref().map(Link::tap),
            merger: recorder.as_ref().map(Recorder::merger),
            auto_merge,
        },
    );
    if let Some(live) = live {
        live.stop();
    }
    if matches!(code, Ok(Outcome::Stopped(_))) {
        while received.try_recv().is_ok() {}
    }
    let abandon: Vec<Arc<AtomicBool>> = recorder
        .as_ref()
        .map(Recorder::abandon_flag)
        .into_iter()
        .chain(pusher.as_ref().map(|(pusher, _)| pusher.interrupt_flag()))
        .collect();
    let (caught, stopped) = mpsc::channel();
    thread::spawn(move || stop_on_signal(&received, &abandon, &caught));
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
    if let Some((pusher, name)) = pusher
        && let Some(told) = pusher.finish().report(&name)
    {
        eprint!("{told}");
    }
    match stopped.try_recv() {
        Ok(signal) => Ok(Outcome::Stopped(signal)),
        Err(_) => code,
    }
}

/// What the run hands the agent's side of the terminal: where its output is copied for
/// teammates, and the recorder's merges.
struct AgentSide {
    tap: Option<OutputTap>,
    merger: Option<Merger>,
    auto_merge: Option<AutoMerge>,
}

/// Passes the stop signals on as events until dropped, then stops listening, so a later
/// command in the same mahi, such as one run from the home screen, can listen again.
struct SignalWatch {
    quit: Option<UnixStream>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SignalWatch {
    fn start(termination: TerminationSignals, events: mpsc::Sender<Event>) -> io::Result<Self> {
        let (quit, quitting) = UnixStream::pair()?;
        let thread = thread::spawn(move || {
            loop {
                match mahi_sandbox::wait_readable(termination.as_fd(), quitting.as_fd()) {
                    Ok((_, true)) => return,
                    Ok((false, false)) => continue,
                    Ok((true, false)) | Err(_) => {}
                }
                let Ok(signal) = termination.wait() else {
                    return;
                };
                let _ = events.send(Event::Stopped(signal));
            }
        });
        Ok(Self {
            quit: Some(quit),
            thread: Some(thread),
        })
    }
}

impl Drop for SignalWatch {
    fn drop(&mut self) {
        drop(self.quit.take());
        if let Some(thread) = self.thread.take() {
            join_within(thread, THREAD_STOP_WAIT);
        }
    }
}

fn supervise(
    child: PtyChild,
    raw: Option<RawMode>,
    user: &UserSide,
    termination: TerminationSignals,
    side: AgentSide,
) -> (
    Result<Outcome, RunError>,
    Receiver<Event>,
    Option<SignalWatch>,
) {
    let (events, received) = mpsc::channel();
    let watch = match SignalWatch::start(termination, events.clone()) {
        Ok(watch) => Some(watch),
        Err(error) => return (Err(RunError::Output(error)), received, None),
    };
    let interactive = raw.is_some() && terminal::is_interactive();
    let AgentSide {
        tap,
        merger,
        auto_merge,
    } = side;
    let code = relay(
        child,
        (interactive.then_some(user.palette_key), user.desk.clone()),
        &user.activity,
        (events, &received),
        tap,
        (merger, auto_merge),
    );
    drop(raw);
    (code, received, watch)
}

fn stop_on_signal(
    received: &Receiver<Event>,
    abandon: &[Arc<AtomicBool>],
    caught: &mpsc::Sender<Termination>,
) {
    let mut stopping = false;
    while let Ok(event) = received.recv() {
        let Event::Stopped(signal) = event else {
            continue;
        };
        if stopping || abandon.is_empty() {
            stop_now(signal);
        }
        let _ = caught.send(signal);
        for flag in abandon {
            flag.store(true, Ordering::SeqCst);
        }
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
        return Err(RunError::NoMahiBinary(profile.name.as_str()));
    }
    let set = profile.set_names();
    match environment
        .pass_env
        .iter()
        .find(|passed| passed.required && set.contains(&passed.name.as_str()))
    {
        Some(passed) => Err(RunError::SetByProfile {
            name: passed.name.clone(),
            profile: profile.name.as_str(),
        }),
        None => Ok(()),
    }
}

/// Returns the directory that holds this repository's thread worktrees, under the user's
/// worktree root, after checking that it is not a private place and making sure it is a
/// directory of the user's that only the user can use.
pub(crate) fn worktree_dir(
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
        .map(|profile| profile.hosts.as_slice())
        .unwrap_or_default()
        .iter()
        .cloned();
    allowed.iter().cloned().chain(from_profile).collect()
}

fn stop_now(signal: Termination) -> ! {
    crate::ui::before_dying();
    signal.reraise();
    process::exit(128 + signal.number())
}

pub(crate) fn until_stopped<T>(
    termination: &TerminationSignals,
    work: impl FnOnce(&Arc<AtomicBool>) -> T,
) -> (T, Option<Termination>) {
    let interrupt = Arc::new(AtomicBool::new(false));
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

/// Where to restore the agent's recorded session, once its state directory is ready.
fn restore_of<'a>(
    store: &'a Store,
    session: Option<&'a SessionSource>,
    started: &'a Started,
) -> Option<Restore<'a>> {
    let (source, key) = session.zip(started.key.as_ref())?;
    Some(Restore {
        store,
        of: SessionOf {
            thread: started.thread,
            slot: &started.slot,
            key,
            own: started.commits.key(),
        },
        dir: &source.dir,
    })
}

struct Restore<'a> {
    store: &'a Store,
    of: SessionOf<'a>,
    dir: &'a str,
}

struct Launch<'a> {
    restore: Option<Restore<'a>>,
    credentials: &'a [Handed],
    profile: Option<&'static Profile>,
    approvals: AgentApprovals,
    state: Option<PathBuf>,
    config: &'a Path,
    arguments: &'a [OsString],
    environment: &'a Environment,
    agent: &'a Agent,
    worktree: &'a Path,
    git_dir: &'a Path,
    scratch: &'a Path,
    hook_socket: &'a Path,
    mcp_socket: &'a Path,
    host: &'a Host,
}

impl Launch<'_> {
    /// Returns whether the agent is asked to continue a conversation it has none of here: its
    /// arguments are its profile's resume arguments, and its state holds no session log for
    /// the worktree.
    fn continues_nothing(&self, state: Option<&Path>) -> bool {
        let (Some(profile), Some(state)) = (self.profile, state) else {
            return false;
        };
        let resuming = self.arguments.len() == profile.resume_args.len()
            && self
                .arguments
                .iter()
                .zip(&profile.resume_args)
                .all(|(given, resume)| given == resume.as_str());
        resuming && !profile.resume_args.is_empty() && !profile.has_session(state, self.worktree)
    }

    /// Adds the agent's arguments: the user's, then those its profile always adds, then those
    /// that start it asking no permission unless the user chose otherwise, then, when
    /// mahi serves the agent its tools, what its profile adds for them (a flag and the file in
    /// its state directory `state` that tells it where `mahi mcp` is, or the profile's tool
    /// arguments), then the user's after `--`.
    fn agent_arguments(&self, mut pty: PtyCommand, state: Option<&Path>) -> PtyCommand {
        let arguments = if self.continues_nothing(state) {
            eprintln!(
                "mahi: the agent has no conversation here to continue, so it starts a new one"
            );
            &[][..]
        } else {
            self.arguments
        };
        let (before, after) = split_at_separator(arguments);
        for argument in before {
            pty = pty.arg(argument);
        }
        for argument in self.profile.iter().flat_map(|profile| &profile.args) {
            pty = pty.arg(argument);
        }
        if let Some(profile) = self.profile {
            for argument in profile.approval_args(self.approvals, before) {
                pty = pty.arg(argument);
            }
        }
        if let (Some(profile), Some(tools)) = (self.profile, self.tools_config()) {
            match &profile.tools {
                Tools::None => {}
                Tools::McpFlag(flag) => {
                    if let Some(state) = state {
                        pty = pty.arg(flag).arg(state.join(profile::MCP_CONFIG));
                    }
                }
                Tools::Args(_) => {
                    match profile.tool_args(state.unwrap_or_else(|| Path::new("")), tools) {
                        Some(arguments) => {
                            for argument in arguments {
                                pty = pty.arg(argument);
                            }
                        }
                        None => eprintln!(
                            "mahi: the agent's tools are off, since a value the {} profile \
                             puts in its arguments holds a quote, a backslash or a control \
                             character",
                            profile.name
                        ),
                    }
                }
            }
        }
        for argument in after {
            pty = pty.arg(argument);
        }
        pty
    }

    /// Returns the mahi binary and the socket the agent's tools are served at, as text a
    /// profile's configuration can hold, when both are known and are UTF-8.
    fn tools_config(&self) -> Option<(&str, &str)> {
        let mahi = self.environment.mahi_exe.as_deref()?.to_str()?;
        Some((mahi, self.mcp_socket.to_str()?))
    }

    fn restore_session(&self, state: &Path) {
        let Some(restore) = &self.restore else {
            return;
        };
        let source = SessionSource {
            state: state.to_path_buf(),
            dir: restore.dir.to_owned(),
        };
        match session_sync::restore(restore.store, restore.of, &source) {
            Ok(0) => {}
            Ok(1) => eprintln!("mahi: restored the agent's session (1 file)"),
            Ok(count) => eprintln!("mahi: restored the agent's session ({count} files)"),
            Err(error) => crate::report_with("the agent's session was not restored", &error),
        }
    }

    /// Shows the agent its state directory `state`, writable but for the files that hold
    /// mahi's hooks.
    fn bind_state(&self, sandbox: &mut Sandbox, state: &Path) -> Result<(), RunError> {
        sandbox.bind(state, Access::ReadWrite)?;
        for name in self.profile.iter().flat_map(|profile| profile.hook_files()) {
            sandbox.bind(&state.join(name), Access::ReadOnly)?;
        }
        Ok(())
    }

    fn prepare_state(&self) -> Result<(Option<PathBuf>, Option<HookTrust>), RunError> {
        let (Some(profile), Some(state)) = (self.profile, &self.state) else {
            return Ok((None, None));
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
        let state_path = parent.join(name);
        profile
            .install(&directory, &state_path, self.worktree, self.tools_config())
            .map_err(RunError::State)?;
        if let Err(error) = profile.clear_sessions(&directory) {
            eprintln!(
                "mahi: the agent's sessions of an earlier run could not be cleared, so it may find \
                 no conversation to continue: {}",
                crate::describe(&error)
            );
        }
        let launched = match profile.seed_hook_trust(&directory, &state_path, self.config) {
            Ok(launched) => Some(launched),
            Err(error) => {
                crate::report_with("the approval of mahi's hooks was not carried over", &error);
                None
            }
        };
        Ok((Some(state_path), launched))
    }

    /// Shows the agent the repository's configuration cleaned of what it must not read, which
    /// [`write_git_config`] wrote in the scratch directory, in place of the repository's own.
    #[cfg(target_os = "linux")]
    fn place_git_config(&self, sandbox: &mut Sandbox) -> Result<Option<PathBuf>, RunError> {
        sandbox.place(
            &self.scratch.join(GIT_CONFIG_NAME),
            &self.git_dir.join("config"),
        )?;
        Ok(None)
    }

    /// Returns the git directory that [`write_git_config`] wrote in the scratch directory, for
    /// `GIT_COMMON_DIR`, since the agent cannot read the repository's own configuration.
    #[cfg(not(target_os = "linux"))]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the Linux version can fail, and both share one signature"
    )]
    fn place_git_config(&self, _sandbox: &mut Sandbox) -> Result<Option<PathBuf>, RunError> {
        Ok(Some(self.scratch.join(GIT_STAND_IN)))
    }

    /// Gives the agent the repository's cleaned configuration, as [`Self::place_git_config`]
    /// does, after checking that no system directory the sandbox shows already holds the whole
    /// git directory.
    fn give_git_config(&self, sandbox: &mut Sandbox) -> Result<Option<PathBuf>, RunError> {
        if sandbox.is_bound(self.git_dir) {
            return Err(RunError::GitDirectoryShown(self.git_dir.to_path_buf()));
        }
        self.place_git_config(sandbox)
    }

    fn spawn(&self, mut sandbox: Sandbox, network: Option<Network>) -> Result<Spawned, RunError> {
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
                access == Access::ReadOnly && path != git_file && !path.starts_with(self.git_dir);
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
        sandbox.allow_connect(self.mcp_socket)?;
        let git_common_dir = self.give_git_config(&mut sandbox)?;
        let (state, launched) = self.prepare_state()?;
        if let Some(state) = &state {
            self.restore_session(state);
            self.bind_state(&mut sandbox, state)?;
        }
        if let Some(network) = &network {
            sandbox.open_loopback_port(network.port())?;
        }
        let pty = PtyCommand::new(&self.agent.program, self.worktree, crate::terminal::size())
            .hold_terminal();
        let mut pty = self.agent_arguments(pty, state.as_deref());
        for (name, value) in &self.environment.passed_on {
            pty = pty.env(name, value);
        }
        let mut pty = pty
            .env("HOME", self.scratch.join(HOME))
            .env("TMPDIR", self.scratch.join(TMP))
            .env(HOOK_SOCKET, self.hook_socket)
            .env(MCP_SOCKET, self.mcp_socket);
        if let Some(common) = &git_common_dir {
            pty = pty.env(GIT_COMMON_DIR, common);
        }
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
                || (self.profile.is_some_and(|profile| {
                    profile
                        .optional_env
                        .iter()
                        .any(|name| name == passed.name.as_str())
                }) && !handed(passed.name.as_str()))
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
        if let Some(profile) = self.profile {
            if let (Some(variable), Some(state)) = (&profile.state_env, &state) {
                pty = pty.env(variable, state);
            }
            for (name, value) in &profile.env {
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
        Spawned::start(pty.spawn()?, raw, network, state.zip(launched))
    }
}

/// The agent a launch started, with the terminal mode and proxy it runs with, and its state
/// directory with the approvals of mahi's hooks it recorded at launch.
struct Spawned {
    child: PtyChild,
    raw: Option<RawMode>,
    proxy: Option<Running>,
    hook_trust: Option<(PathBuf, HookTrust)>,
}

impl Spawned {
    fn start(
        mut child: PtyChild,
        raw: Option<RawMode>,
        network: Option<Network>,
        hook_trust: Option<(PathBuf, HookTrust)>,
    ) -> Result<Self, RunError> {
        let proxy = network
            .map(|network| network.start(child.take_loopback_listener()))
            .transpose()?;
        Ok(Self {
            child,
            raw,
            proxy,
            hook_trust,
        })
    }
}

impl Host {
    pub(crate) fn from_environment(environment: &Environment) -> Result<Self, RunError> {
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
    (palette, desk): (Option<PaletteKey>, Option<Arc<Desk>>),
    activity: &Arc<Activity>,
    (events, received): (mpsc::Sender<Event>, &Receiver<Event>),
    tap: Option<OutputTap>,
    (merger, auto_merge): (Option<Merger>, Option<AutoMerge>),
) -> Result<Outcome, RunError> {
    let (stop, stopped) = UnixStream::pair().map_err(RunError::Output)?;
    let writer = Arc::new(Mutex::new(child.writer()?));
    let repainter = Repainter::new(child.resizer()?);
    let palette_key = palette.unwrap_or_default();
    let syncing = auto_merge.zip(merger);
    let waiting = syncing
        .as_ref()
        .filter(|_| palette.is_some())
        .map(|(auto_merge, _)| Arc::clone(&auto_merge.waiting));
    let desk = desk.filter(|_| palette.is_some());
    let screen = user_screen(
        Screen::new(io::stdout(), repainter.clone(), palette_key),
        (waiting.as_ref(), desk.as_ref()),
    );
    let running = Arc::new(AtomicBool::new(palette.is_some()));
    let commands = palette.and_then(|_| crate::commands::take());
    let key_opens = commands.is_none();
    if let Some(commands) = commands {
        let (opener, open) = (Arc::clone(&screen), Arc::clone(&running));
        thread::spawn(move || {
            crate::commands::listen(commands, || {
                if open.load(Ordering::SeqCst) {
                    let _ = open_palette(&opener);
                }
            });
        });
    }
    let input = palette.map(|key| (Arc::clone(&screen), KeyScanner::new(key), key_opens));
    let (input_writer, input_activity) = (Arc::clone(&writer), Arc::clone(activity));
    let (quit, quitting) = UnixStream::pair().map_err(RunError::Output)?;
    let input_quitting = quitting.try_clone().map_err(RunError::Output)?;
    let forwarding = thread::spawn(move || {
        forward_input(&input_writer, input, &input_activity, &input_quitting);
    });
    spawn_ticker(Arc::clone(&screen), Arc::clone(&running), (waiting, desk));
    if let Some((auto_merge, merger)) = syncing {
        spawn_auto_merge(auto_merge, merger, (activity, &screen, &writer), &running);
    }
    let following = follow_resizes(repainter, Arc::clone(&screen), tap.clone(), quitting);
    let mut reader = child.reader()?;
    let progress = Arc::new(AtomicU64::new(0));
    let output_events = events.clone();
    let output_progress = Arc::clone(&progress);
    let (output_screen, output_activity) = (Arc::clone(&screen), Arc::clone(activity));
    thread::spawn(move || {
        let ended = copy_output(
            (&mut reader, &stopped),
            &output_progress,
            tap.as_ref(),
            (&output_screen, &output_activity),
        );
        let _ = output_events.send(Event::OutputEnded(ended));
    });
    let child = Arc::new(Mutex::new(child));
    let waited = Arc::clone(&child);
    thread::spawn(move || {
        let _ = events.send(Event::Exited(wait_for(&waited)));
    });
    let outcome = await_outcome(&child, received, (&progress, stop));
    running.store(false, Ordering::SeqCst);
    drop(quit);
    join_within(forwarding, THREAD_STOP_WAIT);
    join_within(following, THREAD_STOP_WAIT);
    let _ = screen.close();
    outcome
}

/// Shares `screen`, listing the teammates' snapshots in `waiting` too when there is one, and
/// the landing that waits on `desk`.
fn user_screen(
    screen: UserScreen,
    (waiting, desk): (Option<&Arc<HeldQueue>>, Option<&Arc<Desk>>),
) -> Arc<UserScreen> {
    let screen = match waiting {
        Some(waiting) => screen.with_waiting(Arc::clone(waiting)),
        None => screen,
    };
    Arc::new(match desk {
        Some(desk) => screen.with_desk(Arc::clone(desk)),
        None => screen,
    })
}

/// Joins `thread` if it ends within `wait`, and otherwise leaves it running: one stuck writing
/// to a terminal a leftover process still holds must not hang mahi.
pub(crate) fn join_within(thread: thread::JoinHandle<()>, wait: Duration) {
    let deadline = Instant::now() + wait;
    while !thread.is_finished() && Instant::now() < deadline {
        thread::sleep(THREAD_POLL);
    }
    if thread.is_finished() {
        let _ = thread.join();
    }
}

/// Follows the user's terminal size into the agent's, until `quitting` becomes readable.
fn follow_resizes(
    repainter: Repainter,
    screen: Arc<UserScreen>,
    tap: Option<OutputTap>,
    quitting: UnixStream,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let Ok(changes) = WindowChanges::listen() else {
            return;
        };
        loop {
            match mahi_sandbox::wait_readable(changes.as_fd(), quitting.as_fd()) {
                Ok((_, true)) => break,
                Ok((false, false)) => continue,
                Ok((true, false)) | Err(_) => {}
            }
            if changes.wait().is_err() {
                break;
            }
            let Some(size) = repainter.follow() else {
                break;
            };
            let _ = screen.resized();
            if let Some(tap) = &tap {
                tap.resize(size);
            }
        }
    })
}

/// Ticks the palette's `screen` each second while `ticking` holds, and opens it on its own
/// when a teammate's snapshot comes to `waiting`.
fn spawn_ticker(
    screen: Arc<UserScreen>,
    ticking: Arc<AtomicBool>,
    (waiting, desk): (Option<Arc<HeldQueue>>, Option<Arc<Desk>>),
) {
    thread::spawn(move || {
        while ticking.load(Ordering::SeqCst) {
            thread::sleep(PALETTE_TICK);
            if screen.is_opening() {
                let _ = screen.open_now();
            }
            if waiting.as_ref().is_some_and(|waiting| waiting.wants_open())
                || desk.as_ref().is_some_and(|desk| desk.wants_open())
            {
                let _ = screen.open_guarded();
            }
            let _ = screen.tick();
        }
    });
}

fn await_outcome(
    child: &Mutex<PtyChild>,
    received: &Receiver<Event>,
    (progress, stop): (&AtomicU64, UnixStream),
) -> Result<Outcome, RunError> {
    let mut output_done = false;
    loop {
        match received.recv() {
            Ok(Event::Exited(code)) if output_done => return Ok(Outcome::Exited(code?)),
            Ok(Event::Exited(code)) => {
                return finish_output(received, (progress, stop), code?);
            }
            Ok(Event::OutputEnded(Ok(()))) => output_done = true,
            Ok(Event::OutputEnded(Err(error))) => {
                kill(child);
                return output_failure(error).map(Outcome::Exited);
            }
            Ok(Event::Stopped(signal)) => {
                kill(child);
                drop(stop);
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
        let (status, terminal) = match child.lock() {
            Ok(mut child) => {
                let status = child.try_wait()?;
                let terminal = status.and_then(|_| child.take_terminal());
                (status, terminal)
            }
            Err(_) => return Ok(1),
        };
        if let Some(status) = status {
            if let Some(terminal) = terminal {
                thread::spawn(move || drop(terminal));
            }
            return Ok(exit_code(status));
        }
        thread::sleep(EXIT_POLL);
    }
}

fn finish_output(
    received: &Receiver<Event>,
    (progress, stop): (&AtomicU64, UnixStream),
    code: i32,
) -> Result<Outcome, RunError> {
    let exited = Ok(Outcome::Exited(code));
    let give_up = |stop: UnixStream| {
        drop(stop);
        await_output_end(received);
        Ok(Outcome::Exited(code))
    };
    let mut seen = progress.load(Ordering::Relaxed);
    let deadline = Instant::now() + OUTPUT_LIMIT;
    loop {
        if Instant::now() > deadline {
            return give_up(stop);
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
                    return give_up(stop);
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
    (reader, stop): (&mut (impl Read + AsFd), &UnixStream),
    progress: &AtomicU64,
    tap: Option<&OutputTap>,
    screen: (&Screen<impl Write, impl AgentTerminal>, &Activity),
) -> io::Result<()> {
    let mut buffer = [0_u8; OUTPUT_READ];
    loop {
        match wait_for_output(reader, stop)? {
            Ready::Output => {
                if !copy_chunk(reader, &mut buffer, (progress, tap, screen))? {
                    return screen.0.close();
                }
            }
            Ready::Stop => {
                for _ in 0..DRAIN_CHUNKS {
                    if !(output_waiting(reader)?
                        && copy_chunk(reader, &mut buffer, (progress, tap, screen))?)
                    {
                        break;
                    }
                }
                return screen.0.close();
            }
        }
    }
}

fn copy_chunk(
    reader: &mut impl Read,
    buffer: &mut [u8],
    (progress, tap, (screen, activity)): (
        &AtomicU64,
        Option<&OutputTap>,
        (&Screen<impl Write, impl AgentTerminal>, &Activity),
    ),
) -> io::Result<bool> {
    let read = reader.read(buffer)?;
    let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
        return Ok(false);
    };
    activity.touched();
    screen.output(chunk)?;
    if let Some(tap) = tap {
        tap.output(chunk);
    }
    progress.fetch_add(1, Ordering::Relaxed);
    Ok(true)
}

enum Ready {
    Output,
    Stop,
}

fn wait_for_output(reader: &impl AsFd, stop: &UnixStream) -> io::Result<Ready> {
    loop {
        let mut fds = [
            PollFd::new(reader, PollFlags::IN),
            PollFd::new(stop, PollFlags::IN),
        ];
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {
                let [output, stop] = &fds;
                if !stop.revents().is_empty() {
                    return Ok(Ready::Stop);
                }
                if !output.revents().is_empty() {
                    return Ok(Ready::Output);
                }
            }
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn output_waiting(reader: &impl AsFd) -> io::Result<bool> {
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        let mut fds = [PollFd::new(reader, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&now)) {
            Ok(ready) => return Ok(ready > 0),
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

type UserScreen = Screen<io::Stdout, Repainter>;

fn forward_input(
    writer: &Mutex<File>,
    mut palette: Option<(Arc<UserScreen>, KeyScanner, bool)>,
    activity: &Activity,
    quitting: &UnixStream,
) {
    let input = io::stdin();
    let mut buffer = [0_u8; 4096];
    let mut last = b'\n';
    loop {
        match mahi_sandbox::wait_readable(input.as_fd(), quitting.as_fd()) {
            Ok((_, true)) => return,
            Ok((false, false)) => continue,
            Ok((true, false)) | Err(_) => {}
        }
        let read = match rustix::io::read(&input, &mut buffer) {
            Ok(read) => read,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return,
        };
        let Ok(mut writer) = writer.lock() else {
            return;
        };
        let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
            match &palette {
                Some((screen, ..)) => {
                    let _ = screen.close();
                }
                None => end_input(&mut writer, last),
            }
            return;
        };
        activity.touched();
        let forwarded = if let Some((screen, scanner, key_opens)) = &mut palette {
            route_keys(
                chunk,
                (scanner, *key_opens),
                screen,
                (&mut writer, activity),
            )
        } else {
            activity.keys(chunk);
            writer.write_all(chunk)
        };
        if forwarded.is_err() {
            return;
        }
        last = chunk.last().copied().unwrap_or(last);
    }
}

/// Routes the keys in `chunk` to the agent or to its palette while it is open; the palette
/// key closes an open palette and reaches the agent, and opens a closed one only when
/// `key_opens`, since a workspace that started this mahi opens it otherwise.
fn route_keys(
    chunk: &[u8],
    (scanner, key_opens): (&mut KeyScanner, bool),
    screen: &UserScreen,
    (writer, activity): (&mut File, &Activity),
) -> io::Result<()> {
    for segment in scanner.scan(chunk) {
        match segment {
            Segment::Palette(key) if screen.is_open() || !key_opens => {
                if screen.is_open() {
                    screen.close()?;
                }
                activity.keys(key);
                writer.write_all(key)?;
            }
            Segment::Palette(_) => open_palette(screen)?,
            Segment::Pass(bytes) => pass_keys(bytes, screen, (writer, activity))?,
        }
    }
    Ok(())
}

fn pass_keys(
    bytes: &[u8],
    screen: &UserScreen,
    (writer, activity): (&mut File, &Activity),
) -> io::Result<()> {
    let used = screen.typed(bytes)?;
    let forwarded = bytes.get(used..).unwrap_or_default();
    activity.keys(forwarded);
    writer.write_all(forwarded)
}

fn open_palette(screen: &UserScreen) -> io::Result<()> {
    screen.open()?;
    let deadline = Instant::now() + PALETTE_WAIT;
    while screen.is_opening() && Instant::now() < deadline {
        thread::sleep(PALETTE_POLL);
    }
    screen.open_now()
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

/// Returns whether `program`, a file name, is an executable in one of `search_path`'s
/// absolute directories.
pub(crate) fn is_on_path(program: &str, search_path: Option<&OsStr>) -> bool {
    absolute_directories(search_path).any(|directory| is_executable(&directory.join(program)))
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
    for path in [cwd, scratch] {
        if !covered(&binds, path) {
            binds.push((path.to_path_buf(), Access::ReadWrite));
        }
    }
    binds.extend(git_binds(cwd, git_dir)?);
    let program_directories = [&agent.program, &agent.canonical]
        .into_iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf));
    for directory in absolute_directories(search_path).chain(program_directories) {
        let Ok(directory) = fs::canonicalize(directory) else {
            continue;
        };
        if !covered(&binds, &directory)
            && !host.is_private(&directory)
            && !git_dir.starts_with(&directory)
            && !directory.starts_with(git_dir)
        {
            binds.push((directory, Access::ReadOnly));
        }
    }
    for program in [&agent.program, &agent.canonical] {
        if !covered(&binds, program) && !program.starts_with(git_dir) {
            binds.push((program.clone(), Access::ReadOnly));
        }
    }
    Ok(binds)
}

/// The parts of the repository's git directory `git_dir` that git needs in the worktree `cwd`,
/// read-only: the worktree's `.git` file, its own record in `worktrees/`, and the objects and
/// refs. The configuration, the remotes, the other worktrees and mahi's own files are left out.
fn git_binds(cwd: &Path, git_dir: &Path) -> Result<Vec<(PathBuf, Access)>, RunError> {
    let link = cwd.join(".git");
    let metadata = match link.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(RunError::GitDirectory(error)),
    };
    if !metadata.is_file() {
        return Err(RunError::NotLinkedWorktree(cwd.to_path_buf()));
    }
    let admin = linked_admin(&link, git_dir)
        .ok_or_else(|| RunError::NotLinkedWorktree(cwd.to_path_buf()))?;
    if admin.join(WORKTREE_CONFIG).symlink_metadata().is_ok() {
        return Err(RunError::WorktreeConfig(admin.join(WORKTREE_CONFIG)));
    }
    let mut binds = vec![(link, Access::ReadOnly), (admin, Access::ReadOnly)];
    for name in GIT_SHARED {
        let path = git_dir.join(name);
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| !metadata.is_symlink())
        {
            binds.push((path, Access::ReadOnly));
        }
    }
    Ok(binds)
}

/// Returns the record in `git_dir`'s `worktrees/` that the `.git` file `link` points to, when
/// it points to one.
fn linked_admin(link: &Path, git_dir: &Path) -> Option<PathBuf> {
    let mut text = Vec::new();
    File::open(link)
        .ok()?
        .take(MAX_GIT_LINK_BYTES)
        .read_to_end(&mut text)
        .ok()?;
    let target = text.strip_prefix(b"gitdir: ")?;
    let target = target.strip_suffix(b"\n").unwrap_or(target);
    let target = Path::new(OsStr::from_bytes(
        target.strip_suffix(b"\r").unwrap_or(target),
    ));
    let admin = fs::canonicalize(link.parent()?.join(target)).ok()?;
    let name = admin.file_name()?;
    (admin.parent()? == git_dir.join("worktrees") && !name.as_bytes().starts_with(b"."))
        .then_some(admin)
}

/// Chooses how the user's terminal, as `environment` describes it, raises a notification.
pub(crate) fn notice(environment: &Environment) -> Notice {
    Notice::for_terminal(TerminalHints {
        term: environment.term.as_deref(),
        term_program: environment.term_program.as_deref(),
        kitty: environment.kitty,
        vte: environment.vte,
        tmux: environment.tmux,
    })
}

/// Writes in the fresh `scratch` directory the repository's configuration `config`, cleaned of
/// what the agent must not read, where the agent's git reads it: a file shown in place of the
/// repository's own on Linux, and on macOS a git directory of its own with links to the parts
/// of `git_dir` the agent may read.
#[cfg(target_os = "linux")]
fn write_git_config(scratch: &Path, config: &str, _git_dir: &Path) -> io::Result<()> {
    write_private(&scratch.join(GIT_CONFIG_NAME), config.as_bytes())
}

/// Writes in the fresh `scratch` directory the repository's configuration `config`, cleaned of
/// what the agent must not read, where the agent's git reads it: a file shown in place of the
/// repository's own on Linux, and on macOS a git directory of its own with links to the parts
/// of `git_dir` the agent may read.
#[cfg(not(target_os = "linux"))]
fn write_git_config(scratch: &Path, config: &str, git_dir: &Path) -> io::Result<()> {
    let common = scratch.join(GIT_STAND_IN);
    fs::create_dir(&common)?;
    write_private(&common.join("config"), config.as_bytes())?;
    for name in GIT_SHARED {
        std::os::unix::fs::symlink(git_dir.join(name), common.join(name))?;
    }
    Ok(())
}

fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resume_refuses_a_watcher_and_an_agent_without_turn_ends_beside_a_teammate() {
        use crate::workspace_live::tests::{
            add_bob,
            setup,
            sign_participant,
        };

        let setup = setup();
        let owner = setup.owner();
        let alice: ParticipantName = "alice".parse().unwrap();
        let claude = Profile::for_agent(OsStr::new("claude"));
        assert!(claude.and_then(Profile::turn_end_agent).is_some());
        let check = |user: (&ParticipantKey, &ParticipantName), program: &str, profile| {
            let meta = load_meta(&setup.store, setup.thread, &owner, 0).unwrap();
            may_run(&meta, setup.thread, user, (OsStr::new(program), profile))
        };
        assert!(check((&owner, &alice), "/opt/tools/tester.sh", None).is_ok());
        let bob = add_bob(&setup, Role::Watcher);
        assert!(check((&owner, &alice), "/opt/tools/tester.sh", None).is_ok());
        assert!(matches!(
            check((bob.key(), bob.name()), "claude", claude),
            Err(RunError::Watcher { owner, thread }) if owner == alice && thread == setup.thread
        ));
        sign_participant(&setup, bob.clone().with_role(Role::Collaborator));
        assert!(matches!(
            check((&owner, &alice), "/opt/tools/tester.sh", None),
            Err(RunError::NoTurnEnds(name)) if name == "tester.sh"
        ));
        assert!(matches!(
            check((bob.key(), bob.name()), "claude", None),
            Err(RunError::NoTurnEnds(name)) if name == "claude"
        ));
        assert!(check((bob.key(), bob.name()), "claude", claude).is_ok());
        assert!(check((&owner, &alice), "claude", claude).is_ok());
        assert!(matches!(
            check((&owner, bob.name()), "claude", claude),
            Err(RunError::NotListed(..))
        ));
    }

    #[test]
    fn a_watcher_without_an_agent_is_told_they_watch() {
        use crate::workspace_live::tests::{
            add_bob,
            setup,
        };

        let setup = setup();
        let owner = setup.owner();
        let bob = add_bob(&setup, Role::Watcher);
        assert!(matches!(
            no_agent(&setup.store, setup.thread, &owner, bob.key()),
            RunError::Watcher { thread, .. } if thread == setup.thread
        ));
        assert!(matches!(
            no_agent(&setup.store, setup.thread, &owner, &owner),
            RunError::Resume(ResumeError::NoAgent(thread)) if thread == setup.thread
        ));
    }

    struct StillTerminal;

    impl AgentTerminal for StillTerminal {
        fn size(&self) -> mahi_sandbox::WindowSize {
            mahi_sandbox::WindowSize { rows: 24, cols: 80 }
        }

        fn repaint(&self) {}
    }

    struct StallingOnce {
        written: Arc<Mutex<Vec<u8>>>,
        stall: Option<Duration>,
    }

    impl Write for StallingOnce {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(stall) = self.stall.take() {
                thread::sleep(stall);
            }
            self.written.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_already_read_when_waiting_for_the_terminal_ends_is_still_shown() {
        let (mut agent, mut terminal) = UnixStream::pair().unwrap();
        let (stop, stopped) = UnixStream::pair().unwrap();
        let written = Arc::new(Mutex::new(Vec::new()));
        let screen = Screen::new(
            StallingOnce {
                written: Arc::clone(&written),
                stall: Some(OUTPUT_GRACE * 3),
            },
            StillTerminal,
            PaletteKey::default(),
        );
        let progress = Arc::new(AtomicU64::new(0));
        let (events, received) = mpsc::channel();
        let copied = Arc::clone(&progress);
        agent.write_all(b"first ").unwrap();
        thread::spawn(move || {
            let ended = copy_output(
                (&mut terminal, &stopped),
                &copied,
                None,
                (&screen, &Activity::default()),
            );
            let _ = events.send(Event::OutputEnded(ended));
        });
        thread::sleep(Duration::from_millis(100));
        agent.write_all(b"last words").unwrap();

        let outcome = finish_output(&received, (&progress, stop), 0).unwrap();

        assert_eq!(outcome, Outcome::Exited(0));
        assert_eq!(*written.lock().unwrap(), b"first last words");
    }

    #[test]
    fn output_longer_than_one_read_reaches_the_screen_whole_and_in_order() {
        let (mut agent, mut terminal) = UnixStream::pair().unwrap();
        let (_stop, stopped) = UnixStream::pair().unwrap();
        let written = Arc::new(Mutex::new(Vec::new()));
        let screen = Screen::new(
            StallingOnce {
                written: Arc::clone(&written),
                stall: None,
            },
            StillTerminal,
            PaletteKey::default(),
        );
        let sent: Vec<u8> = (0..OUTPUT_READ * 5 + 7)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let writer = {
            let sent = sent.clone();
            thread::spawn(move || agent.write_all(&sent).unwrap())
        };
        let progress = AtomicU64::new(0);

        copy_output(
            (&mut terminal, &stopped),
            &progress,
            None,
            (&screen, &Activity::default()),
        )
        .unwrap();

        writer.join().unwrap();
        assert_eq!(*written.lock().unwrap(), sent);
    }

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

    fn linked_worktree(root: &Path) -> (PathBuf, PathBuf) {
        let git = root.join("repo/.git");
        let worktree = git.join("mahi/worktrees/a");
        let admin = git.join("worktrees/a");
        for directory in [
            &worktree,
            &admin,
            &git.join("objects"),
            &git.join("refs"),
            &git.join("mahi/worktrees/b"),
            &git.join("modules"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(
            git.join("config"),
            "[remote \"origin\"]\n\turl = https://u:t@h/r\n",
        )
        .unwrap();
        fs::write(git.join("packed-refs"), "").unwrap();
        fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", admin.display()),
        )
        .unwrap();
        (git, worktree)
    }

    #[test]
    fn only_the_parts_of_the_git_directory_git_needs_are_bound() {
        let (_dir, root) = canonical_tempdir();
        let (git, worktree) = linked_worktree(&root);
        let search = env::join_paths([root.join("repo"), root.join("repo/.git/hooks")]).unwrap();
        fs::create_dir_all(git.join("hooks")).unwrap();
        let agent = agent_at(Path::new("/usr/bin/true"));
        let binds = binds(
            &worktree,
            &git,
            &agent,
            &root.join("scratch"),
            Some(&search),
            &host_with_home(&root.join("home")),
        )
        .unwrap();
        let bound: Vec<&Path> = binds.iter().map(|(path, _)| path.as_path()).collect();
        for expected in [
            worktree.join(".git"),
            git.join("worktrees/a"),
            git.join("objects"),
            git.join("refs"),
            git.join("packed-refs"),
        ] {
            assert!(
                binds.contains(&(expected.clone(), Access::ReadOnly)),
                "{} missing: {bound:?}",
                expected.display()
            );
        }
        for above in [&git, &root.join("repo")] {
            assert!(
                !bound.iter().any(|path| above.starts_with(path)),
                "{} is reachable: {bound:?}",
                above.display()
            );
        }
        for hidden in [
            git.join("config"),
            git.join("mahi/worktrees/b"),
            git.join("modules"),
            git.join("hooks"),
        ] {
            assert!(
                !bound
                    .iter()
                    .any(|path| hidden.starts_with(path) || path.starts_with(&hidden)),
                "{} is reachable: {bound:?}",
                hidden.display()
            );
        }
    }

    #[test]
    fn a_working_directory_that_is_not_a_linked_worktree_is_refused() {
        let (_dir, root) = canonical_tempdir();
        let (git, worktree) = linked_worktree(&root);
        let agent = agent_at(Path::new("/usr/bin/true"));
        let host = host_with_home(&root.join("home"));
        let attempt = |cwd: &Path| binds(cwd, &git, &agent, Path::new("/scratch"), None, &host);
        let checkout = root.join("checkout");
        fs::create_dir_all(checkout.join(".git")).unwrap();
        assert!(matches!(
            attempt(&checkout),
            Err(RunError::NotLinkedWorktree(_))
        ));
        fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", git.display()),
        )
        .unwrap();
        assert!(matches!(
            attempt(&worktree),
            Err(RunError::NotLinkedWorktree(_))
        ));
        fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", git.join("worktrees/a").display()),
        )
        .unwrap();
        assert!(attempt(&worktree).is_ok());
        fs::write(worktree.join(".git"), "gitdir: ../../../worktrees/a\r\n").unwrap();
        assert!(attempt(&worktree).is_ok());
        fs::write(worktree.join(".git"), "gitdir: ../../../worktrees/b").unwrap();
        assert!(matches!(
            attempt(&worktree),
            Err(RunError::NotLinkedWorktree(_))
        ));
        fs::write(worktree.join(".git"), "gitdir: ../../../worktrees/a\n").unwrap();
        fs::write(git.join("worktrees/a/config.worktree"), "").unwrap();
        assert!(matches!(
            attempt(&worktree),
            Err(RunError::WorktreeConfig(_))
        ));
    }

    #[test]
    fn options_go_before_the_agents_first_separator() {
        let arguments: Vec<OsString> = ["--continue", "--", "a prompt", "--"]
            .into_iter()
            .map(OsString::from)
            .collect();
        let (before, after) = split_at_separator(&arguments);
        assert_eq!(before, &arguments[..1]);
        assert_eq!(after, &arguments[1..]);
        let plain = [OsString::from("x")];
        assert_eq!(split_at_separator(&plain), (&plain[..], &[][..]));
    }
}
