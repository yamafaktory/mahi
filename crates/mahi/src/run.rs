use std::{
    env,
    ffi::{
        OsStr,
        OsString,
    },
    fmt::{
        self,
        Write as _,
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
    mem,
    os::unix::{
        ffi::OsStrExt,
        fs::{
            OpenOptionsExt,
            PermissionsExt,
        },
        io::OwnedFd,
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
    AgentName,
    AgentSlot,
    NameError,
    ParticipantName,
    RefKind,
    ThreadId,
    ThreadRef,
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
    LiveKeys,
    PromptOutcome,
    PromptText,
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
    ParticipantKey,
    VerifiedMeta,
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
    claims::Claims,
    cli::{
        AgentAddCommand,
        HandoffCommand,
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
    handoff::{
        self,
        HandoffError,
    },
    hook,
    hub::{
        Link,
        OutputTap,
    },
    inject::{
        self,
        Activity,
        AgentInput,
        Pace,
    },
    live::{
        self,
        HostError,
        LiveSetup,
    },
    mcp::{
        self,
        ThreadTools,
        Toolbox,
    },
    merge::{
        MergeDone,
        MergeRequest,
    },
    merge_door::{
        self,
        MergeDoor,
    },
    merged::MergedFrom,
    network::{
        Network,
        NetworkError,
        Running,
    },
    palette::{
        Repainter,
        Screen,
    },
    profile::{
        self,
        Profile,
    },
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    prompts::{
        Arrival,
        Prompts,
    },
    recorder::{
        Merger,
        RecordError,
        Recorder,
        Target,
    },
    remote::RemoteName,
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
const MCP_SOCKET_NAME: &str = "mcp.sock";
const HANDOFF_NOTES: &str = "mahi-handoff.md";
const DRAFT_NAME: &str = "PR.md";
const MAX_DRAFT_BYTES: u64 = 256 * 1024;
const HANDOFF_ENV: &str = "MAHI_HANDOFF";
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
const PALETTE_WAIT: Duration = Duration::from_millis(200);
const PALETTE_POLL: Duration = Duration::from_millis(10);
const PALETTE_TICK: Duration = Duration::from_secs(1);
const BROKEN_PIPE_CODE: i32 = 128 + 13;

#[derive(Debug, Error)]
pub(crate) enum RunError {
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
    #[error(
        "thread {0} does not list your signing key for {1}; resume as the user who started or joined it"
    )]
    NotListed(ThreadId, ParticipantName),
    #[error(
        "this clone has a worktree for thread {0}, whose files would hide what is taken from the remote; record and remove it with mahi end, or resume without --take-remote"
    )]
    WorktreeHere(ThreadId),
    #[error(
        "you already have an agent called {1} in thread {0}; resume it with mahi resume --agent {1}"
    )]
    AgentThere(ThreadId, AgentName),
    #[error("thread {0} does not list a participant called {1}")]
    SourceNotListed(ThreadId, ParticipantName),
    #[error(
        "{0} has no snapshot here; fetch the thread first, or check the name with mahi threads"
    )]
    NoSourceSnapshot(AgentSlot),
    #[error("cannot read the previous agent's work")]
    Handoff(#[from] HandoffError),
    #[error("cannot write the handoff notes")]
    HandoffNotes(#[source] io::Error),
    #[error("cannot give the agent the pull request draft")]
    Draft(#[source] io::Error),
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
    prepared.palette_key = settings.palette_key;
    prepared.set_thread(live, own_key(&signing)?);
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
    let owner = session::thread_owner(&store, command.thread, own.clone())
        .map_err(|error| RunError::ThreadOwner(command.thread, error))?;
    let owns_meta = owner == own;
    let bootstrap: Vec<HostAddress> = live::remembered_host(&store, command.thread)
        .into_iter()
        .collect();
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
    let slot = session::pick_slot(&store, command.thread, &participant, command.agent.as_ref())?;
    let _agent_lock = (!command.take_remote)
        .then(|| AgentLock::acquire(&config, command.thread, slot.agent()))
        .transpose()?;
    let (program, arguments, profile) = resumed_command(command, &slot);
    let hosts = allowed_hosts(command.options.allow_hosts(), profile);
    let settings = Settings::load(&config)?;
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
    prepared.palette_key = settings.palette_key;
    prepared.join_thread(environment, &config, owner.clone(), bootstrap)?;
    prepared.sync = SyncSetup::gather(&prepared.store, environment, owns_meta);
    let commits = match listed_and_fetched(
        &prepared.store,
        environment,
        (command.thread, !command.take_remote),
        &owner,
        (&own, &participant),
        &signing,
        taken,
    )? {
        Ok(commits) => commits,
        Err(signal) => return Ok(Outcome::Stopped(signal)),
    };
    let passphrase = TerminalPrompt::open()
        .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
        .map_err(RunError::Terminal)?;
    let identity =
        LocalIdentity::load(&config.identity_file(), &passphrase).map_err(RunError::Unlock)?;
    drop(passphrase);
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
    prepared.launch(environment, started?, termination)
}

/// Checks that the thread's `meta` lists the user's key `own` under the name `participant`,
/// fetches the thread as that participant when `fetch` is set, and
/// returns the key that signs the user's commits: `signer`, or one made from `signing`. The
/// inner `Err` is the signal that stopped the fetch.
pub(crate) fn listed_and_fetched(
    store: &Store,
    environment: &Environment,
    (thread, fetch): (ThreadId, bool),
    owner: &ParticipantKey,
    (own, participant): (&ParticipantKey, &ParticipantName),
    signing: &SigningKey,
    signer: Option<AgentSigner>,
) -> Result<Result<CommitKey, Termination>, RunError> {
    let current = load_meta(store, thread, owner, 0)
        .map_err(|error| ResumeError::Meta(thread, Box::new(error)))?;
    let me = current
        .participants()
        .find(|listed| listed.key() == own)
        .filter(|listed| listed.name() == participant)
        .ok_or_else(|| RunError::NotListed(thread, participant.clone()))?;
    let signer = match signer {
        Some(signer) => signer,
        None => agent_signer(environment, signing)?,
    };
    if fetch {
        let stopped = sync::fetch_until_stopped(store, environment, thread, owner, Some(me.name()));
        if let Some(signal) = stopped {
            return Ok(Err(signal));
        }
        load_meta(store, thread, owner, current.generation())
            .map_err(|error| ResumeError::Meta(thread, Box::new(error)))?;
    }
    Ok(Ok(CommitKey::new(signer).map_err(RunError::OwnerKey)?))
}

/// Starts the user's new agent on the work of `command.from` in `command.thread`: in a
/// worktree holding that agent's latest snapshot, with a briefing of what it was asked and did.
pub(crate) fn handoff(
    command: &HandoffCommand,
    environment: &Environment,
) -> Result<Outcome, RunError> {
    start_new_agent(
        command.thread,
        (&command.command, &command.options),
        Start::Handoff(&command.from),
        environment,
    )
}

/// Starts another of the user's agents in `command.thread`, next to the ones already running,
/// in its own worktree: from the thread's base, or from `command.from`'s latest snapshot.
pub(crate) fn agent_add(
    command: &AgentAddCommand,
    environment: &Environment,
) -> Result<Outcome, RunError> {
    start_new_agent(
        command.thread,
        (&command.command, &command.options),
        Start::Fresh(command.from.as_ref()),
        environment,
    )
}

/// Where a new agent of the user's starts in a thread.
#[derive(Clone, Copy, Debug)]
enum Start<'a> {
    /// From this agent's latest snapshot, with a briefing of its work.
    Handoff(&'a AgentSlot),
    /// From this agent's latest snapshot, or else the thread's base, without a briefing.
    Fresh(Option<&'a AgentSlot>),
}

fn start_new_agent(
    thread: ThreadId,
    (command, options): (&[OsString], &LaunchOptions),
    start: Start<'_>,
    environment: &Environment,
) -> Result<Outcome, RunError> {
    let (program, arguments) = command.split_first().ok_or(RunError::NoAgent)?;
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
    let owner = session::thread_owner(&store, thread, own.clone())
        .map_err(|error| RunError::ThreadOwner(thread, error))?;
    let bootstrap: Vec<HostAddress> = live::remembered_host(&store, thread).into_iter().collect();
    let agent_name = session::agent_from(Path::new(program));
    let _lock = AgentLock::acquire(&config, thread, &agent_name)?;
    let slot = AgentSlot::new(participant.clone(), agent_name.clone());
    if store
        .head(&ThreadRef::new(thread, RefKind::Snapshots(slot.clone())))?
        .is_some()
    {
        return Err(RunError::AgentThere(thread, agent_name));
    }
    let profile = options.profile_for(program);
    let hosts = allowed_hosts(options.allow_hosts(), profile);
    let settings = Settings::load(&config)?;
    let credentials = gather_credentials(&config, options, profile, environment)?;
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
    prepared.palette_key = settings.palette_key;
    prepared.join_thread(environment, &config, owner.clone(), bootstrap)?;
    prepared.sync = SyncSetup::gather(&prepared.store, environment, owner == own);
    let commits = match listed_and_fetched(
        &prepared.store,
        environment,
        (thread, true),
        &owner,
        (&own, &participant),
        &signing,
        None,
    )? {
        Ok(commits) => commits,
        Err(signal) => return Ok(Outcome::Stopped(signal)),
    };
    let meta = load_meta(&prepared.store, thread, &owner, 0)
        .map_err(|error| ResumeError::Meta(thread, Box::new(error)))?;
    let (key, contents, merged) = starting_point(
        start,
        &mut prepared,
        &meta,
        &participant,
        &config,
        &agent_name,
    )?;
    let worktrees = worktree_dir(environment, &prepared.host, &prepared.git_dir)?;
    let termination = TerminationSignals::listen().map_err(RunError::Signals)?;
    let (started, caught) = until_stopped(&termination, |interrupt| {
        session::hand_over(
            &prepared.store,
            session::HandOver {
                thread,
                base: meta.base(),
                key,
                slot,
                contents,
                merged,
                worktrees: &worktrees,
                commits: &commits,
            },
            &prepared.globals,
            interrupt,
        )
    });
    if let Some(signal) = caught {
        return Ok(Outcome::Stopped(signal));
    }
    let started = started
        .inspect_err(|_| {
            let _ = fs::remove_dir(&worktrees);
        })
        .map_err(|error| RunError::Enter(Box::new(error)))?;
    if let Err(error) = keep_private(&worktrees) {
        started.discard_or_report(&prepared.store);
        return Err(error);
    }
    prepared.launch(environment, started, termination)
}

/// Returns the thread key, the tree a new agent's worktree starts from and the snapshot it
/// takes from another agent, if any, writing its briefing first for a handoff.
fn starting_point(
    start: Start<'_>,
    prepared: &mut Prepared,
    meta: &VerifiedMeta,
    participant: &ParticipantName,
    config: &ConfigDir,
    agent_name: &AgentName,
) -> Result<(ThreadKey, ObjectId, MergedFrom), RunError> {
    let mut merged = MergedFrom::default();
    match start {
        Start::Handoff(from) => {
            let (key, (commit, contents)) = brief(prepared, meta, from, participant, config)?;
            eprintln!("mahi: handing {from}'s work over to {agent_name}");
            merged.record(from.clone(), commit);
            Ok((key, contents, merged))
        }
        Start::Fresh(Some(from)) => {
            let (commit, contents) = source_snapshot(&prepared.store, meta, from)?;
            let key = unlock_thread_key(meta, participant, config)?;
            eprintln!("mahi: starting {agent_name} from {from}'s latest snapshot");
            merged.record(from.clone(), commit);
            Ok((key, contents, merged))
        }
        Start::Fresh(None) => {
            let contents = prepared.store.commit_tree(meta.base())?;
            let key = unlock_thread_key(meta, participant, config)?;
            eprintln!("mahi: starting {agent_name} from the thread's base");
            Ok((key, contents, merged))
        }
    }
}

/// Checks that `meta` lists `from`'s participant and that `from` has a snapshot, then asks for
/// the passphrase and writes the briefing of `from`'s work for the agent. Returns the thread
/// key, and `from`'s latest snapshot with its tree.
fn brief(
    prepared: &mut Prepared,
    meta: &VerifiedMeta,
    from: &AgentSlot,
    participant: &ParticipantName,
    config: &ConfigDir,
) -> Result<(ThreadKey, (ObjectId, ObjectId)), RunError> {
    let (commit, contents) = source_snapshot(&prepared.store, meta, from)?;
    let key = unlock_thread_key(meta, participant, config)?;
    let notes =
        handoff::briefing(&prepared.store, &key, meta, from, (meta.base(), contents))?.render();
    prepared.write_handoff(&notes)?;
    Ok((key, (commit, contents)))
}

/// Returns `from`'s latest snapshot and its tree, once `meta` lists `from`'s participant.
pub(crate) fn source_snapshot(
    store: &Store,
    meta: &VerifiedMeta,
    from: &AgentSlot,
) -> Result<(ObjectId, ObjectId), RunError> {
    let thread = meta.thread();
    if !meta
        .participants()
        .any(|listed| listed.name() == from.participant())
    {
        return Err(RunError::SourceNotListed(
            thread,
            from.participant().clone(),
        ));
    }
    let source = store
        .head(&ThreadRef::new(thread, RefKind::Snapshots(from.clone())))?
        .ok_or_else(|| RunError::NoSourceSnapshot(from.clone()))?;
    Ok((source, store.commit_tree(source)?))
}

/// Asks for the passphrase of the user's mahi key and opens `meta`'s thread key with it.
pub(crate) fn unlock_thread_key(
    meta: &VerifiedMeta,
    participant: &ParticipantName,
    config: &ConfigDir,
) -> Result<ThreadKey, RunError> {
    let passphrase = TerminalPrompt::open()
        .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
        .map_err(RunError::Terminal)?;
    let identity =
        LocalIdentity::load(&config.identity_file(), &passphrase).map_err(RunError::Unlock)?;
    drop(passphrase);
    meta.thread_key(participant, identity.as_age())
        .map_err(|error| ResumeError::NotParticipant(meta.thread(), Box::new(error)).into())
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
    prepared.palette_key = settings.palette_key;
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
    mcp_socket: PathBuf,
    mcp: UnixListener,
    owner: Option<ParticipantKey>,
    sandbox: Sandbox,
    network: Option<Network>,
    globals: GlobalPatterns,
    credentials: Vec<Handed>,
    live: Option<LiveSetup>,
    sync: Option<SyncSetup>,
    handoff: Option<PathBuf>,
    palette_key: PaletteKey,
}

impl Prepared {
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

    /// Writes the handoff notes into the agent's private temporary directory, readable by the
    /// user only, and hands them to the agent when it starts.
    fn write_handoff(&mut self, notes: &str) -> Result<(), RunError> {
        let path = self.scratch.join(TMP).join(HANDOFF_NOTES);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(RunError::HandoffNotes)?;
        file.write_all(notes.as_bytes())
            .map_err(RunError::HandoffNotes)?;
        self.handoff = Some(path);
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
            handoff: None,
            palette_key: PaletteKey::default(),
        })
    }

    /// Returns where the agent keeps its session, when its profile names a directory for it.
    fn session_source(&self, started: &Started) -> Option<SessionSource> {
        self.profile.and_then(|profile| profile.session_dir).and_then(|dir| {
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
        if terminal::is_interactive() {
            eprintln!(
                "mahi: {} opens mahi's palette (palette-key in config.toml changes it)",
                self.palette_key
            );
        }
    }

    fn launch(
        mut self,
        environment: &Environment,
        mut started: Started,
        termination: TerminationSignals,
    ) -> Result<Outcome, RunError> {
        self.announce(&started);
        let session = self.session_source(&started);
        let restore = session
            .as_ref()
            .zip(started.key.as_ref())
            .map(|(source, key)| Restore {
                store: &self.store,
                of: SessionOf {
                    thread: started.thread,
                    slot: &started.slot,
                    key,
                    own: started.commits.key(),
                },
                dir: &source.dir,
            });
        let launch = Launch {
            restore,
            handoff: self.handoff.as_deref(),
            worktree_access: Access::ReadWrite,
            tools: true,
            first_prompt: handoff::first_prompt,
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
            state: self.profile.map(|_| started.state_dir(&self.store)),
            credentials: &self.credentials,
        };
        let (sandbox, network) = (self.sandbox, self.network);
        let door = open_door(environment, &started);
        let live = start_live(self.live.take(), &self.git_dir, &started);
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
        let pusher = self.sync.map(|setup| {
            let refs = setup.refs(started.thread, &started.slot);
            let name = setup.name.clone();
            let limit = setup.push_limit;
            let pusher = Pusher::start(self.git_dir.clone(), (refs, limit), move |flag| {
                setup.connect(flag)
            });
            (pusher, name)
        });
        let activity = Arc::new(Activity::default());
        let key = started.key.take().map(Arc::new);
        let (recorder, turns) = start_background(
            &mut started,
            &self.git_dir,
            self.globals,
            (self.hooks, Arc::clone(&activity)),
            pusher.as_ref().map(|(pusher, _)| pusher.poker()),
            session,
            key.clone(),
        );
        let can_merge = raw.is_some() && terminal::is_interactive() && recorder.is_some();
        let (tools, prompts) = serve_tools(
            self.mcp,
            (self.owner, key, live.as_ref(), can_merge),
            &self.git_dir,
            &started,
        );
        let merging = Merging::open(door, recorder.as_ref(), &started);
        let outcome = finish_run(
            child,
            raw,
            &UserSide {
                palette_key: self.palette_key,
                activity,
                notice: notice(environment),
            },
            termination,
            Background {
                recorder,
                turns,
                pusher,
                merging,
                prompts,
            },
            proxy,
            live,
        );
        tools.store(false, Ordering::SeqCst);
        outcome
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
/// records `key` opens, to its `mahi mcp` at `listener` on a thread of its own; the agent may
/// ask for merges when `can_merge`, as the user has a palette and the run takes snapshots.
/// Returns the flag that stops it, and the palette's queue: `live`'s, or else this run's own.
fn serve_tools(
    listener: UnixListener,
    (owner, key, live, can_merge): (
        Option<ParticipantKey>,
        Option<Arc<ThreadKey>>,
        Option<&Link>,
        bool,
    ),
    git_dir: &Path,
    started: &Started,
) -> (Arc<AtomicBool>, Arc<Prompts>) {
    let serving = Arc::new(AtomicBool::new(true));
    let prompts = live.map_or_else(|| Arc::new(Prompts::default()), Link::prompts);
    let claims = live.map_or_else(|| Arc::new(Claims::default()), Link::claims);
    let Some(owner) = owner else {
        eprintln!("mahi: the agent's tools are off, since the thread's owner is not known");
        return (serving, prompts);
    };
    let tools = ThreadTools::new(
        git_dir.to_path_buf(),
        (started.thread, owner, key),
        (
            started.slot.clone(),
            can_merge.then(|| Arc::clone(&prompts)),
            claims,
        ),
    );
    let flag = Arc::clone(&serving);
    thread::spawn(move || {
        let toolbox: Arc<dyn Toolbox> = Arc::new(tools);
        mcp::serve(&listener, &flag, &toolbox);
    });
    (serving, prompts)
}

/// Opens the door `mahi merge` reaches `started`'s running agent at; a failure is reported,
/// and the agent runs without it.
fn open_door(environment: &Environment, started: &Started) -> Option<MergeDoor> {
    merge_door::door_path(
        &environment.runtime_dir(),
        started.thread,
        started.slot.agent(),
    )
    .and_then(MergeDoor::open)
    .inspect_err(|error| {
        eprintln!("mahi: work cannot be merged into this agent while it runs: {error}");
    })
    .ok()
}

/// What lets `mahi merge` reach the running agent: the door it asks at, the recorder that
/// merges between its snapshots, and the user, whose name a prompt about conflicts carries.
struct Merging {
    door: MergeDoor,
    merger: Merger,
    own: ParticipantName,
}

impl Merging {
    /// Returns what lets `mahi merge` reach `started`'s agent, when it has a door and a
    /// recorder.
    fn open(
        door: Option<MergeDoor>,
        recorder: Option<&Recorder>,
        started: &Started,
    ) -> Option<Self> {
        door.zip(recorder.map(Recorder::merger))
            .map(|(door, merger)| Self {
                door,
                merger,
                own: started.slot.participant().clone(),
            })
    }
}

/// Merges what `mahi merge` asks at `merging`'s door while `serving` is set, each once the
/// agent is idle and with its input held, and queues a prompt about conflicts in `prompts`.
fn serve_merges(
    merging: &Merging,
    (activity, agent, writer): (&Activity, &impl AgentInput, &Mutex<impl Write>),
    serving: &AtomicBool,
    prompts: Option<&Prompts>,
) {
    merging.door.serve(serving, |request, waiting| {
        let done = inject::when_idle(activity, agent, writer, (serving, Pace::default()), || {
            waiting().then(|| merging.merger.merge(request))
        });
        match done {
            None => Err("the agent ended before it was idle".to_owned()),
            Some(None) => Err("the merge was called off".to_owned()),
            Some(Some(Err(error))) => Err(crate::describe(&error)),
            Some(Some(Ok(done))) => Ok(after_merge(&done, prompts, &merging.own)),
        }
    });
}

/// The thread serving merges at the running agent's door, if there is one.
struct MergeServer {
    serving: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MergeServer {
    /// Stops serving and waits for the thread, which removes the door.
    fn stop(self) {
        self.serving.store(false, Ordering::SeqCst);
        if let Some(thread) = self.thread {
            let _ = thread.join();
        }
    }
}

/// Gives the agent the prompts the user accepts, on a thread of its own while `running` is
/// set, merging with `merger` the merges the agent asked for once they are accepted.
fn spawn_giver<A: AgentInput + Send + Sync + 'static, W: Write + Send + 'static>(
    prompts: Arc<Prompts>,
    (activity, agent, writer): (Arc<Activity>, Arc<A>, Arc<Mutex<W>>),
    running: Arc<AtomicBool>,
    merger: Option<Merger>,
) {
    thread::spawn(move || {
        let merge = |request: MergeRequest| merged_for_agent(merger.as_ref(), request);
        inject::give_accepted(
            &prompts,
            &activity,
            (&*agent, &merge),
            &writer,
            (&running, Pace::default()),
        );
    });
}

/// Merges `request`, which the user accepted for the agent, and returns what to tell the agent
/// of it, at most as long as a prompt may be.
fn merged_for_agent(merger: Option<&Merger>, request: MergeRequest) -> String {
    let from = request.from.clone();
    let Some(merger) = merger else {
        return format!("mahi could not merge the work of {from}: this run takes no snapshots");
    };
    let mut told = match merger.merge(request) {
        Ok(MergeDone::Merged {
            report,
            prompt: Some(prompt),
            ..
        }) => format!("The user accepted merging the work of {from}. {report}{prompt}"),
        Ok(done) => format!(
            "The user accepted merging the work of {from}. {}",
            done.report()
        ),
        Err(error) => format!(
            "mahi could not merge the work of {from}: {}",
            crate::describe(&error)
        ),
    };
    if told.len() > mahi_live::MAX_PROMPT_BYTES {
        let mut end = mahi_live::MAX_PROMPT_BYTES - 3;
        while !told.is_char_boundary(end) {
            end -= 1;
        }
        told.truncate(end);
        told.push_str("...");
    }
    told
}

/// Serves merges at `merging`'s door on a thread of its own, if there is one.
fn spawn_merges<A: AgentInput + Send + Sync + 'static, W: Write + Send + 'static>(
    merging: Option<Merging>,
    (activity, agent, writer): (Arc<Activity>, Arc<A>, Arc<Mutex<W>>),
    prompts: Option<Arc<Prompts>>,
) -> MergeServer {
    let serving = Arc::new(AtomicBool::new(true));
    let thread = merging.map(|merging| {
        let flag = Arc::clone(&serving);
        thread::spawn(move || {
            serve_merges(
                &merging,
                (&activity, &*agent, &writer),
                &flag,
                prompts.as_deref(),
            );
        })
    });
    MergeServer { serving, thread }
}

/// Returns the report of a merge made while the agent runs, after queueing in `prompts`, the
/// palette's, the prompt asking the agent to resolve the conflicts it left, saying whether it
/// waits there.
fn after_merge(done: &MergeDone, prompts: Option<&Prompts>, own: &ParticipantName) -> String {
    let mut report = done.report().to_owned();
    let MergeDone::Merged {
        prompt: Some(prompt),
        ..
    } = done
    else {
        return report;
    };
    let told = match prompts.map(|prompts| queue_own_prompt(prompts, own, prompt)) {
        None => "the agent was not asked to resolve the conflicts: its palette is off\n",
        Some(PromptOutcome::Queued) => {
            "a prompt asking the agent to resolve the conflicts waits in its palette\n"
        }
        Some(PromptOutcome::Accepted) => {
            "a prompt asking the agent to resolve the conflicts goes to it once it is idle\n"
        }
        Some(_) => "the prompt asking the agent to resolve the conflicts could not be queued\n",
    };
    report.push_str(told);
    report
}

fn queue_own_prompt(prompts: &Prompts, own: &ParticipantName, prompt: &str) -> PromptOutcome {
    let (Ok(id), Ok(text)) = (mahi_live::prompt_id(), PromptText::new(prompt.to_owned())) else {
        return PromptOutcome::Dropped;
    };
    prompts.offer(own.clone(), id, text)
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
        let poker = recorder.as_ref().map(Recorder::poker);
        let (messages, inputs) = mpsc::sync_channel(HOOK_QUEUE);
        let closing = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&closing);
        thread::spawn(move || hook::serve(&hooks, &flag, &messages, &activity));
        let worker = thread::spawn(move || {
            turns::record(&transcript, &inputs, poker.as_ref(), pushes.as_ref())
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
    merging: Option<Merging>,
    prompts: Arc<Prompts>,
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
    notice: Notice,
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
        merging,
        prompts,
    } = background;
    let (code, received) = supervise(
        child,
        raw,
        user,
        termination,
        AgentSide {
            tap: live.as_ref().map(Link::tap),
            prompts,
            merging,
            merger: recorder.as_ref().map(Recorder::merger),
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
/// teammates, the palette's queue, the door `mahi merge` reaches it at, and the recorder's
/// merges.
struct AgentSide {
    tap: Option<OutputTap>,
    prompts: Arc<Prompts>,
    merging: Option<Merging>,
    merger: Option<Merger>,
}

fn supervise(
    child: PtyChild,
    raw: Option<RawMode>,
    user: &UserSide,
    termination: TerminationSignals,
    side: AgentSide,
) -> (Result<Outcome, RunError>, Receiver<Event>) {
    let (events, received) = mpsc::channel();
    let stop_events = events.clone();
    thread::spawn(move || {
        while let Ok(signal) = termination.wait() {
            let _ = stop_events.send(Event::Stopped(signal));
        }
    });
    let interactive = raw.is_some() && terminal::is_interactive();
    let AgentSide {
        tap,
        prompts,
        merging,
        merger,
    } = side;
    let code = relay(
        child,
        interactive.then_some((user.palette_key, user.notice)),
        &user.activity,
        (events, &received),
        tap,
        (Some(prompts), merging, merger),
    );
    drop(raw);
    (code, received)
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
struct Restore<'a> {
    store: &'a Store,
    of: SessionOf<'a>,
    dir: &'a str,
}

struct Launch<'a> {
    restore: Option<Restore<'a>>,
    handoff: Option<&'a Path>,
    worktree_access: Access,
    tools: bool,
    first_prompt: fn(&str) -> String,
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
    mcp_socket: &'a Path,
    host: &'a Host,
}

impl Launch<'_> {
    /// Adds the agent's arguments: the user's, then, when its profile names a flag for it, the
    /// file in its state directory `state` that tells it where `mahi mcp` is, then the first
    /// prompt of a handoff, after the variadic flag so it is not taken as one of its values.
    fn agent_arguments(&self, mut pty: PtyCommand, state: Option<&Path>) -> PtyCommand {
        let flag = self
            .profile
            .and_then(|profile| profile.mcp_flag)
            .zip(state.filter(|_| self.tools_config().is_some()));
        let (before, after) = split_at_separator(self.arguments);
        for argument in before {
            pty = pty.arg(argument);
        }
        if let Some((flag, state)) = flag {
            pty = pty.arg(flag).arg(state.join(profile::MCP_CONFIG));
        }
        for argument in after {
            pty = pty.arg(argument);
        }
        match self.handoff {
            Some(notes) => self.ask_to_read(pty, notes),
            None => pty,
        }
    }

    /// Returns the mahi binary and the socket the agent's tools are served at, as text a
    /// profile's configuration can hold, when both are known and are UTF-8.
    fn tools_config(&self) -> Option<(&str, &str)> {
        if !self.tools {
            return None;
        }
        let mahi = self.environment.mahi_exe.as_deref()?.to_str()?;
        Some((mahi, self.mcp_socket.to_str()?))
    }

    /// Gives the agent the first prompt asking it to read the handoff `notes`, when its
    /// profile takes one, or else tells the user to give it.
    fn ask_to_read(&self, pty: PtyCommand, notes: &Path) -> PtyCommand {
        let prompt = (self.first_prompt)(&notes.display().to_string());
        let takes_prompt = self.profile.is_some_and(|profile| profile.takes_prompt);
        if takes_prompt && notes.to_str().is_some() {
            return pty.arg("--").arg(&prompt);
        }
        eprintln!("mahi: tell the agent: {prompt}");
        pty
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
        profile
            .install(&directory, self.tools_config())
            .map_err(RunError::State)?;
        Ok(Some(parent.join(name)))
    }

    fn spawn(
        &self,
        mut sandbox: Sandbox,
        network: Option<Network>,
    ) -> Result<(PtyChild, Option<RawMode>, Option<Running>), RunError> {
        let git_file = self.worktree.join(".git");
        for (path, access) in binds(
            (self.worktree, self.worktree_access),
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
        sandbox.allow_connect(self.mcp_socket)?;
        let state = self.prepare_state()?;
        if let Some(state) = &state {
            self.restore_session(state);
            sandbox.bind(state, Access::ReadWrite)?;
        }
        if let Some(network) = &network {
            sandbox.open_loopback_port(network.port())?;
        }
        let pty = PtyCommand::new(&self.agent.program, self.worktree, terminal::size());
        let mut pty = self.agent_arguments(pty, state.as_deref());
        for (name, value) in &self.environment.passed_on {
            pty = pty.env(name, value);
        }
        let mut pty = pty
            .env("HOME", self.scratch.join(HOME))
            .env("TMPDIR", self.scratch.join(TMP))
            .env(HOOK_SOCKET, self.hook_socket)
            .env(MCP_SOCKET, self.mcp_socket);
        if let Some(mahi) = &self.environment.mahi_exe {
            pty = pty.env(MAHI_BIN, mahi);
        }
        if let Some(notes) = self.handoff {
            pty = pty.env(HANDOFF_ENV, notes);
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
    palette: Option<(PaletteKey, Notice)>,
    activity: &Arc<Activity>,
    (events, received): (mpsc::Sender<Event>, &Receiver<Event>),
    tap: Option<OutputTap>,
    (prompts, merging, merger): (Option<Arc<Prompts>>, Option<Merging>, Option<Merger>),
) -> Result<Outcome, RunError> {
    let writer = Arc::new(Mutex::new(child.writer()?));
    let repainter = Repainter::new(child.resizer()?);
    let screen = Arc::new(Screen::new(
        io::stdout(),
        repainter.clone(),
        palette.map(|(key, _)| key).unwrap_or_default(),
        prompts.clone(),
    ));
    let input = palette.map(|(key, _)| (Arc::clone(&screen), KeyScanner::new(key)));
    let (input_writer, input_activity) = (Arc::clone(&writer), Arc::clone(activity));
    thread::spawn(move || forward_input(&input_writer, input, &input_activity));
    let running = Arc::new(AtomicBool::new(palette.is_some()));
    let (tick_screen, ticking) = (Arc::clone(&screen), Arc::clone(&running));
    let told = prompts.clone().zip(palette);
    thread::spawn(move || {
        let mut arrivals = Vec::new();
        let mut notice = Vec::new();
        let mut text = String::new();
        while ticking.load(Ordering::SeqCst) {
            thread::sleep(PALETTE_TICK);
            let _ = tick_screen.tick();
            if let Some((prompts, (key, notifier))) = &told {
                prompts.take_arrivals(&mut arrivals);
                for arrival in arrivals.drain(..) {
                    notice.clear();
                    text.clear();
                    arrival_text(&arrival, *key, &mut text);
                    notifier.write("mahi", &text, &mut notice);
                    let _ = tick_screen.notify(&notice);
                }
            }
        }
    });
    let merge_server = spawn_merges(
        merging,
        (
            Arc::clone(activity),
            Arc::clone(&screen),
            Arc::clone(&writer),
        ),
        prompts.clone().filter(|_| palette.is_some()),
    );
    if let Some(prompts) = prompts.filter(|_| palette.is_some()) {
        spawn_giver(
            prompts,
            (Arc::clone(activity), Arc::clone(&screen), writer),
            Arc::clone(&running),
            merger,
        );
    }
    let resize_tap = tap.clone();
    let resize_screen = Arc::clone(&screen);
    thread::spawn(move || {
        let Ok(changes) = WindowChanges::listen() else {
            return;
        };
        while changes.wait().is_ok() {
            let Some(size) = repainter.follow() else {
                break;
            };
            let _ = resize_screen.resized();
            if let Some(tap) = &resize_tap {
                tap.resize(size);
            }
        }
    });
    let mut reader = child.reader()?;
    let progress = Arc::new(AtomicU64::new(0));
    let output_events = events.clone();
    let output_progress = Arc::clone(&progress);
    let (output_screen, output_activity) = (Arc::clone(&screen), Arc::clone(activity));
    thread::spawn(move || {
        let ended = copy_output(
            &mut reader,
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
    let outcome = await_outcome(&child, received, &progress);
    running.store(false, Ordering::SeqCst);
    merge_server.stop();
    let _ = screen.close();
    outcome
}

fn arrival_text(arrival: &Arrival, key: PaletteKey, out: &mut String) {
    let _ = if arrival.accepted {
        write!(
            out,
            "{}'s prompt goes to the agent: {}",
            arrival.from, arrival.first_words
        )
    } else {
        write!(
            out,
            "{} sent a prompt ({key} to read it): {}",
            arrival.from, arrival.first_words
        )
    };
}

fn await_outcome(
    child: &Mutex<PtyChild>,
    received: &Receiver<Event>,
    progress: &AtomicU64,
) -> Result<Outcome, RunError> {
    let mut output_done = false;
    loop {
        match received.recv() {
            Ok(Event::Exited(code)) if output_done => return Ok(Outcome::Exited(code?)),
            Ok(Event::Exited(code)) => {
                return finish_output(received, progress, code?);
            }
            Ok(Event::OutputEnded(Ok(()))) => output_done = true,
            Ok(Event::OutputEnded(Err(error))) => {
                kill(child);
                return output_failure(error).map(Outcome::Exited);
            }
            Ok(Event::Stopped(signal)) => {
                kill(child);
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
    (screen, activity): (&UserScreen, &Activity),
) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return screen.close();
        }
        activity.touched();
        screen.output(&buffer[..read])?;
        if let Some(tap) = tap {
            tap.output(&buffer[..read]);
        }
        progress.fetch_add(1, Ordering::Relaxed);
    }
}

type UserScreen = Screen<io::Stdout, Repainter>;

fn forward_input(
    writer: &Mutex<File>,
    mut palette: Option<(Arc<UserScreen>, KeyScanner)>,
    activity: &Activity,
) {
    let mut input = io::stdin().lock();
    let mut buffer = [0_u8; 4096];
    let mut last = b'\n';
    loop {
        let read = match input.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let Ok(mut writer) = writer.lock() else {
            return;
        };
        let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty()) else {
            match &palette {
                Some((screen, _)) => {
                    let _ = screen.close();
                }
                None => end_input(&mut writer, last),
            }
            return;
        };
        activity.touched();
        let forwarded = if let Some((screen, scanner)) = &mut palette {
            route_keys(chunk, scanner, screen, (&mut writer, activity))
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

fn route_keys(
    chunk: &[u8],
    scanner: &mut KeyScanner,
    screen: &UserScreen,
    (writer, activity): (&mut File, &Activity),
) -> io::Result<()> {
    for segment in scanner.scan(chunk) {
        match segment {
            Segment::Palette(key) if screen.is_open() => {
                screen.close()?;
                activity.keys(key);
                writer.write_all(key)?;
            }
            Segment::Palette(_) => open_palette(screen)?,
            Segment::Pass(bytes) => {
                let used = screen.typed(bytes)?;
                let forwarded = bytes.get(used..).unwrap_or_default();
                activity.keys(forwarded);
                writer.write_all(forwarded)?;
            }
        }
    }
    Ok(())
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
    (cwd, cwd_access): (&Path, Access),
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
    for (path, access) in [(cwd, cwd_access), (scratch, Access::ReadWrite)] {
        if !covered(&binds, path) {
            binds.push((path.to_path_buf(), access));
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

fn notice(environment: &Environment) -> Notice {
    Notice::for_terminal(TerminalHints {
        term: environment.term.as_deref(),
        term_program: environment.term_program.as_deref(),
        kitty: environment.kitty,
        vte: environment.vte,
        tmux: environment.tmux,
    })
}

/// An agent set up to rewrite a pull request draft: sandboxed as any other, with a worktree it
/// can only read, and no snapshots, transcript, tools or teammates.
pub(crate) struct DraftWriter {
    prepared: Prepared,
}

impl fmt::Debug for DraftWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DraftWriter").finish_non_exhaustive()
    }
}

impl DraftWriter {
    /// Sets up the agent `program` with `arguments` and what `options` let it reach, for the
    /// repository around the current directory, checking everything a launch needs before any
    /// change is made.
    pub(crate) fn prepare(
        (program, arguments): (&OsStr, &[OsString]),
        options: &LaunchOptions,
        environment: &Environment,
    ) -> Result<Self, RunError> {
        let cwd = env::current_dir()
            .and_then(fs::canonicalize)
            .map_err(RunError::CurrentDirectory)?;
        let host = Host::from_environment(environment)?;
        let config = ConfigDir::resolve(
            environment.home.as_deref(),
            environment.xdg_config_home.as_deref(),
        )?;
        let profile = options.profile_for(program);
        let hosts = allowed_hosts(options.allow_hosts(), profile);
        let settings = Settings::load(&config)?;
        let credentials = gather_credentials(&config, options, profile, environment)?;
        let store = Store::discover(&cwd)?;
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
        prepared.palette_key = settings.palette_key;
        Ok(Self { prepared })
    }

    /// Runs the agent in `worktree`, which it can only read, with the draft `draft` in its
    /// private temporary directory and the notes `notes` writes for that path, keeping its
    /// profile's state in `state`. Returns how it ended and the draft it left, or `None` if it
    /// left no readable one.
    pub(crate) fn rewrite(
        mut self,
        environment: &Environment,
        (worktree, state): (&Path, PathBuf),
        draft: &str,
        notes: &dyn Fn(&Path) -> String,
    ) -> Result<(Outcome, Option<String>), RunError> {
        let prepared = &mut self.prepared;
        let draft_path = prepared.scratch.join(TMP).join(DRAFT_NAME);
        write_private(&draft_path, draft.as_bytes()).map_err(RunError::Draft)?;
        let tmp = rustix::fs::open(
            prepared.scratch.join(TMP),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| RunError::Draft(error.into()))?;
        prepared.write_handoff(&notes(&draft_path))?;
        let termination = TerminationSignals::listen().map_err(RunError::Signals)?;
        let launch = Launch {
            restore: None,
            handoff: prepared.handoff.as_deref(),
            worktree_access: Access::ReadOnly,
            tools: false,
            first_prompt: draft_prompt,
            arguments: &prepared.arguments,
            environment,
            agent: &prepared.agent,
            worktree,
            git_dir: &prepared.git_dir,
            scratch: &prepared.scratch,
            hook_socket: &prepared.hook_socket,
            mcp_socket: &prepared.mcp_socket,
            host: &prepared.host,
            profile: prepared.profile,
            state: prepared.profile.map(|_| state),
            credentials: &prepared.credentials,
        };
        let sandbox = mem::take(&mut prepared.sandbox);
        let (child, raw, proxy) = launch.spawn(sandbox, prepared.network.take())?;
        let activity = Arc::new(Activity::default());
        let closing = Arc::new(AtomicBool::new(false));
        let (messages, inputs) = mpsc::sync_channel(HOOK_QUEUE);
        let hooks = prepared.hooks.try_clone().map_err(RunError::Scratch)?;
        let (flag, seen) = (Arc::clone(&closing), Arc::clone(&activity));
        thread::spawn(move || hook::serve(&hooks, &flag, &messages, &seen));
        thread::spawn(move || for _ in inputs {});
        let (code, received) = supervise(
            child,
            raw,
            &UserSide {
                palette_key: prepared.palette_key,
                activity,
                notice: notice(environment),
            },
            termination,
            AgentSide {
                tap: None,
                prompts: Arc::new(Prompts::default()),
                merging: None,
                merger: None,
            },
        );
        closing.store(true, Ordering::SeqCst);
        if matches!(code, Ok(Outcome::Stopped(_))) {
            while received.try_recv().is_ok() {}
        }
        let (caught, _) = mpsc::channel();
        thread::spawn(move || stop_on_signal(&received, &[], &caught));
        for error in proxy.into_iter().flat_map(Running::stopped) {
            eprintln!("mahi: the proxy stopped serving the agent: {error}");
        }
        let code = code?;
        let left = matches!(code, Outcome::Exited(0))
            .then(|| read_draft(&tmp))
            .flatten();
        Ok((code, left))
    }
}

fn draft_prompt(notes: &str) -> String {
    format!("Read the notes at {notes} and rewrite the pull request description they point to.")
}

fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

fn read_draft(directory: &OwnedFd) -> Option<String> {
    let file = rustix::fs::openat(
        directory,
        DRAFT_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .ok()?;
    let stat = rustix::fs::fstat(&file).ok()?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return None;
    }
    let mut text = Vec::new();
    File::from(file)
        .take(MAX_DRAFT_BYTES + 1)
        .read_to_end(&mut text)
        .ok()?;
    if text.len() as u64 > MAX_DRAFT_BYTES {
        return None;
    }
    String::from_utf8(text).ok()
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
                    (cwd, Access::ReadWrite),
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
                (&home.join("project"), Access::ReadWrite),
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
            (&project, Access::ReadWrite),
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
            (&home.join("project"), Access::ReadWrite),
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
            (&home.join("project"), Access::ReadWrite),
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
            (&project, Access::ReadWrite),
            Path::new("/repo/.git"),
            &agent,
            Path::new("/scratch"),
            None,
            &host_with_home(&home),
        )
        .unwrap();
        assert!(binds.contains(&(project.join(".git"), Access::ReadOnly)));
    }

    #[test]
    fn a_merge_with_conflicts_queues_a_prompt_from_the_user_and_says_so() {
        let own = ParticipantName::new("tester").unwrap();
        let merged = |prompt: Option<String>| MergeDone::Merged {
            report: "merged\n".to_owned(),
            commit: mahi_store::ObjectId::empty_tree(gix::hash::Kind::Sha1),
            tree: mahi_store::ObjectId::empty_tree(gix::hash::Kind::Sha1),
            prompt,
        };
        let prompts = Prompts::default();
        let resolve = Some("resolve the markers in a.txt".to_owned());
        let report = after_merge(&merged(resolve.clone()), Some(&prompts), &own);
        assert_eq!(
            report,
            "merged\na prompt asking the agent to resolve the conflicts waits in its palette\n"
        );
        let mut waiting = Vec::new();
        prompts.each_waiting(|prompt| {
            waiting.push((prompt.from.clone(), prompt.text.as_str().to_owned()));
        });
        assert_eq!(waiting, [(own.clone(), resolve.clone().unwrap())]);
        assert!(after_merge(&merged(resolve), None, &own).ends_with("its palette is off\n"));
        let huge = Some("x".repeat(mahi_live::MAX_PROMPT_BYTES + 1));
        assert!(
            after_merge(&merged(huge), Some(&prompts), &own).ends_with("could not be queued\n")
        );
        assert_eq!(after_merge(&merged(None), Some(&prompts), &own), "merged\n");
        let already = MergeDone::Already("already\n".to_owned());
        assert_eq!(after_merge(&already, Some(&prompts), &own), "already\n");
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
