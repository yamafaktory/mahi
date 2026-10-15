use std::{
    env,
    fs,
    io::{
        self,
        Write,
    },
    os::fd::AsFd,
    path::Path,
    process,
    time::{
        Duration,
        Instant,
    },
};

use clap::{
    CommandFactory,
    Parser,
};
use mahi_core::{
    AgentSlot,
    ParticipantName,
    ThreadId,
};
use mahi_identity::{
    ConfigDir,
    CredentialName,
    CredentialNameError,
    credential_names,
};
use mahi_sandbox::{
    InputWait,
    Termination,
    TerminationSignals,
    WindowSize,
};
use mahi_store::Store;
use mahi_term::{
    AnsiBackend,
    Answer,
    Dialog,
    Home,
    HomeAction,
    HomeRow,
    HomeView,
    PaletteInput,
    PaletteKeys,
    TabBar,
    ThreadView,
};
use mahi_thread::ParticipantKey;
use ratatui_core::terminal::Terminal;

use crate::{
    cli::{
        Cli,
        Command,
    },
    environment::{
        Environment,
        LiveMode,
    },
    profile::Profile,
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    remote::{
        self,
        RemoteName,
        Visibility,
    },
    run,
    run_command,
    session,
    settings::Settings,
    terminal::{
        self,
        RawMode,
    },
    threads,
    ui::{
        self,
        Captured,
        DialogPrompt,
        Showing,
    },
    unlocked,
    workspace::{
        Moved,
        NEW_TAB,
        Workspace,
    },
    workspace_live::WorkspaceLive,
};

const ENTER_SCREEN: &[u8] =
    b"\x1b[?1049h\x1b[?2004h\x1b[?25l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[2J";
const LEAVE_SCREEN: &[u8] = b"\x1b[?25h\x1b[?2004l\x1b[?1002l\x1b[?1006l\x1b[?1049l";
const REREAD: Duration = Duration::from_secs(2);
const KEY_WAIT: Duration = Duration::from_millis(200);
const SEQUENCE_WAIT: Duration = Duration::from_millis(30);
const ESC: u8 = 0x1b;
const MAX_READ: usize = 1024;
const AFTER_ESCAPE: Duration = Duration::from_millis(500);
const CHILD_WAIT: Duration = Duration::from_millis(15);
const STOP_WITHIN: Duration = Duration::from_secs(30);

/// Opens the home screen in the repository around the current directory and runs the actions
/// chosen there until the user quits; returns the exit code. Everything happens on its
/// alternate screen: questions are dialogs, what mahi prints goes to the activity, and an
/// agent draws on the same screen. Outside a repository, or without a terminal, it prints the
/// help instead.
pub(crate) fn home(environment: &Environment) -> i32 {
    let store = env::current_dir()
        .and_then(fs::canonicalize)
        .ok()
        .and_then(|cwd| Store::discover(&cwd).ok());
    let Some(mut store) = store.filter(|_| terminal::is_interactive()) else {
        let _ = Cli::command().write_help(&mut io::stderr());
        return 2;
    };
    let repository = store
        .common_dir()
        .parent()
        .and_then(|dir| dir.file_name())
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let identity = session::participant_from(environment.user.as_deref())
        .map_or_else(|_| "unknown".to_owned(), |name| name.to_string());
    ui::set_true_color(matches!(
        environment.colorterm.as_deref(),
        Some("truecolor" | "24bit")
    ));
    let saved = rustix::termios::tcgetattr(io::stdin()).ok();
    let screen = match Screen::enter() {
        Ok(screen) => screen,
        Err(error) => {
            crate::report_with("the home screen failed", &error);
            return 1;
        }
    };
    let showing = Showing::start(saved);
    let captured = Captured::start().ok();
    let mut home = Home::default();
    let mut status = String::new();
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )
    .ok();
    let palette_key = config
        .as_ref()
        .and_then(|config| Settings::load(config).ok())
        .map(|settings| settings.palette_key)
        .unwrap_or_default();
    let mut workspace = Workspace::new(palette_key, crate::run::notice(environment));
    workspace.host_with(workspace_live(environment, config.as_ref(), &store));
    let outcome = loop {
        let own = threads::own_key(environment);
        let place = Place {
            store: &store,
            own: own.as_ref(),
            repository: &repository,
            identity: &identity,
            captured: captured.as_ref(),
        };
        match choose(&place, &mut home, &mut status, &mut workspace) {
            Ok(Chosen::Quit) if workspace.is_running() && !stop_to_quit(&workspace) => {
                "the agents keep running".clone_into(&mut status);
            }
            Ok(Chosen::Quit | Chosen::InputEnded) => break Ok(()),
            Ok(Chosen::Stopped(signal)) => break Err(Ended::Stopped(signal)),
            Ok(Chosen::Action(action)) if runs_agent(&action) => {
                let identity_file = config.as_ref().map(ConfigDir::identity_file);
                if let Err(told) = open_agent(
                    action,
                    &mut store,
                    environment,
                    &mut workspace,
                    identity_file.as_deref(),
                ) {
                    status = told;
                }
            }
            Ok(Chosen::Action(action)) => {
                status = act(action, &mut store, environment);
                ui::keys_make_signals(false);
                workspace.set_screen(terminal::size(), true);
                if let Err(error) = Screen::restore() {
                    break Err(Ended::Failed(error));
                }
            }
            Err(error) => break Err(Ended::Failed(error)),
        }
    };
    crate::unlocked::forget();
    drop(captured);
    drop(showing);
    drop(screen);
    stop_agents(&mut workspace);
    workspace.host_with(None);
    match outcome {
        Ok(()) => 0,
        Err(Ended::Stopped(signal)) => {
            signal.reraise();
            process::exit(128 + signal.number());
        }
        Err(Ended::Failed(error)) => {
            crate::report_with("the home screen failed", &error);
            1
        }
    }
}

/// What the home screen shows around its threads.
struct Place<'a> {
    store: &'a Store,
    own: Option<&'a ParticipantKey>,
    repository: &'a str,
    identity: &'a str,
    captured: Option<&'a Captured>,
}

/// Why the home screen ended other than by the user quitting.
enum Ended {
    Stopped(Termination),
    Failed(io::Error),
}

/// How the home screen was left.
enum Chosen {
    Quit,
    InputEnded,
    Action(HomeAction),
    Stopped(Termination),
}

/// Keeps the alternate screen, raw mode and bracketed paste on while the home screen lives.
struct Screen {
    _raw: Option<RawMode>,
}

impl Screen {
    fn enter() -> io::Result<Self> {
        let raw = RawMode::enable()?;
        write_screen(ENTER_SCREEN)?;
        Ok(Self { _raw: raw })
    }

    /// Puts the screen back after an action, which may have left the alternate screen, shown
    /// the cursor or turned bracketed paste off, as an agent can.
    fn restore() -> io::Result<()> {
        if let Ok(raw) = rustix::termios::tcgetattr(io::stdin()) {
            let mut wanted = raw.clone();
            wanted.make_raw();
            let _ = rustix::termios::tcsetattr(
                io::stdin(),
                rustix::termios::OptionalActions::Flush,
                &wanted,
            );
        }
        write_screen(ENTER_SCREEN)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = rustix::termios::tcflush(io::stdin(), rustix::termios::QueueSelector::IFlush);
        let _ = write_screen(LEAVE_SCREEN);
    }
}

fn write_screen(bytes: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(bytes)?;
    out.flush()
}

/// Shows the home screen until the user chooses an action, quits, or a signal stops mahi.
fn choose(
    place: &Place<'_>,
    home: &mut Home,
    status: &mut String,
    workspace: &mut Workspace,
) -> io::Result<Chosen> {
    let signals = TerminationSignals::listen().map_err(io::Error::other)?;
    ui::keys_make_signals(false);
    let mut size = terminal::size();
    let mut terminal = Terminal::new(ui::backend(size.rows, size.cols))?;
    terminal.clear()?;
    let mut keys = PaletteKeys::default();
    let mut rows = rows(place.store, place.own);
    let mut remote = remote::summary(place.store);
    home.fit(&rows);
    let mut activity = activity(place.captured);
    let mut seen = place.captured.map(Captured::generation);
    let mut read_at = Instant::now();
    let mut buffer = [0_u8; MAX_READ];
    let mut dirty = true;
    let mut ignore_until = None;
    let mut passed = Vec::new();
    let mut for_threads = Vec::with_capacity(MAX_READ);
    loop {
        dirty |= follow_children(workspace, status, &mut passed)?;
        if read_at.elapsed() >= REREAD {
            let fresh = self::rows(place.store, place.own);
            if fresh != rows {
                rows = fresh;
                home.fit(&rows);
                dirty = true;
            }
            let summary = remote::summary(place.store);
            if summary != remote {
                remote = summary;
                dirty = true;
            }
            crate::unlocked::forget_unused(Instant::now());
            read_at = Instant::now();
        }
        let now_seen = place.captured.map(Captured::generation);
        if now_seen != seen {
            seen = now_seen;
            activity = self::activity(place.captured);
            dirty = true;
        }
        let now = terminal::size();
        if now != size {
            size = now;
            terminal.backend_mut().resize(size.rows, size.cols);
            terminal.autoresize()?;
            dirty = true;
        }
        workspace.set_screen(size, false);
        workspace.resize(agents_size(size, workspace));
        if dirty {
            let view = home_view(place, &remote, &rows, &activity);
            draw(&mut terminal, home, &view, status, workspace)?;
            dirty = false;
        }
        match wait(&signals, key_wait(workspace))? {
            InputWait::Timeout => continue,
            InputWait::Signal(signal) => return Ok(Chosen::Stopped(signal)),
            InputWait::Input => {}
        }
        let read = match read_chunk(&signals, &mut buffer)? {
            Chunk::Read(read) => read,
            Chunk::End => return Ok(Chosen::InputEnded),
            Chunk::Stopped(signal) => return Ok(Chosen::Stopped(signal)),
        };
        match route_keys(
            workspace,
            buffer.get(..read).unwrap_or_default(),
            &mut for_threads,
        ) {
            Moved::Nothing => {}
            Moved::Shown => dirty = true,
            Moved::New => return Ok(Chosen::Action(HomeAction::New)),
        }
        if for_threads.is_empty() || ignore_until.is_some_and(|until| Instant::now() < until) {
            continue;
        }
        let (chosen, escaped) = thread_list_keys(&mut keys, home, &rows, &for_threads);
        if escaped {
            ignore_until = Some(Instant::now() + AFTER_ESCAPE);
        }
        dirty = true;
        match chosen {
            Some(HomeAction::Quit) => return Ok(Chosen::Quit),
            Some(action) => {
                let view = home_view(place, &remote, &rows, &activity);
                draw(&mut terminal, home, &view, status, workspace)?;
                return Ok(Chosen::Action(action));
            }
            None => {}
        }
    }
}

/// Takes in what the workspace's children wrote, writing out what the shown one asks of the
/// terminal itself, and the children that ended, telling the last one's outcome in `status`;
/// returns whether the screen must be drawn again.
fn follow_children(
    workspace: &mut Workspace,
    status: &mut String,
    passed: &mut Vec<u8>,
) -> io::Result<bool> {
    let mut changed = workspace.take_output(passed);
    let (told, ended) = workspace.take_ended();
    if let Some(told) = told {
        *status = told;
    }
    changed |= ended;
    workspace.apply_shown(passed);
    if !passed.is_empty() {
        write_screen(passed)?;
        passed.clear();
    }
    Ok(changed)
}

/// Reads the thread list's keys from `typed`, and returns the action they choose, if any, and
/// whether Escape was among them.
fn thread_list_keys(
    keys: &mut PaletteKeys,
    home: &mut Home,
    rows: &[HomeRow],
    typed: &[u8],
) -> (Option<HomeAction>, bool) {
    let mut chosen = None;
    let mut escaped = false;
    keys.read(typed, |input| {
        escaped |= input == PaletteInput::Escape;
        if let Some(action) = home.key(input, rows) {
            chosen = Some(action);
            return false;
        }
        input != PaletteInput::Escape
    });
    (chosen, escaped)
}

/// Returns how long to wait for a key before looking again: briefly while agents run, whose
/// output must be drawn as it comes.
fn key_wait(workspace: &Workspace) -> Duration {
    if workspace.is_running() {
        CHILD_WAIT
    } else {
        KEY_WAIT
    }
}

/// Returns the size of an agent's terminal in a thread's tab on a terminal of `size`, with
/// the list where the workspace has it.
fn agents_size(size: WindowSize, workspace: &Workspace) -> WindowSize {
    let (rows, cols) =
        ThreadView::agent_size(size.rows, size.cols, workspace.list_place(size.cols));
    WindowSize { rows, cols }
}

/// Gives what was `typed` to the workspace, which keeps its own keys and the shown agent's,
/// and leaves in `for_threads` what the thread list reads; returns whether another tab is
/// shown.
fn route_keys(workspace: &mut Workspace, typed: &[u8], for_threads: &mut Vec<u8>) -> Moved {
    for_threads.clear();
    if workspace.has_tabs() {
        workspace.type_keys(typed, for_threads)
    } else {
        workspace.type_without_tabs(typed, for_threads);
        Moved::Nothing
    }
}

/// Returns what the home screen shows of `place`, its `remote`, its thread `rows` and the
/// `activity` it caught.
fn home_view<'a>(
    place: &'a Place<'_>,
    remote: &'a str,
    rows: &'a [HomeRow],
    activity: &'a [String],
) -> HomeView<'a> {
    HomeView {
        repository: place.repository,
        remote,
        identity: place.identity,
        rows,
        activity,
    }
}

/// Draws the home screen and keeps the frame as the backdrop of the dialogs that follow.
fn draw(
    terminal: &mut Terminal<AnsiBackend<io::Stdout>>,
    home: &Home,
    view: &HomeView<'_>,
    status: &str,
    workspace: &Workspace,
) -> io::Result<()> {
    let drawn = terminal.draw(|frame| {
        let area = frame.area();
        if !workspace.has_tabs() {
            home.render(view, status, area, frame.buffer_mut());
            return;
        }
        let (bar, body) = TabBar::split(area);
        let cursor = workspace.render(bar, body, frame.buffer_mut());
        if workspace.shows_threads() {
            home.render(view, status, body, frame.buffer_mut());
        } else if let Some(cursor) = cursor {
            frame.set_cursor_position(cursor);
        }
    })?;
    ui::keep_backdrop(drawn.buffer);
    Ok(())
}

/// What reading the keys gave.
enum Chunk {
    Read(usize),
    End,
    Stopped(Termination),
}

/// Reads what was typed, waiting briefly for the rest of a sequence that starts with an
/// escape, so a split arrow key is not read as Escape.
fn read_chunk(signals: &TerminationSignals, buffer: &mut [u8; MAX_READ]) -> io::Result<Chunk> {
    let mut read = read_input(buffer)?;
    if read == 0 {
        return Ok(Chunk::End);
    }
    while buffer.get(read - 1) == Some(&ESC) && read < MAX_READ {
        match wait(signals, SEQUENCE_WAIT)? {
            InputWait::Input => {
                let more = read_input(buffer.get_mut(read..).unwrap_or_default())?;
                if more == 0 {
                    break;
                }
                read += more;
            }
            InputWait::Signal(signal) => return Ok(Chunk::Stopped(signal)),
            InputWait::Timeout => break,
        }
    }
    if let Some(signal) = signals
        .wait_timeout(Duration::ZERO)
        .map_err(io::Error::other)?
    {
        return Ok(Chunk::Stopped(signal));
    }
    Ok(Chunk::Read(read))
}

fn activity(captured: Option<&Captured>) -> Vec<String> {
    captured.map(Captured::lines).unwrap_or_default()
}

fn wait(signals: &TerminationSignals, timeout: Duration) -> io::Result<InputWait> {
    signals
        .wait_for_input_within(io::stdin().as_fd(), timeout)
        .map_err(io::Error::other)
}

fn read_input(buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match rustix::io::read(io::stdin(), &mut *buffer) {
            Err(rustix::io::Errno::INTR) => {}
            read => return read.map_err(io::Error::from),
        }
    }
}

fn rows(store: &Store, own: Option<&ParticipantKey>) -> Vec<HomeRow> {
    threads::home_rows(store, own).unwrap_or_default()
}

/// Runs the chosen action as its command does, without leaving the alternate screen, and
/// returns what the home screen says about it.
fn act(action: HomeAction, store: &mut Store, environment: &Environment) -> String {
    match command_words(action, store, environment) {
        Ok(words) => run_words(&words, environment),
        Err(told) => told,
    }
}

/// Asks whether to stop the agents the workspace runs in order to quit; returns whether the
/// user says so.
fn stop_to_quit(workspace: &Workspace) -> bool {
    let count = workspace.running_count();
    let (running, them) = if count == 1 {
        ("1 agent is", "it")
    } else {
        ("agents are", "them")
    };
    let running = if count == 1 {
        running.to_owned()
    } else {
        format!("{count} {running}")
    };
    let confirmed = DialogPrompt::default().ask(Dialog::confirm(
        "Quit",
        vec![format!(
            "{running} running: stop {them} and quit? Each ends as a stop signal ends it, with \
             its last snapshot unless it was already taking it."
        )],
    ));
    matches!(confirmed, Ok(Answer::Confirmed(true)))
}

/// Stops the agents the workspace still runs, once mahi has left its screen, saying so, and
/// says how many had to be killed without their last snapshot.
fn stop_agents(workspace: &mut Workspace) {
    let count = workspace.running_count();
    if count == 0 {
        return;
    }
    eprintln!("mahi: stopping {count} agent(s), each with its last snapshot");
    let left = workspace.stop_all(STOP_WITHIN);
    if left > 0 {
        eprintln!(
            "mahi: {left} agent(s) did not stop within {} s and were killed without their last snapshot",
            STOP_WITHIN.as_secs()
        );
    }
}

/// Returns whether the action runs an agent, which the workspace runs in a thread's tab.
fn runs_agent(action: &HomeAction) -> bool {
    matches!(
        action,
        HomeAction::New | HomeAction::Resume(_) | HomeAction::AddAgent(_) | HomeAction::Handoff(_)
    )
}

/// Returns the live layer the workspace hosts its threads' agents on, unless it is off or
/// mahi is not set up in `config`.
fn workspace_live(
    environment: &Environment,
    config: Option<&ConfigDir>,
    store: &Store,
) -> Option<WorkspaceLive> {
    WorkspaceLive::new(environment, config?, store.common_dir())
}

/// Starts the agent `action` runs in its thread's tab of the workspace, with the user's mahi
/// key unlocked first when the agent needs it, from the `identity_file`; returns what to tell
/// the user when it does not start.
fn open_agent(
    action: HomeAction,
    store: &mut Store,
    environment: &Environment,
    workspace: &mut Workspace,
    identity_file: Option<&Path>,
) -> Result<(), String> {
    let (title, resumes) = match &action {
        HomeAction::Resume(thread) => (short(thread), true),
        HomeAction::AddAgent(thread) | HomeAction::Handoff(thread) => (short(thread), false),
        _ => (NEW_TAB.to_owned(), false),
    };
    let needs_key = !matches!(action, HomeAction::New) || environment.live != LiveMode::Off;
    let words = command_words(action, store, environment)?;
    let name = if resumes {
        "agent".to_owned()
    } else {
        words.last().cloned().unwrap_or_default()
    };
    let key = match identity_file {
        Some(file) if needs_key => Some(unlocked::identity(
            file,
            || {
                TerminalPrompt::open()
                    .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
                    .map_err(|error| format!("the passphrase cannot be asked: {error}"))
            },
            |error| format!("the mahi key cannot be unlocked: {error}"),
        )?),
        Some(file) => unlocked::current(file),
        None => None,
    };
    let shown = format!("mahi {}", words.join(" "));
    workspace.open(
        environment,
        (&title, &name, &shown),
        (&words, title == NEW_TAB),
        key.as_ref(),
    )
}

fn short(thread: &str) -> String {
    thread.chars().take(8).collect()
}

/// Returns the words of the mahi command that does `action`, asking in dialogs what it needs,
/// or what to tell the user when there is nothing to run.
fn command_words(
    action: HomeAction,
    store: &mut Store,
    environment: &Environment,
) -> Result<Vec<String>, String> {
    let words: Vec<String> = match action {
        HomeAction::New => vec![
            "run".to_owned(),
            agent_to_run(
                environment,
                ("New thread", "Which agent should start the thread?"),
                &[],
            )?,
        ],
        HomeAction::Resume(thread) => vec!["resume".to_owned(), thread],
        HomeAction::Land(thread) => vec!["land".to_owned(), thread],
        HomeAction::End(thread) => vec!["end".to_owned(), thread],
        HomeAction::Invite(thread) => vec!["invite".to_owned(), thread],
        HomeAction::Purge(thread) => vec!["purge".to_owned(), thread],
        HomeAction::AddAgent(thread) => agent_add_words(store, thread, environment)?,
        HomeAction::Handoff(thread) => handoff_words(store, thread, environment)?,
        HomeAction::Merge(thread) => merge_words(store, &thread, environment)?,
        HomeAction::Push(thread) => push_words(store, thread, environment)?,
        HomeAction::Join => vec!["join".to_owned()],
        HomeAction::Remote => return Err(choose_remote(store)),
        HomeAction::Card => vec!["id".to_owned()],
        HomeAction::Credentials => credential_words(environment)?,
        HomeAction::Quit => return Err(String::new()),
    };
    Ok(words)
}

/// Runs the mahi command `words` as it would run on its own, without leaving the alternate
/// screen, and returns what the home screen says about it.
fn run_words(words: &[String], environment: &Environment) -> String {
    let shown = format!("mahi {}", words.join(" "));
    let Ok(Cli {
        command: Some(command),
    }) = Cli::try_parse_from(std::iter::once("mahi").chain(words.iter().map(String::as_str)))
    else {
        return format!("{shown} is not a command mahi knows");
    };
    eprintln!("› {shown}");
    let code = match command {
        Command::Purge(purge) => match crate::purge_unless_declined(&purge, environment) {
            Some(code) => code,
            None => return format!("{shown}: nothing was purged"),
        },
        command => run_command(command, environment),
    };
    match code {
        0 => format!("{shown}: done"),
        code => format!("{shown} failed with exit code {code}; see the activity"),
    }
}

/// Asks in a dialog whether to add a credential or remove a stored one, and returns the
/// command that does it, or what to say when there is nothing to do; the command asks for the
/// token itself, masked.
fn credential_words(environment: &Environment) -> Result<Vec<String>, String> {
    let names = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )
    .ok()
    .and_then(|config| credential_names(&config).ok())
    .ok_or_else(|| "cannot read the stored credentials".to_owned())?;
    let mut items = Vec::with_capacity(names.len() + 1);
    items.push("Add a credential".to_owned());
    items.extend(names.iter().map(|name| format!("Remove {name}")));
    let stored = if names.is_empty() {
        "None is stored yet."
    } else {
        "Pick one to remove it, or add another."
    };
    let dialog = Dialog::choose(
        "Credentials",
        vec![
            "Tokens agents sign in with, and remotes over HTTPS, kept in files only you can \
             read (not encrypted); mahi never shows them."
                .to_owned(),
            stored.to_owned(),
        ],
        items,
    );
    let mut prompt = DialogPrompt::default();
    let Ok(Answer::Choice(index)) = prompt.ask(dialog) else {
        return Err(String::new());
    };
    let Some(name) = index.checked_sub(1).and_then(|index| names.get(index)) else {
        let typed = match prompt.ask(Dialog::input(
            "Add a credential",
            vec![
                "Its name: the agent's, such as `claude` or `codex`, or the `https-…` name \
                 `mahi remote` gives an HTTPS remote. mahi then asks for the token."
                    .to_owned(),
            ],
            false,
        )) {
            Ok(Answer::Text(text)) => text.trim().to_owned(),
            _ => return Err(String::new()),
        };
        let name: CredentialName = typed.parse().map_err(|_: CredentialNameError| {
            "that is not a credential name: use lowercase letters, digits and inner hyphens"
                .to_owned()
        })?;
        if names.contains(&name) {
            return Err(format!(
                "a credential named {name} exists; remove it first to replace it"
            ));
        }
        return Ok(vec![
            "credential".to_owned(),
            "add".to_owned(),
            name.to_string(),
        ]);
    };
    let confirmed = prompt.ask(Dialog::confirm(
        "Credentials",
        vec![format!(
            "Remove the credential {name}? What signs in with it has to be given a token again."
        )],
    ));
    match confirmed {
        Ok(Answer::Confirmed(true)) => Ok(vec![
            "credential".to_owned(),
            "remove".to_owned(),
            name.to_string(),
        ]),
        _ => Err(format!("kept the credential {name}")),
    }
}

/// Returns the agent to start a thread with: the one mahi has a profile for that is on `PATH`,
/// or the one the user picks in a dialog when there are several.
fn agent_to_run(
    environment: &Environment,
    (title, question): (&str, &str),
    taken: &[&AgentSlot],
) -> Result<String, String> {
    let found: Vec<&str> = programs_on_path(environment)
        .filter(|program| {
            let agent = session::agent_from(Path::new(program));
            !taken.iter().any(|slot| slot.agent() == &agent)
        })
        .collect();
    match found.as_slice() {
        [] if taken.is_empty() => {
            Err("no agent mahi has a profile for is on PATH; run mahi run <agent>".to_owned())
        }
        [] => Err("each agent mahi has a profile for on PATH is already yours here".to_owned()),
        [only] => Ok((*only).to_owned()),
        several => {
            let dialog = Dialog::choose(
                title,
                vec![question.to_owned()],
                several
                    .iter()
                    .map(|program| (*program).to_owned())
                    .collect(),
            );
            match DialogPrompt::default().ask(dialog) {
                Ok(Answer::Choice(index)) => several
                    .get(index)
                    .map(|program| (*program).to_owned())
                    .ok_or_else(|| "no agent was chosen".to_owned()),
                Ok(_) => Err("no agent was chosen".to_owned()),
                Err(error) => Err(format!("cannot ask which agent: {error}")),
            }
        }
    }
}

/// Returns the agents the thread named `thread` has work of here.
fn agents_of(store: &Store, thread: &str) -> Result<Vec<AgentSlot>, String> {
    let parsed: ThreadId = thread
        .parse()
        .map_err(|_| format!("{thread} is not a thread id"))?;
    threads::thread_agents(store, parsed)
        .map_err(|error| format!("cannot read thread {thread}'s refs: {error}"))
}

/// Returns the user's own agents among `slots`.
fn own_agents<'a>(slots: &'a [AgentSlot], me: &ParticipantName) -> Vec<&'a AgentSlot> {
    slots
        .iter()
        .filter(|slot| slot.participant() == me)
        .collect()
}

/// Returns the agents whose work a merge can take: all of them, but the user's own when it is
/// their only agent, since it would merge into itself.
fn merge_sources<'a>(slots: &'a [AgentSlot], mine: &[&AgentSlot]) -> Vec<&'a AgentSlot> {
    slots
        .iter()
        .filter(|slot| !matches!(mine, [only] if *only == *slot))
        .collect()
}

/// Picks one of `slots` in a dialog, after `first` when it is given, which picks `None`;
/// returns `Err` with an empty status when the user stopped asking.
fn pick_agent<'a>(
    title: &str,
    question: &str,
    first: Option<&str>,
    slots: &[&'a AgentSlot],
    item: impl Fn(&AgentSlot) -> String,
) -> Result<Option<&'a AgentSlot>, String> {
    let mut items = Vec::with_capacity(slots.len() + 1);
    items.extend(first.map(str::to_owned));
    items.extend(slots.iter().map(|slot| item(slot)));
    let dialog = Dialog::choose(title, vec![question.to_owned()], items);
    let index = match DialogPrompt::default().ask(dialog) {
        Ok(Answer::Choice(index)) => index,
        Ok(_) => return Err(String::new()),
        Err(error) => return Err(format!("cannot ask which agent: {error}")),
    };
    Ok(match (first, index) {
        (Some(_), 0) => None,
        (Some(_), index) => slots.get(index - 1).copied(),
        (None, index) => slots.get(index).copied(),
    })
}

fn me(environment: &Environment) -> Result<ParticipantName, String> {
    session::participant_from(environment.user.as_deref())
        .map_err(|error| format!("USER does not give a participant name: {error}"))
}

/// Asks which agent to add to the thread and what it starts from, and returns the command.
fn agent_add_words(
    store: &Store,
    thread: String,
    environment: &Environment,
) -> Result<Vec<String>, String> {
    let slots = agents_of(store, &thread)?;
    let me = me(environment)?;
    let mine = own_agents(&slots, &me);
    let program = agent_to_run(
        environment,
        (
            "Add an agent",
            "Which of your agents should join the thread?",
        ),
        &mine,
    )?;
    let from = if slots.is_empty() {
        None
    } else {
        let all: Vec<&AgentSlot> = slots.iter().collect();
        pick_agent(
            "Add an agent",
            "What should its worktree start from?",
            Some("The thread's base, as its first agent started"),
            &all,
            |slot| format!("{slot}'s latest snapshot"),
        )?
    };
    let mut words = vec!["agent".to_owned(), "add".to_owned(), thread];
    if let Some(slot) = from {
        words.extend(["--from".to_owned(), slot.to_string()]);
    }
    words.extend(["--".to_owned(), program]);
    Ok(words)
}

/// Asks whose work the user's agent takes over and which agent that is, and returns the
/// command.
fn handoff_words(
    store: &Store,
    thread: String,
    environment: &Environment,
) -> Result<Vec<String>, String> {
    let slots = agents_of(store, &thread)?;
    if slots.is_empty() {
        return Err(format!("thread {thread} has no agent's work to take over"));
    }
    let me = me(environment)?;
    let all: Vec<&AgentSlot> = slots.iter().collect();
    let from = pick_agent(
        "Hand off",
        "Whose work should your agent take over?",
        None,
        &all,
        ToString::to_string,
    )?
    .ok_or_else(|| "no agent was chosen".to_owned())?
    .to_string();
    let program = agent_to_run(
        environment,
        ("Hand off", "Which of your agents should take it over?"),
        &own_agents(&slots, &me),
    )?;
    Ok(vec![
        "handoff".to_owned(),
        thread,
        "--from".to_owned(),
        from,
        "--".to_owned(),
        program,
    ])
}

/// Asks whose work to merge and, when the user has several agents in the thread, into which,
/// and returns the command.
fn merge_words(
    store: &Store,
    thread: &str,
    environment: &Environment,
) -> Result<Vec<String>, String> {
    let slots = agents_of(store, thread)?;
    let me = me(environment)?;
    let mine = own_agents(&slots, &me);
    if mine.is_empty() {
        return Err(format!(
            "you have no agent in thread {thread} to merge into"
        ));
    }
    let sources = merge_sources(&slots, &mine);
    if sources.is_empty() {
        return Err(format!(
            "thread {thread} has no other agent's work to merge"
        ));
    }
    let from = pick_agent(
        "Merge",
        "Whose latest work should be merged?",
        None,
        &sources,
        ToString::to_string,
    )?
    .ok_or_else(|| "no agent was chosen".to_owned())?;
    let targets: Vec<&AgentSlot> = mine.into_iter().filter(|slot| *slot != from).collect();
    let into = match targets.as_slice() {
        [] => return Err(format!("{from} is your only agent in thread {thread}")),
        [only] => *only,
        several => pick_agent(
            "Merge",
            "Into which of your agents?",
            None,
            several,
            ToString::to_string,
        )?
        .ok_or_else(|| "no agent was chosen".to_owned())?,
    };
    Ok(vec![
        "merge".to_owned(),
        thread.to_owned(),
        "--from".to_owned(),
        from.to_string(),
        "--into".to_owned(),
        into.agent().to_string(),
    ])
}

/// Returns the programs mahi has a profile for that are on `PATH`.
fn programs_on_path(environment: &Environment) -> impl Iterator<Item = &'static str> + '_ {
    Profile::programs().filter(|program| run::is_on_path(program, environment.path.as_deref()))
}

/// Asks whether an agent should rewrite the pull request draft after the push, and returns
/// the command that pushes the thread's landing branch, once the thread has been landed here.
fn push_words(
    store: &Store,
    thread: String,
    environment: &Environment,
) -> Result<Vec<String>, String> {
    if store.worktree_dir(&format!("{thread}@land")).is_err() {
        return Err(format!(
            "thread {thread} is not landed here yet: land it first, with Land in its menu"
        ));
    }
    let writers: Vec<&str> = programs_on_path(environment).collect();
    let mut items = Vec::with_capacity(writers.len() + 1);
    items.push("Just push".to_owned());
    items.extend(
        writers
            .iter()
            .map(|program| format!("Push, then let {program} rewrite the pull request draft")),
    );
    let dialog = Dialog::choose(
        "Push",
        vec![format!(
            "Push thread {thread}'s landing branch to the chosen remote, fast-forward only, \
             with the thread's trailers added to the commits that are not pushed yet?"
        )],
        items,
    );
    let index = match DialogPrompt::default().ask(dialog) {
        Ok(Answer::Choice(index)) => index,
        Ok(_) => return Err(String::new()),
        Err(error) => return Err(format!("cannot ask how to push: {error}")),
    };
    let mut words = vec!["land".to_owned(), thread, "--push".to_owned()];
    if let Some(index) = index.checked_sub(1) {
        let writer = writers
            .get(index)
            .ok_or_else(|| "no agent was chosen".to_owned())?;
        words.extend(["--with".to_owned(), (*writer).to_owned()]);
    }
    Ok(words)
}

/// What the Remote dialog can do with one of its items.
enum RemoteChoice {
    Push(RemoteName, Visibility),
    Add,
    Off,
}

/// Asks in a dialog which remote threads are pushed to, and whether it is private, or which
/// git remote to add to the repository first.
fn choose_remote(store: &mut Store) -> String {
    let names = store.remote_names();
    let mut items = Vec::with_capacity(names.len() * 2 + 2);
    let mut choices = Vec::with_capacity(names.len() * 2 + 2);
    for name in &names {
        let Ok(remote) = name.parse::<RemoteName>() else {
            continue;
        };
        items.push(format!("{name} · private: push the agents' snapshots too"));
        choices.push(RemoteChoice::Push(remote.clone(), Visibility::Private));
        items.push(format!("{name} · public: keep the snapshots here"));
        choices.push(RemoteChoice::Push(remote, Visibility::Public));
    }
    items.push("Add a git remote to this repository".to_owned());
    choices.push(RemoteChoice::Add);
    items.push("Don't push threads".to_owned());
    choices.push(RemoteChoice::Off);
    let mut lines = vec![
        format!("Threads are pushed to: {}", remote::summary(store)),
        "Teammates and your other machines pick threads up from there.".to_owned(),
    ];
    if choices.len() == 2 {
        lines.push(
            "This repository has no git remote yet: add one, such as the GitHub repository \
             your team shares."
                .to_owned(),
        );
    }
    let dialog = Dialog::choose("Remote", lines, items);
    let picked = match DialogPrompt::default().ask(dialog) {
        Ok(Answer::Choice(index)) => choices.into_iter().nth(index),
        _ => return String::new(),
    };
    let told = match picked {
        Some(RemoteChoice::Push(name, visibility)) => remote::choose(store, &name, visibility),
        Some(RemoteChoice::Add) => match add_remote(store) {
            Ok(Added::Chosen(name, visibility)) => remote::choose(store, &name, visibility),
            Ok(Added::NotChosen(name)) => {
                return format!("added the git remote {name}; threads are not pushed to it yet");
            }
            Ok(Added::Nothing) => return String::new(),
            Err(error) => Err(error),
        },
        Some(RemoteChoice::Off) => {
            remote::stop_pushing(store).map(|()| "threads are not pushed".to_owned())
        }
        None => return String::new(),
    };
    match told {
        Ok(told) => {
            eprint!("{told}");
            format!("remote: {}", remote::summary(store))
        }
        Err(error) => {
            crate::report_with("cannot choose the remote", &error);
            "the remote was not changed; see the activity".to_owned()
        }
    }
}

/// What adding a git remote from the Remote dialog did.
enum Added {
    Nothing,
    NotChosen(RemoteName),
    Chosen(RemoteName, Visibility),
}

/// Asks for the name and URL of a git remote, adds it to the repository, and asks whether
/// it is private.
fn add_remote(store: &mut Store) -> Result<Added, remote::RemoteError> {
    let mut prompt = DialogPrompt::default();
    let name = match prompt.ask(Dialog::input(
        "Add a git remote",
        vec!["Its name, as git calls it; empty for `origin`.".to_owned()],
        false,
    )) {
        Ok(Answer::Text(text)) if text.trim().is_empty() => "origin".to_owned(),
        Ok(Answer::Text(text)) => text.trim().to_owned(),
        _ => return Ok(Added::Nothing),
    };
    let name = name
        .parse::<RemoteName>()
        .map_err(remote::RemoteError::InvalidName)?;
    let url = match prompt.ask(Dialog::input(
        "Add a git remote",
        vec![
            format!("The URL of {name}, over SSH or HTTPS, such as:"),
            "`git@github.com:team/project.git` or `https://github.com/team/project.git`".to_owned(),
        ],
        false,
    )) {
        Ok(Answer::Text(text)) => text.trim().to_owned(),
        _ => return Ok(Added::Nothing),
    };
    remote::add(store, &name, &url)?;
    eprintln!("added the git remote {name}");
    let visibility = match prompt.ask(Dialog::choose(
        "Remote",
        vec![format!("Push threads to {name}?")],
        vec![
            "Private: push the agents' snapshots too".to_owned(),
            "Public: keep the snapshots here".to_owned(),
        ],
    )) {
        Ok(Answer::Choice(0)) => Visibility::Private,
        Ok(Answer::Choice(1)) => Visibility::Public,
        _ => return Ok(Added::NotChosen(name)),
    };
    Ok(Added::Chosen(name, visibility))
}

#[cfg(test)]
mod tests {
    use mahi_core::AgentName;

    use super::*;

    fn slot(participant: &str, agent: &str) -> AgentSlot {
        AgentSlot::new(
            ParticipantName::new(participant).unwrap(),
            AgentName::new(agent).unwrap(),
        )
    }

    #[test]
    fn a_merge_takes_any_agents_work_but_never_the_users_only_agent_into_itself() {
        let slots = [
            slot("alice", "codex"),
            slot("bob", "claude"),
            slot("bob", "codex"),
        ];
        let bob = ParticipantName::new("bob").unwrap();
        let mine = own_agents(&slots, &bob);
        assert_eq!(mine, [&slots[1], &slots[2]]);
        assert_eq!(merge_sources(&slots, &mine).len(), 3);
        let alone = [slot("alice", "codex"), slot("bob", "claude")];
        let mine = own_agents(&alone, &bob);
        assert_eq!(merge_sources(&alone, &mine), [&alone[0]]);
        let carol = ParticipantName::new("carol").unwrap();
        assert!(own_agents(&alone, &carol).is_empty());
        assert_eq!(merge_sources(&alone, &[]).len(), 2);
    }
}
