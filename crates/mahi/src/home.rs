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
    LocalIdentity,
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
    Header,
    Home,
    HomeAction,
    HomeRow,
    HomeView,
    PaletteKeys,
    ThreadView,
    TopBar,
};
use mahi_thread::{
    ParticipantKey,
    Role,
};
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
    init,
    join,
    pair,
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
        SPIN_EVERY,
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
const INVITED: (&str, &str) = ("invite", "done");
const INVITE_ROLES: [(&str, &str); 2] = [
    (
        "--collaborator",
        "✎ Collaborator: they run their own agent, kept in sync with yours",
    ),
    ("--watcher", "🔒 Watcher: they watch your agents"),
];

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
    let identity_file = config.as_ref().map(ConfigDir::identity_file);
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
                status = act_and_show(action, &mut store, environment, &mut workspace);
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
    ui::clear_notice();
    let mut size = terminal::size();
    let mut terminal = Terminal::new(ui::backend(size.rows, size.cols))?;
    terminal.clear()?;
    let mut keys = ThreadListKeys::default();
    let mut rows = rows(place.store, place.own);
    let mut remote = remote::summary(place.store);
    home.fit(&rows);
    let mut activity = activity(place.captured);
    let mut seen = place.captured.map(Captured::generation);
    let mut read_at = Instant::now();
    let mut buffer = [0_u8; MAX_READ];
    let mut dirty = true;
    let mut passed = Vec::new();
    let mut for_threads = Vec::with_capacity(MAX_READ);
    loop {
        give_mouse(workspace, home, size);
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
        if dirty && !workspace.waits_for_redraw(Instant::now()) {
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
            moved => {
                let view = home_view(place, &remote, &rows, &activity);
                draw(&mut terminal, home, &view, status, workspace)?;
                if let Some(chosen) = chosen_in_palette(moved) {
                    return Ok(chosen);
                }
                terminal.clear()?;
                dirty = true;
            }
        }
        if for_threads.is_empty() {
            continue;
        }
        let chosen = keys.read(home, &rows, &mut for_threads, Instant::now());
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

/// Leaves the mouse to the terminal while the home screen shows a dialog, and takes it back
/// for the tabs after a dialog of an action left it, on a terminal of `size`.
fn give_mouse(workspace: &mut Workspace, home: &Home, size: WindowSize) {
    workspace.pause_mouse(home.has_dialog() && workspace.shows_threads());
    if ui::mouse_was_left() {
        workspace.set_screen(size, true);
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
    changed |= workspace.forget_told();
    changed |= workspace.spin(Instant::now());
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

/// The thread list's keys, and when the escape byte a read ended with alone may still be the
/// start of a sequence whose rest comes in the next read.
#[derive(Debug, Default)]
struct ThreadListKeys {
    keys: PaletteKeys,
    escaped_until: Option<Instant>,
}

impl ThreadListKeys {
    /// Reads the keys in `typed` at `now`, and returns the action they choose, if any. A read
    /// that ends in an escape byte alone, outside a paste, gives the next read, when it comes
    /// within half a second and starts with `[` or `O`, that byte back, so the rest of a paste
    /// split after it is read as a paste.
    fn read(
        &mut self,
        home: &mut Home,
        rows: &[HomeRow],
        typed: &mut Vec<u8>,
        now: Instant,
    ) -> Option<HomeAction> {
        if self.escaped_until.take().is_some_and(|until| now < until)
            && matches!(typed.first(), Some(b'[' | b'O'))
        {
            typed.insert(0, ESC);
        }
        let mut chosen = None;
        self.keys.read(typed, |input| {
            chosen = home.key(input, rows);
            chosen.is_none()
        });
        if typed.last() == Some(&ESC) && !self.keys.is_pasting() {
            self.escaped_until = Some(now + AFTER_ESCAPE);
        }
        chosen
    }
}

/// Returns how long to wait for a key before looking again: briefly while agents run, whose
/// output must be drawn as it comes.
fn key_wait(workspace: &Workspace) -> Duration {
    if workspace.is_running() {
        CHILD_WAIT
    } else if workspace.waiting().is_some() {
        SPIN_EVERY
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
    remote: &'a remote::Summary,
    rows: &'a [HomeRow],
    activity: &'a [String],
) -> HomeView<'a> {
    HomeView {
        header: Header {
            repository: place.repository,
            remote: remote.text(),
            remote_chosen: remote.chosen(),
            remote_key: true,
            identity: place.identity,
        },
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
    ui::clear_notice();
    let drawn = terminal.draw(|frame| {
        let (top, body) = TopBar::split(frame.area());
        if !workspace.has_tabs() {
            TopBar {
                tabs: None,
                header: view.header,
            }
            .render(top, frame.buffer_mut());
            home.render(view, status, body, frame.buffer_mut());
            return;
        }
        let header = Header {
            remote_key: workspace.shows_threads(),
            ..view.header
        };
        let cursor = workspace.render(header, top, body, frame.buffer_mut());
        if workspace.shows_threads() {
            home.render(view, status, body, frame.buffer_mut());
        } else if let Some(cursor) = cursor.filter(|_| !workspace.palette_open()) {
            frame.set_cursor_position(cursor);
        }
        workspace.render_palette(body, frame.buffer_mut());
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

/// Runs the chosen action as `act` does, then shows the thread's tab when it invited a
/// teammate to a thread open in one, and otherwise the thread list; returns what the home
/// screen says about it.
fn act_and_show(
    action: HomeAction,
    store: &mut Store,
    environment: &Environment,
    workspace: &mut Workspace,
) -> String {
    let invited = match &action {
        HomeAction::Invite(thread) => thread.parse::<ThreadId>().ok(),
        _ => None,
    };
    let mut hidden = Vec::new();
    workspace.hide_shown(&mut hidden);
    if let Err(error) = write_screen(&hidden) {
        return format!("the terminal cannot be written: {error}");
    }
    let done = stop_thread_first(&action, workspace).and_then(|()| act(action, store, environment));
    let shown =
        done.is_ok() && invited.is_some_and(|thread| workspace.show_thread(thread, INVITED));
    if !shown {
        workspace.show_threads();
    }
    done.unwrap_or_else(|told| told)
}

/// Runs the chosen action as its command does, without leaving the alternate screen, and
/// returns what the home screen says about it, as an error when it ran no command or the
/// command failed.
fn act(action: HomeAction, store: &mut Store, environment: &Environment) -> Result<String, String> {
    run_words(&command_words(action, store, environment)?, environment)
}

/// Returns what the workspace's palette chose with `moved`, once confirmed: quitting, or an
/// action on a thread.
fn chosen_in_palette(moved: Moved) -> Option<Chosen> {
    match moved {
        Moved::Quit => Some(Chosen::Quit),
        Moved::Act(choice, thread) => Some(choice.action(thread.to_string()))
            .filter(confirmed)
            .map(Chosen::Action),
        Moved::Nothing | Moved::Shown | Moved::New => None,
    }
}

/// Asks the question `action` is confirmed with, if any; returns whether it runs.
fn confirmed(action: &HomeAction) -> bool {
    action.question().is_none_or(|question| {
        let answer = DialogPrompt::default().ask(Dialog::confirm("Confirm", vec![question]));
        matches!(answer, Ok(Answer::Confirmed(true)))
    })
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

/// Unlocks the user's mahi key from `file`, asking for its passphrase in a dialog unless the
/// home screen keeps it; returns what to tell the user when it is not unlocked.
fn unlock_key(file: &Path) -> Result<LocalIdentity, String> {
    unlocked::identity(
        file,
        || {
            TerminalPrompt::open()
                .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
                .map_err(|error| match error.kind() {
                    io::ErrorKind::Interrupted => String::new(),
                    _ => format!("the passphrase cannot be asked: {error}"),
                })
        },
        |error| format!("the mahi key cannot be unlocked: {error}"),
    )
}

/// Pairs with the teammate whose code the user types, records the thread they add the user
/// to, and opens it in a tab that watches its agents, with the mahi key unlocked to host it;
/// when the owner made the user a collaborator, then starts the agent they pick there, as
/// `mahi join` with an agent does. Returns what to tell the user when it does not.
fn join_in_tab(
    environment: &Environment,
    workspace: &mut Workspace,
    identity_file: Option<&Path>,
) -> Result<(), String> {
    const SHOWN: &str = "mahi join";
    eprintln!("› {SHOWN}");
    let busy = ui::Busy::start();
    let joined = init::set_up_if_needed(environment, TerminalPrompt::open_interactive)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
        .and_then(|()| match identity_file {
            Some(file) => unlock_key(file).map(drop).map_err(Into::into),
            None => Ok(()),
        })
        .and_then(|()| pair::join_by_code(environment).map_err(Into::into))
        .and_then(|ticket| {
            join::record(&ticket, environment)
                .map(|joined| (ticket, joined))
                .map_err(Into::into)
        });
    drop(busy);
    ui::keys_make_signals(false);
    let (ticket, (thread, role)) = match joined {
        Ok(joined) => joined,
        Err(error) => {
            crate::report(&*error);
            return Err(format!("{SHOWN} failed"));
        }
    };
    workspace.watch_thread(thread);
    match role {
        Role::Watcher => Ok(()),
        Role::Collaborator => {
            let agent = agent_to_run(
                environment,
                ("Join a thread", "Which agent should work in this thread?"),
                &[],
            )
            .map_err(|told| match told.split_once("; run mahi run") {
                Some((none, _)) => none.to_owned(),
                None => told,
            })?;
            let words = vec![
                "join".to_owned(),
                ticket.to_string(),
                "--".to_owned(),
                agent.clone(),
            ];
            let shown = format!("mahi join -- {agent}");
            let key = identity_file.and_then(unlocked::current);
            workspace.open(
                environment,
                (&short(&thread.to_string()), &agent, &shown),
                (&words, false),
                key.as_ref(),
            )
        }
    }
}

/// Before an action that ends or purges a thread whose agents run in the workspace's tabs,
/// asks whether to stop them, and stops them as quitting does; returns what to tell the user
/// when the action does not go on.
fn stop_thread_first(action: &HomeAction, workspace: &mut Workspace) -> Result<(), String> {
    let (thread, verb, done) = match action {
        HomeAction::End(thread) => (thread, "end", "ended"),
        HomeAction::Purge(thread) => (thread, "purge", "purged"),
        _ => return Ok(()),
    };
    let Ok(thread) = thread.parse::<ThreadId>() else {
        return Ok(());
    };
    workspace.leave_thread(thread);
    let count = workspace.running_in(thread);
    if count == 0 {
        return Ok(());
    }
    let (running, them) = if count == 1 {
        ("1 agent is".to_owned(), "it")
    } else {
        (format!("{count} agents are"), "them")
    };
    let confirmed = DialogPrompt::default().ask(Dialog::confirm(
        "Confirm",
        vec![format!(
            "{running} running in this thread: stop {them} and {verb}? Each ends as a stop \
             signal ends it, with its last snapshot unless it was already taking it."
        )],
    ));
    if !matches!(confirmed, Ok(Answer::Confirmed(true))) {
        return Err("the agents keep running".to_owned());
    }
    let busy = ui::Busy::start();
    let left = workspace.stop_thread(thread, STOP_WITHIN);
    drop(busy);
    if left > 0 {
        return Err(format!(
            "{left} agent(s) did not stop within {} s; the thread was not {done}",
            STOP_WITHIN.as_secs()
        ));
    }
    Ok(())
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

/// Returns whether the action opens a thread's tab in the workspace: one that runs an agent,
/// or a join, whose tab watches the owner's agents.
fn runs_agent(action: &HomeAction) -> bool {
    matches!(
        action,
        HomeAction::New
            | HomeAction::Resume(_)
            | HomeAction::AddAgent(_)
            | HomeAction::Handoff(_)
            | HomeAction::Join
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

/// Starts the agent `action` runs, as `start_agent` does, and shows the thread list when it
/// does not start, where what it returns to tell the user is drawn, unless the user only
/// declined one of its questions.
fn open_agent(
    action: HomeAction,
    store: &mut Store,
    environment: &Environment,
    workspace: &mut Workspace,
    identity_file: Option<&Path>,
) -> Result<(), String> {
    let started = if action == HomeAction::Join {
        join_in_tab(environment, workspace, identity_file)
    } else {
        start_agent(action, store, environment, workspace, identity_file)
    };
    if started.as_ref().is_err_and(|told| !told.is_empty()) {
        workspace.show_threads();
    }
    started
}

/// Starts the agent `action` runs in its thread's tab of the workspace, with the user's mahi
/// key unlocked first when the agent needs it, from the `identity_file`; returns what to tell
/// the user when it does not start.
fn start_agent(
    action: HomeAction,
    store: &mut Store,
    environment: &Environment,
    workspace: &mut Workspace,
    identity_file: Option<&Path>,
) -> Result<(), String> {
    let (title, resumed_thread) = match &action {
        HomeAction::Resume(thread) => (short(thread), Some(thread.as_str())),
        HomeAction::AddAgent(thread) | HomeAction::Handoff(thread) => (short(thread), None),
        _ => (NEW_TAB.to_owned(), None),
    };
    if resumed_thread.is_some() && workspace.show_running(&title) {
        return Ok(());
    }
    workspace.room_for_agent()?;
    let resumed = resumed_thread.map(|thread| resumed_name(store, thread, environment));
    let needs_key = !matches!(action, HomeAction::New) || environment.live != LiveMode::Off;
    let words = command_words(action, store, environment)?;
    let name = resumed.unwrap_or_else(|| words.last().cloned().unwrap_or_default());
    if needs_key {
        init::set_up_if_needed(environment, TerminalPrompt::open_interactive).map_err(|error| {
            match error {
                init::InitError::Prompt(error) if error.kind() == io::ErrorKind::Interrupted => {
                    String::new()
                }
                error => format!("mahi cannot be set up: {error}"),
            }
        })?;
    }
    let key = match identity_file {
        Some(file) if needs_key => Some(unlock_key(file)?),
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

/// Returns the name of the user's agent that resuming `thread` starts, or `agent` when the
/// thread names none or several.
fn resumed_name(store: &Store, thread: &str, environment: &Environment) -> String {
    session::participant_from(environment.user.as_deref())
        .ok()
        .zip(thread.parse().ok())
        .and_then(|(participant, thread)| {
            session::pick_slot(store, thread, &participant, None).ok()
        })
        .map_or_else(
            || "agent".to_owned(),
            |slot| slot.agent().as_str().to_owned(),
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
        HomeAction::Invite(thread) => invite_words(store, thread)?,
        HomeAction::Purge(thread) => vec!["purge".to_owned(), thread],
        HomeAction::AddAgent(thread) => agent_add_words(store, thread, environment)?,
        HomeAction::Handoff(thread) => handoff_words(store, thread, environment)?,
        HomeAction::Merge(thread) => merge_words(store, &thread, environment)?,
        HomeAction::Push(thread) => push_words(store, thread, environment)?,
        HomeAction::Join => vec!["join".to_owned()],
        HomeAction::Remote => return Err(choose_remote(store, None)),
        HomeAction::Card => vec!["id".to_owned()],
        HomeAction::Credentials => credential_words(environment)?,
        HomeAction::Quit => return Err(String::new()),
    };
    Ok(words)
}

/// Runs the mahi command `words` as it would run on its own, without leaving the alternate
/// screen, and returns what the home screen says about it, as an error when it did not
/// succeed.
fn run_words(words: &[String], environment: &Environment) -> Result<String, String> {
    let shown = format!("mahi {}", words.join(" "));
    let Ok(Cli {
        command: Some(command),
    }) = Cli::try_parse_from(std::iter::once("mahi").chain(words.iter().map(String::as_str)))
    else {
        return Err(format!("{shown} is not a command mahi knows"));
    };
    eprintln!("› {shown}");
    let busy = ui::Busy::start();
    let code = match command {
        Command::Purge(purge) => match crate::purge_unless_declined(&purge, environment) {
            Some(code) => code,
            None => return Err(format!("{shown}: nothing was purged")),
        },
        command => run_command(command, environment),
    };
    drop(busy);
    match code {
        0 => Ok(format!("{shown}: done")),
        code => Err(format!("{shown} failed with exit code {code}")),
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
                Ok(_) => Err(String::new()),
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

/// Returns the words of `mahi invite` for `thread`, first asking in the Remote dialog for a
/// remote to meet through when none is chosen, then what the teammate may do with the user's
/// agents, or what to tell the user when either is not answered.
fn invite_words(store: &mut Store, thread: String) -> Result<Vec<String>, String> {
    if matches!(remote::sync_remote(store), Ok(None)) {
        let told = choose_remote(store, Some("Pairing needs a remote to meet through."));
        if !matches!(remote::sync_remote(store), Ok(Some(_))) {
            return Err(told);
        }
    }
    let dialog = Dialog::choose(
        "Invite a teammate",
        vec!["What may they do with your agents?".to_owned()],
        INVITE_ROLES
            .iter()
            .map(|(_, item)| (*item).to_owned())
            .collect(),
    );
    let Ok(Answer::Choice(index)) = DialogPrompt::default().ask(dialog) else {
        return Err(String::new());
    };
    let (flag, _) = INVITE_ROLES
        .get(index)
        .ok_or_else(|| "no role was chosen".to_owned())?;
    Ok(vec!["invite".to_owned(), (*flag).to_owned(), thread])
}

/// Asks in a dialog which remote threads are pushed to, and whether it is private, or which
/// git remote to add to the repository first, telling first `why` it is asked.
fn choose_remote(store: &mut Store, why: Option<&str>) -> String {
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
    let mut lines: Vec<String> = why.map(str::to_owned).into_iter().collect();
    lines.extend([
        format!("Threads are pushed to: {}", remote::summary(store)),
        "Teammates and your other machines pick threads up from there.".to_owned(),
    ]);
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
            "the remote was not changed".to_owned()
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
    fn the_home_screen_wakes_for_each_turn_of_a_waiting_tabs_spinner() {
        let mut workspace = Workspace::new(
            mahi_term::PaletteKey::default(),
            mahi_term::Notice::for_terminal(mahi_term::TerminalHints::default()),
        );
        let setup = crate::workspace_live::tests::setup();
        workspace.host_with(Some(crate::workspace_live::tests::hosting(&setup)));
        assert_eq!(key_wait(&workspace), KEY_WAIT);
        workspace.watch_thread(setup.thread);
        workspace.spin(Instant::now());
        assert_eq!(key_wait(&workspace), SPIN_EVERY);
    }

    fn home_rows() -> Vec<HomeRow> {
        ["t1", "t2"]
            .map(|thread| HomeRow {
                thread: thread.to_owned(),
                agents: "you.claude".to_owned(),
                worktree: true,
                owned: true,
            })
            .to_vec()
    }

    struct Typing {
        keys: ThreadListKeys,
        home: Home,
        rows: Vec<HomeRow>,
        now: Instant,
    }

    impl Typing {
        fn with_help_open() -> Self {
            let mut typing = Self {
                keys: ThreadListKeys::default(),
                home: Home::default(),
                rows: home_rows(),
                now: Instant::now(),
            };
            assert_eq!(typing.read(b"?"), None);
            typing
        }

        fn read(&mut self, typed: &[u8]) -> Option<HomeAction> {
            let mut typed = typed.to_vec();
            self.keys
                .read(&mut self.home, &self.rows, &mut typed, self.now)
        }
    }

    #[test]
    fn an_arrow_read_with_the_escape_that_closes_a_dialog_still_moves_the_selection() {
        let mut typing = Typing::with_help_open();
        assert_eq!(typing.read(b"\x1b\x1b[B"), None);
        assert_eq!(typing.home.selected(), 1);
        assert_eq!(typing.keys.escaped_until, None);
    }

    #[test]
    fn a_key_read_after_the_escape_that_closes_a_dialog_is_not_dropped() {
        let mut typing = Typing::with_help_open();
        assert_eq!(typing.read(b"\x1b"), None);
        assert!(typing.keys.escaped_until.is_some());
        assert_eq!(typing.read(b"j"), None);
        assert_eq!(typing.home.selected(), 1);
    }

    #[test]
    fn the_rest_of_a_paste_split_after_its_escape_is_read_as_a_paste() {
        for split in [
            &[&b"[200~qey\r\x1b[201~"[..]][..],
            &[b"[20", b"0~qey\r\x1b[201~"],
        ] {
            let mut typing = Typing::with_help_open();
            assert_eq!(typing.read(b"\x1b"), None);
            for rest in split {
                assert_eq!(typing.read(rest), None, "{split:?}");
            }
            assert!(!typing.keys.keys.is_pasting(), "{split:?}");
            assert_eq!(typing.home.selected(), 0, "{split:?}");
            assert_eq!(typing.read(b"j"), None);
            assert_eq!(typing.home.selected(), 1, "{split:?}");
        }
    }

    #[test]
    fn only_the_next_read_within_half_a_second_gets_the_escape_byte_back() {
        let mut late = Typing::with_help_open();
        assert_eq!(late.read(b"\x1b"), None);
        late.now += AFTER_ESCAPE;
        assert_eq!(late.read(b"[200~"), None);
        assert!(!late.keys.keys.is_pasting());
        let mut after = Typing::with_help_open();
        assert_eq!(after.read(b"\x1b"), None);
        assert_eq!(after.read(b"j"), None);
        assert_eq!(after.read(b"[200~"), None);
        assert!(!after.keys.keys.is_pasting());
        let mut next = Typing::with_help_open();
        assert_eq!(next.read(b"\x1b"), None);
        assert_eq!(next.read(b"[200~"), None);
        assert!(next.keys.keys.is_pasting());
    }

    #[test]
    fn only_a_read_that_ends_in_a_lone_escape_opens_the_window() {
        let mut typing = Typing::with_help_open();
        assert_eq!(typing.read(b"\x03"), None);
        assert_eq!(typing.keys.escaped_until, None);
        assert_eq!(typing.read(b"?"), None);
        assert_eq!(typing.read(b"\x1b[27u"), None);
        assert_eq!(typing.keys.escaped_until, None);
    }

    #[test]
    fn each_invite_choice_gives_the_role_its_words_name() {
        let thread = "7f3a9c2e00010203040506070809abff";
        let roles: Vec<(Role, &str)> = INVITE_ROLES
            .iter()
            .map(|(flag, item)| {
                let Cli {
                    command: Some(Command::Invite(invite)),
                } = Cli::try_parse_from(["mahi", "invite", flag, thread]).unwrap()
                else {
                    panic!("not an invite");
                };
                (invite.role(), *item)
            })
            .collect();
        assert_eq!(
            roles,
            [
                (
                    Role::Collaborator,
                    "✎ Collaborator: they run their own agent, kept in sync with yours"
                ),
                (Role::Watcher, "🔒 Watcher: they watch your agents"),
            ]
        );
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
