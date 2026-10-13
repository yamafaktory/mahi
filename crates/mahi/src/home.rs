use std::{
    env,
    fs,
    io::{
        self,
        Write,
    },
    os::fd::AsFd,
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
use mahi_sandbox::{
    InputWait,
    Termination,
    TerminationSignals,
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
};
use ratatui_core::terminal::Terminal;

use crate::{
    cli::{
        Cli,
        Command,
    },
    environment::Environment,
    profile::Profile,
    remote::{
        self,
        RemoteName,
        Visibility,
    },
    run,
    run_command,
    session,
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
};

const ENTER_SCREEN: &[u8] =
    b"\x1b[?1049h\x1b[?2004h\x1b[?25l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[2J";
const LEAVE_SCREEN: &[u8] = b"\x1b[?25h\x1b[?2004l\x1b[?1049l";
const REREAD: Duration = Duration::from_secs(2);
const KEY_WAIT: Duration = Duration::from_millis(200);
const SEQUENCE_WAIT: Duration = Duration::from_millis(30);
const ESC: u8 = 0x1b;
const MAX_READ: usize = 1024;
const AFTER_ESCAPE: Duration = Duration::from_millis(500);

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
    let outcome = loop {
        let place = Place {
            store: &store,
            repository: &repository,
            identity: &identity,
            captured: captured.as_ref(),
        };
        match choose(&place, &mut home, &status) {
            Ok(Chosen::Quit) => break Ok(()),
            Ok(Chosen::Stopped(signal)) => break Err(Ended::Stopped(signal)),
            Ok(Chosen::Action(action)) => {
                status = act(action, &mut store, environment);
                ui::keys_make_signals(false);
                if let Err(error) = Screen::restore() {
                    break Err(Ended::Failed(error));
                }
            }
            Err(error) => break Err(Ended::Failed(error)),
        }
    };
    drop(captured);
    drop(showing);
    drop(screen);
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
fn choose(place: &Place<'_>, home: &mut Home, status: &str) -> io::Result<Chosen> {
    let signals = TerminationSignals::listen().map_err(io::Error::other)?;
    ui::keys_make_signals(false);
    let mut size = terminal::size();
    let mut terminal = Terminal::new(AnsiBackend::new(io::stdout(), size.rows, size.cols))?;
    terminal.clear()?;
    let mut keys = PaletteKeys::default();
    let mut rows = rows(place.store);
    let mut remote = remote::summary(place.store);
    home.fit(&rows);
    let mut activity = activity(place.captured);
    let mut seen = place.captured.map(Captured::generation);
    let mut read_at = Instant::now();
    let mut buffer = [0_u8; MAX_READ];
    let mut dirty = true;
    let mut ignore_until = None;
    loop {
        if read_at.elapsed() >= REREAD {
            let fresh = self::rows(place.store);
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
        if dirty {
            let view = HomeView {
                repository: place.repository,
                remote: &remote,
                identity: place.identity,
                rows: &rows,
                activity: &activity,
            };
            let drawn = terminal.draw(|frame| {
                home.render(&view, status, frame.area(), frame.buffer_mut());
            })?;
            ui::keep_backdrop(drawn.buffer);
            dirty = false;
        }
        match wait(&signals, KEY_WAIT)? {
            InputWait::Timeout => continue,
            InputWait::Signal(signal) => return Ok(Chosen::Stopped(signal)),
            InputWait::Input => {}
        }
        let read = match read_chunk(&signals, &mut buffer)? {
            Chunk::Read(read) => read,
            Chunk::End => return Ok(Chosen::Quit),
            Chunk::Stopped(signal) => return Ok(Chosen::Stopped(signal)),
        };
        if ignore_until.is_some_and(|until| Instant::now() < until) {
            continue;
        }
        let mut chosen = None;
        let mut escaped = false;
        keys.read(buffer.get(..read).unwrap_or_default(), |input| {
            escaped |= input == PaletteInput::Escape;
            if let Some(action) = home.key(input, &rows) {
                chosen = Some(action);
                return false;
            }
            input != PaletteInput::Escape
        });
        if escaped {
            ignore_until = Some(Instant::now() + AFTER_ESCAPE);
        }
        dirty = true;
        match chosen {
            Some(HomeAction::Quit) => return Ok(Chosen::Quit),
            Some(action) => return Ok(Chosen::Action(action)),
            None => {}
        }
    }
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

fn rows(store: &Store) -> Vec<HomeRow> {
    threads::home_rows(store).unwrap_or_default()
}

/// Runs the chosen action as its command does, without leaving the alternate screen, and
/// returns what the home screen says about it.
fn act(action: HomeAction, store: &mut Store, environment: &Environment) -> String {
    let words: Vec<String> = match action {
        HomeAction::New => match agent_to_run(environment) {
            Ok(agent) => vec!["run".to_owned(), agent],
            Err(told) => return told,
        },
        HomeAction::Resume(thread) => vec!["resume".to_owned(), thread],
        HomeAction::Land(thread) => vec!["land".to_owned(), thread],
        HomeAction::End(thread) => vec!["end".to_owned(), thread],
        HomeAction::Invite(thread) => vec!["invite".to_owned(), thread],
        HomeAction::Purge(thread) => vec!["purge".to_owned(), thread],
        HomeAction::Join => vec!["join".to_owned()],
        HomeAction::Remote => return choose_remote(store),
        HomeAction::Card => vec!["id".to_owned()],
        HomeAction::Quit => return String::new(),
    };
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

/// Returns the agent to start a thread with: the one mahi has a profile for that is on `PATH`,
/// or the one the user picks in a dialog when there are several.
fn agent_to_run(environment: &Environment) -> Result<String, String> {
    let found: Vec<&str> = Profile::programs()
        .filter(|program| run::is_on_path(program, environment.path.as_deref()))
        .collect();
    match found.as_slice() {
        [] => Err("no agent mahi has a profile for is on PATH; run mahi run <agent>".to_owned()),
        [only] => Ok((*only).to_owned()),
        several => {
            let dialog = Dialog::choose(
                "New thread",
                vec!["Which agent should start the thread?".to_owned()],
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
