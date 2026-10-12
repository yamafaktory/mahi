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
    Home,
    HomeAction,
    HomeRow,
    PaletteInput,
    PaletteKeys,
};
use ratatui_core::terminal::Terminal;

use crate::{
    cli::Cli,
    environment::Environment,
    profile::Profile,
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    run,
    run_command,
    terminal::{
        self,
        RawMode,
    },
    threads,
};

const ENTER_SCREEN: &[u8] = b"\x1b[?1049h\x1b[?2004h\x1b[?25l";
const LEAVE_SCREEN: &[u8] = b"\x1b[?25h\x1b[?2004l\x1b[?1049l";
const REREAD: Duration = Duration::from_secs(2);
const KEY_WAIT: Duration = Duration::from_millis(200);
const SEQUENCE_WAIT: Duration = Duration::from_millis(30);
const ESC: u8 = 0x1b;
const MAX_READ: usize = 1024;
const PAIRING_LATER: &str = "pairing codes are not built yet: use mahi id, mahi invite <thread> \
                             <card> and mahi join <ticket>";

/// Opens the home screen in the repository around the current directory and runs the actions
/// chosen there until the user quits; returns the exit code. Outside a repository, or without
/// a terminal, it prints the help instead.
pub(crate) fn home(environment: &Environment) -> i32 {
    let store = env::current_dir()
        .and_then(fs::canonicalize)
        .ok()
        .and_then(|cwd| Store::discover(&cwd).ok());
    let Some(store) = store.filter(|_| terminal::is_interactive()) else {
        let _ = Cli::command().write_help(&mut io::stderr());
        return 2;
    };
    let repository = store
        .common_dir()
        .parent()
        .and_then(|dir| dir.file_name())
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let mut home = Home::default();
    let mut status = String::new();
    loop {
        match choose(&store, &repository, &mut home, &status) {
            Ok(Chosen::Quit) => return 0,
            Ok(Chosen::Stopped(signal)) => {
                signal.reraise();
                process::exit(128 + signal.number());
            }
            Ok(Chosen::Action(action)) => status = act(action, environment),
            Err(error) => {
                crate::report_with("the home screen failed", &error);
                return 1;
            }
        }
    }
}

/// How the home screen was left.
enum Chosen {
    Quit,
    Action(HomeAction),
    Stopped(Termination),
}

/// Keeps the home screen's alternate screen, raw mode and bracketed paste on while it lives.
struct Screen {
    _raw: Option<RawMode>,
}

impl Screen {
    fn enter() -> io::Result<Self> {
        let raw = RawMode::enable()?;
        let mut out = io::stdout().lock();
        out.write_all(ENTER_SCREEN)?;
        out.flush()?;
        Ok(Self { _raw: raw })
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let mut out = io::stdout().lock();
        let _ = out.write_all(LEAVE_SCREEN);
        let _ = out.flush();
    }
}

/// Shows the home screen until the user chooses an action, quits, or a signal stops mahi;
/// the screen is left before it returns.
fn choose(store: &Store, repository: &str, home: &mut Home, status: &str) -> io::Result<Chosen> {
    let signals = TerminationSignals::listen().map_err(io::Error::other)?;
    let _screen = Screen::enter()?;
    let mut size = terminal::size();
    let mut terminal = Terminal::new(AnsiBackend::new(io::stdout(), size.rows, size.cols))?;
    let mut keys = PaletteKeys::default();
    let mut rows = rows(store);
    home.fit(&rows);
    let mut read_at = Instant::now();
    let mut buffer = [0_u8; MAX_READ];
    let mut dirty = true;
    loop {
        if read_at.elapsed() >= REREAD {
            let fresh = self::rows(store);
            if fresh != rows {
                rows = fresh;
                home.fit(&rows);
                dirty = true;
            }
            read_at = Instant::now();
        }
        let now = terminal::size();
        if now != size {
            size = now;
            terminal.backend_mut().resize(size.rows, size.cols);
            terminal.autoresize()?;
            dirty = true;
        }
        if dirty {
            terminal.draw(|frame| {
                home.render(repository, &rows, status, frame.area(), frame.buffer_mut());
            })?;
            dirty = false;
        }
        match wait(&signals, KEY_WAIT)? {
            InputWait::Timeout => continue,
            InputWait::Signal(signal) => return Ok(Chosen::Stopped(signal)),
            InputWait::Input => {}
        }
        let mut read = read_input(&mut buffer)?;
        if read == 0 {
            return Ok(Chosen::Quit);
        }
        while buffer.get(read - 1) == Some(&ESC) && read < MAX_READ {
            match wait(&signals, SEQUENCE_WAIT)? {
                InputWait::Input => {
                    let more = read_input(buffer.get_mut(read..).unwrap_or_default())?;
                    if more == 0 {
                        break;
                    }
                    read += more;
                }
                InputWait::Signal(signal) => return Ok(Chosen::Stopped(signal)),
                InputWait::Timeout => break,
            }
        }
        if let Some(signal) = signals
            .wait_timeout(Duration::ZERO)
            .map_err(io::Error::other)?
        {
            return Ok(Chosen::Stopped(signal));
        }
        let mut chosen = None;
        keys.read(buffer.get(..read).unwrap_or_default(), |input| {
            if let Some(action) = home.key(input, &rows) {
                chosen = Some(action);
                return false;
            }
            input != PaletteInput::Escape
        });
        dirty = true;
        match chosen {
            Some(HomeAction::Quit) => return Ok(Chosen::Quit),
            Some(action) => return Ok(Chosen::Action(action)),
            None => {}
        }
    }
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

/// Runs the chosen action as its command does, on the normal screen, and returns what the
/// home screen says about it.
fn act(action: HomeAction, environment: &Environment) -> String {
    let words: [String; 2] = match action {
        HomeAction::New => match agent_to_run(environment) {
            Ok(agent) => ["run".to_owned(), agent],
            Err(told) => return told,
        },
        HomeAction::Resume(thread) => ["resume".to_owned(), thread],
        HomeAction::Land(thread) => ["land".to_owned(), thread],
        HomeAction::End(thread) => ["end".to_owned(), thread],
        HomeAction::Invite(_) | HomeAction::Join => return PAIRING_LATER.to_owned(),
        HomeAction::Quit => return String::new(),
    };
    let Ok(Cli {
        command: Some(command),
    }) = Cli::try_parse_from(std::iter::once("mahi").chain(words.iter().map(String::as_str)))
    else {
        return format!("mahi {} is not a command mahi knows", words.join(" "));
    };
    let code = run_command(command, environment);
    if let Ok(mut prompt) = TerminalPrompt::open_interactive() {
        let _ = prompt.answer("Press Enter to go back to the home screen. ");
    }
    format!("mahi {} exited with {code}", words.join(" "))
}

/// Returns the agent to start a thread with: the one mahi has a profile for that is on `PATH`,
/// or the one the user picks when there are several.
fn agent_to_run(environment: &Environment) -> Result<String, String> {
    let found: Vec<&str> = Profile::programs()
        .filter(|program| run::is_on_path(program, environment.path.as_deref()))
        .collect();
    match found.as_slice() {
        [] => Err("no agent mahi has a profile for is on PATH; run mahi run <agent>".to_owned()),
        [only] => Ok((*only).to_owned()),
        several => {
            let mut prompt =
                TerminalPrompt::open_interactive().map_err(|error| error.to_string())?;
            let _ = prompt.say("Which agent should start the thread?");
            for (number, program) in several.iter().enumerate() {
                let _ = prompt.say(&format!("  {}) {program}", number + 1));
            }
            let answer = prompt
                .answer("Number: ")
                .map_err(|error| error.to_string())?;
            answer
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|number| number.checked_sub(1))
                .and_then(|index| several.get(index))
                .map(|program| (*program).to_owned())
                .ok_or_else(|| "no agent was chosen".to_owned())
        }
    }
}
