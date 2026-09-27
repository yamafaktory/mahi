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
    },
    path::{
        Path,
        PathBuf,
    },
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicU64,
            Ordering,
        },
        mpsc::{
            self,
            Receiver,
            RecvTimeoutError,
        },
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mahi_sandbox::{
    Access,
    PtyChild,
    PtyCommand,
    PtyError,
    Sandbox,
    SandboxError,
    WindowChanges,
    exit_code,
};
use rustix::termios::{
    LocalModes,
    SpecialCodeIndex,
};
use thiserror::Error;

use crate::{
    cli::RunCommand,
    terminal::{
        self,
        RawMode,
    },
};

const PASSED_ON: [&str; 10] = [
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "PATH",
    "USER",
    "LOGNAME",
    "TZ",
];
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
const BROKEN_PIPE_CODE: i32 = 128 + 13;

#[derive(Debug, Error)]
pub(crate) enum RunError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("HOME is not set or does not exist, so mahi cannot tell which directories are private")]
    NoHome,
    #[error("refusing to give the agent {}, which holds private files", .0.display())]
    PrivateDirectory(PathBuf),
    #[error("cannot find {0:?} on PATH")]
    AgentNotFound(OsString),
    #[error("cannot find the agent {}", .0.display())]
    Agent(PathBuf, #[source] io::Error),
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

enum Event {
    Exited(Result<i32, PtyError>),
    OutputEnded(io::Result<()>),
}

pub(crate) fn run(command: &RunCommand) -> Result<i32, RunError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(RunError::CurrentDirectory)?;
    let host = Host::from_environment()?;
    let search_path = env::var_os("PATH");
    let agent = resolve(&command.agent, &cwd, search_path.as_deref())?;
    let scratch = tempfile::Builder::new()
        .prefix("mahi-")
        .tempdir()
        .map_err(RunError::Scratch)?;
    let scratch_path = fs::canonicalize(scratch.path()).map_err(RunError::Scratch)?;
    let home = scratch_path.join("home");
    let temporary = scratch_path.join("tmp");
    for directory in [&home, &temporary] {
        fs::create_dir(directory).map_err(RunError::Scratch)?;
    }
    let mut sandbox = Sandbox::system()?;
    for (path, access) in binds(&cwd, &agent, &scratch_path, search_path.as_deref(), &host)? {
        sandbox.bind(&path, access)?;
    }
    let mut pty = PtyCommand::new(&agent.program, &cwd, terminal::size());
    for argument in &command.arguments {
        pty = pty.arg(argument);
    }
    for name in PASSED_ON {
        if let Some(value) = env::var_os(name) {
            pty = pty.env(name, value);
        }
    }
    let pty = pty
        .env("HOME", &home)
        .env("TMPDIR", &temporary)
        .sandbox(sandbox);
    let raw = RawMode::enable().map_err(RunError::Terminal)?;
    let interactive = raw.is_some();
    let code = relay(pty.spawn()?, interactive);
    drop(raw);
    code
}

impl Host {
    fn from_environment() -> Result<Self, RunError> {
        let canonical = |name| env::var_os(name).and_then(|path| fs::canonicalize(path).ok());
        let home = canonical("HOME").ok_or(RunError::NoHome)?;
        let mut holders = vec![home.clone()];
        holders.extend(fs::canonicalize(env::temp_dir()).ok());
        let mut private: Vec<PathBuf> =
            PRIVATE_IN_HOME.iter().map(|name| home.join(name)).collect();
        let resolved: Vec<PathBuf> = private
            .iter()
            .filter_map(|path| fs::canonicalize(path).ok())
            .collect();
        private.extend(resolved);
        private.extend(PRIVATE_ON_SYSTEM.iter().map(PathBuf::from));
        private.extend(canonical("XDG_RUNTIME_DIR"));
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

fn relay(child: PtyChild, interactive: bool) -> Result<i32, RunError> {
    let writer = child.writer()?;
    thread::spawn(move || forward_input(writer, interactive));
    let resizer = child.resizer()?;
    thread::spawn(move || {
        let Ok(changes) = WindowChanges::listen() else {
            return;
        };
        while changes.wait().is_ok() {
            if resizer.resize(terminal::size()).is_err() {
                break;
            }
        }
    });
    let mut reader = child.reader()?;
    let progress = Arc::new(AtomicU64::new(0));
    let (events, received) = mpsc::channel();
    let output_events = events.clone();
    let output_progress = Arc::clone(&progress);
    thread::spawn(move || {
        let ended = copy_output(&mut reader, &output_progress);
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
            Ok(Event::Exited(code)) if output_done => return Ok(code?),
            Ok(Event::Exited(code)) => return finish_output(&received, &progress, code?),
            Ok(Event::OutputEnded(Ok(()))) => output_done = true,
            Ok(Event::OutputEnded(Err(error))) => {
                if let Ok(mut child) = child.lock() {
                    let _ = child.kill();
                }
                return output_failure(error);
            }
            Err(_) => return Ok(1),
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
) -> Result<i32, RunError> {
    let mut seen = progress.load(Ordering::Relaxed);
    let deadline = Instant::now() + OUTPUT_LIMIT;
    loop {
        if Instant::now() > deadline {
            return Ok(code);
        }
        match received.recv_timeout(OUTPUT_GRACE) {
            Ok(Event::OutputEnded(Err(error))) => return output_failure(error).map(|_| code),
            Ok(Event::OutputEnded(Ok(()))) | Err(RecvTimeoutError::Disconnected) => {
                return Ok(code);
            }
            Ok(Event::Exited(_)) => {}
            Err(RecvTimeoutError::Timeout) => {
                let now = progress.load(Ordering::Relaxed);
                if now == seen {
                    return Ok(code);
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

fn copy_output(reader: &mut impl Read, progress: &AtomicU64) -> io::Result<()> {
    let mut output = io::stdout().lock();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        output.write_all(&buffer[..read])?;
        output.flush()?;
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

fn binds(
    cwd: &Path,
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
                binds(cwd, &agent, Path::new("/scratch"), None, &host),
                Err(RunError::PrivateDirectory(_))
            ));
        }
        assert!(
            binds(
                &home.join("project"),
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
            &agent,
            Path::new("/scratch"),
            None,
            &host_with_home(&home),
        )
        .unwrap();
        assert!(binds.contains(&(project.join(".git"), Access::ReadOnly)));
    }
}
