use std::{
    ffi::{
        OsStr,
        OsString,
    },
    fmt,
    fs::File,
    io::{
        self,
        Read,
    },
    os::{
        fd::{
            BorrowedFd,
            OwnedFd,
        },
        unix::{
            ffi::OsStringExt,
            process::{
                CommandExt,
                ExitStatusExt,
            },
        },
    },
    path::{
        Path,
        PathBuf,
    },
    process::{
        Child,
        Command,
        ExitStatus,
        Stdio,
    },
};

use rustix::{
    fs::{
        Mode,
        OFlags,
    },
    io::Errno,
    pty::{
        OpenptFlags,
        grantpt,
        openpt,
        ptsname,
        unlockpt,
    },
    termios::{
        Winsize,
        tcsetwinsize,
    },
};
use thiserror::Error;

use crate::Sandbox;

/// The size of a terminal, in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSize {
    /// Rows of text.
    pub rows: u16,
    /// Columns of text.
    pub cols: u16,
}

/// A program to run in a new pseudo-terminal.
///
/// It starts with an empty environment: only the variables set with [`PtyCommand::env`] are
/// passed to it. Their values, which may be secrets, never appear in `Debug` output.
#[derive(Clone)]
pub struct PtyCommand {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    cwd: PathBuf,
    size: WindowSize,
    sandbox: Option<Sandbox>,
}

/// A program running in a pseudo-terminal, and the terminal's controlling side.
///
/// Dropping it while the program runs kills the program's process group and waits for the
/// program to be reaped. That blocks the dropping thread until the program dies, which can take
/// as long as a pending uninterruptible read, so async code drops it inside `spawn_blocking`.
#[derive(Debug)]
pub struct PtyChild {
    master: File,
    child: Child,
}

/// Starting or driving a program in a pseudo-terminal failed.
#[derive(Debug, Error)]
pub enum PtyError {
    /// Creating the pseudo-terminal failed.
    #[error("cannot create a pseudo-terminal")]
    Open(#[source] io::Error),
    /// Starting the program failed.
    #[error("cannot start {}", .0.display())]
    Spawn(PathBuf, #[source] io::Error),
    /// Reading from, writing to or resizing the terminal failed.
    #[error("pseudo-terminal input or output failed")]
    Io(#[from] io::Error),
}

impl PtyCommand {
    /// Runs `program` in `cwd`, in a terminal of `size`.
    #[must_use]
    pub fn new(program: &Path, cwd: &Path, size: WindowSize) -> Self {
        Self {
            program: program.to_path_buf(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: cwd.to_path_buf(),
            size,
            sandbox: None,
        }
    }

    /// Adds an argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Sets an environment variable.
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((key.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Runs the program inside `sandbox`. The program path and `cwd` are then paths inside the
    /// sandbox.
    #[must_use]
    pub fn sandbox(mut self, sandbox: Sandbox) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    /// Starts the program in a new session, with a new pseudo-terminal as its controlling
    /// terminal and as its standard input, output and error.
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Open`] if the pseudo-terminal cannot be created, or
    /// [`PtyError::Spawn`] if the program cannot be started or the sandbox cannot be entered.
    pub fn spawn(self) -> Result<PtyChild, PtyError> {
        let (master, slave, terminal) = open_pty(self.size).map_err(PtyError::Open)?;
        let sandbox = self
            .sandbox
            .as_ref()
            .map(|sandbox| prepare_sandbox(sandbox, &self.program, &self.cwd, &terminal))
            .transpose()?;
        let stdio = |fd: &OwnedFd| fd.try_clone().map(Stdio::from).map_err(PtyError::Io);
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .env_clear()
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .stdin(stdio(&slave)?)
            .stdout(stdio(&slave)?)
            .stderr(stdio(&slave)?);
        if sandbox.is_none() || cfg!(target_os = "macos") {
            command.current_dir(&self.cwd);
        }
        set_up_child(&mut command, sandbox);
        let child = command
            .spawn()
            .map_err(|error| PtyError::Spawn(self.program.clone(), error))?;
        drop(slave);
        Ok(PtyChild {
            master: File::from(master),
            child,
        })
    }
}

impl fmt::Debug for PtyCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PtyCommand")
            .field("program", &self.program)
            .field("args", &self.args)
            .field(
                "env",
                &self.env.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            )
            .field("cwd", &self.cwd)
            .field("size", &self.size)
            .field("sandbox", &self.sandbox)
            .finish()
    }
}

#[cfg(target_os = "linux")]
type ChildSetup = crate::sandbox::linux::Plan;

#[cfg(target_os = "linux")]
fn prepare_sandbox(
    sandbox: &Sandbox,
    program: &Path,
    cwd: &Path,
    terminal: &Path,
) -> Result<ChildSetup, PtyError> {
    ChildSetup::new(sandbox, cwd, terminal)
        .map_err(|error| PtyError::Spawn(program.to_path_buf(), error))
}

#[cfg(target_os = "macos")]
type ChildSetup = crate::sandbox::macos::Profile;

#[cfg(target_os = "macos")]
fn prepare_sandbox(
    sandbox: &Sandbox,
    program: &Path,
    _: &Path,
    terminal: &Path,
) -> Result<ChildSetup, PtyError> {
    ChildSetup::new(sandbox, terminal)
        .map_err(|error| PtyError::Spawn(program.to_path_buf(), error))
}

#[expect(
    unsafe_code,
    reason = "the child must start a session, take the terminal and enter the sandbox between fork and exec"
)]
fn set_up_child(command: &mut Command, mut sandbox: Option<ChildSetup>) {
    // SAFETY: the hook runs in the forked child before exec, where only async-signal-safe work
    // is allowed. On Linux it makes system calls through rustix and libc and allocates
    // nothing: every path and buffer the sandbox needs was prepared before the fork. On macOS
    // `sandbox_init` allocates while compiling the profile: libSystem's fork resets malloc
    // and dyld in the child, and the parent never uses libsandbox, so no lock it needs can be
    // held (the same pattern as Nix's macOS builder). Only libdispatch or XPC use would be
    // unsafe here; profile compilation is not known to use them, and a crash, not a
    // deadlock, would be the symptom. Fd 0 is the pseudo-terminal's slave that
    // `Command` installed as standard input.
    unsafe {
        command.pre_exec(move || {
            crate::window::reset_in_child()?;
            rustix::process::setsid()?;
            if let Some(sandbox) = sandbox.as_mut() {
                sandbox.enter()
            } else {
                rustix::process::ioctl_tiocsctty(BorrowedFd::borrow_raw(0))?;
                Ok(())
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn open_master() -> io::Result<OwnedFd> {
    Ok(openpt(
        OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
    )?)
}

#[cfg(not(target_os = "linux"))]
fn open_master() -> io::Result<OwnedFd> {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)?;
    Ok(master)
}

fn open_pty(size: WindowSize) -> io::Result<(OwnedFd, OwnedFd, PathBuf)> {
    let master = open_master()?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let name = ptsname(&master, Vec::new())?;
    let slave = rustix::fs::open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    tcsetwinsize(
        &master,
        Winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )?;
    Ok((
        master,
        slave,
        PathBuf::from(OsString::from_vec(name.into_bytes())),
    ))
}

impl PtyChild {
    /// Returns the process id of the program, or, in a Linux sandbox, of the process outside
    /// the sandbox that watches it and exits with its status.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Returns a handle to read what the program writes to its terminal.
    ///
    /// A read returns 0 once the program and everything it started have closed the terminal.
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Io`] if the handle cannot be duplicated.
    pub fn reader(&self) -> Result<PtyReader, PtyError> {
        Ok(PtyReader(self.master.try_clone()?))
    }

    /// Returns a handle to type into the program's terminal.
    ///
    /// A write blocks while the terminal's input queue is full, which happens when the program
    /// stops reading, so write from a dedicated thread.
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Io`] if the handle cannot be duplicated.
    pub fn writer(&self) -> Result<File, PtyError> {
        Ok(self.master.try_clone()?)
    }

    /// Changes the terminal's size; the program receives `SIGWINCH`.
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Io`] if the size cannot be set.
    pub fn resize(&self, size: WindowSize) -> Result<(), PtyError> {
        set_size(&self.master, size)
    }

    /// Returns a handle that changes the terminal's size from another thread.
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Io`] if the handle cannot be duplicated.
    pub fn resizer(&self) -> Result<PtyResizer, PtyError> {
        Ok(PtyResizer(self.master.try_clone()?))
    }

    /// Waits for the program to exit.
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Io`] if waiting fails.
    pub fn wait(&mut self) -> Result<ExitStatus, PtyError> {
        Ok(self.child.wait()?)
    }

    /// Returns the program's exit status if it has exited, without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Io`] if the status cannot be read.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, PtyError> {
        Ok(self.child.try_wait()?)
    }

    /// Kills the program and every process in its process group, including what it started in
    /// the background. A process that left the group, by starting its own session or group, is
    /// not reached here. In a Linux sandbox the group is the program's watchers, and killing
    /// them ends the sandbox's PID namespace and everything in it.
    ///
    /// The group is addressed by the program's process id, which stays reserved until the
    /// program is reaped by this handle, so nothing else in mahi may reap child processes (for
    /// example by ignoring `SIGCHLD`).
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Io`] if the signal cannot be sent.
    pub fn kill(&mut self) -> Result<(), PtyError> {
        if self.child.try_wait()?.is_none() {
            let group = i32::try_from(self.child.id())
                .ok()
                .and_then(rustix::process::Pid::from_raw);
            if let Some(group) = group {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
        }
        Ok(self.child.kill()?)
    }
}

impl Drop for PtyChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) && self.kill().is_ok() {
            let _ = self.child.wait();
        }
    }
}

/// Changes the size of a program's pseudo-terminal.
#[derive(Debug)]
pub struct PtyResizer(File);

impl PtyResizer {
    /// Changes the terminal's size; the program receives `SIGWINCH`.
    ///
    /// # Errors
    ///
    /// Returns [`PtyError::Io`] if the size cannot be set.
    pub fn resize(&self, size: WindowSize) -> Result<(), PtyError> {
        set_size(&self.0, size)
    }
}

fn set_size(master: &File, size: WindowSize) -> Result<(), PtyError> {
    tcsetwinsize(
        master,
        Winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .map_err(io::Error::from)?;
    Ok(())
}

/// Reads what a program writes to its pseudo-terminal.
#[derive(Debug)]
pub struct PtyReader(File);

impl Read for PtyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.read(buf) {
            Err(error) if error.raw_os_error() == Some(Errno::IO.raw_os_error()) => Ok(0),
            other => other,
        }
    }
}

/// Returns the exit code, or 128 plus the signal number if the program was killed.
#[must_use]
pub fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use super::*;

    const SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };

    fn sh(script: &str) -> PtyCommand {
        PtyCommand::new(Path::new("/bin/sh"), Path::new("/"), SIZE)
            .arg("-c")
            .arg(script)
    }

    fn output_of(child: &PtyChild) -> String {
        let mut reader = child.reader().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut output = Vec::new();
            let _ = reader.read_to_end(&mut output);
            let _ = sender.send(output);
        });
        let output = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("the program closes its terminal");
        String::from_utf8_lossy(&output).into_owned()
    }

    #[test]
    fn output_arrives_through_the_terminal() {
        let mut child = sh("echo hello").spawn().unwrap();
        assert!(output_of(&child).contains("hello"));
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn the_program_has_a_controlling_terminal() {
        let mut child = sh("test -t 0 && test -t 1 && echo ok > /dev/tty")
            .spawn()
            .unwrap();
        assert!(output_of(&child).contains("ok"));
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn input_reaches_the_program() {
        let mut child = sh("read line; echo got:$line").spawn().unwrap();
        child.writer().unwrap().write_all(b"hi\n").unwrap();
        assert!(output_of(&child).contains("got:hi"));
        child.wait().unwrap();
    }

    #[test]
    fn the_environment_holds_only_what_was_given() {
        let mut child = sh("echo \"[$MAHI_TEST][$HOME]\"")
            .env("MAHI_TEST", "yes")
            .spawn()
            .unwrap();
        assert!(output_of(&child).contains("[yes][]"));
        child.wait().unwrap();
    }

    #[test]
    fn the_initial_size_and_resizes_reach_the_program() {
        let mut child = sh("stty size; read go; stty size").spawn().unwrap();
        let mut reader = child.reader().unwrap();
        let mut seen = Vec::new();
        while !String::from_utf8_lossy(&seen).contains("24 80") {
            let mut chunk = [0u8; 64];
            let read = reader.read(&mut chunk).unwrap();
            assert_ne!(read, 0, "the first size never arrived");
            seen.extend_from_slice(&chunk[..read]);
        }
        child
            .resizer()
            .unwrap()
            .resize(WindowSize {
                rows: 40,
                cols: 100,
            })
            .unwrap();
        child.writer().unwrap().write_all(b"\n").unwrap();
        assert!(output_of(&child).contains("40 100"));
        child.wait().unwrap();
    }

    #[test]
    fn exit_codes_and_signals_are_reported() {
        let mut child = sh("exit 3").spawn().unwrap();
        let _ = output_of(&child);
        assert_eq!(exit_code(child.wait().unwrap()), 3);

        let mut child = sh("sleep 30").spawn().unwrap();
        child.kill().unwrap();
        assert_eq!(exit_code(child.wait().unwrap()), 128 + 9);
    }

    #[test]
    fn kill_takes_background_processes_with_it() {
        let mut child = sh("sleep 60 & sleep 60 & echo started; wait")
            .spawn()
            .unwrap();
        let mut reader = child.reader().unwrap();
        let mut seen = Vec::new();
        while !String::from_utf8_lossy(&seen).contains("started") {
            let mut chunk = [0u8; 64];
            let read = reader.read(&mut chunk).unwrap();
            assert_ne!(read, 0);
            seen.extend_from_slice(&chunk[..read]);
        }
        child.kill().unwrap();
        let _ = output_of(&child);
        child.wait().unwrap();
    }

    #[test]
    fn dropping_a_running_child_kills_and_reaps_it() {
        let child = sh("sleep 60").spawn().unwrap();
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
        drop(child);
        assert!(rustix::process::test_kill_process(pid).is_err());
    }

    #[test]
    fn writing_after_the_program_exited_does_not_panic() {
        let mut child = sh("exit 0").spawn().unwrap();
        let _ = output_of(&child);
        child.wait().unwrap();
        let _ = child.writer().unwrap().write_all(b"late\n");
    }

    #[test]
    fn debug_output_carries_no_env_values() {
        let command = sh("true").env("ANTHROPIC_API_KEY", "sk-secret-value");
        let debug = format!("{command:?}");
        assert!(debug.contains("ANTHROPIC_API_KEY"));
        assert!(!debug.contains("sk-secret-value"));
    }

    #[test]
    fn a_missing_working_directory_is_a_spawn_error() {
        let result =
            PtyCommand::new(Path::new("/bin/sh"), Path::new("/nonexistent/dir"), SIZE).spawn();
        assert!(matches!(result, Err(PtyError::Spawn(..))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_program_does_not_inherit_an_ignored_window_change_signal() {
        let previous = crate::window::set_disposition(libc::SIGWINCH, libc::SIG_IGN).unwrap();
        let mut child = sh("grep SigIgn /proc/self/status").spawn().unwrap();
        crate::window::set_disposition(libc::SIGWINCH, previous).unwrap();
        let output = output_of(&child);
        child.wait().unwrap();
        let mask = output
            .split_whitespace()
            .nth(1)
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .unwrap();
        let window_change = 1_u64 << (libc::SIGWINCH - 1);
        assert_eq!(mask & window_change, 0, "{output}");
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let result = PtyCommand::new(Path::new("/nonexistent/agent"), Path::new("/"), SIZE).spawn();
        assert!(matches!(result, Err(PtyError::Spawn(..))));
    }
}
