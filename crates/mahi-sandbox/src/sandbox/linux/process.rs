use std::{
    io,
    os::fd::{
        BorrowedFd,
        OwnedFd,
    },
};

use rustix::{
    event::{
        PollFd,
        PollFlags,
        Timespec,
    },
    io::Errno,
    process::{
        DumpableBehavior,
        Pid,
        PidfdFlags,
        Signal,
        WaitOptions,
        WaitStatus,
    },
};

const HANGUP_GRACE_SECONDS: i64 = 3;

pub(super) enum Forked {
    Parent(Pid),
    Child,
}

#[expect(
    unsafe_code,
    reason = "rustix has no safe fork, so the forked child forks again through libc"
)]
pub(super) fn fork() -> io::Result<Forked> {
    // SAFETY: the caller is the single-threaded child of `Command::spawn`, so no other thread
    // holds a lock or is left inconsistent in the new process, and both sides only go on to
    // make system calls that allocate nothing.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Forked::Child),
        pid => Pid::from_raw(pid)
            .map(Forked::Parent)
            .ok_or_else(|| Errno::INVAL.into()),
    }
}

pub(super) fn watch(init: Pid) -> ! {
    if close_all_from(3).is_err() {
        exit_now(1);
    }
    let Ok(init_fd) = rustix::process::pidfd_open(init, PidfdFlags::empty()) else {
        exit_now(1)
    };
    if wait_for_hangup(&init_fd).is_ok() {
        let grace = Timespec {
            tv_sec: HANGUP_GRACE_SECONDS,
            tv_nsec: 0,
        };
        let mut fds = [PollFd::new(&init_fd, PollFlags::IN)];
        if matches!(rustix::event::poll(&mut fds, Some(&grace)), Ok(0)) {
            let _ = rustix::process::kill_process(init, Signal::KILL);
        }
    }
    reap(init, false)
}

pub(super) fn reap_all_until(agent: Pid) -> ! {
    if close_all_from(3).is_err() {
        exit_now(1);
    }
    reap(agent, true)
}

fn wait_for_hangup(init: &OwnedFd) -> Result<(), Errno> {
    let terminal = standard_input();
    let mut fds = [
        PollFd::new(init, PollFlags::IN),
        PollFd::new(&terminal, PollFlags::empty()),
    ];
    loop {
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => {
                let [init, terminal] = &fds;
                if !init.revents().is_empty() {
                    return Err(Errno::CHILD);
                }
                if terminal
                    .revents()
                    .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
                {
                    return Ok(());
                }
            }
            Err(Errno::INTR) => {}
            Err(error) => return Err(error),
        }
    }
}

fn reap(child: Pid, any_child: bool) -> ! {
    let every_child = WaitOptions::from_bits_retain(libc::__WALL.cast_unsigned());
    loop {
        let waited = if any_child {
            rustix::process::wait(every_child)
        } else {
            rustix::process::waitpid(Some(child), WaitOptions::empty())
        };
        match waited {
            Ok(Some((pid, status))) if pid == child => exit_now(code_of(status)),
            Ok(_) | Err(Errno::INTR) => {}
            Err(_) => exit_now(1),
        }
    }
}

pub(super) fn hide_memory() -> io::Result<()> {
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    Ok(())
}

pub(super) fn open_self() -> io::Result<OwnedFd> {
    Ok(rustix::process::pidfd_open(
        rustix::process::getpid(),
        PidfdFlags::empty(),
    )?)
}

pub(super) fn die_with(parent: &OwnedFd) -> io::Result<()> {
    rustix::process::set_parent_process_death_signal(Some(Signal::KILL))?;
    let mut fds = [PollFd::new(parent, PollFlags::IN)];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if rustix::event::poll(&mut fds, Some(&now))? == 0 {
        Ok(())
    } else {
        exit_now(1)
    }
}

pub(super) fn take_terminal() -> io::Result<()> {
    rustix::process::setsid()?;
    rustix::process::ioctl_tiocsctty(standard_input())?;
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "the pseudo-terminal is reached through a borrowed descriptor for standard input"
)]
pub(super) fn standard_input() -> BorrowedFd<'static> {
    // SAFETY: fd 0 is the pseudo-terminal's slave that `Command` installed as standard input.
    // Nothing between fork and exec closes it, and the watchers never close it.
    unsafe { BorrowedFd::borrow_raw(0) }
}

fn code_of(status: WaitStatus) -> i32 {
    status
        .exit_status()
        .or_else(|| status.terminating_signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[expect(
    unsafe_code,
    reason = "rustix has no close_range, so the system call is made through libc"
)]
fn close_all_from(first: libc::c_uint) -> io::Result<()> {
    // SAFETY: the caller never returns to Rust code that owns a descriptor at or above `first`:
    // it only waits for a child and exits.
    let result = unsafe { libc::syscall(libc::SYS_close_range, first, libc::c_uint::MAX, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[expect(
    unsafe_code,
    reason = "a process forked inside the pre-exec hook must exit without running Rust exit code"
)]
fn exit_now(code: i32) -> ! {
    // SAFETY: `_exit` ends the process at once without running destructors or exit handlers,
    // which is what a forked copy of the parent must do.
    unsafe { libc::_exit(code) }
}
