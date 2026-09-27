mod landlock;
mod process;
mod seccomp;

use std::{
    ffi::{
        CStr,
        CString,
    },
    io,
    os::{
        fd::{
            AsFd,
            AsRawFd,
            BorrowedFd,
            OwnedFd,
        },
        unix::ffi::OsStrExt,
    },
    path::{
        Component,
        Path,
    },
};

use rustix::{
    fs::{
        CWD,
        FileType,
        Mode,
        OFlags,
        ResolveFlags,
    },
    io::Errno,
    mount::{
        MountFlags,
        MountPropagationFlags,
        MoveMountFlags,
        OpenTreeFlags,
        UnmountFlags,
    },
    net::{
        AddressFamily,
        SocketFlags,
        SocketType,
    },
    thread::{
        CapabilitiesSecureBits,
        CapabilitySet,
        UnshareFlags,
    },
};

use self::{
    landlock::Landlock,
    process::Forked,
    seccomp::Filter,
};
use super::{
    Access,
    Sandbox,
};

const DEVICES: [&str; 6] = [
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];
const DEVICE_ATTRIBUTES: u64 = libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NOEXEC;
const STAGING: &CStr = c"/tmp";
const STAGED_PROC: &CStr = c"/tmp/proc";
const PROC_READ_ONLY: [&CStr; 6] = [
    c"/proc/bus",
    c"/proc/dynamic_debug",
    c"/proc/fs",
    c"/proc/irq",
    c"/proc/sys",
    c"/proc/sysrq-trigger",
];
const PROC_MASKED: [&CStr; 12] = [
    c"/proc/acpi",
    c"/proc/asound",
    c"/proc/kcore",
    c"/proc/keys",
    c"/proc/latency_stats",
    c"/proc/pagetypeinfo",
    c"/proc/sched_debug",
    c"/proc/scsi",
    c"/proc/slabinfo",
    c"/proc/timer_list",
    c"/proc/timer_stats",
    c"/proc/vmallocinfo",
];
const LOCKED_DOWN: u64 = libc::MOUNT_ATTR_RDONLY
    | libc::MOUNT_ATTR_NOSUID
    | libc::MOUNT_ATTR_NODEV
    | libc::MOUNT_ATTR_NOEXEC;

/// Everything the child needs to enter the sandbox, prepared before the fork so the child
/// allocates nothing.
#[derive(Debug)]
pub(crate) struct Plan {
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    mounts: Vec<PlannedMount>,
    links: Vec<PlannedLink>,
    landlock: Landlock,
    filter: Filter,
    cwd: CString,
}

#[derive(Debug)]
struct PlannedMount {
    source: CString,
    names: Vec<CString>,
    attributes: u64,
    tree: Option<OwnedFd>,
    is_dir: bool,
}

#[derive(Debug)]
struct PlannedLink {
    names: Vec<CString>,
    target: CString,
}

impl Plan {
    pub(crate) fn new(sandbox: &Sandbox, cwd: &Path, terminal: &Path) -> io::Result<Self> {
        Landlock::check_available()?;
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let devices = DEVICES
            .iter()
            .map(|device| planned_mount(Path::new(device), Path::new(device), DEVICE_ATTRIBUTES))
            .chain([planned_mount(
                terminal,
                Path::new("/dev/console"),
                DEVICE_ATTRIBUTES,
            )]);
        let mut full_access = vec![c"/tmp".to_owned(), c"/dev/shm".to_owned()];
        for bind in &sandbox.binds {
            if bind.access == Access::ReadWrite {
                full_access.push(c_path(&bind.path)?);
            }
        }
        let mut binds = sandbox.binds.iter().collect::<Vec<_>>();
        binds.sort_by_key(|bind| bind.path.components().count());
        let binds = binds.into_iter().map(|bind| {
            let read_only = match bind.access {
                Access::ReadOnly => libc::MOUNT_ATTR_RDONLY,
                Access::ReadWrite => 0,
            };
            planned_mount(
                &bind.path,
                &bind.path,
                libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV | read_only,
            )
        });
        let links = sandbox
            .links
            .iter()
            .map(|link| {
                Ok(PlannedLink {
                    names: names(&link.path)?,
                    target: c_string(link.target.as_bytes())?,
                })
            })
            .collect::<io::Result<_>>()?;
        Ok(Self {
            uid_map: format!("{uid} {uid} 1").into_bytes(),
            gid_map: format!("{gid} {gid} 1").into_bytes(),
            mounts: devices.chain(binds).collect::<io::Result<_>>()?,
            links,
            landlock: Landlock::new(full_access),
            filter: Filter::new()?,
            cwd: c_path(cwd)?,
        })
    }

    /// Moves the calling process into new user, mount and PID namespaces, makes the sandbox the
    /// root, and leaves the agent's process ready to exec in a session of its own with the
    /// terminal. The calling process stays outside the PID namespace and waits for its init,
    /// which waits for the agent. Runs in the forked child, so it must not allocate.
    pub(crate) fn enter(&mut self) -> io::Result<()> {
        unshare_namespaces()?;
        write_file(c"/proc/self/setgroups", b"deny")?;
        write_file(c"/proc/self/uid_map", &self.uid_map)?;
        write_file(c"/proc/self/gid_map", &self.gid_map)?;
        process::hide_memory()?;
        let monitor = process::open_self()?;
        if let Forked::Parent(init) = process::fork()? {
            process::watch(init);
        }
        process::die_with(&monitor)?;
        drop(monitor);
        bring_up_loopback()?;
        self.build_root()?;
        if let Forked::Parent(agent) = process::fork()? {
            process::reap_all_until(agent);
        }
        process::take_terminal()?;
        rustix::process::chdir(self.cwd.as_c_str())?;
        drop_privileges()?;
        self.landlock.restrict_self()?;
        mark_inherited_fds_close_on_exec()?;
        self.filter.install()
    }

    fn build_root(&mut self) -> io::Result<()> {
        rustix::mount::mount_change(
            c"/",
            MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
        )?;
        for mount in &mut self.mounts {
            mount.clone_tree()?;
        }
        pivot_to_empty_root()?;
        mount_tmpfs(c"/tmp", c"mode=1777")?;
        for mount in &mut self.mounts {
            mount.attach()?;
        }
        make_dev()?;
        write_file(c"/proc/sys/user/max_user_namespaces", b"0")?;
        restrict_proc()?;
        for link in &self.links {
            let (parent, name) = open_parent(&link.names)?;
            rustix::fs::symlinkat(link.target.as_c_str(), &parent, name)?;
        }
        rustix::mount::mount_remount(
            c"/",
            MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
            c"",
        )?;
        Ok(())
    }
}

impl PlannedMount {
    fn clone_tree(&mut self) -> io::Result<()> {
        let source = rustix::fs::openat2(
            CWD,
            self.source.as_c_str(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;
        let tree = rustix::mount::open_tree(
            &source,
            c"",
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_EMPTY_PATH
                | OpenTreeFlags::AT_RECURSIVE,
        )?;
        set_attributes(tree.as_fd(), self.attributes)?;
        self.is_dir =
            FileType::from_raw_mode(rustix::fs::fstat(&tree)?.st_mode) == FileType::Directory;
        self.tree = Some(tree);
        Ok(())
    }

    fn attach(&mut self) -> io::Result<()> {
        let Some(tree) = self.tree.take() else {
            return Err(Errno::INVAL.into());
        };
        let (parent, name) = open_parent(&self.names)?;
        if self.is_dir {
            make_dir_at(&parent, name)?;
        } else {
            match rustix::fs::mknodat(
                &parent,
                name,
                FileType::RegularFile,
                Mode::from_raw_mode(0o644),
                0,
            ) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let target = open_beneath(&parent, name, OFlags::PATH)?;
        rustix::mount::move_mount(
            &tree,
            c"",
            &target,
            c"",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        )?;
        Ok(())
    }
}

fn open_parent(names: &[CString]) -> io::Result<(OwnedFd, &CStr)> {
    let Some((last, parents)) = names.split_last() else {
        return Err(Errno::INVAL.into());
    };
    let mut dir = rustix::fs::open(
        c"/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for name in parents {
        make_dir_at(&dir, name)?;
        dir = open_beneath(&dir, name, OFlags::PATH | OFlags::DIRECTORY)?;
    }
    Ok((dir, last))
}

fn open_beneath(dir: &OwnedFd, name: &CStr, flags: OFlags) -> io::Result<OwnedFd> {
    Ok(rustix::fs::openat2(
        dir,
        name,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | ResolveFlags::BENEATH,
    )?)
}

fn make_dir_at(dir: &OwnedFd, name: &CStr) -> io::Result<()> {
    match rustix::fs::mkdirat(dir, name, Mode::from_raw_mode(0o755)) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn drop_privileges() -> io::Result<()> {
    rustix::thread::set_capabilities_secure_bits(
        CapabilitiesSecureBits::NO_ROOT
            | CapabilitiesSecureBits::NO_ROOT_LOCKED
            | CapabilitiesSecureBits::NO_SETUID_FIXUP
            | CapabilitiesSecureBits::NO_SETUID_FIXUP_LOCKED
            | CapabilitiesSecureBits::KEEP_CAPS_LOCKED
            | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE
            | CapabilitiesSecureBits::NO_CAP_AMBIENT_RAISE_LOCKED,
    )?;
    rustix::thread::clear_ambient_capability_set()?;
    for bit in 0..u64::BITS {
        match rustix::thread::remove_capability_from_bounding_set(CapabilitySet::from_bits_retain(
            1 << bit,
        )) {
            Ok(()) | Err(Errno::INVAL) => {}
            Err(error) => return Err(error.into()),
        }
    }
    rustix::thread::set_no_new_privs(true)?;
    Ok(())
}

fn planned_mount(source: &Path, target: &Path, attributes: u64) -> io::Result<PlannedMount> {
    Ok(PlannedMount {
        source: c_path(source)?,
        names: names(target)?,
        attributes,
        tree: None,
        is_dir: false,
    })
}

fn pivot_to_empty_root() -> io::Result<()> {
    rustix::mount::mount(
        c"tmpfs",
        STAGING,
        c"tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        c"mode=0755",
    )?;
    make_dir(STAGED_PROC)?;
    rustix::mount::mount(
        c"proc",
        STAGED_PROC,
        c"proc",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        None,
    )?;
    rustix::process::chdir(STAGING)?;
    rustix::process::pivot_root(c".", c".")?;
    rustix::mount::unmount(c".", UnmountFlags::DETACH)?;
    rustix::process::chdir(c"/")?;
    Ok(())
}

fn make_dev() -> io::Result<()> {
    make_dir(c"/dev/pts")?;
    rustix::mount::mount(
        c"devpts",
        c"/dev/pts",
        c"devpts",
        MountFlags::NOSUID | MountFlags::NOEXEC,
        c"newinstance,ptmxmode=0666,mode=620",
    )?;
    rustix::fs::symlink(c"pts/ptmx", c"/dev/ptmx")?;
    rustix::fs::symlink(c"/proc/self/fd", c"/dev/fd")?;
    rustix::fs::symlink(c"/proc/self/fd/0", c"/dev/stdin")?;
    rustix::fs::symlink(c"/proc/self/fd/1", c"/dev/stdout")?;
    rustix::fs::symlink(c"/proc/self/fd/2", c"/dev/stderr")?;
    mount_tmpfs(c"/dev/shm", c"mode=1777")
}

fn restrict_proc() -> io::Result<()> {
    for path in PROC_READ_ONLY {
        let tree = match clone_path(path) {
            Ok(tree) => tree,
            Err(Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        set_attributes(tree.as_fd(), LOCKED_DOWN)?;
        move_onto(&tree, path)?;
    }
    for path in PROC_MASKED {
        let is_dir = match rustix::fs::stat(path) {
            Ok(stat) => FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
            Err(Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        if is_dir {
            rustix::mount::mount(
                c"tmpfs",
                path,
                c"tmpfs",
                MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                c"mode=0555",
            )?;
        } else {
            move_onto(&clone_path(c"/dev/null")?, path)?;
        }
    }
    Ok(())
}

fn clone_path(path: &CStr) -> Result<OwnedFd, Errno> {
    rustix::mount::open_tree(
        CWD,
        path,
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_RECURSIVE
            | OpenTreeFlags::AT_SYMLINK_NOFOLLOW,
    )
}

fn move_onto(tree: &OwnedFd, path: &CStr) -> io::Result<()> {
    rustix::mount::move_mount(
        tree,
        c"",
        CWD,
        path,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}

fn mount_tmpfs(path: &CStr, options: &CStr) -> io::Result<()> {
    make_dir(path)?;
    rustix::mount::mount(
        c"tmpfs",
        path,
        c"tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        options,
    )?;
    Ok(())
}

fn make_dir(path: &CStr) -> io::Result<()> {
    match rustix::fs::mkdir(path, Mode::from_raw_mode(0o755)) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_file(path: &CStr, contents: &[u8]) -> io::Result<()> {
    let file = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())?;
    if rustix::io::write(&file, contents)? == contents.len() {
        Ok(())
    } else {
        Err(Errno::IO.into())
    }
}

#[expect(
    unsafe_code,
    reason = "rustix marks unshare unsafe because of the file table flag, which is not used here"
)]
fn unshare_namespaces() -> io::Result<()> {
    // SAFETY: the flags do not include `UnshareFlags::FILES`, so no thread can lose access to
    // file descriptors, and the forked child that calls this has a single thread.
    unsafe {
        rustix::thread::unshare_unsafe(
            UnshareFlags::NEWUSER
                | UnshareFlags::NEWNS
                | UnshareFlags::NEWPID
                | UnshareFlags::NEWNET,
        )?;
    };
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "rustix has no ioctl for interface flags, so the request is made through libc"
)]
fn bring_up_loopback() -> io::Result<()> {
    let socket = rustix::net::socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let mut request = libc::ifreq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_flags: 0 },
    };
    for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo") {
        *slot = libc::c_char::from_ne_bytes([*byte]);
    }
    let up = libc::c_short::try_from(libc::IFF_UP).map_err(|_| Errno::INVAL)?;
    // SAFETY: `request` is a valid `ifreq` with a NUL-terminated name that outlives both calls,
    // the socket is open, and these requests only read and write the flags in `request`.
    unsafe {
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &raw mut request) == -1 {
            return Err(io::Error::last_os_error());
        }
        request.ifr_ifru.ifru_flags |= up;
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &raw const request) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "rustix has no mount_setattr, so the system call is made through libc"
)]
fn set_attributes(tree: BorrowedFd<'_>, attributes: u64) -> io::Result<()> {
    let attr = libc::mount_attr {
        attr_set: attributes,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: the path is a valid NUL-terminated string, `attr` is a valid `mount_attr` that
    // outlives the call and its size is passed with it, and the kernel only reads from both.
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_RECURSIVE,
            &raw const attr,
            size_of::<libc::mount_attr>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[expect(
    unsafe_code,
    reason = "rustix has no close_range, so the system call is made through libc"
)]
fn mark_inherited_fds_close_on_exec() -> io::Result<()> {
    // SAFETY: close_range with `CLOSE_RANGE_CLOEXEC` takes no pointers and only sets the
    // close-on-exec flag, so no file descriptor that Rust code owns is closed or invalidated.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn names(path: &Path) -> io::Result<Vec<CString>> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(c_string(name.as_bytes())),
            _ => None,
        })
        .collect()
}

fn c_path(path: &Path) -> io::Result<CString> {
    c_string(path.as_os_str().as_bytes())
}

fn c_string(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}
