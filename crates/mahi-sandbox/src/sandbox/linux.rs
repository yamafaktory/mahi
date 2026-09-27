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
    thread::{
        CapabilitiesSecureBits,
        CapabilitySet,
        UnshareFlags,
    },
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
const STAGING: &CStr = c"/tmp";

/// Everything the child needs to enter the sandbox, prepared before the fork so the child
/// allocates nothing.
#[derive(Debug)]
pub(crate) struct Plan {
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    mounts: Vec<PlannedMount>,
    links: Vec<PlannedLink>,
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
    pub(crate) fn new(sandbox: &Sandbox, cwd: &Path) -> io::Result<Self> {
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let devices = DEVICES.iter().map(|device| {
            planned_mount(
                Path::new(device),
                libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NOEXEC,
            )
        });
        let mut binds = sandbox.binds.iter().collect::<Vec<_>>();
        binds.sort_by_key(|bind| bind.path.components().count());
        let binds = binds.into_iter().map(|bind| {
            let read_only = match bind.access {
                Access::ReadOnly => libc::MOUNT_ATTR_RDONLY,
                Access::ReadWrite => 0,
            };
            planned_mount(
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
            cwd: c_path(cwd)?,
        })
    }

    /// Moves the calling process into new user and mount namespaces and makes the sandbox its
    /// root. Runs in the forked child, so it must not allocate.
    pub(crate) fn enter(&mut self) -> io::Result<()> {
        unshare_user_and_mounts()?;
        write_file(c"/proc/self/setgroups", b"deny")?;
        write_file(c"/proc/self/uid_map", &self.uid_map)?;
        write_file(c"/proc/self/gid_map", &self.gid_map)?;
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
        for link in &self.links {
            let (parent, name) = open_parent(&link.names)?;
            rustix::fs::symlinkat(link.target.as_c_str(), &parent, name)?;
        }
        rustix::mount::mount_remount(
            c"/",
            MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
            c"",
        )?;
        rustix::process::chdir(self.cwd.as_c_str())?;
        drop_privileges()?;
        mark_inherited_fds_close_on_exec()
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

fn planned_mount(path: &Path, attributes: u64) -> io::Result<PlannedMount> {
    Ok(PlannedMount {
        source: c_path(path)?,
        names: names(path)?,
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
    mount_tmpfs(c"/dev/shm", c"mode=1777")
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
fn unshare_user_and_mounts() -> io::Result<()> {
    // SAFETY: the flags do not include `UnshareFlags::FILES`, so no thread can lose access to
    // file descriptors, and the forked child that calls this has a single thread.
    unsafe { rustix::thread::unshare_unsafe(UnshareFlags::NEWUSER | UnshareFlags::NEWNS)? };
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
