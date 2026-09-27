use std::{
    ffi::{
        CStr,
        CString,
    },
    io,
    os::fd::{
        AsFd,
        AsRawFd,
        BorrowedFd,
        FromRawFd,
        OwnedFd,
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
};

use super::process::standard_input;

const CREATE_RULESET_VERSION: libc::c_uint = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_BLOCK: u64 = 1 << 11;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const IOCTL_DEV: u64 = 1 << 15;
const ALL_ABI_1: u64 = (1 << 13) - 1;

const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

const READ_AND_EXECUTE: u64 = READ_FILE | READ_DIR | EXECUTE;
const DEVICE_USE: u64 = READ_FILE | WRITE_FILE | TRUNCATE | IOCTL_DEV;
const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
const PROC_WRITE: u64 = WRITE_FILE | TRUNCATE;
const MINIMUM_ABI: i64 = 2;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[derive(Debug)]
pub(super) struct Landlock {
    full_access: Vec<CString>,
}

impl Landlock {
    pub(super) fn new(full_access: Vec<CString>) -> Self {
        Self { full_access }
    }

    pub(super) fn check_available() -> io::Result<()> {
        match abi() {
            Ok(abi) if abi >= MINIMUM_ABI => Ok(()),
            Ok(abi) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "the kernel's Landlock ABI {abi} is too old; the sandbox needs ABI {MINIMUM_ABI} (Linux 5.19)"
                ),
            )),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("the kernel has no Landlock, which the sandbox needs: {error}"),
            )),
        }
    }

    pub(super) fn restrict_self(&self) -> io::Result<()> {
        let abi = abi()?;
        if abi < MINIMUM_ABI {
            return Err(Errno::NOSYS.into());
        }
        let handled = handled_access(abi);
        let ruleset = create_ruleset(&RulesetAttr {
            handled_access_fs: handled,
            handled_access_net: 0,
            scoped: if abi >= 6 {
                SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
            } else {
                0
            },
        })?;
        allow_path(&ruleset, c"/", READ_AND_EXECUTE & handled)?;
        allow_path(&ruleset, c"/dev", DEVICE_USE & handled)?;
        allow_path(&ruleset, c"/proc", PROC_WRITE & handled)?;
        let full_access = handled & !(MAKE_CHAR | MAKE_BLOCK);
        for path in &self.full_access {
            allow_path(&ruleset, path, full_access)?;
        }
        add_rule(&ruleset, standard_input(), DEVICE_USE & handled)?;
        restrict(&ruleset)
    }
}

fn handled_access(abi: i64) -> u64 {
    let mut handled = ALL_ABI_1;
    if abi >= 2 {
        handled |= REFER;
    }
    if abi >= 3 {
        handled |= TRUNCATE;
    }
    if abi >= 5 {
        handled |= IOCTL_DEV;
    }
    handled
}

fn allow_path(ruleset: &OwnedFd, path: &CStr, access: u64) -> io::Result<()> {
    let parent = rustix::fs::openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    let is_dir =
        FileType::from_raw_mode(rustix::fs::fstat(&parent)?.st_mode) == FileType::Directory;
    let access = if is_dir { access } else { access & FILE_RIGHTS };
    add_rule(ruleset, parent.as_fd(), access)
}

#[expect(
    unsafe_code,
    reason = "rustix has no Landlock calls, so the system calls are made through libc"
)]
fn abi() -> io::Result<i64> {
    // SAFETY: with a null attribute, a zero size and the version flag, the kernel reads no
    // memory and returns the highest supported ABI.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0_usize,
            CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(abi)
    }
}

#[expect(
    unsafe_code,
    reason = "rustix has no Landlock calls, so the system calls are made through libc"
)]
fn create_ruleset(attr: &RulesetAttr) -> io::Result<OwnedFd> {
    // SAFETY: `attr` is a valid `RulesetAttr` that outlives the call and its size is passed
    // with it; the kernel only reads it.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const *attr,
            size_of::<RulesetAttr>(),
            0_u32,
        )
    };
    let fd = i32::try_from(fd).map_err(|_| Errno::INVAL)?;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[expect(
    unsafe_code,
    reason = "rustix has no Landlock calls, so the system calls are made through libc"
)]
fn add_rule(ruleset: &OwnedFd, parent: BorrowedFd<'_>, access: u64) -> io::Result<()> {
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: both descriptors are open for the whole call, and `attr` is a valid
    // `PathBeneathAttr` that outlives it; the kernel only reads it.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &raw const attr,
            0_u32,
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
    reason = "rustix has no Landlock calls, so the system calls are made through libc"
)]
fn restrict(ruleset: &OwnedFd) -> io::Result<()> {
    // SAFETY: the ruleset descriptor is open for the whole call and no pointer is passed.
    let result =
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0_u32) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
