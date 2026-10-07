use std::io;

use rustix::io::Errno;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const NR_OFFSET: u32 = 0;
const ARCH_OFFSET: u32 = 4;
const ARG0_LOW_OFFSET: u32 = 16;
const ARG1_LOW_OFFSET: u32 = 24;

const NAMESPACE_FLAGS: libc::c_int = libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWTIME
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWUTS;

const DENIED_IOCTLS: [libc::Ioctl; 2] = [libc::TIOCSTI, libc::TIOCLINUX];
const DENIED_SOCKET_FAMILIES: [libc::c_int; 1] = [libc::AF_VSOCK];
const SYS_OPEN_TREE_ATTR: libc::c_long = 467;
const MAXIMUM_LENGTH: usize = 4096;

const DENIED: &[libc::c_long] = &[
    libc::SYS_acct,
    libc::SYS_add_key,
    libc::SYS_adjtimex,
    libc::SYS_bpf,
    libc::SYS_clock_adjtime,
    libc::SYS_clock_settime,
    libc::SYS_delete_module,
    libc::SYS_finit_module,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fsopen,
    libc::SYS_fspick,
    libc::SYS_init_module,
    libc::SYS_kexec_file_load,
    libc::SYS_kexec_load,
    libc::SYS_keyctl,
    libc::SYS_lookup_dcookie,
    libc::SYS_mount,
    libc::SYS_mount_setattr,
    libc::SYS_move_mount,
    libc::SYS_open_by_handle_at,
    libc::SYS_open_tree,
    SYS_OPEN_TREE_ATTR,
    libc::SYS_perf_event_open,
    libc::SYS_pivot_root,
    libc::SYS_quotactl,
    libc::SYS_quotactl_fd,
    libc::SYS_reboot,
    libc::SYS_request_key,
    libc::SYS_setns,
    libc::SYS_settimeofday,
    libc::SYS_swapoff,
    libc::SYS_swapon,
    libc::SYS_syslog,
    libc::SYS_umount2,
    libc::SYS_userfaultfd,
    libc::SYS_vhangup,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_ioperm,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_iopl,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_modify_ldt,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_uselib,
];

const UNAVAILABLE: &[libc::c_long] = &[
    libc::SYS_clone3,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_io_uring_setup,
];

#[derive(Debug)]
pub(super) struct Filter {
    program: Vec<libc::sock_filter>,
}

impl Filter {
    pub(super) fn new() -> io::Result<Self> {
        let mut program = vec![
            load(ARCH_OFFSET),
            jump_if_equal(AUDIT_ARCH, 1, 0),
            ret(libc::SECCOMP_RET_KILL_PROCESS),
            load(NR_OFFSET),
        ];
        #[cfg(target_arch = "x86_64")]
        program.extend([
            jump(libc::BPF_JGE, X32_SYSCALL_BIT, 0, 1),
            ret(errno(Errno::NOSYS)),
        ]);
        for &nr in DENIED {
            program.extend(deny(syscall_number(nr)?, errno(Errno::PERM)));
        }
        for &nr in UNAVAILABLE {
            program.extend(deny(syscall_number(nr)?, errno(Errno::NOSYS)));
        }
        for nr in [libc::SYS_clone, libc::SYS_unshare] {
            program.extend(deny_argument(
                syscall_number(nr)?,
                ARG0_LOW_OFFSET,
                libc::BPF_JSET,
                NAMESPACE_FLAGS.cast_unsigned(),
            ));
        }
        for request in DENIED_IOCTLS {
            program.extend(deny_argument(
                syscall_number(libc::SYS_ioctl)?,
                ARG1_LOW_OFFSET,
                libc::BPF_JEQ,
                u32::try_from(request).map_err(|_| Errno::INVAL)?,
            ));
        }
        for family in DENIED_SOCKET_FAMILIES {
            program.extend(deny_argument(
                syscall_number(libc::SYS_socket)?,
                ARG0_LOW_OFFSET,
                libc::BPF_JEQ,
                family.cast_unsigned(),
            ));
        }
        program.push(ret(libc::SECCOMP_RET_ALLOW));
        if program.len() > MAXIMUM_LENGTH {
            return Err(Errno::TOOBIG.into());
        }
        Ok(Self { program })
    }

    #[expect(
        unsafe_code,
        reason = "rustix has no seccomp call, so the filter is installed through libc"
    )]
    pub(super) fn install(&self) -> io::Result<()> {
        let length = u16::try_from(self.program.len()).map_err(|_| Errno::TOOBIG)?;
        let program = libc::sock_fprog {
            len: length,
            filter: self.program.as_ptr().cast_mut(),
        };
        // SAFETY: `program` points at the filter's instructions and their count, both of which
        // outlive the call, and the kernel only reads them. The caller has set no_new_privs.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0_u32,
                &raw const program,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn deny(nr: u32, action: u32) -> [libc::sock_filter; 2] {
    [jump_if_equal(nr, 0, 1), ret(action)]
}

fn deny_argument(nr: u32, offset: u32, test: u32, value: u32) -> [libc::sock_filter; 5] {
    [
        jump_if_equal(nr, 0, 3),
        load(offset),
        jump(test, value, 0, 1),
        ret(errno(Errno::PERM)),
        load(NR_OFFSET),
    ]
}

fn errno(error: Errno) -> u32 {
    libc::SECCOMP_RET_ERRNO | (error.raw_os_error().cast_unsigned() & 0xFFFF)
}

fn syscall_number(nr: libc::c_long) -> io::Result<u32> {
    Ok(u32::try_from(nr).map_err(|_| Errno::INVAL)?)
}

fn load(offset: u32) -> libc::sock_filter {
    statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset)
}

fn ret(action: u32) -> libc::sock_filter {
    statement(libc::BPF_RET | libc::BPF_K, action)
}

fn jump_if_equal(value: u32, if_true: u8, if_false: u8) -> libc::sock_filter {
    jump(libc::BPF_JEQ, value, if_true, if_false)
}

fn jump(test: u32, value: u32, if_true: u8, if_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: instruction_code(libc::BPF_JMP | test | libc::BPF_K),
        jt: if_true,
        jf: if_false,
        k: value,
    }
}

fn statement(code: u32, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: instruction_code(code),
        jt: 0,
        jf: 0,
        k: value,
    }
}

fn instruction_code(code: u32) -> u16 {
    u16::try_from(code).expect("classic BPF instruction codes fit in 16 bits")
}
