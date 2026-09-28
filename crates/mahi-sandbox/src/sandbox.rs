#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;

use std::{
    ffi::{
        OsStr,
        OsString,
    },
    io,
    os::unix::ffi::OsStrExt,
    path::{
        Path,
        PathBuf,
    },
};

use thiserror::Error;

const RESERVED: [&str; 2] = ["/dev", "/proc"];
#[cfg(target_os = "linux")]
const SYSTEM: &[&str] = &["/usr", "/etc", "/bin", "/sbin", "/lib", "/lib32", "/lib64"];
#[cfg(target_os = "macos")]
const SYSTEM: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System/Library",
    "/System/Cryptexes",
    "/System/Volumes/Preboot/Cryptexes",
    "/Library/Apple",
    "/private/etc",
    "/private/var/db/dyld",
    "/private/var/db/timezone",
];

/// What of the host filesystem an agent sees.
///
/// On Linux the agent starts in an empty root. It sees the paths bound here, a private `/tmp`, a
/// minimal `/dev`, and nothing else. A bound path is opened without following any symbolic
/// link, so a link planted on the way cannot redirect the bind. The root itself is read-only.
///
/// On macOS the agent sees the host's filesystem through a Seatbelt profile: it can read the
/// bound paths and write the read-write ones, and it can read the metadata, but not the
/// contents, of every other file.
#[derive(Debug, Clone, Default)]
pub struct Sandbox {
    binds: Vec<Bind>,
    links: Vec<Link>,
    sockets: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct Bind {
    path: PathBuf,
    access: Access,
}

#[derive(Debug, Clone)]
struct Link {
    path: PathBuf,
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "macOS sees the host's own links, so only the Linux sandbox recreates them"
        )
    )]
    target: OsString,
}

/// Whether the agent may change a bound path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// The agent can read the path and everything mounted under it, and change nothing.
    ReadOnly,
    /// The agent can read and change the path.
    ReadWrite,
}

/// A sandbox rule is invalid.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// The path is not absolute, is the root, or has `.` or `..` in it.
    #[error("{} is not a plain absolute path", .0.display())]
    NotPlain(PathBuf),
    /// The path is under `/dev` or `/proc`, which the sandbox builds itself.
    #[error("{} is reserved by the sandbox", .0.display())]
    Reserved(PathBuf),
    /// The path is already used by another rule, or a link would sit inside a bound path or
    /// above another rule.
    #[error("{} overlaps another sandbox rule", .0.display())]
    Overlaps(PathBuf),
    /// The path is not inside a bound path, so the agent could not reach it.
    #[error("{} is not inside a bound path", .0.display())]
    NotBound(PathBuf),
    /// Inspecting a host system path failed.
    #[error("cannot inspect {}", .0.display())]
    Inspect(PathBuf, #[source] io::Error),
}

impl Sandbox {
    /// An empty sandbox: the agent sees only `/tmp` and `/dev`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A sandbox with the host's programs and libraries readable: `/usr`, `/etc`, `/bin`,
    /// `/sbin`, `/lib`, `/lib32` and `/lib64` as they are on the host, each either bound
    /// read-only or recreated as the same symbolic link.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Inspect`] if a system path exists but cannot be inspected.
    pub fn system() -> Result<Self, SandboxError> {
        let mut sandbox = Self::new();
        for path in SYSTEM.iter().map(Path::new) {
            match path.symlink_metadata() {
                Ok(metadata) if metadata.is_symlink() => {
                    let target = path
                        .read_link()
                        .map_err(|error| SandboxError::Inspect(path.to_path_buf(), error))?;
                    sandbox.link(path, target.as_os_str())?;
                }
                Ok(metadata) if metadata.is_dir() => {
                    sandbox.bind(path, Access::ReadOnly)?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(SandboxError::Inspect(path.to_path_buf(), error)),
            }
        }
        Ok(sandbox)
    }

    /// Shows the host path `path` at the same place in the sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not plain, is reserved, is already bound, or is below or
    /// above a link.
    pub fn bind(&mut self, path: &Path, access: Access) -> Result<&mut Self, SandboxError> {
        check_plain(path)?;
        let taken = self.binds.iter().any(|bind| bind.path == path)
            || self
                .links
                .iter()
                .any(|link| path.starts_with(&link.path) || link.path.starts_with(path));
        if taken {
            return Err(SandboxError::Overlaps(path.to_path_buf()));
        }
        self.binds.push(Bind {
            path: path.to_path_buf(),
            access,
        });
        Ok(self)
    }

    /// Lets the agent connect to the Unix socket at `path`, which must be inside a path
    /// bound before.
    ///
    /// On Linux a socket in a bound path can always be reached, so this only checks the path.
    /// On macOS, where Seatbelt refuses every outbound connection by default, it allows
    /// connections to this one socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not plain, is reserved, or is not inside a bound path.
    pub fn allow_connect(&mut self, path: &Path) -> Result<&mut Self, SandboxError> {
        check_plain(path)?;
        if !self.binds.iter().any(|bind| path.starts_with(&bind.path)) {
            return Err(SandboxError::NotBound(path.to_path_buf()));
        }
        self.sockets.push(path.to_path_buf());
        Ok(self)
    }

    /// Creates a symbolic link at `path` in the sandbox that points to `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not plain, is reserved, is already used, is inside a
    /// bound path, or is above another rule.
    pub fn link(&mut self, path: &Path, target: &OsStr) -> Result<&mut Self, SandboxError> {
        check_plain(path)?;
        let taken = self
            .binds
            .iter()
            .any(|bind| path.starts_with(&bind.path) || bind.path.starts_with(path))
            || self
                .links
                .iter()
                .any(|link| path.starts_with(&link.path) || link.path.starts_with(path));
        if taken {
            return Err(SandboxError::Overlaps(path.to_path_buf()));
        }
        self.links.push(Link {
            path: path.to_path_buf(),
            target: target.to_os_string(),
        });
        Ok(self)
    }
}

fn check_plain(path: &Path) -> Result<(), SandboxError> {
    let bytes = path.as_os_str().as_bytes();
    let plain = bytes.len() > 1
        && bytes.first() == Some(&b'/')
        && bytes
            .split(|byte| *byte == b'/')
            .skip(1)
            .all(|segment| !matches!(segment, b"" | b"." | b".."));
    if !plain {
        return Err(SandboxError::NotPlain(path.to_path_buf()));
    }
    if RESERVED.iter().any(|reserved| path.starts_with(reserved)) {
        return Err(SandboxError::Reserved(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_absolute_paths_are_accepted() {
        let mut sandbox = Sandbox::new();
        for path in [
            "relative", "/", "/a/../b", "/a/./b", "", "//a", "/a/", "/a/.",
        ] {
            assert!(
                matches!(
                    sandbox.bind(Path::new(path), Access::ReadOnly),
                    Err(SandboxError::NotPlain(_))
                ),
                "{path}"
            );
        }
        assert!(sandbox.bind(Path::new("/a/b"), Access::ReadOnly).is_ok());
    }

    #[test]
    fn a_socket_must_be_inside_a_bound_path() {
        let mut sandbox = Sandbox::new();
        assert!(matches!(
            sandbox.allow_connect(Path::new("/run/mahi.sock")),
            Err(SandboxError::NotBound(_))
        ));
        sandbox
            .bind(Path::new("/scratch"), Access::ReadWrite)
            .unwrap();
        assert!(
            sandbox
                .allow_connect(Path::new("/scratch/mahi.sock"))
                .is_ok()
        );
        assert!(matches!(
            sandbox.allow_connect(Path::new("/scratch/../x.sock")),
            Err(SandboxError::NotPlain(_))
        ));
    }

    #[test]
    fn dev_and_proc_are_reserved() {
        let mut sandbox = Sandbox::new();
        for path in ["/dev", "/dev/sda", "/proc/1/root"] {
            assert!(matches!(
                sandbox.bind(Path::new(path), Access::ReadWrite),
                Err(SandboxError::Reserved(_))
            ));
        }
        assert!(
            sandbox
                .bind(Path::new("/devices"), Access::ReadWrite)
                .is_ok()
        );
    }

    #[test]
    fn a_path_is_bound_once() {
        let mut sandbox = Sandbox::new();
        sandbox.bind(Path::new("/a"), Access::ReadOnly).unwrap();
        assert!(matches!(
            sandbox.bind(Path::new("/a"), Access::ReadWrite),
            Err(SandboxError::Overlaps(_))
        ));
        assert!(sandbox.bind(Path::new("/a/b"), Access::ReadWrite).is_ok());
    }

    #[test]
    fn links_never_share_a_path_with_other_rules() {
        let mut sandbox = Sandbox::new();
        sandbox.bind(Path::new("/work"), Access::ReadWrite).unwrap();
        sandbox.link(Path::new("/bin"), "usr/bin".as_ref()).unwrap();
        for path in ["/work", "/work/x", "/bin", "/bin/x", "/"] {
            assert!(
                sandbox.link(Path::new(path), "t".as_ref()).is_err(),
                "{path}"
            );
        }
        assert!(matches!(
            sandbox.bind(Path::new("/bin/sh"), Access::ReadOnly),
            Err(SandboxError::Overlaps(_))
        ));
        let mut sandbox = Sandbox::new();
        sandbox.bind(Path::new("/a/b"), Access::ReadOnly).unwrap();
        assert!(sandbox.link(Path::new("/a"), "x".as_ref()).is_err());
        let mut sandbox = Sandbox::new();
        sandbox
            .link(Path::new("/work/planted"), "/etc/passwd".as_ref())
            .unwrap();
        assert!(matches!(
            sandbox.bind(Path::new("/work"), Access::ReadWrite),
            Err(SandboxError::Overlaps(_))
        ));
    }

    #[test]
    fn the_system_sandbox_mirrors_the_host_layout() {
        let sandbox = Sandbox::system().unwrap();
        for path in SYSTEM.iter().map(Path::new) {
            let bound = sandbox.binds.iter().any(|bind| bind.path == path);
            let linked = sandbox.links.iter().any(|link| link.path == path);
            assert_eq!(bound || linked, path.exists(), "{}", path.display());
            assert_eq!(linked, path.is_symlink(), "{}", path.display());
        }
    }
}
