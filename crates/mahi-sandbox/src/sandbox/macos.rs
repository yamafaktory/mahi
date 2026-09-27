use std::{
    ffi::{
        CStr,
        CString,
        c_char,
        c_int,
    },
    fmt::{
        self,
        Write,
    },
    fs,
    io,
    os::fd::BorrowedFd,
    path::Path,
};

use rustix::io::Errno;

use super::{
    Access,
    Sandbox,
};

const BASE: &str = r#"(version 1)
(deny default)
(allow process-exec process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow sysctl-read)
(deny sysctl-read (sysctl-name-prefix "kern.procargs"))
(allow file-read-metadata)
(allow file-read* (literal "/") (literal "/private/var/select/sh") (literal "/dev/random") (literal "/dev/urandom"))
(allow file-read* file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/tty") (literal "/dev/dtracehelper") (subpath "/dev/fd"))
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))
(allow system-socket (socket-domain AF_UNIX))
"#;

#[expect(
    unsafe_code,
    reason = "Seatbelt is only reachable through libSystem's sandbox_init"
)]
unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
}

/// A Seatbelt profile, written before the fork so the child only applies it.
#[derive(Debug)]
pub(crate) struct Profile {
    source: CString,
}

impl Profile {
    pub(crate) fn new(sandbox: &Sandbox, terminal: &Path) -> io::Result<Self> {
        let mut binds = Vec::with_capacity(sandbox.binds.len());
        for bind in &sandbox.binds {
            if fs::canonicalize(&bind.path)? != bind.path {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{} must be a canonical path, without symbolic links",
                        bind.path.display()
                    ),
                ));
            }
            binds.push((bind.path.as_path(), bind.access));
        }
        binds.sort_by_key(|(path, _)| path.components().count());
        let mut source = String::from(BASE);
        let terminal = quoted(terminal)?;
        push_rule(
            &mut source,
            format_args!(
                "(allow file-ioctl (literal {terminal}) (literal \"/dev/tty\") (literal \"/dev/dtracehelper\"))"
            ),
        )?;
        for (path, _) in &binds {
            push_rule(
                &mut source,
                format_args!("(allow file-read* (subpath {}))", quoted(path)?),
            )?;
        }
        for (index, (path, access)) in binds.iter().enumerate() {
            if *access == Access::ReadWrite {
                push_rule(
                    &mut source,
                    format_args!("(allow file-write* (subpath {}))", quoted(path)?),
                )?;
                continue;
            }
            let enclosing = binds
                .iter()
                .take(index)
                .rev()
                .find(|(outer, _)| path.starts_with(outer));
            let Some((outer, Access::ReadWrite)) = enclosing else {
                continue;
            };
            push_rule(
                &mut source,
                format_args!("(deny file-write* (subpath {}))", quoted(path)?),
            )?;
            for ancestor in path.ancestors().skip(1) {
                if ancestor == *outer {
                    break;
                }
                push_rule(
                    &mut source,
                    format_args!("(deny file-write* (literal {}))", quoted(ancestor)?),
                )?;
            }
        }
        let source = CString::new(source)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self { source })
    }

    #[expect(
        unsafe_code,
        reason = "the child must take the terminal and apply the Seatbelt profile before exec"
    )]
    pub(crate) fn enter(&mut self) -> io::Result<()> {
        // SAFETY: fd 0 is the pseudo-terminal's slave that `Command` installed as standard
        // input, and fd 2 the same terminal as standard error. The profile is a valid
        // NUL-terminated string that outlives the call, the error buffer is a valid pointer
        // that `sandbox_init` may fill, and a non-null error it returns is a NUL-terminated
        // string.
        unsafe {
            rustix::process::ioctl_tiocsctty(BorrowedFd::borrow_raw(0))?;
            let mut error = std::ptr::null_mut();
            if sandbox_init(self.source.as_ptr(), 0, &raw mut error) != 0 {
                if !error.is_null() {
                    let message = CStr::from_ptr(error).to_bytes();
                    let _ = rustix::io::write(BorrowedFd::borrow_raw(2), message);
                }
                return Err(Errno::PERM.into());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn source(&self) -> &CStr {
        &self.source
    }
}

fn push_rule(source: &mut String, rule: fmt::Arguments<'_>) -> io::Result<()> {
    source.write_fmt(rule).map_err(io::Error::other)?;
    source.push('\n');
    Ok(())
}

fn quoted(path: &Path) -> io::Result<String> {
    let Some(text) = path.to_str() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not valid UTF-8", path.display()),
        ));
    };
    if text.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has a control character", path.display()),
        ));
    }
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for character in text.chars() {
        if matches!(character, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    Ok(quoted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_backslashes_are_escaped() {
        assert_eq!(quoted(Path::new("/a\"b\\c")).unwrap(), "\"/a\\\"b\\\\c\"");
    }

    #[test]
    fn control_characters_are_refused() {
        assert!(quoted(Path::new("/a\nb")).is_err());
    }

    fn nested_policy() -> (tempfile::TempDir, std::path::PathBuf, Sandbox) {
        let dir = tempfile::tempdir().unwrap();
        let work = fs::canonicalize(dir.path()).unwrap().join("work");
        fs::create_dir_all(work.join("a/ro/rw")).unwrap();
        let mut sandbox = Sandbox::system().unwrap();
        sandbox.bind(&work, Access::ReadWrite).unwrap();
        sandbox.bind(&work.join("a/ro"), Access::ReadOnly).unwrap();
        sandbox
            .bind(&work.join("a/ro/rw"), Access::ReadWrite)
            .unwrap();
        (dir, work, sandbox)
    }

    #[test]
    fn a_read_only_bind_inside_a_read_write_one_stays_read_only() {
        let (_dir, work, sandbox) = nested_policy();
        let profile = Profile::new(&sandbox, Path::new("/dev/ttys000")).unwrap();
        let source = profile.source().to_str().unwrap();
        let rule = |kind: &str, path: &Path| format!("({kind} (subpath \"{}\"))", path.display());
        let literal = |path: &Path| format!("(deny file-write* (literal \"{}\"))", path.display());
        let deny = source
            .find(&rule("deny file-write*", &work.join("a/ro")))
            .unwrap();
        let outer = source.find(&rule("allow file-write*", &work)).unwrap();
        let inner = source
            .find(&rule("allow file-write*", &work.join("a/ro/rw")))
            .unwrap();
        assert!(outer < deny && deny < inner, "{source}");
        assert!(source.contains(&literal(&work.join("a"))), "{source}");
        assert!(!source.contains(&literal(&work)), "{source}");
    }

    #[test]
    fn a_bind_through_a_symbolic_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let mut sandbox = Sandbox::new();
        sandbox.bind(&root.join("link"), Access::ReadWrite).unwrap();
        assert!(Profile::new(&sandbox, Path::new("/dev/ttys000")).is_err());
    }

    #[test]
    fn the_profile_compiles() {
        let (_dir, _work, sandbox) = nested_policy();
        let profile = Profile::new(&sandbox, Path::new("/dev/ttys000")).unwrap();
        let output = std::process::Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(profile.source().to_str().unwrap())
            .arg("/usr/bin/true")
            .output()
            .expect("sandbox-exec ships with macOS");
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            profile.source().to_str().unwrap()
        );
    }
}
