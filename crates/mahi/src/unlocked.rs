use std::{
    fs::File,
    io::{
        self,
        Read,
    },
    path::{
        Path,
        PathBuf,
    },
    sync::{
        Mutex,
        MutexGuard,
        PoisonError,
    },
    time::{
        Duration,
        Instant,
    },
};

use age::secrecy::SecretString;
use mahi_identity::{
    IdentityError,
    LocalIdentity,
};
use rustix::{
    fs::OFlags,
    process::{
        Resource,
        Rlimit,
        getrlimit,
        setrlimit,
    },
};
use zeroize::Zeroizing;

use crate::ui;

const KEEP_FOR: Duration = Duration::from_mins(15);

const MAX_GIVEN_BYTES: usize = 256;

static KEPT: Mutex<Option<Kept>> = Mutex::new(None);
static GIVEN: Mutex<Option<Given>> = Mutex::new(None);

/// The user's mahi key, unlocked by the workspace that started this mahi and handed to it, for
/// its whole run.
struct Given {
    file: PathBuf,
    identity: LocalIdentity,
    _no_cores: NoCores,
}

/// The user's mahi key, unlocked by an earlier action on the home screen.
struct Kept {
    file: PathBuf,
    identity: LocalIdentity,
    used: Instant,
    no_cores: NoCores,
}

/// The core file size limit mahi had before it was set to 0 while a key is kept, given back
/// when dropped.
struct NoCores(Rlimit);

impl NoCores {
    fn start() -> Option<Self> {
        let before = getrlimit(Resource::Core);
        let none = Rlimit {
            current: Some(0),
            maximum: before.maximum,
        };
        setrlimit(Resource::Core, none).ok()?;
        Some(Self(before))
    }
}

impl Drop for NoCores {
    fn drop(&mut self) {
        let _ = setrlimit(Resource::Core, self.0);
    }
}

/// Returns the user's mahi key from `file`, unlocked with the passphrase `ask` gives. While
/// the home screen owns the terminal, the key one action unlocked is kept in memory for the
/// next, so the passphrase is asked once until the home screen ends or the key goes unused for
/// 15 minutes; a wrong passphrase keeps nothing. While a key is kept, mahi's core file size
/// limit is 0, and a key that cannot have it is not kept.
///
/// # Errors
///
/// Returns what `ask` returns when it fails, or the [`IdentityError`] of unlocking the key,
/// made into the caller's error by `unlock_error`.
pub(crate) fn identity<E>(
    file: &Path,
    ask: impl FnOnce() -> Result<SecretString, E>,
    unlock_error: impl FnOnce(IdentityError) -> E,
) -> Result<LocalIdentity, E> {
    if let Some(given) = given().as_ref().filter(|given| given.file == file) {
        return Ok(given.identity.clone());
    }
    let showing = ui::is_showing();
    if showing && let Some(identity) = take_kept(file, Instant::now()) {
        return Ok(identity);
    }
    let passphrase = ask()?;
    let identity = LocalIdentity::load(file, &passphrase).map_err(unlock_error)?;
    drop(passphrase);
    if showing {
        keep(file, &identity, Instant::now());
    }
    Ok(identity)
}

/// Keeps `identity`, the key setting mahi up just made or unlocked from `file`, as
/// [`identity`] keeps one, so the action that set mahi up does not ask for its passphrase again.
pub(crate) fn hold(file: &Path, identity: &LocalIdentity) {
    if ui::is_showing() {
        keep(file, identity, Instant::now());
    }
}

/// Forgets the key the home screen kept unlocked, and the one a workspace handed over.
pub(crate) fn forget() {
    *kept() = None;
    *given() = None;
}

/// Returns the key the home screen keeps unlocked for `file`, if it keeps one, counting this
/// as a use of it.
pub(crate) fn current(file: &Path) -> Option<LocalIdentity> {
    take_kept(file, Instant::now())
}

/// Takes the key a workspace handed over on the inherited pipe `fd` for the identity `file`,
/// if it did, and keeps it for this mahi's whole run; one that cannot be read, or a pipe that
/// has not ended, is reported and left, so the passphrase is asked as usual.
pub(crate) fn receive(fd: i32, file: &Path) {
    match mahi_sandbox::inherited_pipe(fd).and_then(|pipe| read_given(&pipe)) {
        Ok(identity) => give(identity, file),
        Err(error) => crate::report_with("the key the workspace handed over is not usable", &error),
    }
}

fn read_given(mut pipe: &File) -> io::Result<LocalIdentity> {
    rustix::fs::fcntl_setfl(pipe, OFlags::NONBLOCK)?;
    let mut buffer = Zeroizing::new([0_u8; MAX_GIVEN_BYTES + 1]);
    let mut length = 0;
    loop {
        let free = buffer.get_mut(length..).unwrap_or_default();
        if free.is_empty() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        match pipe.read(free) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let text = std::str::from_utf8(buffer.get(..length).unwrap_or_default())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    LocalIdentity::from_secret(&SecretString::from(text.to_owned()))
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

fn give(identity: LocalIdentity, file: &Path) {
    let Some(no_cores) = NoCores::start() else {
        return;
    };
    *given() = Some(Given {
        file: file.to_path_buf(),
        identity,
        _no_cores: no_cores,
    });
}

fn given() -> MutexGuard<'static, Option<Given>> {
    GIVEN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Forgets the kept key if no action has used it for 15 minutes before `now`.
pub(crate) fn forget_unused(now: Instant) {
    let mut kept = kept();
    if kept.as_ref().is_some_and(|kept| !kept.is_fresh(now)) {
        *kept = None;
    }
}

impl Kept {
    fn is_fresh(&self, now: Instant) -> bool {
        now.duration_since(self.used) < KEEP_FOR
    }
}

fn kept() -> MutexGuard<'static, Option<Kept>> {
    KEPT.lock().unwrap_or_else(PoisonError::into_inner)
}

fn take_kept(file: &Path, now: Instant) -> Option<LocalIdentity> {
    let mut kept = kept();
    let fresh = kept
        .as_ref()
        .is_some_and(|kept| kept.file == file && kept.is_fresh(now));
    if !fresh {
        *kept = None;
        return None;
    }
    let kept = kept.as_mut()?;
    kept.used = now;
    Some(kept.identity.clone())
}

fn keep(file: &Path, identity: &LocalIdentity, now: Instant) {
    let mut kept = kept();
    let Some(no_cores) = kept.take().map(|old| old.no_cores).or_else(NoCores::start) else {
        return;
    };
    *kept = Some(Kept {
        file: file.to_path_buf(),
        identity: identity.clone(),
        used: now,
        no_cores,
    });
}

#[cfg(test)]
mod tests {
    use age::secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn a_key_held_while_no_home_screen_shows_is_not_kept() {
        let file = Path::new("/config/held");
        hold(file, &LocalIdentity::generate());
        assert!(take_kept(file, Instant::now()).is_none());
    }

    #[test]
    fn a_kept_key_is_given_back_for_its_file_until_it_goes_unused_too_long() {
        let identity = LocalIdentity::generate();
        let file = Path::new("/config/identity");
        let start = Instant::now();
        keep(file, &identity, start);
        assert!(take_kept(Path::new("/other/identity"), start).is_none());
        assert!(take_kept(file, start).is_none());
        keep(file, &identity, start);
        let later = start + KEEP_FOR / 2;
        let again = take_kept(file, later).unwrap();
        assert_eq!(
            again.recipient().to_string(),
            identity.recipient().to_string()
        );
        assert!(take_kept(file, later + KEEP_FOR / 2).is_some());
        assert!(take_kept(file, later + KEEP_FOR * 3).is_none());
        assert!(take_kept(file, later + KEEP_FOR / 2).is_none());
        keep(file, &identity, start);
        forget();
        assert!(take_kept(file, start).is_none());
    }

    #[test]
    fn an_unused_kept_key_is_forgotten_without_waiting_for_the_next_action() {
        let identity = LocalIdentity::generate();
        let file = Path::new("/config/identity");
        let start = Instant::now();
        keep(file, &identity, start);
        forget_unused(start + KEEP_FOR / 2);
        assert!(kept().is_some());
        forget_unused(start + KEEP_FOR);
        assert!(kept().is_none());
    }

    #[test]
    fn no_core_file_is_written_while_a_key_is_kept() {
        let hard = getrlimit(Resource::Core).maximum;
        let soft = hard.map_or(4096, |hard| hard.min(4096));
        assert!(soft > 0, "the hard core file size limit is 0");
        let before = Rlimit {
            current: Some(soft),
            maximum: hard,
        };
        setrlimit(Resource::Core, before).unwrap();
        let identity = LocalIdentity::generate();
        let file = Path::new("/config/identity");
        keep(file, &identity, Instant::now());
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        keep(file, &identity, Instant::now());
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        forget();
        assert_eq!(getrlimit(Resource::Core), before);
    }

    #[test]
    fn a_key_handed_over_on_a_pipe_is_used_without_asking_until_forgotten() {
        let identity = LocalIdentity::generate();
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut writer = std::fs::File::from(writer);
        std::io::Write::write_all(&mut writer, identity.to_secret().expose_secret().as_bytes())
            .unwrap();
        drop(writer);
        receive(
            std::os::fd::IntoRawFd::into_raw_fd(reader),
            Path::new("/config/identity"),
        );
        assert!(
            super::identity(
                Path::new("/other/identity"),
                || Err(IdentityError::WrongPassphrase),
                |error| error,
            )
            .is_err()
        );
        let used = super::identity(
            Path::new("/config/identity"),
            || -> Result<SecretString, IdentityError> { panic!("the passphrase was asked") },
            |error| error,
        )
        .unwrap();
        assert_eq!(
            used.recipient().to_string(),
            identity.recipient().to_string()
        );
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        forget();
        assert!(given().is_none());
    }

    #[test]
    fn the_key_kept_for_a_file_is_the_current_one_for_that_file_only() {
        let identity = LocalIdentity::generate();
        let file = Path::new("/config/identity");
        keep(file, &identity, Instant::now());
        assert!(current(Path::new("/other/identity")).is_none());
        keep(file, &identity, Instant::now());
        assert_eq!(
            current(file).unwrap().recipient().to_string(),
            identity.recipient().to_string()
        );
    }

    #[test]
    fn a_pipe_that_holds_no_key_gives_nothing() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut writer = std::fs::File::from(writer);
        std::io::Write::write_all(&mut writer, b"not a key").unwrap();
        drop(writer);
        receive(
            std::os::fd::IntoRawFd::into_raw_fd(reader),
            Path::new("/config/identity"),
        );
        assert!(given().is_none());
    }

    #[test]
    fn a_pipe_still_open_for_writing_is_left_at_once() {
        let identity = LocalIdentity::generate();
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut writer = std::fs::File::from(writer);
        std::io::Write::write_all(&mut writer, identity.to_secret().expose_secret().as_bytes())
            .unwrap();
        let started = Instant::now();
        receive(
            std::os::fd::IntoRawFd::into_raw_fd(reader),
            Path::new("/config/identity"),
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(given().is_none());
        drop(writer);
    }

    #[test]
    fn a_kept_key_is_forgotten_before_mahi_dies_of_a_signal() {
        let identity = LocalIdentity::generate();
        keep(Path::new("/config/identity"), &identity, Instant::now());
        ui::before_dying();
        assert!(kept().is_none());
    }
}
