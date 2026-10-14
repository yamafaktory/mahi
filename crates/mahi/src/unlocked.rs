use std::{
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

use crate::ui;

const KEEP_FOR: Duration = Duration::from_mins(15);

static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

/// The user's mahi key, unlocked by an earlier action on the home screen.
struct Kept {
    file: PathBuf,
    identity: LocalIdentity,
    used: Instant,
}

/// Returns the user's mahi key from `file`, unlocked with the passphrase `ask` gives. While
/// the home screen owns the terminal, the key one action unlocked is kept in memory for the
/// next, so the passphrase is asked once until the home screen ends or the key goes unused for
/// 15 minutes; a wrong passphrase keeps nothing.
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

/// Forgets the key the home screen kept unlocked.
pub(crate) fn forget() {
    *kept() = None;
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
    *kept() = Some(Kept {
        file: file.to_path_buf(),
        identity: identity.clone(),
        used: now,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
