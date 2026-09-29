use std::{
    fs::{
        self,
        File,
    },
    io::{
        self,
        Write,
    },
    path::{
        Path,
        PathBuf,
    },
    time::Duration,
};

use gix_lock::acquire::Fail;
use mahi_core::ThreadId;
use mahi_store::Store;
use thiserror::Error;

use crate::VerifiedMeta;

const PIN_BYTES: usize = 8 + 32;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// The newest meta document accepted for each thread, kept outside git so a push cannot move it.
///
/// Each thread's pin is its highest accepted generation and that document's body hash, stored
/// under `mahi/pins/` in the repository's common git directory.
#[derive(Debug, Clone)]
pub(crate) struct Pins {
    dir: PathBuf,
    boundary: PathBuf,
}

/// Checking or advancing a pin failed.
#[derive(Debug, Error)]
pub enum PinError {
    /// The document is older than one already accepted.
    #[error("meta generation {found} is older than the accepted generation {pinned}")]
    Rollback {
        /// The highest accepted generation.
        pinned: u64,
        /// The generation offered.
        found: u64,
    },
    /// A different document has the same generation as one already accepted.
    #[error("a different meta document has the accepted generation {generation}")]
    Equivocation {
        /// The generation both documents claim.
        generation: u64,
    },
    /// The document is older than the generation the caller requires.
    #[error("meta generation {found} is older than the required generation {required}")]
    BelowMinimum {
        /// The lowest generation the caller accepts.
        required: u64,
        /// The generation offered.
        found: u64,
    },
    /// The pin file exists but is not a pin.
    #[error("pin for thread {0} is corrupt")]
    Corrupt(ThreadId),
    /// Another process holds the pin's lock, or a crashed one left it behind.
    #[error("pin is locked; if no mahi process is running, delete {}", .lock.display())]
    Locked {
        /// The lock file.
        lock: PathBuf,
    },
    /// Reading or writing the pin failed.
    #[error("cannot read or write pin")]
    Io(#[from] io::Error),
}

impl Pins {
    pub(crate) fn new(store: &Store) -> Self {
        let boundary = store.common_dir().to_path_buf();
        Self {
            dir: boundary.join("mahi").join("pins"),
            boundary,
        }
    }

    /// Pins `meta` if it is new or newer, and refuses it if it is older or conflicts.
    ///
    /// If only the final directory sync fails, the pin has already moved and the error is
    /// still returned; accepting the same document again then succeeds.
    pub(crate) fn accept(&self, meta: &VerifiedMeta) -> Result<(), PinError> {
        self.accept_hash(meta.thread(), meta.generation(), meta.body_hash())
    }

    /// Checks `meta` as [`Pins::accept`] does and runs `then` under the pin's lock, moving the
    /// pin only once `then` succeeded, so a refused document or a failed `then` leaves the pin
    /// where it was.
    pub(crate) fn accept_then<E: From<PinError>>(
        &self,
        meta: &VerifiedMeta,
        then: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E> {
        self.accept_hash_then(meta.thread(), meta.generation(), meta.body_hash(), then)
    }

    /// Runs `remove_thread` and then removes `thread`'s pin, all under the pin's lock, but only
    /// while the pin is missing or still at generation 0.
    ///
    /// A pin past generation 0 means the thread has been used, so nothing is removed and
    /// [`PinError::Rollback`] is returned.
    pub(crate) fn forget_new<E: From<PinError>>(
        &self,
        thread: ThreadId,
        remove_thread: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E> {
        let path = self.path(thread);
        let lock = self.lock(&path)?;
        if let Some((pinned, _)) = read_pin(&path, thread)?
            && pinned != 0
        {
            return Err(PinError::Rollback { pinned, found: 0 }.into());
        }
        remove_thread()?;
        match fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(PinError::from(error).into());
            }
            _ => {}
        }
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(PinError::from)?;
        drop(lock);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn get(&self, thread: ThreadId) -> Result<Option<(u64, [u8; 32])>, PinError> {
        read_pin(&self.path(thread), thread)
    }

    fn path(&self, thread: ThreadId) -> PathBuf {
        self.dir.join(thread.to_string())
    }

    fn lock(&self, path: &Path) -> Result<gix_lock::File, PinError> {
        gix_lock::File::acquire_to_update_resource(
            path,
            Fail::AfterDurationWithBackoff(LOCK_TIMEOUT),
            Some(self.boundary.clone()),
        )
        .map_err(|error| {
            let lock = path.with_extension("lock");
            if lock.exists() {
                PinError::Locked { lock }
            } else {
                PinError::Io(io::Error::other(error.to_string()))
            }
        })
    }

    fn accept_hash(
        &self,
        thread: ThreadId,
        generation: u64,
        hash: [u8; 32],
    ) -> Result<(), PinError> {
        self.accept_hash_then(thread, generation, hash, || Ok::<(), PinError>(()))
    }

    fn accept_hash_then<E: From<PinError>>(
        &self,
        thread: ThreadId,
        generation: u64,
        hash: [u8; 32],
        then: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E> {
        let path = self.path(thread);
        let mut lock = self.lock(&path)?;

        if let Some((pinned, pinned_hash)) = read_pin(&path, thread)? {
            if generation < pinned {
                return Err(PinError::Rollback {
                    pinned,
                    found: generation,
                }
                .into());
            }
            if generation == pinned {
                return if hash == pinned_hash {
                    then()
                } else {
                    Err(PinError::Equivocation { generation }.into())
                };
            }
        }

        then()?;
        write_pin(&mut lock, generation, hash)?;
        lock.commit().map_err(|error| PinError::from(error.error))?;
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(PinError::from)?;
        Ok(())
    }
}

fn write_pin(lock: &mut gix_lock::File, generation: u64, hash: [u8; 32]) -> Result<(), PinError> {
    let mut pin = [0; PIN_BYTES];
    pin[..8].copy_from_slice(&generation.to_le_bytes());
    pin[8..].copy_from_slice(&hash);
    lock.write_all(&pin)?;
    lock.with_mut(|file| file.sync_all())?;
    Ok(())
}

fn read_pin(path: &Path, thread: ThreadId) -> Result<Option<(u64, [u8; 32])>, PinError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let pin =
        <[u8; PIN_BYTES]>::try_from(bytes.as_slice()).map_err(|_| PinError::Corrupt(thread))?;
    let (generation, hash) = pin
        .split_first_chunk::<8>()
        .ok_or(PinError::Corrupt(thread))?;
    let hash = <[u8; 32]>::try_from(hash).map_err(|_| PinError::Corrupt(thread))?;
    Ok(Some((u64::from_le_bytes(*generation), hash)))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn pins() -> (TempDir, Pins) {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let pins = Pins::new(&store);
        (dir, pins)
    }

    fn thread() -> ThreadId {
        ThreadId::random().unwrap()
    }

    fn no_lock_left(pins: &Pins, thread: ThreadId) -> bool {
        !pins.path(thread).with_extension("lock").exists()
    }

    #[test]
    fn a_pin_moves_only_after_what_it_guards_succeeded() {
        let (_dir, pins) = pins();
        let t = thread();
        pins.accept_hash(t, 1, [1; 32]).unwrap();
        let failed = pins.accept_hash_then(t, 2, [2; 32], || Err(PinError::Corrupt(t)));
        assert!(matches!(failed, Err(PinError::Corrupt(_))));
        assert_eq!(pins.get(t).unwrap(), Some((1, [1; 32])));
        let mut ran = false;
        let refused = pins.accept_hash_then(t, 0, [0; 32], || {
            ran = true;
            Ok::<(), PinError>(())
        });
        assert!(matches!(refused, Err(PinError::Rollback { .. })));
        assert!(!ran);
        pins.accept_hash_then(t, 2, [2; 32], || Ok::<(), PinError>(()))
            .unwrap();
        assert_eq!(pins.get(t).unwrap(), Some((2, [2; 32])));
    }

    #[test]
    fn the_first_document_is_pinned_and_newer_ones_advance_it() {
        let (_dir, pins) = pins();
        let t = thread();
        assert_eq!(pins.get(t).unwrap(), None);
        pins.accept_hash(t, 0, [1; 32]).unwrap();
        assert_eq!(pins.get(t).unwrap(), Some((0, [1; 32])));
        pins.accept_hash(t, 0, [1; 32]).unwrap();
        pins.accept_hash(t, 3, [3; 32]).unwrap();
        assert_eq!(pins.get(t).unwrap(), Some((3, [3; 32])));
        assert!(no_lock_left(&pins, t));
    }

    #[test]
    fn an_older_generation_is_refused_and_leaves_no_lock() {
        let (_dir, pins) = pins();
        let t = thread();
        pins.accept_hash(t, 2, [2; 32]).unwrap();
        assert!(matches!(
            pins.accept_hash(t, 1, [1; 32]),
            Err(PinError::Rollback {
                pinned: 2,
                found: 1
            })
        ));
        assert_eq!(pins.get(t).unwrap(), Some((2, [2; 32])));
        assert!(no_lock_left(&pins, t));
    }

    #[test]
    fn a_different_document_with_the_same_generation_is_refused() {
        let (_dir, pins) = pins();
        let t = thread();
        pins.accept_hash(t, 2, [2; 32]).unwrap();
        assert!(matches!(
            pins.accept_hash(t, 2, [9; 32]),
            Err(PinError::Equivocation { generation: 2 })
        ));
        assert_eq!(pins.get(t).unwrap(), Some((2, [2; 32])));
        assert!(no_lock_left(&pins, t));
    }

    #[test]
    fn pins_are_per_thread() {
        let (_dir, pins) = pins();
        let (a, b) = (thread(), thread());
        pins.accept_hash(a, 5, [5; 32]).unwrap();
        pins.accept_hash(b, 0, [0; 32]).unwrap();
        assert_eq!(pins.get(a).unwrap(), Some((5, [5; 32])));
        assert_eq!(pins.get(b).unwrap(), Some((0, [0; 32])));
    }

    #[test]
    fn a_damaged_pin_is_refused_not_ignored() {
        let (_dir, pins) = pins();
        let t = thread();
        pins.accept_hash(t, 1, [1; 32]).unwrap();
        fs::write(pins.path(t), b"short").unwrap();
        assert!(matches!(pins.get(t), Err(PinError::Corrupt(_))));
        assert!(matches!(
            pins.accept_hash(t, 9, [9; 32]),
            Err(PinError::Corrupt(_))
        ));
    }

    #[test]
    fn a_stale_lock_is_reported_with_its_path() {
        let (_dir, pins) = pins();
        let t = thread();
        pins.accept_hash(t, 0, [0; 32]).unwrap();
        let lock = pins.path(t).with_extension("lock");
        fs::write(&lock, b"").unwrap();
        match pins.accept_hash(t, 1, [1; 32]) {
            Err(PinError::Locked { lock: reported }) => assert_eq!(reported, lock),
            other => panic!("{other:?}"),
        }
        assert_eq!(pins.get(t).unwrap(), Some((0, [0; 32])));
    }

    #[test]
    fn an_unwritable_pin_directory_is_an_io_error_not_a_lock() {
        let (dir, pins) = pins();
        fs::write(dir.path().join(".git/mahi"), b"not a directory").unwrap();
        assert!(matches!(
            pins.accept_hash(thread(), 0, [0; 32]),
            Err(PinError::Io(_))
        ));
    }

    #[test]
    fn concurrent_accepts_never_move_the_pin_backwards() {
        let (_dir, pins) = pins();
        let t = thread();
        std::thread::scope(|scope| {
            for worker in 0..8u8 {
                let pins = pins.clone();
                scope.spawn(move || {
                    let mut last = 0;
                    for generation in 0..30u64 {
                        let hash = [u8::try_from(generation).unwrap(); 32];
                        match pins.accept_hash(t, generation, hash) {
                            Ok(()) | Err(PinError::Rollback { .. }) => {}
                            Err(other) => panic!("worker {worker}: {other:?}"),
                        }
                        let (pinned, _) = pins.get(t).unwrap().unwrap();
                        assert!(pinned >= last, "pin moved back from {last} to {pinned}");
                        last = pinned;
                    }
                });
            }
        });
        assert_eq!(pins.get(t).unwrap(), Some((29, [29; 32])));
    }
}
