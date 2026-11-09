use std::{
    fmt::Write as _,
    fs,
    io::{
        self,
        Read,
    },
    path::PathBuf,
    sync::{
        Mutex,
        MutexGuard,
    },
};

use mahi_core::{
    ThreadId,
    is_invisible,
};
use mahi_store::{
    ObjectId,
    Store,
};

const DIRECTORY: [&str; 2] = ["mahi", "branches"];
const MAX_RECORD_BYTES: u64 = 4096;

/// What a landing left on the remote for a thread: the thread branch, the commit it pushed
/// there, the landing branch it is meant for and, when the `land` tool pushed it, the tree of
/// the owner's worktree it landed and the tree it measured its changed paths from; and whether
/// a later fetch found the thread branch gone from the remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BranchRecord {
    pub(crate) remote: String,
    pub(crate) branch: String,
    pub(crate) tip: ObjectId,
    pub(crate) landing: String,
    pub(crate) worktree: Option<ObjectId>,
    pub(crate) from: Option<ObjectId>,
    pub(crate) gone: bool,
}

impl BranchRecord {
    /// Reads `thread`'s record, or `None` when there is none or it cannot be read.
    pub(crate) fn read(store: &Store, thread: ThreadId) -> Option<Self> {
        let file = fs::File::open(path(store, thread)).ok()?;
        let mut text = String::new();
        file.take(MAX_RECORD_BYTES).read_to_string(&mut text).ok()?;
        let mut lines = text.lines();
        let remote = lines.next()?.strip_prefix("remote ")?.to_owned();
        let branch = lines.next()?.strip_prefix("branch ")?.to_owned();
        let tip = ObjectId::from_hex(lines.next()?.strip_prefix("tip ")?.as_bytes()).ok()?;
        let landing = lines.next()?.strip_prefix("landing ")?.to_owned();
        let mut next = lines.next();
        let worktree = match next.and_then(|line| line.strip_prefix("worktree ")) {
            Some(hex) => {
                next = lines.next();
                Some(ObjectId::from_hex(hex.as_bytes()).ok()?)
            }
            None => None,
        };
        let from = match next.and_then(|line| line.strip_prefix("from ")) {
            Some(hex) => {
                next = lines.next();
                Some(ObjectId::from_hex(hex.as_bytes()).ok()?)
            }
            None => None,
        };
        let gone = next == Some("gone");
        let valid =
            |name: &str| !name.is_empty() && name.chars().all(|character| !character.is_control());
        (valid(&remote) && valid(&branch) && valid(&landing)).then_some(Self {
            remote,
            branch,
            tip,
            landing,
            worktree,
            from,
            gone,
        })
    }

    /// Writes this record for `thread`, replacing any earlier one whole.
    pub(crate) fn write(&self, store: &Store, thread: ThreadId) -> io::Result<()> {
        let _held = locked()?;
        self.write_unlocked(store, thread)
    }

    /// Reads `thread`'s record, lets `change` change it, and writes it back when `change` says
    /// so, with no other write of a record in between; says whether it wrote.
    pub(crate) fn update(
        store: &Store,
        thread: ThreadId,
        change: impl FnOnce(&mut Self) -> bool,
    ) -> io::Result<bool> {
        let _held = locked()?;
        let Some(mut record) = Self::read(store, thread) else {
            return Ok(false);
        };
        if !change(&mut record) {
            return Ok(false);
        }
        record.write_unlocked(store, thread)?;
        Ok(true)
    }

    pub(crate) fn note_gone(&mut self, seen: &Self, gone: bool) -> bool {
        let same = self.tip == seen.tip && self.branch == seen.branch && self.gone != gone;
        if same {
            self.gone = gone;
        }
        same
    }

    fn write_unlocked(&self, store: &Store, thread: ThreadId) -> io::Result<()> {
        let target = path(store, thread);
        let directory = target
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        fs::create_dir_all(directory)?;
        let staged = directory.join(format!(".{thread}.mahi"));
        let mut text = format!(
            "remote {}\nbranch {}\ntip {}\nlanding {}\n",
            self.remote, self.branch, self.tip, self.landing
        );
        if let Some(worktree) = self.worktree {
            let _ = writeln!(text, "worktree {worktree}");
        }
        if let Some(from) = self.from {
            let _ = writeln!(text, "from {from}");
        }
        if self.gone {
            text.push_str("gone\n");
        }
        fs::write(&staged, text)?;
        fs::rename(&staged, target)
    }

    /// Returns `name`, a branch or remote name from a record, as it may be shown: without
    /// control or invisible characters, which git allows in branch names.
    pub(crate) fn shown(name: &str) -> String {
        name.chars()
            .filter(|character| !character.is_control() && !is_invisible(*character))
            .collect()
    }

    /// Removes `thread`'s record, if any.
    pub(crate) fn remove(store: &Store, thread: ThreadId) -> io::Result<()> {
        match fs::remove_file(path(store, thread)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

static WRITING: Mutex<()> = Mutex::new(());

fn locked() -> io::Result<MutexGuard<'static, ()>> {
    WRITING
        .lock()
        .map_err(|_| io::Error::other("the lock on branch records is poisoned"))
}

fn path(store: &Store, thread: ThreadId) -> PathBuf {
    let mut path = store.common_dir().to_path_buf();
    path.extend(DIRECTORY);
    path.join(thread.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_branch_is_noted_gone_or_back_only_on_the_record_that_was_checked() {
        let seen = BranchRecord {
            remote: "up".to_owned(),
            branch: "mahi/t".to_owned(),
            tip: ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap(),
            landing: "main".to_owned(),
            worktree: None,
            from: None,
            gone: false,
        };
        let mut now = seen.clone();
        assert!(now.note_gone(&seen, true));
        assert!(now.gone);
        assert!(!now.note_gone(&seen, true));
        assert!(now.note_gone(&seen, false));
        assert!(!now.gone);
        let mut landed = BranchRecord {
            tip: ObjectId::from_hex(b"89abcdef0123456789abcdef0123456789abcdef").unwrap(),
            ..seen.clone()
        };
        assert!(!landed.note_gone(&seen, true));
        assert!(!landed.gone);
        let mut renamed = BranchRecord {
            branch: "mahi/u".to_owned(),
            ..seen.clone()
        };
        assert!(!renamed.note_gone(&seen, true));
        assert!(!renamed.gone);
    }

    #[test]
    fn a_record_is_written_read_back_marked_gone_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread = ThreadId::random().unwrap();
        assert_eq!(BranchRecord::read(&store, thread), None);
        let mut record = BranchRecord {
            remote: "up".to_owned(),
            branch: format!("mahi/{thread}"),
            tip: ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap(),
            landing: "main".to_owned(),
            worktree: None,
            from: None,
            gone: false,
        };
        record.write(&store, thread).unwrap();
        assert_eq!(BranchRecord::read(&store, thread), Some(record.clone()));
        record.gone = true;
        record.write(&store, thread).unwrap();
        assert_eq!(BranchRecord::read(&store, thread), Some(record.clone()));
        record.worktree =
            Some(ObjectId::from_hex(b"89abcdef0123456789abcdef0123456789abcdef").unwrap());
        record.write(&store, thread).unwrap();
        assert_eq!(BranchRecord::read(&store, thread), Some(record.clone()));
        record.from =
            Some(ObjectId::from_hex(b"fedcba9876543210fedcba9876543210fedcba98").unwrap());
        record.write(&store, thread).unwrap();
        assert_eq!(BranchRecord::read(&store, thread), Some(record.clone()));
        record.gone = false;
        record.worktree = None;
        record.write(&store, thread).unwrap();
        assert_eq!(BranchRecord::read(&store, thread), Some(record));
        BranchRecord::remove(&store, thread).unwrap();
        BranchRecord::remove(&store, thread).unwrap();
        assert_eq!(BranchRecord::read(&store, thread), None);
        let path = path(&store, thread);
        fs::write(
            &path,
            "remote up\nbranch a\u{1b}[2J\ntip 0123456789abcdef0123456789abcdef01234567\nlanding main\n",
        )
        .unwrap();
        assert_eq!(BranchRecord::read(&store, thread), None);
        fs::write(
            &path,
            "remote up\nbranch mahi/a\u{202e}b\ntip 0123456789abcdef0123456789abcdef01234567\nlanding main\n",
        )
        .unwrap();
        let record = BranchRecord::read(&store, thread).unwrap();
        assert_eq!(record.branch, "mahi/a\u{202e}b");
        assert_eq!(BranchRecord::shown(&record.branch), "mahi/ab");
    }
}
