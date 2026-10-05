use std::{
    fs,
    io::{
        self,
        Read,
    },
    path::PathBuf,
};

use mahi_core::ThreadId;
use mahi_store::{
    ObjectId,
    Store,
};

const DIRECTORY: [&str; 2] = ["mahi", "branches"];
const MAX_RECORD_BYTES: u64 = 4096;

/// What `mahi land --push` left on the remote for a thread: the thread branch, the commit it
/// pushed there and the landing branch it is meant for; and whether a later fetch found the
/// thread branch gone from the remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BranchRecord {
    pub(crate) remote: String,
    pub(crate) branch: String,
    pub(crate) tip: ObjectId,
    pub(crate) landing: String,
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
        let gone = lines.next() == Some("gone");
        let valid =
            |name: &str| !name.is_empty() && name.chars().all(|character| !character.is_control());
        (valid(&remote) && valid(&branch) && valid(&landing)).then_some(Self {
            remote,
            branch,
            tip,
            landing,
            gone,
        })
    }

    /// Writes this record for `thread`, replacing any earlier one whole.
    pub(crate) fn write(&self, store: &Store, thread: ThreadId) -> io::Result<()> {
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
        if self.gone {
            text.push_str("gone\n");
        }
        fs::write(&staged, text)?;
        fs::rename(&staged, target)
    }

    /// Removes `thread`'s record, if any.
    pub(crate) fn remove(store: &Store, thread: ThreadId) -> io::Result<()> {
        match fs::remove_file(path(store, thread)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
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
            gone: false,
        };
        record.write(&store, thread).unwrap();
        assert_eq!(BranchRecord::read(&store, thread), Some(record.clone()));
        record.gone = true;
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
    }
}
