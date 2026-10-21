use std::{
    fs,
    io::{
        self,
        Read,
    },
    path::{
        Path,
        PathBuf,
    },
};

use mahi_core::{
    ParticipantName,
    ThreadId,
};
use rustix::fs::FlockOperation;

const DIRECTORY: [&str; 2] = ["mahi", "roles"];
const MAX_ROLES_BYTES: u64 = 64 * 1024;
const CAN_PROMPT: &str = "can-prompt";
const READ_ONLY: &str = "read-only";

/// What a teammate the owner invited may do with the owner's agents in a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TeammateRole {
    /// Their prompts go to the owner's agents without the owner accepting each one.
    CanPrompt,
    /// They watch the owner's agents, and the owner's mahi takes no prompt from them.
    ReadOnly,
}

impl TeammateRole {
    fn word(self) -> &'static str {
        match self {
            Self::CanPrompt => CAN_PROMPT,
            Self::ReadOnly => READ_ONLY,
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        match word {
            CAN_PROMPT => Some(Self::CanPrompt),
            READ_ONLY => Some(Self::ReadOnly),
            _ => None,
        }
    }
}

/// The roles the owner gave the teammates of one thread, kept on the owner's machine in
/// the repository's git directory; a teammate without one is asked about, prompt by prompt.
#[derive(Debug, Clone)]
pub(crate) struct Roles {
    path: PathBuf,
    thread: ThreadId,
}

impl Roles {
    /// Returns the roles of `thread` in the repository whose common git directory is
    /// `git_dir`.
    pub(crate) fn of(git_dir: &Path, thread: ThreadId) -> Self {
        let mut path = git_dir.to_path_buf();
        path.extend(DIRECTORY);
        Self {
            path: path.join(thread.to_string()),
            thread,
        }
    }

    /// Returns the role of `teammate`, or `None` when they have none or the roles cannot be
    /// read.
    pub(crate) fn role(&self, teammate: &ParticipantName) -> Option<TeammateRole> {
        let text = self.read().ok()?;
        lines(&text)
            .find(|(name, _)| *name == teammate.as_str())
            .map(|(_, role)| role)
    }

    /// Gives `teammate` the role `role`, keeping the others' roles.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the roles from being read or written.
    pub(crate) fn set(&self, teammate: &ParticipantName, role: TeammateRole) -> io::Result<()> {
        let directory = self
            .path
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        fs::create_dir_all(directory)?;
        let _lock = self.lock()?;
        let text = match self.read() {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error),
        };
        let mut written = String::with_capacity(text.len() + 64);
        let kept = lines(&text)
            .filter(|(name, _)| *name != teammate.as_str() && ParticipantName::new(name).is_ok());
        for (name, role) in kept {
            push_line(&mut written, name, role);
        }
        push_line(&mut written, teammate.as_str(), role);
        let staged = directory.join(format!(".{}.mahi", self.thread));
        fs::write(&staged, written)?;
        fs::rename(&staged, &self.path)
    }

    /// Forgets every role of the thread.
    ///
    /// # Errors
    ///
    /// Returns the error that kept the roles from being removed, unless there were none.
    pub(crate) fn remove(&self) -> io::Result<()> {
        let _lock = match self.lock() {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        for path in [&self.path, &self.lock_path()] {
            match fs::remove_file(path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        Ok(())
    }

    fn lock_path(&self) -> PathBuf {
        self.path.with_file_name(format!(".{}.lock", self.thread))
    }

    /// Takes the lock that keeps the roles' writers apart, held until it is dropped.
    fn lock(&self) -> io::Result<fs::File> {
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.lock_path())?;
        rustix::fs::flock(&lock, FlockOperation::LockExclusive)?;
        Ok(lock)
    }

    fn read(&self) -> io::Result<String> {
        let mut text = String::new();
        fs::File::open(&self.path)?
            .take(MAX_ROLES_BYTES)
            .read_to_string(&mut text)?;
        Ok(text)
    }
}

fn lines(text: &str) -> impl Iterator<Item = (&str, TeammateRole)> {
    text.lines().filter_map(|line| {
        let (name, word) = line.split_once(' ')?;
        Some((name, TeammateRole::from_word(word)?))
    })
}

fn push_line(text: &mut String, name: &str, role: TeammateRole) {
    text.push_str(name);
    text.push(' ');
    text.push_str(role.word());
    text.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(name: &str) -> ParticipantName {
        ParticipantName::new(name).unwrap()
    }

    #[test]
    fn a_role_is_kept_per_teammate_replaced_and_forgotten_with_the_thread() {
        let dir = tempfile::tempdir().unwrap();
        let thread = ThreadId::random().unwrap();
        let roles = Roles::of(dir.path(), thread);
        let other = Roles::of(dir.path(), ThreadId::random().unwrap());
        assert_eq!(roles.role(&name("bob")), None);
        roles.set(&name("bob"), TeammateRole::CanPrompt).unwrap();
        roles.set(&name("carol"), TeammateRole::ReadOnly).unwrap();
        assert_eq!(roles.role(&name("bob")), Some(TeammateRole::CanPrompt));
        assert_eq!(roles.role(&name("carol")), Some(TeammateRole::ReadOnly));
        assert_eq!(other.role(&name("bob")), None);
        roles.set(&name("bob"), TeammateRole::ReadOnly).unwrap();
        assert_eq!(roles.role(&name("bob")), Some(TeammateRole::ReadOnly));
        assert_eq!(roles.role(&name("carol")), Some(TeammateRole::ReadOnly));
        roles.remove().unwrap();
        assert_eq!(roles.role(&name("carol")), None);
        roles.remove().unwrap();
    }

    #[test]
    fn roles_given_at_once_from_several_threads_are_all_kept() {
        let dir = tempfile::tempdir().unwrap();
        let roles = Roles::of(dir.path(), ThreadId::random().unwrap());
        let names: Vec<String> = (0..16).map(|index| format!("teammate{index}")).collect();
        std::thread::scope(|scope| {
            for teammate in &names {
                let roles = roles.clone();
                scope.spawn(move || {
                    roles.set(&name(teammate), TeammateRole::CanPrompt).unwrap();
                });
            }
        });
        for teammate in &names {
            assert_eq!(roles.role(&name(teammate)), Some(TeammateRole::CanPrompt));
        }
        roles.remove().unwrap();
        assert_eq!(
            fs::read_dir(roles.path.parent().unwrap()).unwrap().count(),
            0
        );
    }

    #[test]
    fn a_line_that_is_not_a_name_and_a_known_role_gives_no_role() {
        let dir = tempfile::tempdir().unwrap();
        let roles = Roles::of(dir.path(), ThreadId::random().unwrap());
        fs::create_dir_all(roles.path.parent().unwrap()).unwrap();
        fs::write(
            &roles.path,
            "bob owner\nBad can-prompt\ncarol  can-prompt\ndave read-only\n",
        )
        .unwrap();
        assert_eq!(roles.role(&name("bob")), None);
        assert_eq!(roles.role(&name("carol")), None);
        assert_eq!(roles.role(&name("dave")), Some(TeammateRole::ReadOnly));
        roles.set(&name("erin"), TeammateRole::CanPrompt).unwrap();
        assert_eq!(
            fs::read_to_string(&roles.path).unwrap(),
            "dave read-only\nerin can-prompt\n"
        );
    }
}
