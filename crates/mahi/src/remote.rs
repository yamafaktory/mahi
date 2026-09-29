use std::{
    env,
    fmt,
    fs::{
        self,
        File,
    },
    io::{
        self,
        Read,
    },
    os::fd::OwnedFd,
    str::FromStr,
};

use mahi_ssh::{
    RemoteError as UrlError,
    SshRemote,
};
use mahi_store::{
    Store,
    StoreError,
};
use rustix::fs::{
    AtFlags,
    Mode,
    OFlags,
};
use thiserror::Error;

use crate::{
    cli::RemoteCommand,
    profile,
};

const SYNC: &str = "sync";
const REMOTE: &str = "remote";
const MAX_SETTING_BYTES: u64 = 512;

/// A git remote name, as `mahi remote` takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteName(String);

/// Whether a remote is private, or readable by anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Visibility {
    /// Only the project's members can read it: snapshots are pushed as they are.
    Private,
    /// Anyone may read it: snapshots, which are not encrypted, stay local.
    Public,
}

/// The remote this clone pushes its threads to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyncRemote {
    pub(crate) name: RemoteName,
    pub(crate) visibility: Visibility,
}

#[derive(Debug, Error)]
pub(crate) enum RemoteError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error("this repository has no remote called {0}")]
    NoSuchRemote(RemoteName),
    #[error("remote {name} is not an ssh remote, and mahi reaches remotes over ssh only")]
    NotSsh {
        name: RemoteName,
        #[source]
        source: UrlError,
    },
    #[error("cannot read or write the remote setting")]
    Io(#[from] io::Error),
    #[error("the remote setting in the git directory is not one mahi wrote")]
    Corrupt,
}

/// A remote name that holds characters git remote names do not, or starts with `-` or `.`.
#[derive(Debug, Error)]
#[error("{0:?} is not a remote name")]
pub(crate) struct RemoteNameError(String);

impl FromStr for RemoteName {
    type Err = RemoteNameError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let plain = !name.is_empty()
            && name.len() <= 100
            && !name.starts_with(['-', '.'])
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
        if plain {
            Ok(Self(name.to_owned()))
        } else {
            Err(RemoteNameError(name.to_owned()))
        }
    }
}

impl fmt::Display for RemoteName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl RemoteName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Visibility {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Private => "private",
            Self::Public => "public",
        })
    }
}

/// Shows, sets or clears the remote the clone around the current directory pushes its threads
/// to, and returns what to print.
pub(crate) fn remote(command: &RemoteCommand) -> Result<String, RemoteError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(RemoteError::CurrentDirectory)?;
    let store = Store::discover(&cwd)?;
    if command.off {
        clear(&store)?;
        return Ok("threads of this clone are no longer pushed\n".to_owned());
    }
    let chosen = match (&command.name, command.private, command.public) {
        (Some(name), true, _) => Some((name, Visibility::Private)),
        (Some(name), _, true) => Some((name, Visibility::Public)),
        _ => None,
    };
    if let Some((name, visibility)) = chosen {
        let url = ssh_push_url(&store, name)?;
        let setting = SyncRemote {
            name: name.clone(),
            visibility,
        };
        save(&store, &setting)?;
        return Ok(describe(&setting, &url));
    }
    Ok(match sync_remote(&store)? {
        Some(setting) => describe(&setting, &ssh_push_url(&store, &setting.name)?),
        None => "threads of this clone are not pushed; choose a remote with \
                 mahi remote <name> --private or --public\n"
            .to_owned(),
    })
}

fn describe(setting: &SyncRemote, url: &SshRemote) -> String {
    let snapshots = match setting.visibility {
        Visibility::Private => "with the agents' snapshots",
        Visibility::Public => "without the agents' snapshots, which stay here",
    };
    format!(
        "threads of this clone are pushed to {} ({url}), a {} remote, {snapshots}\n",
        setting.name, setting.visibility
    )
}

/// Returns the SSH URL the remote `name` pushes to.
pub(crate) fn ssh_push_url(store: &Store, name: &RemoteName) -> Result<SshRemote, RemoteError> {
    ssh_url(name, store.remote_url(name.as_str(), true)?)
}

/// Returns the SSH URL the remote `name` fetches from.
pub(crate) fn ssh_fetch_url(store: &Store, name: &RemoteName) -> Result<SshRemote, RemoteError> {
    ssh_url(name, store.remote_url(name.as_str(), false)?)
}

fn ssh_url(name: &RemoteName, url: Option<String>) -> Result<SshRemote, RemoteError> {
    let url = url.ok_or_else(|| RemoteError::NoSuchRemote(name.clone()))?;
    SshRemote::parse(&url).map_err(|source| RemoteError::NotSsh {
        name: name.clone(),
        source,
    })
}

/// Returns the remote this clone pushes its threads to, if one was chosen.
pub(crate) fn sync_remote(store: &Store) -> Result<Option<SyncRemote>, RemoteError> {
    let Some(directory) = existing_sync_dir(store)? else {
        return Ok(None);
    };
    let file = match rustix::fs::openat(
        &directory,
        REMOTE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io::Error::from(error).into()),
    };
    let stat = rustix::fs::fstat(&file).map_err(io::Error::from)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(RemoteError::Corrupt);
    }
    let mut text = String::new();
    File::from(file)
        .take(MAX_SETTING_BYTES)
        .read_to_string(&mut text)
        .map_err(|_| RemoteError::Corrupt)?;
    parse_setting(&text).map(Some).ok_or(RemoteError::Corrupt)
}

fn parse_setting(text: &str) -> Option<SyncRemote> {
    let (visibility, name) = text.strip_suffix('\n')?.split_once(' ')?;
    let visibility = match visibility {
        "private" => Visibility::Private,
        "public" => Visibility::Public,
        _ => return None,
    };
    Some(SyncRemote {
        name: name.parse().ok()?,
        visibility,
    })
}

fn save(store: &Store, setting: &SyncRemote) -> Result<(), RemoteError> {
    let text = format!("{} {}\n", setting.visibility, setting.name);
    profile::replace(&sync_dir(store)?, REMOTE, text.as_bytes())?;
    Ok(())
}

fn clear(store: &Store) -> Result<(), RemoteError> {
    let Some(directory) = existing_sync_dir(store)? else {
        return Ok(());
    };
    match rustix::fs::unlinkat(&directory, REMOTE, AtFlags::empty()) {
        Err(error) if error != rustix::io::Errno::NOENT => Err(io::Error::from(error).into()),
        _ => Ok(()),
    }
}

fn existing_sync_dir(store: &Store) -> io::Result<Option<OwnedFd>> {
    let path = store.common_dir().join("mahi").join(SYNC);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
        Ok(_) => sync_dir(store).map(Some),
    }
}

fn sync_dir(store: &Store) -> io::Result<OwnedFd> {
    let parent = store.common_dir().join("mahi");
    profile::create_private_dir(&parent)?;
    let parent = rustix::fs::open(
        &parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    profile::open_private_dir(&parent, SYNC)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the sync directory is not a private directory",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(remotes: &str) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let config = dir.path().join(".git").join("config");
        let mut text = fs::read_to_string(&config).unwrap();
        text.push_str(remotes);
        fs::write(&config, text).unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn name(text: &str) -> RemoteName {
        text.parse().unwrap()
    }

    #[test]
    fn the_chosen_remote_is_kept_until_cleared() {
        let (_dir, store) = store_with("");
        assert_eq!(sync_remote(&store).unwrap(), None);
        clear(&store).unwrap();
        assert!(!store.common_dir().join("mahi").exists());
        let setting = SyncRemote {
            name: name("origin"),
            visibility: Visibility::Public,
        };
        save(&store, &setting).unwrap();
        assert_eq!(sync_remote(&store).unwrap(), Some(setting));
        let private = SyncRemote {
            name: name("backup"),
            visibility: Visibility::Private,
        };
        save(&store, &private).unwrap();
        assert_eq!(sync_remote(&store).unwrap(), Some(private));
        clear(&store).unwrap();
        clear(&store).unwrap();
        assert_eq!(sync_remote(&store).unwrap(), None);
    }

    #[test]
    fn a_setting_mahi_did_not_write_is_refused() {
        for text in [
            "",
            "private origin",
            "secret origin\n",
            "private -x\n",
            "private a b\n",
        ] {
            assert_eq!(parse_setting(text), None, "{text:?}");
        }
        let (_dir, store) = store_with("");
        let sync = store.common_dir().join("mahi").join(SYNC);
        sync_dir(&store).unwrap();
        fs::create_dir(sync.join(REMOTE)).unwrap();
        assert!(matches!(sync_remote(&store), Err(RemoteError::Corrupt)));
    }

    #[test]
    fn only_an_existing_remote_with_an_ssh_push_url_is_taken() {
        let (_dir, store) = store_with(
            "[remote \"origin\"]\n\turl = git@github.com:org/repo.git\n\
             [remote \"web\"]\n\turl = https://user:secret@example.org/r.git\n\
             [remote \"home\"]\n\turl = ssh://me@[::1]:22/~/repo\n",
        );
        assert_eq!(
            ssh_push_url(&store, &name("origin")).unwrap().to_string(),
            "git@github.com:org/repo.git"
        );
        assert_eq!(
            ssh_push_url(&store, &name("home")).unwrap().to_string(),
            "me@[::1]:~/repo"
        );
        let refused = ssh_push_url(&store, &name("web")).unwrap_err();
        assert!(matches!(refused, RemoteError::NotSsh { .. }));
        assert!(!refused.to_string().contains("secret"), "{refused}");
        assert!(matches!(
            ssh_push_url(&store, &name("missing")),
            Err(RemoteError::NoSuchRemote(_))
        ));
        for bad in ["", "-o", ".x", "a/b", "git@host:x"] {
            assert!(bad.parse::<RemoteName>().is_err(), "{bad}");
        }
    }
}
