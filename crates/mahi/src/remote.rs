use std::{
    env,
    fmt::{
        self,
        Write as _,
    },
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

use mahi_http::{
    HttpsRemote,
    RemoteError as HttpsUrlError,
};
use mahi_identity::{
    ConfigDir,
    Credential,
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
    Mode,
    OFlags,
};
use thiserror::Error;

use crate::{
    cli::RemoteCommand,
    profile,
    prompt::Prompt,
};

const SYNC: &str = "sync";
const REMOTE: &str = "remote";
const MAX_SETTING_BYTES: u64 = 512;
const HTTPS: &str = "https://";
const OFF: &str = "off\n";
const ORIGIN: &str = "origin";
const MAX_ASKS: usize = 3;

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

/// What the user chose for the clone: no pushing, or a remote.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Setting {
    Off,
    Remote(SyncRemote),
}

#[derive(Debug, Error)]
pub(crate) enum RemoteError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error("this repository has no remote called {0}")]
    NoSuchRemote(RemoteName),
    #[error("remote {name} is not an ssh remote, and mahi reaches remotes over ssh or https only")]
    NotSsh {
        name: RemoteName,
        #[source]
        source: UrlError,
    },
    #[error("remote {name} cannot be used over https")]
    NotHttps {
        name: RemoteName,
        #[source]
        source: HttpsUrlError,
    },
    #[error("cannot read or write the remote setting")]
    Io(#[from] io::Error),
    #[error("the remote setting in the git directory is not one mahi wrote")]
    Corrupt,
    #[error("cannot ask the user")]
    Prompt(#[source] io::Error),
    #[error("that is not a remote name")]
    InvalidName(#[source] RemoteNameError),
    #[error("cannot add the git remote {0}")]
    Add(RemoteName, #[source] Box<StoreError>),
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
            && !name.contains("..")
            && !name.as_bytes().ends_with(b".lock")
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
        turn_off(&store)?;
        return Ok("threads of this clone are no longer pushed\n".to_owned());
    }
    let chosen = match (&command.name, command.private, command.public) {
        (Some(name), true, _) => Some((name, Visibility::Private)),
        (Some(name), _, true) => Some((name, Visibility::Public)),
        _ => None,
    };
    if let Some((name, visibility)) = chosen {
        let url = push_url(&store, name)?;
        let setting = SyncRemote {
            name: name.clone(),
            visibility,
        };
        save(&store, &setting)?;
        return Ok(describe(&setting, &url));
    }
    Ok(match setting(&store)? {
        Some(Setting::Remote(setting)) => describe(&setting, &push_url(&store, &setting.name)?),
        Some(Setting::Off) => "threads of this clone are not pushed (turned off); choose a \
                               remote with mahi remote <name> --private or --public\n"
            .to_owned(),
        None => "threads of this clone are not pushed; choose a remote with \
                 mahi remote <name> --private or --public\n"
            .to_owned(),
    })
}

/// Offers `origin` as the remote to push threads to, on the terminal `open` gives, when the
/// clone has chosen none, was never asked, and `origin` is a remote mahi can push to. An empty
/// answer is no, so a remote's visibility is never guessed.
pub(crate) fn offer_origin<P: Prompt>(
    store: &Store,
    config: &ConfigDir,
    open: impl FnOnce() -> io::Result<P>,
) -> Result<(), RemoteError> {
    let origin = RemoteName(ORIGIN.to_owned());
    let Ok(url) = push_url(store, &origin) else {
        return Ok(());
    };
    let Ok(mut prompt) = open() else {
        return Ok(());
    };
    if setting(store)?.is_some() {
        return Ok(());
    }
    let say = |prompt: &mut P, line: &str| prompt.say(line).map_err(RemoteError::Prompt);
    say(
        &mut prompt,
        &format!(
            "Push this clone's threads to origin ({url}), so teammates and your other machines \
             can pick them up? The agents' snapshots go only to a private remote."
        ),
    )?;
    if let RemoteUrl::Https(https) = &url
        && let Some(name) = crate::sync::https_credential(https)
        && !matches!(Credential::load(config, &name), Ok(Some(_)))
    {
        say(
            &mut prompt,
            &format!(
                "Pushing over https uses the credential {name}: store it with mahi credential \
                 add {name}"
            ),
        )?;
    }
    for _ in 0..MAX_ASKS {
        let answer = prompt
            .pick(
                "[p]rivate, p[u]blic or [n]o: ",
                &[
                    ("p", "Private: push the agents' snapshots too"),
                    ("u", "Public: keep the snapshots here"),
                    ("n", "Don't push threads"),
                ],
            )
            .map_err(RemoteError::Prompt)?;
        let visibility = match answer.trim().to_ascii_lowercase().as_str() {
            "p" | "private" => Visibility::Private,
            "u" | "public" => Visibility::Public,
            "" | "n" | "no" => {
                turn_off(store)?;
                return say(
                    &mut prompt,
                    "threads of this clone are not pushed; mahi remote chooses a remote later",
                );
            }
            _ => continue,
        };
        save(
            store,
            &SyncRemote {
                name: origin,
                visibility,
            },
        )?;
        return say(
            &mut prompt,
            &format!("threads of this clone are pushed to origin, a {visibility} remote"),
        );
    }
    Ok(())
}

/// Chooses `name` as the remote the clone pushes its threads to, with `visibility`, as
/// `mahi remote <name> --private` or `--public` does, and returns what it now does.
pub(crate) fn choose(
    store: &Store,
    name: &RemoteName,
    visibility: Visibility,
) -> Result<String, RemoteError> {
    let url = push_url(store, name)?;
    let setting = SyncRemote {
        name: name.clone(),
        visibility,
    };
    save(store, &setting)?;
    Ok(describe(&setting, &url))
}

/// Adds the git remote `name` at `url` to the repository, once `url` reads as an SSH or
/// HTTPS remote mahi can push to.
pub(crate) fn add(store: &mut Store, name: &RemoteName, url: &str) -> Result<(), RemoteError> {
    parse_remote_url(name, url)?;
    store
        .add_remote(name.as_str(), url)
        .map_err(|error| RemoteError::Add(name.clone(), Box::new(error)))
}

/// Stops pushing the clone's threads, as `mahi remote --off` does.
pub(crate) fn stop_pushing(store: &Store) -> Result<(), RemoteError> {
    turn_off(store)
}

/// Where the clone pushes its threads, described for a header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Summary {
    text: String,
    chosen: bool,
}

impl Summary {
    /// Returns the description, such as `origin (private)`.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Returns whether a remote, or not pushing, was chosen.
    pub(crate) fn chosen(&self) -> bool {
        self.chosen
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

/// Returns a short description of where the clone pushes its threads, for a header.
pub(crate) fn summary(store: &Store) -> Summary {
    let (text, chosen) = match setting(store) {
        Ok(Some(Setting::Remote(remote))) => {
            (format!("{} ({})", remote.name, remote.visibility), true)
        }
        Ok(Some(Setting::Off)) => ("off".to_owned(), true),
        Ok(None) => ("none chosen".to_owned(), false),
        Err(_) => ("unreadable".to_owned(), false),
    };
    Summary { text, chosen }
}

/// Where a remote is reached: over SSH, or over HTTPS.
#[derive(Debug, Clone)]
pub(crate) enum RemoteUrl {
    Ssh(SshRemote),
    Https(HttpsRemote),
}

impl fmt::Display for RemoteUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssh(url) => url.fmt(formatter),
            Self::Https(url) => url.fmt(formatter),
        }
    }
}

fn describe(setting: &SyncRemote, url: &RemoteUrl) -> String {
    let snapshots = match setting.visibility {
        Visibility::Private => "with the agents' snapshots",
        Visibility::Public => "without the agents' snapshots, which stay here",
    };
    let mut text = format!(
        "threads of this clone are pushed to {} ({url}), a {} remote, {snapshots}\n",
        setting.name, setting.visibility
    );
    if let RemoteUrl::Https(url) = url {
        match crate::sync::https_credential(url) {
            Some(name) => {
                let _ = writeln!(
                    text,
                    "its token is the credential {name}: store it with mahi credential add {name}"
                );
            }
            None => {
                text.push_str(
                    "its host has no credential name, so it is reached without a token\n",
                );
            }
        }
    }
    text
}

/// Returns the URL the remote `name` pushes to.
pub(crate) fn push_url(store: &Store, name: &RemoteName) -> Result<RemoteUrl, RemoteError> {
    remote_url(name, store.remote_url(name.as_str(), true)?)
}

/// Returns the URL the remote `name` fetches from.
pub(crate) fn fetch_url(store: &Store, name: &RemoteName) -> Result<RemoteUrl, RemoteError> {
    remote_url(name, store.remote_url(name.as_str(), false)?)
}

fn remote_url(name: &RemoteName, url: Option<String>) -> Result<RemoteUrl, RemoteError> {
    let url = url.ok_or_else(|| RemoteError::NoSuchRemote(name.clone()))?;
    parse_remote_url(name, &url)
}

fn parse_remote_url(name: &RemoteName, url: &str) -> Result<RemoteUrl, RemoteError> {
    if url.starts_with(HTTPS) {
        return HttpsRemote::parse(url)
            .map(RemoteUrl::Https)
            .map_err(|source| RemoteError::NotHttps {
                name: name.clone(),
                source,
            });
    }
    SshRemote::parse(url)
        .map(RemoteUrl::Ssh)
        .map_err(|source| RemoteError::NotSsh {
            name: name.clone(),
            source,
        })
}

/// Returns the remote this clone pushes its threads to, if one was chosen.
pub(crate) fn sync_remote(store: &Store) -> Result<Option<SyncRemote>, RemoteError> {
    Ok(match setting(store)? {
        Some(Setting::Remote(remote)) => Some(remote),
        Some(Setting::Off) | None => None,
    })
}

fn setting(store: &Store) -> Result<Option<Setting>, RemoteError> {
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

fn parse_setting(text: &str) -> Option<Setting> {
    if text == OFF {
        return Some(Setting::Off);
    }
    let (visibility, name) = text.strip_suffix('\n')?.split_once(' ')?;
    let visibility = match visibility {
        "private" => Visibility::Private,
        "public" => Visibility::Public,
        _ => return None,
    };
    Some(Setting::Remote(SyncRemote {
        name: name.parse().ok()?,
        visibility,
    }))
}

fn save(store: &Store, setting: &SyncRemote) -> Result<(), RemoteError> {
    let text = format!("{} {}\n", setting.visibility, setting.name);
    profile::replace(&sync_dir(store)?, REMOTE, text.as_bytes())?;
    Ok(())
}

fn turn_off(store: &Store) -> Result<(), RemoteError> {
    profile::replace(&sync_dir(store)?, REMOTE, OFF.as_bytes())?;
    Ok(())
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
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::prompt::tests::Script;

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
    fn the_chosen_remote_is_kept_until_turned_off() {
        let (_dir, store) = store_with("");
        assert_eq!(sync_remote(&store).unwrap(), None);
        assert_eq!(setting(&store).unwrap(), None);
        let public = SyncRemote {
            name: name("origin"),
            visibility: Visibility::Public,
        };
        save(&store, &public).unwrap();
        assert_eq!(sync_remote(&store).unwrap(), Some(public));
        let private = SyncRemote {
            name: name("backup"),
            visibility: Visibility::Private,
        };
        save(&store, &private).unwrap();
        assert_eq!(sync_remote(&store).unwrap(), Some(private));
        turn_off(&store).unwrap();
        turn_off(&store).unwrap();
        assert_eq!(sync_remote(&store).unwrap(), None);
        assert_eq!(setting(&store).unwrap(), Some(Setting::Off));
        assert_eq!(
            fs::read_to_string(store.common_dir().join("mahi").join(SYNC).join(REMOTE)).unwrap(),
            "off\n"
        );
    }

    const ORIGIN_OVER_SSH: &str = "[remote \"origin\"]\n\turl = git@github.com:org/repo.git\n";

    fn config() -> (tempfile::TempDir, ConfigDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigDir::resolve(Some(dir.path()), Some(dir.path())).unwrap();
        (dir, config)
    }

    fn offered(store: &Store, answers: &[&'static str]) -> Script {
        let (_dir, config) = config();
        offered_with(store, &config, answers)
    }

    fn offered_with(store: &Store, config: &ConfigDir, answers: &[&'static str]) -> Script {
        let mut script = Script {
            answers: answers.iter().copied().collect(),
            ..Script::default()
        };
        offer_origin(store, config, || Ok(&mut script)).unwrap();
        assert!(script.answers.is_empty(), "{:?}", script.answers);
        script
    }

    #[test]
    fn a_remote_chosen_from_the_home_screen_is_kept_and_summarised() {
        let (_dir, store) = store_with(ORIGIN_OVER_SSH);
        assert_eq!(summary(&store).text(), "none chosen");
        assert!(!summary(&store).chosen());
        let told = choose(&store, &name("origin"), Visibility::Private).unwrap();
        assert!(told.contains("a private remote"), "{told}");
        assert_eq!(summary(&store).text(), "origin (private)");
        assert!(summary(&store).chosen());
        stop_pushing(&store).unwrap();
        assert_eq!(summary(&store).text(), "off");
        assert!(summary(&store).chosen());
        assert!(choose(&store, &name("missing"), Visibility::Public).is_err());
        assert_eq!(store.remote_names(), ["origin"]);
    }

    #[test]
    fn origin_is_offered_once_and_no_is_the_default() {
        let (_dir, store) = store_with(ORIGIN_OVER_SSH);
        let script = offered(&store, &[""]);
        assert!(script.said[0].contains("git@github.com:org/repo.git"));
        assert_eq!(setting(&store).unwrap(), Some(Setting::Off));
        offered(&store, &[]);
        assert_eq!(sync_remote(&store).unwrap(), None);
    }

    #[test]
    fn origin_is_taken_as_private_or_public_once_the_answer_is_clear() {
        let (_dir, store) = store_with(ORIGIN_OVER_SSH);
        let script = offered(&store, &["maybe", "u"]);
        assert_eq!(
            sync_remote(&store).unwrap(),
            Some(SyncRemote {
                name: name("origin"),
                visibility: Visibility::Public,
            })
        );
        assert!(
            script
                .said
                .iter()
                .any(|line| line.contains("a public remote"))
        );
        let (_dir, store) = store_with(ORIGIN_OVER_SSH);
        offered(&store, &["P"]);
        assert_eq!(
            sync_remote(&store).unwrap().map(|remote| remote.visibility),
            Some(Visibility::Private)
        );
        let (_dir, store) = store_with(ORIGIN_OVER_SSH);
        offered(&store, &["x", "y", "z"]);
        assert_eq!(setting(&store).unwrap(), None);
    }

    #[test]
    fn an_https_origin_is_offered_with_the_credential_it_needs() {
        let https = "[remote \"origin\"]\n\turl = https://git.example.org/r.git\n";
        let (_dir, store) = store_with(https);
        let named = |script: &Script| {
            script
                .said
                .iter()
                .any(|line| line.contains("mahi credential add https-git-example-org"))
        };
        assert!(named(&offered(&store, &["n"])));
        let (_dir, store) = store_with(https);
        let (_config_dir, config) = config();
        fs::create_dir_all(config.path()).unwrap();
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o700)).unwrap();
        Credential::new(b"t0ken".to_vec().into())
            .unwrap()
            .save(&config, &"https-git-example-org".parse().unwrap())
            .unwrap();
        let script = offered_with(&store, &config, &["u"]);
        assert!(!named(&script), "{:?}", script.said);
    }

    #[test]
    fn nothing_is_offered_without_a_usable_origin_a_terminal_or_after_a_choice() {
        for remotes in [
            "",
            "[remote \"origin\"]\n\turl = http://example.org/r.git\n",
        ] {
            let (_dir, store) = store_with(remotes);
            offered(&store, &[]);
            assert_eq!(setting(&store).unwrap(), None);
        }
        let (_dir, store) = store_with(ORIGIN_OVER_SSH);
        let (_config_dir, config) = config();
        let no_terminal =
            || -> io::Result<Script> { Err(io::Error::from(io::ErrorKind::NotFound)) };
        offer_origin(&store, &config, no_terminal).unwrap();
        assert_eq!(setting(&store).unwrap(), None);
        sync_dir(&store).unwrap();
        let file = store.common_dir().join("mahi").join(SYNC).join(REMOTE);
        fs::write(&file, "not mahi's\n").unwrap();
        offer_origin(&store, &config, no_terminal).unwrap();
        assert!(matches!(
            offer_origin(&store, &config, || Ok(Script::default())),
            Err(RemoteError::Corrupt)
        ));
        fs::remove_file(&file).unwrap();
        let backup = SyncRemote {
            name: name("backup"),
            visibility: Visibility::Private,
        };
        save(&store, &backup).unwrap();
        offered(&store, &[]);
        assert_eq!(sync_remote(&store).unwrap(), Some(backup));
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
        for text in ["off", "off \n", "OFF\n"] {
            assert_eq!(parse_setting(text), None, "{text:?}");
        }
        let (_dir, store) = store_with("");
        let sync = store.common_dir().join("mahi").join(SYNC);
        sync_dir(&store).unwrap();
        fs::create_dir(sync.join(REMOTE)).unwrap();
        assert!(matches!(sync_remote(&store), Err(RemoteError::Corrupt)));
    }

    #[test]
    fn only_an_existing_remote_with_an_ssh_or_https_push_url_is_taken() {
        let (_dir, store) = store_with(
            "[remote \"origin\"]\n\turl = git@github.com:org/repo.git\n\
             [remote \"web\"]\n\turl = https://user:secret@example.org/r.git\n\
             [remote \"forge\"]\n\turl = https://token@git.example.org/r.git\n\
             [remote \"plain\"]\n\turl = http://example.org/r.git\n\
             [remote \"home\"]\n\turl = ssh://me@[::1]:22/~/repo\n",
        );
        assert_eq!(
            push_url(&store, &name("origin")).unwrap().to_string(),
            "git@github.com:org/repo.git"
        );
        assert_eq!(
            push_url(&store, &name("home")).unwrap().to_string(),
            "me@[::1]:~/repo"
        );
        let forge = push_url(&store, &name("forge")).unwrap();
        assert!(matches!(forge, RemoteUrl::Https(_)));
        assert_eq!(forge.to_string(), "https://git.example.org/r.git");
        let refused = push_url(&store, &name("web")).unwrap_err();
        assert!(matches!(refused, RemoteError::NotHttps { .. }));
        assert!(!format!("{refused:?}").contains("secret"), "{refused:?}");
        assert!(matches!(
            push_url(&store, &name("plain")),
            Err(RemoteError::NotSsh { .. })
        ));
        assert!(matches!(
            push_url(&store, &name("missing")),
            Err(RemoteError::NoSuchRemote(_))
        ));
        let setting = SyncRemote {
            name: name("forge"),
            visibility: Visibility::Private,
        };
        let told = describe(&setting, &forge);
        assert!(
            told.contains("mahi credential add https-git-example-org"),
            "{told}"
        );
        assert!(!told.contains("token@"), "{told}");
        for bad in ["", "-o", ".x", "a/b", "git@host:x", "a..b", "x.lock"] {
            assert!(bad.parse::<RemoteName>().is_err(), "{bad}");
        }
    }
}
