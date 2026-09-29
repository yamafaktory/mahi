use std::fmt;

use thiserror::Error;

const DEFAULT_PORT: u16 = 22;
const MAX_PATH_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 255;

/// A git remote reached over SSH, parsed from its URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshRemote {
    user: Option<String>,
    host: String,
    port: u16,
    path: String,
}

/// Why a remote URL is not an SSH remote mahi can reach.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteError {
    /// The URL is not an SSH URL, such as an `https` URL or a local path.
    #[error("not an ssh remote")]
    NotSsh,
    /// The host is empty, starts with `-`, or holds characters a host name cannot hold.
    #[error("the remote's host is not a valid host name")]
    InvalidHost,
    /// The user name is empty, starts with `-`, or holds a space or a control character.
    #[error("the remote's user name is not valid")]
    InvalidUser,
    /// The port is not a number from 1 to 65535.
    #[error("the remote's port is not valid")]
    InvalidPort,
    /// The path is empty, too long, or holds a control character.
    #[error("the remote's path is not valid")]
    InvalidPath,
}

/// The git program run on the remote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitService {
    /// `git-upload-pack`, which serves fetches.
    UploadPack,
    /// `git-receive-pack`, which receives pushes.
    ReceivePack,
}

impl SshRemote {
    /// Parses `url` as `ssh://[user@]host[:port]/path` (also `git+ssh://` and `ssh+git://`)
    /// or as git's short form `[user@]host:path`.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::NotSsh`] for a URL of another kind, and another
    /// [`RemoteError`] for an SSH URL with a part that is not valid.
    pub fn parse(url: &str) -> Result<Self, RemoteError> {
        ["ssh://", "git+ssh://", "ssh+git://"]
            .iter()
            .find_map(|scheme| url.strip_prefix(scheme))
            .map_or_else(|| parse_short(url), parse_url)
    }

    /// Returns the user name the URL names, if any.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Returns the host, in lower case.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the repository's path on the host, as the remote program receives it.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the command that runs `service` on this remote's repository.
    #[must_use]
    pub fn command(&self, service: GitService) -> String {
        format!("{service} {}", shell_quote(&self.path))
    }
}

impl fmt::Display for GitService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        })
    }
}

fn parse_url(rest: &str) -> Result<SshRemote, RemoteError> {
    let (authority, path) = rest
        .find('/')
        .map_or((rest, ""), |slash| rest.split_at(slash));
    let (user, host_port) = split_user(authority)?;
    let (host, port) = match host_port.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed.split_once(']').ok_or(RemoteError::InvalidHost)?;
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':').ok_or(RemoteError::InvalidPort)?),
            };
            (check_ipv6(host)?, port)
        }
        None => match host_port.split_once(':') {
            Some((host, port)) => (check_host(host)?, Some(port)),
            None => (check_host(host_port)?, None),
        },
    };
    let port = match port {
        None | Some("") => DEFAULT_PORT,
        Some(port) => parse_port(port)?,
    };
    let path = match path.strip_prefix('/') {
        Some(home) if home.starts_with('~') => home,
        _ => path,
    };
    Ok(SshRemote {
        user,
        host,
        port,
        path: check_path(path)?,
    })
}

fn parse_short(url: &str) -> Result<SshRemote, RemoteError> {
    let (authority, path) = if let Some(bracketed) = url.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or(RemoteError::NotSsh)?;
        let path = after.strip_prefix(':').ok_or(RemoteError::NotSsh)?;
        return Ok(SshRemote {
            user: None,
            host: check_ipv6(host)?,
            port: DEFAULT_PORT,
            path: check_path(path)?,
        });
    } else {
        url.split_once(':').ok_or(RemoteError::NotSsh)?
    };
    if authority.contains('/') || authority.is_empty() || url.contains("://") {
        return Err(RemoteError::NotSsh);
    }
    let (user, host) = split_user(authority)?;
    Ok(SshRemote {
        user,
        host: check_host(host)?,
        port: DEFAULT_PORT,
        path: check_path(path)?,
    })
}

fn split_user(authority: &str) -> Result<(Option<String>, &str), RemoteError> {
    match authority.rsplit_once('@') {
        Some((user, host)) => Ok((Some(check_user(user)?), host)),
        None => Ok((None, authority)),
    }
}

fn check_user(user: &str) -> Result<String, RemoteError> {
    let valid = !user.is_empty()
        && user.len() <= MAX_NAME_BYTES
        && !user.starts_with('-')
        && !user.chars().any(|c| c.is_whitespace() || c.is_control());
    if valid {
        Ok(user.to_owned())
    } else {
        Err(RemoteError::InvalidUser)
    }
}

fn check_host(host: &str) -> Result<String, RemoteError> {
    let valid = !host.is_empty()
        && host.len() <= MAX_NAME_BYTES
        && !host.starts_with(['-', '.'])
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
    if valid {
        Ok(host.to_ascii_lowercase())
    } else {
        Err(RemoteError::InvalidHost)
    }
}

fn check_ipv6(host: &str) -> Result<String, RemoteError> {
    host.parse::<std::net::Ipv6Addr>()
        .map(|address| address.to_string())
        .map_err(|_| RemoteError::InvalidHost)
}

fn parse_port(port: &str) -> Result<u16, RemoteError> {
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RemoteError::InvalidPort);
    }
    match port.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(RemoteError::InvalidPort),
    }
}

fn check_path(path: &str) -> Result<String, RemoteError> {
    let valid = !path.is_empty()
        && !path.starts_with('-')
        && path.len() <= MAX_PATH_BYTES
        && !path.chars().any(char::is_control);
    if valid {
        Ok(path.to_owned())
    } else {
        Err(RemoteError::InvalidPath)
    }
}

fn shell_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('\'');
    for c in text.chars() {
        match c {
            '\'' => quoted.push_str("'\\''"),
            '!' => quoted.push_str("'\\!'"),
            c => quoted.push(c),
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(user: Option<&str>, host: &str, port: u16, path: &str) -> SshRemote {
        SshRemote {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        }
    }

    #[test]
    fn short_and_url_forms_parse_like_git() {
        let cases = [
            (
                "git@github.com:org/repo.git",
                remote(Some("git"), "github.com", 22, "org/repo.git"),
            ),
            ("GitHub.com:repo", remote(None, "github.com", 22, "repo")),
            (
                "ssh://git@example.org:2222/srv/repo.git",
                remote(Some("git"), "example.org", 2222, "/srv/repo.git"),
            ),
            (
                "git+ssh://example.org/~alice/repo",
                remote(None, "example.org", 22, "~alice/repo"),
            ),
            (
                "ssh+git://me@[::1]:22/repo",
                remote(Some("me"), "::1", 22, "/repo"),
            ),
            ("[::1]:repo", remote(None, "::1", 22, "repo")),
            ("ssh://host:/repo", remote(None, "host", 22, "/repo")),
        ];
        for (url, expected) in cases {
            assert_eq!(SshRemote::parse(url), Ok(expected), "{url}");
        }
    }

    #[test]
    fn other_remotes_are_not_ssh() {
        for url in [
            "https://github.com/org/repo.git",
            "/srv/repo.git",
            "./repo:with-colon",
            "file:///srv/repo",
            "repo",
        ] {
            assert_eq!(SshRemote::parse(url), Err(RemoteError::NotSsh), "{url}");
        }
    }

    #[test]
    fn hostile_parts_are_refused() {
        let cases = [
            ("-oProxyCommand=x:repo", RemoteError::InvalidHost),
            ("ssh://-oProxyCommand=x/repo", RemoteError::InvalidHost),
            ("ssh://host name/repo", RemoteError::InvalidHost),
            ("ssh://[not-ip]/repo", RemoteError::InvalidHost),
            ("-l@host:repo", RemoteError::InvalidUser),
            ("@host:repo", RemoteError::InvalidUser),
            ("ssh://host:0/repo", RemoteError::InvalidPort),
            ("ssh://host:65536/repo", RemoteError::InvalidPort),
            ("ssh://host:+22/repo", RemoteError::InvalidPort),
            ("host:", RemoteError::InvalidPath),
            ("host:--upload-pack=touch /tmp/x", RemoteError::InvalidPath),
            ("ssh://host", RemoteError::InvalidPath),
            ("host:repo\nrm", RemoteError::InvalidPath),
        ];
        for (url, expected) in cases {
            assert_eq!(SshRemote::parse(url), Err(expected), "{url:?}");
        }
    }

    #[test]
    fn the_command_quotes_the_path_for_the_remote_shell() {
        let remote = SshRemote::parse("host:it's here!/$(rm -rf ~)").unwrap();
        assert_eq!(
            remote.command(GitService::UploadPack),
            "git-upload-pack 'it'\\''s here'\\!'/$(rm -rf ~)'"
        );
        assert_eq!(
            SshRemote::parse("ssh://host/srv/r.git")
                .unwrap()
                .command(GitService::ReceivePack),
            "git-receive-pack '/srv/r.git'"
        );
    }
}
