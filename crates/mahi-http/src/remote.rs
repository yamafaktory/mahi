use std::fmt;

use gix::url::Scheme;
use thiserror::Error;

/// An HTTPS remote: its host, port and path, without credentials, which live in mahi's
/// credential store rather than in a URL. A user the URL names, which some write a token in,
/// is kept apart and never part of the URL gix sees or reports.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpsRemote {
    url: gix::Url,
    user: Option<String>,
}

/// Why a URL is not an HTTPS remote mahi can use.
///
/// The URL itself is never included, since it may hold a token.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteError {
    /// The URL does not parse.
    #[error("the remote's url is not valid")]
    Malformed,
    /// The URL is not `https://`; plain `http://` would send the token in the clear.
    #[error("the remote's url is not https")]
    NotHttps,
    /// The URL has no host.
    #[error("the remote's url has no host")]
    NoHost,
    /// The URL holds a password or token.
    #[error("the remote's url holds a password; store the token with mahi credential add")]
    PasswordInUrl,
}

impl HttpsRemote {
    /// Parses `url`, which must be `https://` with a host and no password.
    ///
    /// # Errors
    ///
    /// Returns a [`RemoteError`] saying why the URL cannot be used.
    pub fn parse(url: &str) -> Result<Self, RemoteError> {
        let mut url =
            gix::url::parse(gix::bstr::BStr::new(url)).map_err(|_| RemoteError::Malformed)?;
        if url.scheme != Scheme::Https {
            return Err(RemoteError::NotHttps);
        }
        if url.host().is_none_or(str::is_empty) {
            return Err(RemoteError::NoHost);
        }
        if url.password().is_some() {
            return Err(RemoteError::PasswordInUrl);
        }
        let user = url.set_user(None);
        Ok(Self { url, user })
    }

    /// Returns the remote's host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.url.host().unwrap_or_default()
    }

    /// Returns the port the URL names, if any.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.url.port
    }

    /// Returns the user name the URL names, if any.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    pub(crate) fn url(&self) -> &gix::Url {
        &self.url
    }
}

impl fmt::Display for HttpsRemote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url.to_bstring())
    }
}

impl fmt::Debug for HttpsRemote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsRemote")
            .field("host", &self.host())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_urls_with_a_host_and_no_password_are_remotes() {
        let remote = HttpsRemote::parse("https://git.example.com/team/app.git").unwrap();
        assert_eq!(remote.host(), "git.example.com");
        assert_eq!(remote.user(), None);
        let named = HttpsRemote::parse("https://bob@git.example.com:8443/app.git").unwrap();
        assert_eq!(named.user(), Some("bob"));
        assert_eq!(named.url().user(), None);
        assert!(!named.url().to_bstring().to_string().contains("bob"));
        assert_eq!(named.to_string(), "https://git.example.com:8443/app.git");
        for (url, error) in [
            ("http://git.example.com/app.git", RemoteError::NotHttps),
            ("git@git.example.com:app.git", RemoteError::NotHttps),
            (
                "https://bob:secret@git.example.com/app.git",
                RemoteError::PasswordInUrl,
            ),
            ("https:///app.git", RemoteError::Malformed),
        ] {
            assert_eq!(HttpsRemote::parse(url).err(), Some(error), "{url}");
        }
        assert!(!format!("{named:?}").contains("bob"));
    }
}
