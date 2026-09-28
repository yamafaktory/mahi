use std::{
    fmt,
    str::FromStr,
};

use thiserror::Error;

const LONGEST_NAME: usize = 253;
const LONGEST_LABEL: usize = 63;

/// A DNS host name the agent may reach: lowercase ASCII labels of letters, digits and inner
/// hyphens, at least two of them, and never an IP address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostName(String);

/// A text is not a host name mahi allows.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HostError {
    /// The name is empty, too long, has an empty or too long label, or a character outside
    /// letters, digits, hyphens and dots.
    #[error("{0:?} is not a host name")]
    Invalid(String),
    /// The name has a single label, such as `localhost`.
    #[error("{0:?} has no domain")]
    NoDomain(String),
    /// The name is an IP address; the allowlist holds names only.
    #[error("{0:?} is an IP address, not a host name")]
    Address(String),
}

impl FromStr for HostName {
    type Err = HostError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let name = text.to_ascii_lowercase();
        let invalid = || HostError::Invalid(text.to_owned());
        if name.is_empty() || name.len() > LONGEST_NAME {
            return Err(invalid());
        }
        let labels: Vec<&str> = name.split('.').collect();
        for label in &labels {
            let plain = !label.is_empty()
                && label.len() <= LONGEST_LABEL
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
            if !plain {
                return Err(invalid());
            }
        }
        if labels.len() < 2 {
            return Err(HostError::NoDomain(text.to_owned()));
        }
        let last_numeric = labels
            .last()
            .is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()));
        if last_numeric || labels.iter().all(|label| looks_numeric(label)) {
            return Err(HostError::Address(text.to_owned()));
        }
        Ok(Self(name))
    }
}

fn looks_numeric(label: &str) -> bool {
    let digits = label.strip_prefix("0x").unwrap_or(label);
    let hex = label.len() != digits.len();
    digits
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (hex && byte.is_ascii_hexdigit()))
}

impl HostName {
    /// Returns the name, in lowercase.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The host names an agent may reach, matched exactly. Empty, it allows nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist(Vec<HostName>);

impl Allowlist {
    /// Creates an allowlist of `hosts`.
    #[must_use]
    pub fn new(mut hosts: Vec<HostName>) -> Self {
        hosts.sort();
        hosts.dedup();
        Self(hosts)
    }

    /// Returns whether `host` is on the list.
    #[must_use]
    pub fn allows(&self, host: &HostName) -> bool {
        self.0.binary_search(host).is_ok()
    }

    /// Returns whether the list allows nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(text: &str) -> HostName {
        text.parse().unwrap()
    }

    #[test]
    fn names_are_lowercased_and_checked_label_by_label() {
        assert_eq!(host("API.Anthropic.com").as_str(), "api.anthropic.com");
        assert_eq!(host("a-b.x1.io").as_str(), "a-b.x1.io");
        let longest = format!("{}com", "abcdefghi.".repeat(25));
        assert_eq!(host(&longest).as_str().len(), LONGEST_NAME);
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}com", "abcdefghi.".repeat(26));
        for text in [
            "",
            ".",
            "a..com",
            "-a.com",
            "a-.com",
            "a_b.com",
            "a.com.",
            "*.a.com",
            "a.com:443",
            "é.com",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(
                matches!(text.parse::<HostName>(), Err(HostError::Invalid(_))),
                "{text:?}"
            );
        }
    }

    #[test]
    fn single_labels_and_addresses_are_refused() {
        assert!(matches!(
            "localhost".parse::<HostName>(),
            Err(HostError::NoDomain(_))
        ));
        for text in [
            "127.0.0.1",
            "10.0.0.1",
            "1.2.3.4",
            "0x7f.0x1",
            "127.0.0.0x1",
            "0x7f.1",
            "0177.0.0.1",
            "0x.0x",
        ] {
            assert!(
                matches!(text.parse::<HostName>(), Err(HostError::Address(_))),
                "{text}"
            );
        }
        assert!(matches!(
            "::1".parse::<HostName>(),
            Err(HostError::Invalid(_))
        ));
        assert!("0x7f.example".parse::<HostName>().is_ok());
        assert!("1password.com".parse::<HostName>().is_ok());
    }

    #[test]
    fn the_allowlist_matches_whole_names_only() {
        let list = Allowlist::new(vec![host("api.example.com"), host("API.example.com")]);
        assert!(list.allows(&host("api.example.com")));
        assert!(!list.allows(&host("example.com")));
        assert!(!list.allows(&host("evil.api.example.com")));
        assert!(Allowlist::default().is_empty());
    }
}
