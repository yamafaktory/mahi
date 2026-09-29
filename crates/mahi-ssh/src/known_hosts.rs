use std::{
    fs::File,
    io::{
        self,
        Read,
    },
    path::Path,
};

use base64::{
    Engine,
    engine::general_purpose::STANDARD,
};
use hmac::{
    Hmac,
    Mac,
};
use russh::keys::{
    Algorithm,
    PublicKey,
};
use sha1::Sha1;
use thiserror::Error;

const MAX_FILE_BYTES: u64 = 16 << 20;
const HASH_BYTES: usize = 20;

/// The host keys the user trusts, read from OpenSSH's `known_hosts` files.
#[derive(Clone, Debug, Default)]
pub struct KnownHosts {
    entries: Vec<Entry>,
}

/// What `known_hosts` says about the key a host presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// The key is listed for the host.
    Known,
    /// The host is not listed with a key of this type.
    Unknown,
    /// The host is listed with another key of this type, so the key may be an attacker's.
    Changed,
    /// The key is marked `@revoked`.
    Revoked,
}

/// A `known_hosts` file that cannot be read.
#[derive(Debug, Error)]
pub enum KnownHostsError {
    /// Reading the file failed.
    #[error("cannot read {path}")]
    Read {
        /// The file.
        path: String,
        /// Why reading failed.
        #[source]
        source: io::Error,
    },
    /// The file is larger than mahi reads.
    #[error("{0} is larger than 16 MiB")]
    TooLarge(String),
}

#[derive(Clone, Debug)]
struct Entry {
    revoked: bool,
    hosts: Hosts,
    key: PublicKey,
}

#[derive(Clone, Debug)]
enum Hosts {
    Hashed {
        salt: Vec<u8>,
        hash: [u8; HASH_BYTES],
    },
    Patterns(Vec<String>),
}

impl KnownHosts {
    /// Reads the `known_hosts` files at `paths`, in order; a file that does not exist is
    /// skipped. This blocks, so async code calls it from a blocking thread.
    ///
    /// # Errors
    ///
    /// Returns [`KnownHostsError`] if a file exists but cannot be read or is too large.
    pub fn read(paths: &[&Path]) -> Result<Self, KnownHostsError> {
        let mut known = Self::default();
        for path in paths {
            let failed = |source| KnownHostsError::Read {
                path: path.display().to_string(),
                source,
            };
            let file = match File::open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(failed(error)),
            };
            let mut bytes = Vec::new();
            file.take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(failed)?;
            if bytes.len() as u64 > MAX_FILE_BYTES {
                return Err(KnownHostsError::TooLarge(path.display().to_string()));
            }
            known.add(&String::from_utf8_lossy(&bytes));
        }
        Ok(known)
    }

    /// Parses the lines of a `known_hosts` file; a line mahi cannot use, such as a key type it
    /// does not know or a `@cert-authority` line, is skipped.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut known = Self::default();
        known.add(text);
        known
    }

    fn add(&mut self, text: &str) {
        self.entries.extend(text.lines().filter_map(parse_line));
    }

    /// Returns what the files say about `key`, presented by `host` on `port`.
    #[must_use]
    pub fn check(&self, host: &str, port: u16, key: &PublicKey) -> HostKeyStatus {
        let name = host_name(host, port);
        let matching: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|entry| entry.hosts.matches(&name))
            .collect();
        let same = |entry: &&&Entry| entry.key.key_data() == key.key_data();
        if matching
            .iter()
            .filter(|entry| entry.revoked)
            .any(|e| same(&e))
        {
            HostKeyStatus::Revoked
        } else if matching.iter().any(|entry| !entry.revoked && same(&entry)) {
            HostKeyStatus::Known
        } else if matching
            .iter()
            .any(|entry| !entry.revoked && entry.key.algorithm() == key.algorithm())
        {
            HostKeyStatus::Changed
        } else {
            HostKeyStatus::Unknown
        }
    }

    /// Returns the types of the keys listed for `host` on `port`, without repeats, in the
    /// order they are listed.
    #[must_use]
    pub fn algorithms(&self, host: &str, port: u16) -> Vec<Algorithm> {
        let name = host_name(host, port);
        let mut algorithms = Vec::new();
        for entry in &self.entries {
            let algorithm = entry.key.algorithm();
            if !entry.revoked && entry.hosts.matches(&name) && !algorithms.contains(&algorithm) {
                algorithms.push(algorithm);
            }
        }
        algorithms
    }
}

impl Hosts {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Hashed { salt, hash } => Hmac::<Sha1>::new_from_slice(salt)
                .is_ok_and(|mac| mac.chain_update(name).verify_slice(hash).is_ok()),
            Self::Patterns(patterns) => {
                let mut matched = false;
                for pattern in patterns {
                    if let Some(negated) = pattern.strip_prefix('!') {
                        if wildcard_match(negated.as_bytes(), name.as_bytes()) {
                            return false;
                        }
                    } else if wildcard_match(pattern.as_bytes(), name.as_bytes()) {
                        matched = true;
                    }
                }
                matched
            }
        }
    }
}

fn host_name(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

fn parse_line(line: &str) -> Option<Entry> {
    let mut fields = line.split_ascii_whitespace();
    let mut first = fields.next()?;
    if first.starts_with('#') {
        return None;
    }
    let revoked = match first {
        "@revoked" => true,
        marker if marker.starts_with('@') => return None,
        _ => false,
    };
    if revoked {
        first = fields.next()?;
    }
    let hosts = parse_hosts(first)?;
    let algorithm = fields.next()?;
    let data = fields.next()?;
    let key = PublicKey::from_openssh(&format!("{algorithm} {data}")).ok()?;
    Some(Entry {
        revoked,
        hosts,
        key,
    })
}

fn parse_hosts(field: &str) -> Option<Hosts> {
    match field.strip_prefix("|1|") {
        Some(hashed) => {
            let (salt, hash) = hashed.split_once('|')?;
            Some(Hosts::Hashed {
                salt: STANDARD.decode(salt).ok()?,
                hash: STANDARD.decode(hash).ok()?.try_into().ok()?,
            })
        }
        None => Some(Hosts::Patterns(
            field.split(',').map(str::to_ascii_lowercase).collect(),
        )),
    }
}

fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut resume: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                resume = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || Some(&c) == text.get(t) => {
                p += 1;
                t += 1;
            }
            _ => match resume {
                Some((star, from)) => {
                    p = star + 1;
                    t = from + 1;
                    resume = Some((star, from + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|&c| c == b'*'))
}

#[cfg(test)]
mod tests {
    use russh::keys::{
        PrivateKey,
        key::safe_rng,
    };

    use super::*;

    fn ed25519() -> PublicKey {
        PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    fn line(hosts: &str, key: &PublicKey) -> String {
        format!("{hosts} {}\n", key.to_openssh().unwrap())
    }

    fn hashed(name: &str, salt: &[u8]) -> String {
        let hash = Hmac::<Sha1>::new_from_slice(salt)
            .unwrap()
            .chain_update(name)
            .finalize()
            .into_bytes();
        format!("|1|{}|{}", STANDARD.encode(salt), STANDARD.encode(hash))
    }

    #[test]
    fn a_listed_key_is_known_and_another_of_its_type_has_changed() {
        let (key, other) = (ed25519(), ed25519());
        let known = KnownHosts::parse(&line("github.com,gitlab.com", &key));
        assert_eq!(known.check("GitHub.com", 22, &key), HostKeyStatus::Known);
        assert_eq!(known.check("gitlab.com", 22, &key), HostKeyStatus::Known);
        assert_eq!(
            known.check("github.com", 22, &other),
            HostKeyStatus::Changed
        );
        assert_eq!(known.check("example.org", 22, &key), HostKeyStatus::Unknown);
    }

    #[test]
    fn a_host_listed_with_other_key_types_only_is_unknown() {
        let ecdsa = PrivateKey::random(
            &mut safe_rng(),
            Algorithm::Ecdsa {
                curve: russh::keys::EcdsaCurve::NistP256,
            },
        )
        .unwrap()
        .public_key()
        .clone();
        let key = ed25519();
        let known = KnownHosts::parse(&line("host", &ecdsa));
        assert_eq!(known.check("host", 22, &key), HostKeyStatus::Unknown);
        assert_eq!(known.algorithms("host", 22), vec![ecdsa.algorithm()]);
    }

    #[test]
    fn a_non_default_port_needs_its_bracketed_name() {
        let key = ed25519();
        let known = KnownHosts::parse(&line("[host]:2222", &key));
        assert_eq!(known.check("host", 2222, &key), HostKeyStatus::Known);
        assert_eq!(known.check("host", 22, &key), HostKeyStatus::Unknown);
        assert_eq!(known.check("host", 2223, &key), HostKeyStatus::Unknown);
    }

    #[test]
    fn hashed_names_match_only_their_host() {
        let key = ed25519();
        let text = line(&hashed("github.com", b"0123456789abcdefghij"), &key)
            + &line(&hashed("[other]:2200", b"salt"), &key);
        let known = KnownHosts::parse(&text);
        assert_eq!(known.check("github.com", 22, &key), HostKeyStatus::Known);
        assert_eq!(known.check("other", 2200, &key), HostKeyStatus::Known);
        assert_eq!(known.check("gitlab.com", 22, &key), HostKeyStatus::Unknown);
    }

    #[test]
    fn wildcards_match_and_a_negated_pattern_excludes_the_whole_line() {
        let key = ed25519();
        let known = KnownHosts::parse(&line("*.example.org,!evil.example.org,h?st", &key));
        assert_eq!(
            known.check("git.example.org", 22, &key),
            HostKeyStatus::Known
        );
        assert_eq!(known.check("host", 22, &key), HostKeyStatus::Known);
        assert_eq!(
            known.check("evil.example.org", 22, &key),
            HostKeyStatus::Unknown
        );
        assert_eq!(known.check("example.org", 22, &key), HostKeyStatus::Unknown);
        assert_eq!(known.check("hoost", 22, &key), HostKeyStatus::Unknown);
        assert!(wildcard_match(b"a*b*c", b"aXXbYbZc"));
        assert!(!wildcard_match(b"a*b*c", b"aXXbYbZ"));
        assert!(wildcard_match(b"**", b""));
    }

    #[test]
    fn a_revoked_key_is_refused_even_when_another_line_lists_it() {
        let key = ed25519();
        let text = line("host", &key) + &line("@revoked *", &key);
        let known = KnownHosts::parse(&text);
        assert_eq!(known.check("host", 22, &key), HostKeyStatus::Revoked);
        assert!(known.algorithms("other", 22).is_empty());
    }

    #[test]
    fn comments_certificate_authorities_and_broken_lines_are_skipped() {
        let (key, authority) = (ed25519(), ed25519());
        let text = "# a comment\n\n   \n".to_owned()
            + &line("@cert-authority *", &authority)
            + "host ssh-ed25519 not-base64\n"
            + "host unknown-type AAAA\n"
            + "|1|bad|hash "
            + &key.to_openssh().unwrap()
            + "\n\thost\t"
            + &key.to_openssh().unwrap()
            + " comment with spaces\n";
        let known = KnownHosts::parse(&text);
        assert_eq!(known.entries.len(), 1);
        assert_eq!(known.check("host", 22, &key), HostKeyStatus::Known);
        assert_eq!(known.check("host", 22, &authority), HostKeyStatus::Changed);
    }

    #[test]
    fn files_are_read_in_order_and_missing_ones_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let (first, second) = (ed25519(), ed25519());
        let user = dir.path().join("known_hosts");
        std::fs::write(&user, line("one", &first)).unwrap();
        let global = dir.path().join("ssh_known_hosts");
        std::fs::write(&global, line("two", &second)).unwrap();
        let missing = dir.path().join("missing");
        let known = KnownHosts::read(&[&user, &missing, &global]).unwrap();
        assert_eq!(known.check("one", 22, &first), HostKeyStatus::Known);
        assert_eq!(known.check("two", 22, &second), HostKeyStatus::Known);
        assert!(matches!(
            KnownHosts::read(&[dir.path()]),
            Err(KnownHostsError::Read { .. })
        ));
    }
}
