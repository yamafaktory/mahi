use std::{
    borrow::Cow,
    path::Path,
    sync::{
        Arc,
        atomic::AtomicBool,
    },
    time::Duration,
};

use russh::{
    ChannelMsg,
    Preferred,
    client::{
        self,
        Handle,
    },
    keys::{
        Algorithm,
        HashAlg,
        PublicKeyOrCertificate,
        agent::{
            AgentIdentity,
            client::AgentClient,
        },
    },
};
use thiserror::Error;
use tokio::runtime;

use crate::{
    exec::{
        Exec,
        until_interrupted,
    },
    known_hosts::{
        HostKeyStatus,
        KnownHosts,
    },
    remote::SshRemote,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_EARLY_OUTPUT: usize = 64 << 10;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 4;
const MAX_AGENT_KEYS: usize = 6;

/// An authenticated SSH connection to a git remote's host.
pub struct SshSession {
    handle: Handle<HostCheck>,
    exec_timeout: Duration,
    interrupt: Option<Arc<AtomicBool>>,
}

/// Why connecting to a remote, or running a command there, failed.
#[derive(Debug, Error)]
pub enum SshError {
    /// The host's key is not in `known_hosts`.
    #[error(
        "the {algorithm} host key of {host} ({fingerprint}) is not in known_hosts; check it and \
         add it, for example by connecting once with ssh"
    )]
    UnknownHostKey {
        /// The host, as `known_hosts` names it.
        host: String,
        /// The key's type.
        algorithm: String,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
    },
    /// The host presented a key other than the one `known_hosts` lists for it.
    #[error(
        "the {algorithm} host key of {host} changed to {fingerprint}, which may be an attack; \
         mahi does not connect"
    )]
    ChangedHostKey {
        /// The host, as `known_hosts` names it.
        host: String,
        /// The key's type.
        algorithm: String,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
    },
    /// The host presented a key marked `@revoked` in `known_hosts`.
    #[error("the host key of {host} ({fingerprint}) is revoked in known_hosts")]
    RevokedHostKey {
        /// The host, as `known_hosts` names it.
        host: String,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
    },
    /// `known_hosts` lists the host only with key types mahi does not support, such as `ssh-rsa`.
    #[error("known_hosts lists {0} only with key types mahi does not support, such as ssh-rsa")]
    UnsupportedHostKey(String),
    /// The host presented a certificate, which mahi does not accept.
    #[error("{0} presented a host certificate, which mahi does not accept")]
    HostCertificate(String),
    /// Reaching ssh-agent failed.
    #[error("cannot reach ssh-agent")]
    Agent(#[source] russh::keys::Error),
    /// ssh-agent holds no key the host accepted.
    #[error("the host accepted none of the keys in ssh-agent for {user}@{host}")]
    NotAccepted {
        /// The user mahi logged in as.
        user: String,
        /// The host.
        host: String,
    },
    /// Connecting and logging in took too long.
    #[error("connecting to {0} timed out")]
    Timeout(String),
    /// The host refused to run the command.
    #[error("the host refused to run {0}")]
    ExecRefused(String),
    /// The host did not answer whether it runs the command in time.
    #[error("the host did not start {0} in time")]
    ExecTimeout(String),
    /// The host sent more than 64 KiB before saying it runs the command.
    #[error("the host sent too much before starting {0}")]
    EarlyOutput(String),
    /// Commands need a multi-thread runtime, since their output and input block on it.
    #[error("ssh commands need a multi-thread runtime")]
    CurrentThreadRuntime,
    /// The async runtime the connection runs on cannot start.
    #[error("cannot start the ssh runtime")]
    Runtime(#[source] std::io::Error),
    /// The caller asked to stop.
    #[error("interrupted")]
    Interrupted,
    /// The SSH connection failed.
    #[error("the ssh connection failed")]
    Ssh(#[from] russh::Error),
}

impl std::fmt::Debug for SshSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SshSession").finish_non_exhaustive()
    }
}

impl SshSession {
    /// Connects to `remote`'s host, checks its key against `known_hosts`, and logs in as the
    /// remote's user, or else `default_user`, with the keys of the ssh-agent at `agent`. Once
    /// `interrupt` is set, connecting, and every command's reading and writing, stop within
    /// 100 ms.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] if the host cannot be reached, its key is not trusted, no key is
    /// accepted, this takes longer than 20 s, or `interrupt` is set.
    pub async fn connect(
        remote: &SshRemote,
        known_hosts: &KnownHosts,
        agent: &Path,
        default_user: &str,
        interrupt: Option<Arc<AtomicBool>>,
    ) -> Result<Self, SshError> {
        let user = remote.user().unwrap_or(default_user);
        let connecting =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, connect(remote, known_hosts, agent, user));
        let mut session = until_interrupted(interrupt.as_deref(), connecting)
            .await
            .ok_or(SshError::Interrupted)?
            .map_err(|_| SshError::Timeout(remote.host().to_owned()))??;
        session.interrupt = interrupt;
        Ok(session)
    }

    /// Sets how long [`SshSession::exec`] waits for the host to start a command; 20 s unless
    /// set.
    pub fn set_exec_timeout(&mut self, timeout: Duration) {
        self.exec_timeout = timeout;
    }

    /// Runs `command` on the host, asking it to set the environment variables `env` first; a
    /// host may ignore them.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] if the runtime is a current-thread one, the channel cannot be
    /// opened, the host refuses the command, or it does not start it within the exec timeout.
    pub async fn exec(&self, command: &str, env: &[(&str, &str)]) -> Result<Exec, SshError> {
        if runtime::Handle::current().runtime_flavor() == runtime::RuntimeFlavor::CurrentThread {
            return Err(SshError::CurrentThreadRuntime);
        }
        let starting = tokio::time::timeout(self.exec_timeout, self.start(command, env));
        until_interrupted(self.interrupt.as_deref(), starting)
            .await
            .ok_or(SshError::Interrupted)?
            .map_err(|_| SshError::ExecTimeout(command.to_owned()))?
    }

    async fn start(&self, command: &str, env: &[(&str, &str)]) -> Result<Exec, SshError> {
        let mut channel = self.handle.channel_open_session().await?;
        for (name, value) in env {
            channel.set_env(false, *name, *value).await?;
        }
        channel.exec(true, command).await?;
        let mut early = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) | None => {
                    return Err(SshError::ExecRefused(command.to_owned()));
                }
                Some(ChannelMsg::Data { data }) => {
                    if early.len() + data.len() > MAX_EARLY_OUTPUT {
                        return Err(SshError::EarlyOutput(command.to_owned()));
                    }
                    early.extend_from_slice(&data);
                }
                Some(_) => {}
            }
        }
        Ok(Exec::start(
            runtime::Handle::current(),
            channel,
            early,
            self.interrupt.clone(),
        ))
    }

    /// Closes the connection.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] if the goodbye cannot be sent.
    pub async fn close(self) -> Result<(), SshError> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await?;
        Ok(())
    }
}

async fn connect(
    remote: &SshRemote,
    known_hosts: &KnownHosts,
    agent: &Path,
    user: &str,
) -> Result<SshSession, SshError> {
    let known = known_hosts.algorithms(remote.host(), remote.port());
    let offered = offered_algorithms(&known)
        .ok_or_else(|| SshError::UnsupportedHostKey(host_name(remote.host(), remote.port())))?;
    let preferred = Preferred {
        key: Cow::Owned(offered),
        ..Preferred::default()
    };
    let config = Arc::new(client::Config {
        preferred,
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        nodelay: true,
        ..client::Config::default()
    });
    let check = HostCheck {
        host: remote.host().to_owned(),
        port: remote.port(),
        known_hosts: known_hosts.clone(),
    };
    let mut handle = client::connect(config, (remote.host(), remote.port()), check).await?;
    let mut agent = AgentClient::connect_uds(agent)
        .await
        .map_err(SshError::Agent)?;
    let identities = agent.request_identities().await.map_err(SshError::Agent)?;
    let keys = identities
        .into_iter()
        .filter_map(|identity| match identity {
            AgentIdentity::PublicKey { key, .. } => Some(key),
            AgentIdentity::Certificate { .. } => None,
        })
        .take(MAX_AGENT_KEYS);
    for key in keys {
        let hash = match key.algorithm() {
            Algorithm::Rsa { .. } => handle.best_supported_rsa_hash().await?.flatten(),
            _ => None,
        };
        match handle
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
        {
            Ok(result) if result.success() => {
                return Ok(SshSession {
                    handle,
                    exec_timeout: DEFAULT_EXEC_TIMEOUT,
                    interrupt: None,
                });
            }
            Ok(_) | Err(russh::AgentAuthError::Key(_)) => {}
            Err(russh::AgentAuthError::Send(_)) => break,
        }
    }
    Err(SshError::NotAccepted {
        user: user.to_owned(),
        host: remote.host().to_owned(),
    })
}

fn offered_algorithms(known: &[Algorithm]) -> Option<Vec<Algorithm>> {
    let supported: Vec<Algorithm> = Preferred::default()
        .key
        .iter()
        .filter(|algorithm| !matches!(algorithm, Algorithm::Rsa { .. }))
        .cloned()
        .collect();
    if known.is_empty() {
        return Some(supported);
    }
    let offered: Vec<Algorithm> = known
        .iter()
        .filter(|algorithm| supported.contains(algorithm))
        .cloned()
        .collect();
    (!offered.is_empty()).then_some(offered)
}

fn host_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

struct HostCheck {
    host: String,
    port: u16,
    known_hosts: KnownHosts,
}

impl HostCheck {
    fn name(&self) -> String {
        host_name(&self.host, self.port)
    }
}

impl HostCheck {
    fn verdict(&self, presented: &PublicKeyOrCertificate) -> Result<bool, SshError> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = presented else {
            return Err(SshError::HostCertificate(self.name()));
        };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let algorithm = key.algorithm().to_string();
        match self.known_hosts.check(&self.host, self.port, key) {
            HostKeyStatus::Known => Ok(true),
            HostKeyStatus::Unknown => Err(SshError::UnknownHostKey {
                host: self.name(),
                algorithm,
                fingerprint,
            }),
            HostKeyStatus::Changed => Err(SshError::ChangedHostKey {
                host: self.name(),
                algorithm,
                fingerprint,
            }),
            HostKeyStatus::Revoked => Err(SshError::RevokedHostKey {
                host: self.name(),
                fingerprint,
            }),
        }
    }
}

impl client::Handler for HostCheck {
    type Error = SshError;

    fn check_server_key(
        &mut self,
        presented: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        std::future::ready(self.verdict(presented))
    }
}

#[cfg(test)]
mod tests {
    use russh::keys::EcdsaCurve;

    use super::*;

    #[test]
    fn only_key_types_listed_for_the_host_are_offered_and_rsa_never() {
        let p256 = Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        };
        assert_eq!(
            offered_algorithms(&[p256.clone(), Algorithm::Ed25519]),
            Some(vec![p256, Algorithm::Ed25519])
        );
        let rsa = Algorithm::Rsa { hash: None };
        assert_eq!(offered_algorithms(std::slice::from_ref(&rsa)), None);
        assert_eq!(
            offered_algorithms(&[rsa, Algorithm::Ed25519]),
            Some(vec![Algorithm::Ed25519])
        );
        let unlisted = offered_algorithms(&[]).unwrap();
        assert!(unlisted.contains(&Algorithm::Ed25519));
        assert!(!unlisted.iter().any(|a| matches!(a, Algorithm::Rsa { .. })));
    }
}
