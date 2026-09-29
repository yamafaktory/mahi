use std::{
    any::Any,
    borrow::Cow,
    fmt,
    path::Path,
    sync::{
        Arc,
        atomic::AtomicBool,
    },
};

use gix::protocol::transport::{
    Protocol,
    Service,
    bstr::{
        BStr,
        BString,
    },
    client::{
        self,
        MessageKind,
        TransportWithoutIO,
        WriteMode,
        blocking_io::{
            RequestWriter,
            SetServiceResponse,
            Transport,
        },
        git::{
            ConnectMode,
            blocking_io::Connection,
        },
    },
};
use tokio::runtime::{
    Builder,
    Runtime,
};

use crate::{
    exec::{
        ExecInput,
        ExecOutput,
    },
    known_hosts::KnownHosts,
    remote::{
        GitService,
        SshRemote,
    },
    session::{
        SshError,
        SshSession,
    },
};

/// A git transport that runs `git-upload-pack` or `git-receive-pack` on an SSH remote, for
/// gix to fetch and push through.
///
/// It blocks and runs its own async runtime, so it is used, and dropped, on a thread that is
/// not running async code; doing so from async code panics.
pub struct SshTransport {
    connection: Option<Connection<ExecOutput, ExecInput>>,
    session: SshSession,
    runtime: Option<Runtime>,
    remote: SshRemote,
    url: String,
}

impl SshTransport {
    /// Connects to `remote` as [`SshSession::connect`] does, stopping reads and writes once
    /// `interrupt` is set.
    ///
    /// # Errors
    ///
    /// Returns [`SshError`] if the runtime cannot start or the connection fails.
    ///
    /// # Panics
    ///
    /// Panics if called from async code.
    pub fn connect(
        remote: SshRemote,
        known_hosts: &KnownHosts,
        agent: &Path,
        default_user: &str,
        interrupt: Option<Arc<AtomicBool>>,
    ) -> Result<Self, SshError> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(SshError::Runtime)?;
        let connected = runtime.block_on(SshSession::connect(
            &remote,
            known_hosts,
            agent,
            default_user,
            interrupt,
        ));
        let session = match connected {
            Ok(session) => session,
            Err(error) => {
                runtime.shutdown_background();
                return Err(error);
            }
        };
        let url = remote.to_string();
        Ok(Self {
            connection: None,
            session,
            runtime: Some(runtime),
            remote,
            url,
        })
    }
}

impl TransportWithoutIO for SshTransport {
    fn to_url(&self) -> Cow<'_, BStr> {
        Cow::Borrowed(self.url.as_str().into())
    }

    fn connection_persists_across_multiple_requests(&self) -> bool {
        true
    }

    fn configure(&mut self, _config: &dyn Any) -> gix::ExnResult {
        Ok(())
    }
}

impl Transport for SshTransport {
    fn handshake<'a>(
        &mut self,
        service: Service,
        extra_parameters: &'a [(&'a str, Option<&'a str>)],
    ) -> Result<SetServiceResponse<'_>, client::Error> {
        let (git_service, protocol, env): (_, _, &[(&str, &str)]) = match service {
            Service::UploadPack => (
                GitService::UploadPack,
                Protocol::V2,
                &[("GIT_PROTOCOL", "version=2")],
            ),
            Service::ReceivePack => (GitService::ReceivePack, Protocol::V1, &[]),
        };
        let command = self.remote.command(git_service);
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| client::Error::Io(std::io::Error::other(SshError::Interrupted)))?;
        let exec = runtime
            .block_on(self.session.exec(&command, env))
            .map_err(|error| client::Error::Io(std::io::Error::other(error)))?;
        let (output, input) = exec.split();
        let connection = self.connection.insert(Connection::new(
            output,
            input,
            protocol,
            BString::from(self.remote.path()),
            None::<(&str, Option<u16>)>,
            ConnectMode::Process,
            false,
        ));
        connection.handshake(service, extra_parameters)
    }

    fn request(
        &mut self,
        write_mode: WriteMode,
        on_into_read: MessageKind,
        trace: bool,
    ) -> Result<RequestWriter<'_>, client::Error> {
        self.connection
            .as_mut()
            .ok_or(client::Error::MissingHandshake)?
            .request(write_mode, on_into_read, trace)
    }
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        drop(self.connection.take());
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl fmt::Debug for SshTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshTransport")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}
