//! Connects to an SSH server and an ssh-agent that run in the test.

#[cfg(test)]
mod tests {
    use std::{
        future::ready,
        io::{
            ErrorKind,
            Read,
            Write,
        },
        net::SocketAddr,
        path::{
            Path,
            PathBuf,
        },
        sync::{
            Arc,
            atomic::{
                AtomicUsize,
                Ordering,
            },
        },
        time::Duration,
    };

    use mahi_ssh::{
        Exec,
        KnownHosts,
        RemoteFailure,
        SshError,
        SshRemote,
        SshSession,
    };
    use russh::{
        Channel,
        ChannelId,
        Sig,
        keys::{
            Algorithm,
            PrivateKey,
            PublicKey,
            agent::{
                client::AgentClient,
                server::{
                    Agent,
                    serve,
                },
            },
            key::safe_rng,
        },
        server::{
            self,
            Auth,
            ChannelOpenHandle,
            Msg,
            Session,
        },
    };
    use tokio::{
        net::{
            TcpListener,
            UnixListener,
        },
        runtime::Runtime,
    };
    use tokio_stream::wrappers::UnixListenerStream;

    const RSA_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCon5LKy0wKilz4XciwFziIQp1K5se6f/fSH7d9re1rFspyRZiiUwgo51S35FCUUwaDULJEiBTb6VDNULuiPeYtAIBmRWyMvvQTchT2UNTSVYj5vOkuMpu/eBtkuzI6EtnVbqwhXeEAjIHn+dHpJNGB6o3d2uHolL+L48qCD4YQhQ==";

    #[derive(Clone)]
    struct TestAgent;

    impl Agent for TestAgent {}

    #[derive(Clone)]
    struct Server {
        accepted: PublicKey,
        logins: Arc<AtomicUsize>,
    }

    impl Server {
        fn exec(
            channel: ChannelId,
            command: &[u8],
            session: &mut Session,
        ) -> Result<(), russh::Error> {
            if command.starts_with(b"git-upload-pack ") {
                session.channel_success(channel)?;
                session.data(channel, [b"ran ", command, b"\n"].concat())
            } else if command.starts_with(b"git-receive-pack ") {
                session.data(channel, b"early\n".to_vec())?;
                session.channel_success(channel)
            } else if command == b"hang" {
                Ok(())
            } else if command == b"fail" {
                session.channel_success(channel)?;
                session.extended_data(
                    channel,
                    1,
                    b"fatal: no such\x1b[2J repository\n".to_vec(),
                )?;
                session.exit_status_request(channel, 128)?;
                Self::close(channel, session)
            } else if command == b"signal" {
                session.channel_success(channel)?;
                session.exit_signal_request(
                    channel,
                    Sig::KILL,
                    false,
                    "out of \u{202e}memory",
                    "",
                )?;
                Self::close(channel, session)
            } else if command == b"cut" {
                session.channel_success(channel)?;
                session.data(channel, b"partial".to_vec())?;
                session.disconnect(russh::Disconnect::ByApplication, "", "")
            } else if command == b"exit 3" {
                session.channel_success(channel)?;
                session.exit_status_request(channel, 3)?;
                Self::close(channel, session)
            } else {
                session.channel_failure(channel)
            }
        }

        fn finish(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
            session.exit_status_request(channel, 0)?;
            Self::close(channel, session)
        }

        fn close(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
            session.eof(channel)?;
            session.close(channel)
        }
    }

    impl server::Handler for Server {
        type Error = russh::Error;

        fn auth_publickey(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
            self.logins.fetch_add(1, Ordering::SeqCst);
            let accepted = user == "git" && key.key_data() == self.accepted.key_data();
            ready(Ok(if accepted {
                Auth::Accept
            } else {
                Auth::reject()
            }))
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        fn exec_request(
            &mut self,
            channel: ChannelId,
            command: &[u8],
            session: &mut Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Self::exec(channel, command, session))
        }

        fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(session.data(channel, data.to_vec()))
        }

        fn channel_eof(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Self::finish(channel, session))
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        runtime: Runtime,
        address: SocketAddr,
        host_key: PublicKey,
        agent: PathBuf,
        logins: Arc<AtomicUsize>,
    }

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap()
    }

    fn fixture(accepted: &PublicKey, in_agent: &PrivateKey) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let host = ed25519();
        let host_key = host.public_key().clone();
        let agent = dir.path().join("agent.sock");
        let accepted = accepted.clone();
        let logins = Arc::new(AtomicUsize::new(0));
        let counted = logins.clone();
        let address = runtime.block_on(async {
            let agent_listener = UnixListener::bind(&agent).unwrap();
            tokio::spawn(serve(UnixListenerStream::new(agent_listener), TestAgent));
            AgentClient::connect_uds(&agent)
                .await
                .unwrap()
                .add_identity(in_agent, &[])
                .await
                .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let config = Arc::new(server::Config {
                keys: vec![host],
                auth_rejection_time: Duration::ZERO,
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..server::Config::default()
            });
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let handler = Server {
                        accepted: accepted.clone(),
                        logins: counted.clone(),
                    };
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, socket, handler).await {
                            let _ = session.await;
                        }
                    });
                }
            });
            address
        });
        Fixture {
            _dir: dir,
            runtime,
            address,
            host_key,
            agent,
            logins,
        }
    }

    impl Fixture {
        fn remote(&self) -> SshRemote {
            SshRemote::parse(&format!("ssh://git@127.0.0.1:{}/repo", self.address.port())).unwrap()
        }

        fn known_hosts(&self, key: &PublicKey) -> KnownHosts {
            KnownHosts::parse(&format!(
                "[127.0.0.1]:{} {}\n",
                self.address.port(),
                key.to_openssh().unwrap()
            ))
        }

        fn exec(&self, session: &SshSession, command: &str) -> Result<Exec, SshError> {
            self.runtime.block_on(session.exec(command, &[]))
        }

        fn connect(&self, known_hosts: &KnownHosts, agent: &Path) -> Result<SshSession, SshError> {
            self.runtime.block_on(SshSession::connect(
                &self.remote(),
                known_hosts,
                agent,
                "nobody",
            ))
        }
    }

    #[test]
    fn a_command_runs_on_a_known_host_logged_in_with_an_agent_key() {
        let user = ed25519();
        let fixture = fixture(user.public_key(), &user);
        let session = fixture
            .connect(&fixture.known_hosts(&fixture.host_key), &fixture.agent)
            .unwrap();
        let command = fixture.remote().command(mahi_ssh::GitService::UploadPack);
        let (mut output, mut input) = fixture.exec(&session, &command).unwrap().split();
        input.write_all(b"want\n").unwrap();
        input.finish().unwrap();
        let mut said = String::new();
        output.read_to_string(&mut said).unwrap();
        assert_eq!(said, "ran git-upload-pack '/repo'\nwant\n");
        let refused = fixture.exec(&session, "rm -rf /");
        assert!(matches!(refused, Err(SshError::ExecRefused(command)) if command == "rm -rf /"));
        fixture.runtime.block_on(session.close()).unwrap();
    }

    #[test]
    fn output_sent_before_the_host_starts_the_command_is_kept_and_a_silent_host_times_out() {
        let user = ed25519();
        let fixture = fixture(user.public_key(), &user);
        let mut session = fixture
            .connect(&fixture.known_hosts(&fixture.host_key), &fixture.agent)
            .unwrap();
        let command = fixture.remote().command(mahi_ssh::GitService::ReceivePack);
        let (mut output, mut input) = fixture.exec(&session, &command).unwrap().split();
        let mut early = [0; 6];
        output.read_exact(&mut early).unwrap();
        input.write_all(b"then\n").unwrap();
        input.finish().unwrap();
        let mut rest = String::new();
        output.read_to_string(&mut rest).unwrap();
        assert_eq!((early, rest), (*b"early\n", "then\n".to_owned()));
        session.set_exec_timeout(Duration::from_millis(200));
        let silent = fixture.exec(&session, "hang");
        assert!(matches!(silent, Err(SshError::ExecTimeout(command)) if command == "hang"));
    }

    #[test]
    fn a_failed_command_reports_what_it_said_its_status_its_signal_or_a_cut_connection() {
        let user = ed25519();
        let fixture = fixture(user.public_key(), &user);
        let session = fixture
            .connect(&fixture.known_hosts(&fixture.host_key), &fixture.agent)
            .unwrap();
        let failure = |command| {
            let (mut output, _input) = fixture.exec(&session, command).unwrap().split();
            let error = output.read_to_end(&mut Vec::new()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Other);
            error
                .into_inner()
                .unwrap()
                .downcast::<RemoteFailure>()
                .map(|failure| *failure)
                .unwrap()
        };
        assert_eq!(
            failure("fail"),
            RemoteFailure::Said("fatal: no such?[2J repository".to_owned())
        );
        assert_eq!(failure("exit 3"), RemoteFailure::Status(3));
        assert_eq!(
            failure("signal"),
            RemoteFailure::Signal("KILL out of ?memory".to_owned())
        );
        assert_eq!(failure("cut"), RemoteFailure::Cut);
    }

    #[test]
    fn a_command_needs_a_multi_thread_runtime() {
        let user = ed25519();
        let fixture = fixture(user.public_key(), &user);
        let local = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let session = local
            .block_on(SshSession::connect(
                &fixture.remote(),
                &fixture.known_hosts(&fixture.host_key),
                &fixture.agent,
                "nobody",
            ))
            .unwrap();
        let refused = local.block_on(session.exec("git-upload-pack 'x'", &[]));
        assert!(
            matches!(refused, Err(SshError::CurrentThreadRuntime)),
            "{refused:?}"
        );
    }

    #[test]
    fn an_unknown_changed_revoked_or_unsupported_host_key_is_refused_before_logging_in() {
        let user = ed25519();
        let fixture = fixture(user.public_key(), &user);
        let unknown = fixture.connect(&KnownHosts::default(), &fixture.agent);
        let name = format!("[127.0.0.1]:{}", fixture.address.port());
        assert!(
            matches!(&unknown, Err(SshError::UnknownHostKey { host, .. }) if *host == name),
            "{unknown:?}"
        );
        assert_eq!(fixture.logins.load(Ordering::SeqCst), 0);
        let impostor = ed25519();
        let changed = fixture.connect(&fixture.known_hosts(impostor.public_key()), &fixture.agent);
        assert!(
            matches!(&changed, Err(SshError::ChangedHostKey { host, .. }) if *host == name),
            "{changed:?}"
        );
        let revoked = KnownHosts::parse(&format!(
            "{name} {key}\n@revoked * {key}\n",
            key = fixture.host_key.to_openssh().unwrap()
        ));
        let refused = fixture.connect(&revoked, &fixture.agent);
        assert!(
            matches!(&refused, Err(SshError::RevokedHostKey { host, .. }) if *host == name),
            "{refused:?}"
        );
        let rsa_only = KnownHosts::parse(&format!("{name} {RSA_KEY}\n"));
        let unsupported = fixture.connect(&rsa_only, &fixture.agent);
        assert!(
            matches!(&unsupported, Err(SshError::UnsupportedHostKey(host)) if *host == name),
            "{unsupported:?}"
        );
        assert_eq!(fixture.logins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_host_that_accepts_no_agent_key_is_reported() {
        let (user, stranger) = (ed25519(), ed25519());
        let fixture = fixture(user.public_key(), &stranger);
        let refused = fixture.connect(&fixture.known_hosts(&fixture.host_key), &fixture.agent);
        assert!(
            matches!(&refused, Err(SshError::NotAccepted { user, .. }) if user == "git"),
            "{refused:?}"
        );
        let missing = fixture.connect(
            &fixture.known_hosts(&fixture.host_key),
            &fixture.agent.with_file_name("missing.sock"),
        );
        assert!(matches!(missing, Err(SshError::Agent(_))), "{missing:?}");
    }
}
