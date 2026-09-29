//! Fetches with gix through `SshTransport` from an SSH server in the test that runs the real
//! `git upload-pack`, so it needs `git` and runs with `just test-git`.

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        fmt::Write as _,
        future::ready,
        net::SocketAddr,
        path::{
            Path,
            PathBuf,
        },
        process::{
            Command,
            Stdio,
        },
        sync::{
            Arc,
            Mutex,
            atomic::AtomicBool,
        },
        time::Duration,
    };

    use mahi_ssh::{
        KnownHosts,
        SshRemote,
        SshTransport,
    };
    use russh::{
        Channel,
        ChannelId,
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
            Handle,
            Msg,
            Session,
        },
    };
    use tokio::{
        io::{
            AsyncReadExt,
            AsyncWriteExt,
        },
        net::{
            TcpListener,
            UnixListener,
        },
        process::{
            Child,
            ChildStdin,
        },
        runtime::Runtime,
    };
    use tokio_stream::wrappers::UnixListenerStream;

    #[derive(Clone)]
    struct TestAgent;

    impl Agent for TestAgent {}

    struct Server {
        accepted: PublicKey,
        protocols: Arc<Mutex<Vec<String>>>,
        protocol: Option<String>,
        inputs: HashMap<ChannelId, ChildStdin>,
    }

    impl server::Handler for Server {
        type Error = russh::Error;

        fn auth_publickey(
            &mut self,
            user: &str,
            key: &PublicKey,
        ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
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

        fn env_request(
            &mut self,
            _channel: ChannelId,
            name: &str,
            value: &str,
            _session: &mut Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            if name == "GIT_PROTOCOL" {
                self.protocol = Some(value.to_owned());
            }
            ready(Ok(()))
        }

        fn exec_request(
            &mut self,
            channel: ChannelId,
            command: &[u8],
            session: &mut Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(self.start(channel, command, session))
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            if let Some(input) = self.inputs.get_mut(&channel) {
                input.write_all(data).await.unwrap();
            }
            Ok(())
        }

        fn channel_eof(
            &mut self,
            channel: ChannelId,
            _session: &mut Session,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            self.inputs.remove(&channel);
            ready(Ok(()))
        }
    }

    impl Server {
        fn start(
            &mut self,
            channel: ChannelId,
            command: &[u8],
            session: &mut Session,
        ) -> Result<(), russh::Error> {
            let command = String::from_utf8(command.to_vec()).unwrap();
            let (service, quoted) = command.split_once(' ').unwrap();
            let service = service.strip_prefix("git-").unwrap();
            let path = quoted
                .strip_prefix('\'')
                .and_then(|path| path.strip_suffix('\''))
                .unwrap()
                .replace("'\\''", "'");
            let protocol = self.protocol.clone().unwrap_or_default();
            self.protocols.lock().unwrap().push(protocol.clone());
            let mut child = tokio::process::Command::new("git")
                .arg(service)
                .arg(path)
                .env("GIT_PROTOCOL", protocol)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("git is installed");
            self.inputs.insert(channel, child.stdin.take().unwrap());
            session.channel_success(channel)?;
            tokio::spawn(relay(child, session.handle(), channel));
            Ok(())
        }
    }

    async fn relay(mut child: Child, handle: Handle, channel: ChannelId) {
        let mut errors = child.stderr.take().unwrap();
        let errors = tokio::spawn(async move {
            let mut said = Vec::new();
            errors.read_to_end(&mut said).await.unwrap();
            said
        });
        let mut output = child.stdout.take().unwrap();
        let mut buffer = vec![0; 32 << 10];
        loop {
            let count = output.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            handle
                .data(channel, buffer[..count].to_vec())
                .await
                .unwrap();
        }
        let said = errors.await.unwrap();
        if !said.is_empty() {
            handle.extended_data(channel, 1, said).await.unwrap();
        }
        let status = child.wait().await.unwrap().code().unwrap_or(255);
        handle
            .exit_status_request(channel, u32::try_from(status).unwrap())
            .await
            .unwrap();
        handle.eof(channel).await.unwrap();
        handle.close(channel).await.unwrap();
    }

    struct Fixture {
        dir: tempfile::TempDir,
        _runtime: Runtime,
        address: SocketAddr,
        known_hosts: KnownHosts,
        agent: PathBuf,
        protocols: Arc<Mutex<Vec<String>>>,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let host = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        let user = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        let host_key = host.public_key().to_openssh().unwrap();
        let agent = dir.path().join("agent.sock");
        let protocols = Arc::new(Mutex::new(Vec::new()));
        let recorded = protocols.clone();
        let address = runtime.block_on(async {
            tokio::spawn(serve(
                UnixListenerStream::new(UnixListener::bind(&agent).unwrap()),
                TestAgent,
            ));
            AgentClient::connect_uds(&agent)
                .await
                .unwrap()
                .add_identity(&user, &[])
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
            let accepted = user.public_key().clone();
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let handler = Server {
                        accepted: accepted.clone(),
                        protocols: recorded.clone(),
                        protocol: None,
                        inputs: HashMap::new(),
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
        let known_hosts =
            KnownHosts::parse(&format!("[127.0.0.1]:{} {host_key}\n", address.port()));
        Fixture {
            dir,
            _runtime: runtime,
            address,
            known_hosts,
            agent,
            protocols,
        }
    }

    fn git(repository: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["-c", "user.name=test", "-c", "user.email=test@example.org"])
            .args(args)
            .output()
            .expect("git is installed");
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    impl Fixture {
        fn source(&self) -> (PathBuf, String) {
            let source = self.dir.path().join("source");
            std::fs::create_dir(&source).unwrap();
            git(&source, &["init", "-q", "-b", "main"]);
            std::fs::write(source.join("README"), "hello\n").unwrap();
            git(&source, &["add", "README"]);
            git(&source, &["commit", "-q", "-m", "first"]);
            let head = git(&source, &["rev-parse", "HEAD"]);
            git(&source, &["update-ref", "refs/threads/t1/meta", &head]);
            (source, head)
        }

        fn fetch(&self, path: &Path) -> Result<gix::Repository, Box<dyn Error>> {
            let target = self.dir.path().join("target");
            let repository = gix::init_bare(&target)?;
            let url = format!(
                "ssh://git@127.0.0.1:{}{}",
                self.address.port(),
                path.display()
            );
            let transport = SshTransport::connect(
                SshRemote::parse(&url)?,
                &self.known_hosts,
                &self.agent,
                "nobody",
            )?;
            let remote = repository.remote_at(url.as_str())?.with_refspecs(
                [
                    "+refs/heads/*:refs/heads/*",
                    "+refs/threads/*:refs/threads/*",
                ],
                gix::remote::Direction::Fetch,
            )?;
            remote
                .to_connection_with_transport(transport)
                .prepare_fetch(
                    gix::progress::Discard,
                    gix::remote::ref_map::Options::default(),
                )?
                .receive(gix::progress::Discard, &AtomicBool::new(false))?;
            Ok(gix::open(&target)?)
        }
    }

    #[test]
    fn gix_fetches_heads_and_thread_refs_over_ssh_with_protocol_version_2() {
        let fixture = fixture();
        let (source, head) = fixture.source();
        let fetched = fixture.fetch(&source).unwrap();
        for name in ["refs/heads/main", "refs/threads/t1/meta"] {
            let reference = fetched.find_reference(name).unwrap();
            assert_eq!(reference.id().to_string(), head, "{name}");
        }
        let commit = fetched
            .find_object(gix::ObjectId::from_hex(head.as_bytes()).unwrap())
            .unwrap()
            .into_commit();
        let readme = commit.tree().unwrap().find_entry("README").unwrap().id();
        assert_eq!(&*fetched.find_object(readme).unwrap().data, b"hello\n");
        assert_eq!(*fixture.protocols.lock().unwrap(), ["version=2"]);
    }

    #[test]
    fn thread_refs_are_pushed_over_ssh_with_git_receive_pack() {
        let fixture = fixture();
        let remote = fixture.dir.path().join("remote.git");
        std::fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare"]);
        let local = fixture.dir.path().join("local");
        gix::init(&local).unwrap();
        let store = mahi_store::Store::open(&local).unwrap();
        let meta = mahi_core::ThreadRef::new(
            mahi_core::ThreadId::random().unwrap(),
            mahi_core::RefKind::Meta,
        );
        let blob = store.write_blob(b"meta").unwrap();
        let tree = store
            .write_tree(&[("meta", mahi_store::EntryKind::Blob, blob)])
            .unwrap();
        let commit = store.append(&meta, None, tree, "meta").unwrap();
        let url = format!(
            "ssh://git@127.0.0.1:{}{}",
            fixture.address.port(),
            remote.display()
        );
        let transport = SshTransport::connect(
            SshRemote::parse(&url).unwrap(),
            &fixture.known_hosts,
            &fixture.agent,
            "nobody",
        )
        .unwrap();
        let pushed = store
            .push_refs(
                transport,
                std::slice::from_ref(&meta),
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(pushed, [(meta.clone(), mahi_store::Pushed::Updated)]);
        assert_eq!(
            git(&remote, &["rev-parse", &meta.to_string()]),
            commit.to_string()
        );
        git(&remote, &["fsck", "--strict", "--no-dangling"]);
        assert_eq!(*fixture.protocols.lock().unwrap(), [""]);
    }

    #[test]
    fn a_missing_repository_reports_what_the_remote_said() {
        let fixture = fixture();
        let missing = fixture.dir.path().join("missing");
        let error = fixture.fetch(&missing).unwrap_err();
        let mut chain = String::new();
        let mut cause: Option<&dyn Error> = Some(&*error);
        while let Some(error) = cause {
            write!(chain, "{error}: ").unwrap();
            cause = error.source();
        }
        assert!(chain.contains("the remote said: "), "{chain}");
        assert!(chain.contains("missing"), "{chain}");
    }
}
