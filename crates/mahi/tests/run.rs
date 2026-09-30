//! Runs the `mahi` binary and checks what `mahi run` gives the agent.

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsStr,
        fs,
        io::{
            Read,
            Write,
        },
        net::{
            SocketAddr,
            TcpListener,
            TcpStream,
        },
        os::unix::{
            fs::PermissionsExt,
            net::UnixListener,
            process::ExitStatusExt,
        },
        path::{
            Path,
            PathBuf,
        },
        process::{
            Command,
            Output,
            Stdio,
        },
        sync::{
            Arc,
            Mutex,
            mpsc,
        },
        thread,
        time::{
            Duration,
            Instant,
        },
    };

    use age::secrecy::SecretString;
    use base64::{
        Engine,
        engine::general_purpose::STANDARD,
    };
    use gix::{
        ObjectId,
        date::Time,
        objs::{
            Commit,
            Tree,
            tree::{
                Entry,
                EntryKind,
            },
        },
    };
    use mahi_core::{
        AgentName,
        AgentSlot,
        ParticipantName,
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use mahi_identity::{
        ConfigDir,
        LocalIdentity,
        NodeKey,
        PublicIdentity,
        SigningKey,
    };
    use mahi_sandbox::{
        PtyChild,
        PtyCommand,
        WindowSize,
        exit_code,
    };
    use mahi_store::Store;
    use mahi_thread::{
        ParticipantKey,
        TurnRecord,
        load_meta,
        read_turns,
    };
    use rustix::termios::LocalModes;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        Signature,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    const SIGN_REQUEST: u8 = 13;
    const SIGN_RESPONSE: u8 = 14;
    const IDENTITIES_REQUEST: u8 = 11;
    const IDENTITIES_ANSWER: u8 = 12;

    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        home: PathBuf,
        repo: PathBuf,
        socket: PathBuf,
        base: ObjectId,
        identity: LocalIdentity,
        owner: ParticipantKey,
    }

    fn repository_on_main(repo: &Path) -> ObjectId {
        let repository = gix::init(repo).unwrap();
        fs::write(repo.join("README"), "hello from the repository\n").unwrap();
        let readme = repository
            .write_blob(b"hello from the repository\n")
            .unwrap()
            .detach();
        let tree = Tree {
            entries: vec![Entry {
                mode: EntryKind::Blob.into(),
                filename: "README".into(),
                oid: readme,
            }],
        };
        let tree = repository.write_object(&tree).unwrap().detach();
        let signature = gix::actor::Signature {
            name: "tester".into(),
            email: "tester@example.com".into(),
            time: Time::new(0, 0),
        };
        let commit = Commit {
            tree,
            parents: std::iter::empty().collect(),
            author: signature.clone(),
            committer: signature,
            encoding: None,
            message: "base".into(),
            extra_headers: Vec::new(),
        };
        let commit = repository.write_object(&commit).unwrap().detach();
        fs::create_dir_all(repo.join(".git/refs/heads")).unwrap();
        fs::write(repo.join(".git/refs/heads/main"), format!("{commit}\n")).unwrap();
        fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        commit
    }

    fn fixture() -> Fixture {
        fixture_with(None)
    }

    fn fixture_with(hold: Option<Hold>) -> Fixture {
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let repo = root.join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&home).unwrap();
        let base = repository_on_main(&repo);
        let socket = root.join("agent.sock");
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let identity = initialise(&home, &key);
        let owner = ParticipantKey::from_public_key(key.public_key()).unwrap();
        serve_signatures(&socket, key, hold);
        Fixture {
            _dir: dir,
            root,
            home,
            repo,
            socket,
            base,
            identity,
            owner,
        }
    }

    fn config_dir(home: &Path) -> ConfigDir {
        ConfigDir::resolve(Some(home), Some(&home.join(".config"))).unwrap()
    }

    fn initialise(home: &Path, key: &PrivateKey) -> LocalIdentity {
        let config = config_dir(home);
        fs::create_dir_all(config.path()).unwrap();
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = LocalIdentity::generate();
        PublicIdentity::from(&identity)
            .save(&config.recipient_file())
            .unwrap();
        SigningKey::try_from(key.public_key().clone())
            .unwrap()
            .save(&config.signing_key_file())
            .unwrap();
        NodeKey::generate()
            .unwrap()
            .save(&config.node_key_file())
            .unwrap();
        identity
    }

    fn take_string(bytes: &[u8]) -> (&[u8], &[u8]) {
        let (length, rest) = bytes.split_first_chunk::<4>().unwrap();
        rest.split_at(usize::try_from(u32::from_be_bytes(*length)).unwrap())
    }

    fn put_string(buffer: &mut Vec<u8>, bytes: &[u8]) {
        buffer.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        buffer.extend_from_slice(bytes);
    }

    struct Hold {
        asked: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    fn serve_signatures(socket: &Path, key: PrivateKey, hold: Option<Hold>) {
        let listener = UnixListener::bind(socket).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut length = [0_u8; 4];
                if stream.read_exact(&mut length).is_err() {
                    continue;
                }
                let mut request = vec![0_u8; usize::try_from(u32::from_be_bytes(length)).unwrap()];
                if stream.read_exact(&mut request).is_err() {
                    continue;
                }
                if request == [IDENTITIES_REQUEST] {
                    let mut body = vec![IDENTITIES_ANSWER, 0, 0, 0, 1];
                    put_string(&mut body, &key.public_key().to_bytes().unwrap());
                    put_string(&mut body, b"test");
                    let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
                    frame.extend_from_slice(&body);
                    let _ = stream.write_all(&frame);
                    continue;
                }
                let Some((&SIGN_REQUEST, rest)) = request.split_first() else {
                    continue;
                };
                if let Some(hold) = &hold {
                    let _ = hold.asked.send(());
                    let _ = hold.release.recv();
                }
                let (_, rest) = take_string(rest);
                let (data, _) = take_string(rest);
                let signature: Signature = signature::Signer::try_sign(&key, data).unwrap();
                let mut body = vec![SIGN_RESPONSE];
                put_string(&mut body, &Vec::<u8>::try_from(signature).unwrap());
                let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
                frame.extend_from_slice(&body);
                let _ = stream.write_all(&frame);
            }
        });
    }

    impl Fixture {
        fn command(&self, arguments: &[&str]) -> Command {
            let mut command = Command::new(env!("CARGO_BIN_EXE_mahi"));
            command
                .args(arguments)
                .current_dir(&self.repo)
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr")
                .env("HOME", &self.home)
                .env("XDG_CONFIG_HOME", self.home.join(".config"))
                .env("SSH_AUTH_SOCK", &self.socket)
                .env("USER", "tester")
                .env("MAHI_TEST_SECRET", "secret-value")
                .env("MAHI_LIVE", "off");
            command
        }

        fn worktrees_root(&self) -> PathBuf {
            self.home.join(".local/share/mahi/worktrees")
        }

        fn thread_worktrees(&self) -> Vec<PathBuf> {
            let Ok(repositories) = fs::read_dir(self.worktrees_root()) else {
                return Vec::new();
            };
            repositories
                .flat_map(|repository| fs::read_dir(repository.unwrap().path()).unwrap())
                .map(|worktree| worktree.unwrap().path())
                .collect()
        }

        fn mahi(&self, arguments: &[&str]) -> Output {
            self.command(arguments).output().unwrap()
        }

        fn threads(&self) -> Vec<String> {
            gix::open(&self.repo)
                .unwrap()
                .references()
                .unwrap()
                .prefixed("refs/threads/")
                .unwrap()
                .map(|reference| reference.unwrap().name().as_bstr().to_string())
                .collect()
        }
    }

    fn worktree_of(stderr: &str) -> PathBuf {
        let line = stderr
            .lines()
            .find(|line| line.starts_with("mahi: thread "))
            .unwrap_or_else(|| panic!("no thread line in {stderr}"));
        PathBuf::from(line.split(" in ").nth(1).unwrap())
    }

    #[test]
    fn run_starts_a_thread_and_the_agent_in_its_own_worktree() {
        let fixture = fixture();
        let output = fixture.mahi(&[
            "run",
            "--",
            "sh",
            "-c",
            "echo agent-ran; pwd; cat README; echo written > file; \
             echo home=$HOME; echo secret=$MAHI_TEST_SECRET; exit 3",
        ]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{stdout}{stderr}");
        let worktree = worktree_of(&stderr);
        assert!(
            worktree.starts_with(fixture.worktrees_root()),
            "{worktree:?}"
        );
        assert!(!worktree.starts_with(fixture.repo.join(".git")));
        assert!(stdout.contains("agent-ran"), "{stdout}");
        assert!(stdout.contains(&worktree.display().to_string()), "{stdout}");
        assert!(stdout.contains("hello from the repository"), "{stdout}");
        assert!(stdout.contains("home=/"), "{stdout}");
        assert!(!stdout.contains("secret-value"), "{stdout}");
        assert_eq!(
            fs::read_to_string(worktree.join("file")).unwrap(),
            "written\n"
        );
        assert!(!fixture.repo.join("file").exists());
        let thread = worktree.file_name().unwrap().to_string_lossy().into_owned();
        let snapshots = format!("refs/threads/{thread}/agents/tester.sh/snapshots");
        assert_eq!(
            fixture.threads(),
            [snapshots.clone(), format!("refs/threads/{thread}/meta")]
        );
        let repository = gix::open(&fixture.repo).unwrap();
        let last = repository
            .find_reference(snapshots.as_str())
            .unwrap()
            .peel_to_commit()
            .unwrap();
        let tree = last.tree().unwrap();
        let file = tree.find_entry("file").unwrap().object().unwrap();
        assert_eq!(file.data, b"written\n");
        assert!(tree.find_entry("README").is_some());
    }

    #[test]
    fn hook_events_from_inside_the_sandbox_become_encrypted_turns() {
        let fixture = fixture();
        let script = "printf 'fix it' | \"$MAHI_BIN\" hook prompt; \
                      echo edit > file; \
                      \"$MAHI_BIN\" hook tool < /dev/null; \
                      \"$MAHI_BIN\" hook turn-end < /dev/null; \
                      printf again | \"$MAHI_BIN\" hook prompt";
        let output = fixture.mahi(&["run", "sh", "-c", script]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{stderr}");
        let worktree = worktree_of(&stderr);
        let thread: ThreadId = worktree
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let store = Store::open(&fixture.repo).unwrap();
        let meta = load_meta(&store, thread, &fixture.owner, 0).unwrap();
        let tester = ParticipantName::new("tester").unwrap();
        let node = NodeKey::load(&config_dir(&fixture.home).node_key_file())
            .unwrap()
            .public();
        let owner = meta.participants().next().unwrap();
        assert_eq!(owner.node().as_bytes(), &node);
        let key = meta.thread_key(&tester, fixture.identity.as_age()).unwrap();
        let slot = AgentSlot::new(tester, AgentName::new("sh").unwrap());
        let turns = read_turns(&store, &key, thread, &slot, 10).unwrap();
        let texts = |turn: &TurnRecord| -> Vec<String> {
            turn.events()
                .iter()
                .map(|event| String::from_utf8_lossy(event.payload()).into_owned())
                .collect()
        };
        assert_eq!(turns.len(), 2, "{stderr}");
        assert_eq!(texts(&turns[0]), ["prompt\nfix it", "tool\n", "turn-end\n"]);
        assert_eq!(texts(&turns[1]), ["prompt\nagain"]);
    }

    #[test]
    fn a_named_variable_reaches_the_agent_and_a_missing_one_stops_mahi() {
        let fixture = fixture();
        let output = fixture
            .command(&[
                "run",
                "--pass-env",
                "MAHI_TEST_TOKEN",
                "sh",
                "-c",
                "echo token=$MAHI_TEST_TOKEN; echo secret=$MAHI_TEST_SECRET",
            ])
            .env("MAHI_TEST_TOKEN", "t0ken")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{stdout}");
        assert!(stdout.contains("token=t0ken"), "{stdout}");
        assert!(
            stdout.contains("secret=\r") || stdout.contains("secret=\n"),
            "{stdout}"
        );
        let threads = fixture.threads();
        assert_eq!(threads.len(), 2, "{threads:?}");

        let missing = fixture.mahi(&["run", "--pass-env", "MAHI_TEST_MISSING", "true"]);
        assert_eq!(missing.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("MAHI_TEST_MISSING is not set"));
        let reserved = fixture.mahi(&["run", "--pass-env", "HTTPS_PROXY", "true"]);
        assert_eq!(reserved.status.code(), Some(2));
        assert_eq!(fixture.threads(), threads);
    }

    #[test]
    fn the_agent_reaches_only_allowed_hosts_through_the_proxy() {
        let fixture = fixture();
        let host = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_port = host.local_addr().unwrap().port().to_string();
        let exe = std::env::current_exe().unwrap();
        let output = fixture
            .command(&[
                "run",
                "--allow-host",
                "allowed.invalid",
                "--pass-env",
                "MAHI_TEST_HOST_PORT",
                exe.to_str().unwrap(),
                "--exact",
                "tests::the_agent_reaches_only_allowed_hosts_through_the_proxy_inner",
                "--ignored",
                "--nocapture",
            ])
            .env("MAHI_TEST_HOST_PORT", &host_port)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
        assert!(stdout.contains("1 passed"), "{stdout}");
    }

    fn connect_through(proxy: &str, target: &str) -> String {
        let (credentials, address) = match proxy.split_once('@') {
            Some((credentials, address)) => (Some(credentials), address),
            None => (None, proxy),
        };
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let authorization = credentials.map_or_else(String::new, |credentials| {
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                STANDARD.encode(credentials)
            )
        });
        let request = format!("CONNECT {target} HTTP/1.1\r\n{authorization}\r\n");
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        let mut byte = [0_u8; 1];
        while !response.ends_with("\r\n") && stream.read(&mut byte).unwrap() == 1 {
            response.push(char::from(byte[0]));
        }
        response.trim_end().to_owned()
    }

    #[test]
    #[ignore = "run inside the sandbox by the_agent_reaches_only_allowed_hosts_through_the_proxy"]
    fn the_agent_reaches_only_allowed_hosts_through_the_proxy_inner() {
        let proxy = std::env::var("HTTPS_PROXY").expect("mahi sets the proxy");
        assert_eq!(std::env::var("https_proxy").unwrap(), proxy);
        let proxy = proxy.strip_prefix("http://").unwrap().to_owned();
        assert_eq!(
            connect_through(&proxy, "blocked.example.com:443"),
            "HTTP/1.1 403 Forbidden"
        );
        assert_eq!(
            connect_through(&proxy, "allowed.invalid:80"),
            "HTTP/1.1 403 Forbidden"
        );
        assert_eq!(
            connect_through(&proxy, "allowed.invalid:443"),
            "HTTP/1.1 502 Bad Gateway"
        );
        let host_port: u16 = std::env::var("MAHI_TEST_HOST_PORT")
            .unwrap()
            .parse()
            .unwrap();
        for direct in [
            SocketAddr::from(([127, 0, 0, 1], host_port)),
            SocketAddr::from(([1, 1, 1, 1], 443)),
        ] {
            assert!(
                TcpStream::connect_timeout(&direct, Duration::from_secs(3)).is_err(),
                "{direct}"
            );
        }
    }

    #[test]
    fn without_allowed_hosts_the_agent_has_no_proxy() {
        let fixture = fixture();
        let output = fixture.mahi(&[
            "run",
            "sh",
            "-c",
            "echo proxy=${HTTPS_PROXY:-none}${https_proxy:-none}",
        ]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{stdout}");
        assert!(stdout.contains("proxy=nonenone"), "{stdout}");
    }

    #[test]
    fn a_hook_outside_mahi_run_succeeds_and_does_nothing() {
        let fixture = fixture();
        let output = fixture
            .command(&["hook", "tool"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        let output = fixture
            .command(&["hook", "tool"])
            .env("MAHI_HOOK_SOCKET", fixture.root.join("nothing.sock"))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
    }

    const FAKE_CLAUDE: &str = r#"#!/bin/sh
echo args=$*
echo config=$CLAUDE_CONFIG_DIR
echo quiet=$CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC
echo updates=$DISABLE_AUTOUPDATER
echo connectors=$ENABLE_CLAUDEAI_MCP_SERVERS
echo token=${CLAUDE_CODE_OAUTH_TOKEN:-none}
echo apikey=${ANTHROPIC_API_KEY:-none}
echo proxy=${HTTPS_PROXY:-none}
grep -q 'hook turn-end' "$CLAUDE_CONFIG_DIR/settings.json" && echo hooks=ok
project="$CLAUDE_CONFIG_DIR/projects/$(pwd -P | sed 's/[^a-zA-Z0-9]/-/g')"
[ -f "$project/s.jsonl" ] && echo "session=$(tr '\n' '|' < "$project/s.jsonl")"
{ mkdir -p "$project" && echo "turn in $(basename "$(pwd -P)")" >> "$project/s.jsonl"; } 2>/dev/null
printf 'fix it' | "$MAHI_BIN" hook prompt
"$MAHI_BIN" hook tool < /dev/null
"$MAHI_BIN" hook turn-end < /dev/null
{ echo kept > "$CLAUDE_CONFIG_DIR/written" && echo state=writable; } 2>/dev/null || echo state=none
"#;

    fn fake_claude(fixture: &Fixture) -> PathBuf {
        let tools = fixture.root.join("tools");
        fs::create_dir_all(&tools).unwrap();
        let claude = tools.join("claude");
        fs::write(&claude, FAKE_CLAUDE).unwrap();
        fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).unwrap();
        claude
    }

    #[test]
    fn claude_gets_its_profile_hooks_state_and_subscription_token_only() {
        let fixture = fixture();
        let claude = fake_claude(&fixture);
        let output = fixture
            .command(&["run", claude.to_str().unwrap()])
            .env("CLAUDE_CODE_OAUTH_TOKEN", "subscription")
            .env("ANTHROPIC_API_KEY", "per-token")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
        assert!(stderr.contains("claude-code profile"), "{stderr}");
        let worktree = worktree_of(&stderr);
        let thread_name = worktree.file_name().unwrap().to_str().unwrap();
        let state = fixture
            .repo
            .join(".git/mahi/state")
            .join(thread_name)
            .join("tester.claude");
        let state = fs::canonicalize(state).unwrap();
        assert!(
            stdout.contains(&format!("config={}", state.display())),
            "{stdout}"
        );
        for expected in [
            "quiet=1",
            "updates=1",
            "connectors=false",
            "token=subscription",
            "apikey=none",
            "proxy=http://",
            "hooks=ok",
            "state=writable",
        ] {
            assert!(stdout.contains(expected), "{expected}: {stdout}");
        }
        assert_eq!(fs::read_to_string(state.join("written")).unwrap(), "kept\n");
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let overridden = fixture.mahi(&[
            "run",
            "--pass-env",
            "CLAUDE_CONFIG_DIR",
            claude.to_str().unwrap(),
        ]);
        assert_eq!(overridden.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&overridden.stderr).contains("set by the claude-code profile")
        );

        let thread: ThreadId = thread_name.parse().unwrap();
        let store = Store::open(&fixture.repo).unwrap();
        let meta = load_meta(&store, thread, &fixture.owner, 0).unwrap();
        let tester = ParticipantName::new("tester").unwrap();
        let key = meta.thread_key(&tester, fixture.identity.as_age()).unwrap();
        let slot = AgentSlot::new(tester, AgentName::new("claude").unwrap());
        let turns = read_turns(&store, &key, thread, &slot, 10).unwrap();
        assert_eq!(turns.len(), 1, "{stderr}");
        assert_eq!(turns[0].events().len(), 3);
    }

    #[test]
    fn no_profile_runs_claude_bare() {
        let fixture = fixture();
        let claude = fake_claude(&fixture);
        let output = fixture
            .command(&["run", "--no-profile", claude.to_str().unwrap()])
            .env("CLAUDE_CODE_OAUTH_TOKEN", "subscription")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
        assert!(!stderr.contains("profile"), "{stderr}");
        for expected in ["config=\r", "token=none", "proxy=none", "state=none"] {
            assert!(stdout.contains(expected), "{expected}: {stdout}");
        }
        assert!(!stdout.contains("hooks=ok"), "{stdout}");
    }

    #[test]
    fn threads_lists_each_thread_with_its_agents_and_worktree() {
        let fixture = fixture();
        let empty = fixture.mahi(&["threads"]);
        assert_eq!(empty.status.code(), Some(0));
        assert_eq!(
            String::from_utf8_lossy(&empty.stdout),
            "no threads in this repository\n"
        );
        let run = fixture.mahi(&["run", "true"]);
        let worktree = worktree_of(&String::from_utf8_lossy(&run.stderr));
        let thread = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        let listed = fixture.mahi(&["threads"]);
        assert_eq!(listed.status.code(), Some(0));
        assert_eq!(
            String::from_utf8_lossy(&listed.stdout),
            format!("{thread}  tester.true  worktree\n")
        );
        fs::remove_dir_all(&worktree).unwrap();
        let listed = fixture.mahi(&["threads"]);
        assert_eq!(
            String::from_utf8_lossy(&listed.stdout),
            format!("{thread}  tester.true  no worktree\n")
        );
    }

    const PASSPHRASE: &str = "correct horse battery";

    fn save_identity(fixture: &Fixture) {
        fixture
            .identity
            .save(
                &config_dir(&fixture.home).identity_file(),
                &SecretString::from(PASSPHRASE.to_owned()),
            )
            .unwrap();
    }

    fn in_terminal(
        fixture: &Fixture,
        arguments: &[&str],
        passphrase: Option<&str>,
    ) -> (i32, String) {
        let mut command = PtyCommand::new(
            Path::new(env!("CARGO_BIN_EXE_mahi")),
            &fixture.repo,
            WindowSize {
                rows: 24,
                cols: 200,
            },
        );
        for argument in arguments {
            command = command.arg(argument);
        }
        let command = command
            .env("PATH", "/usr/bin:/bin:/usr")
            .env("HOME", &fixture.home)
            .env("XDG_CONFIG_HOME", fixture.home.join(".config"))
            .env("SSH_AUTH_SOCK", &fixture.socket)
            .env("USER", "tester")
            .env("MAHI_LIVE", "off");
        in_terminal_with(command, passphrase)
    }

    fn in_terminal_with(command: PtyCommand, passphrase: Option<&str>) -> (i32, String) {
        let mut mahi = command.spawn().unwrap();
        let mut terminal = mahi.writer().unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&output);
        let mut reader = mahi.reader().unwrap();
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                collected.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        });
        if let Some(passphrase) = passphrase {
            wait_until("the passphrase question", || {
                String::from_utf8_lossy(&output.lock().unwrap()).contains("Passphrase")
            });
            terminal
                .write_all(format!("{passphrase}\n").as_bytes())
                .unwrap();
        }
        let mut status = None;
        let deadline = Instant::now() + Duration::from_secs(60);
        while status.is_none() {
            assert!(Instant::now() < deadline, "mahi did not finish");
            status = mahi.try_wait().unwrap();
            thread::sleep(Duration::from_millis(20));
        }
        thread::sleep(Duration::from_millis(100));
        let text = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
        (exit_code(status.unwrap()), text)
    }

    struct Session {
        mahi: mahi_sandbox::PtyChild,
        terminal: std::fs::File,
        output: Arc<Mutex<Vec<u8>>>,
        reader: thread::JoinHandle<()>,
    }

    impl Session {
        fn start(fixture: &Fixture, arguments: &[&str]) -> Self {
            Self::start_with(fixture, arguments, "off")
        }

        fn start_with(fixture: &Fixture, arguments: &[&str], live: &str) -> Self {
            let mut command = PtyCommand::new(
                Path::new(env!("CARGO_BIN_EXE_mahi")),
                &fixture.repo,
                WindowSize { rows: 24, cols: 80 },
            );
            for argument in arguments {
                command = command.arg(argument);
            }
            let mahi = command
                .env("PATH", "/usr/bin:/bin:/usr")
                .env("HOME", &fixture.home)
                .env("XDG_CONFIG_HOME", fixture.home.join(".config"))
                .env("SSH_AUTH_SOCK", &fixture.socket)
                .env("USER", "tester")
                .env("MAHI_LIVE", live)
                .spawn()
                .unwrap();
            let terminal = mahi.writer().unwrap();
            let output = Arc::new(Mutex::new(Vec::new()));
            let collected = Arc::clone(&output);
            let mut reader = mahi.reader().unwrap();
            let reader = thread::spawn(move || {
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = reader.read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                    collected.lock().unwrap().extend_from_slice(&buffer[..read]);
                }
            });
            Self {
                mahi,
                terminal,
                output,
                reader,
            }
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }

        fn screen(&self) -> String {
            let mut parser = vt100::Parser::new(24, 80, 0);
            parser.process(&self.output.lock().unwrap());
            parser.screen().contents()
        }

        fn wait_for(&self, text: &str) {
            wait_until(text, || self.text().contains(text));
        }

        fn wait_for_screen(&self, text: &str) {
            wait_until(text, || self.screen().contains(text));
        }

        fn type_keys(&mut self, keys: &[u8]) {
            self.terminal.write_all(keys).unwrap();
        }

        fn pause_between_keys() {
            thread::sleep(Duration::from_millis(300));
        }

        fn finish(mut self) -> (i32, String) {
            let deadline = Instant::now() + Duration::from_secs(60);
            let status = loop {
                if let Some(status) = self.mahi.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < deadline, "mahi did not finish");
                thread::sleep(Duration::from_millis(20));
            };
            wait_until("the end of mahi's output", || self.reader.is_finished());
            (exit_code(status), self.text())
        }
    }

    const ECHO_AGENT: [&str; 3] = [
        "sh",
        "-c",
        "printf 'ready\\n'; read line; echo \"got:$line\"",
    ];

    #[test]
    fn ctrl_space_opens_the_palette_over_the_agent_and_escape_gives_the_keys_back() {
        let fixture = fixture();
        let mut session = Session::start(&fixture, &[&["run"][..], &ECHO_AGENT].concat());
        session.wait_for("ready");
        assert!(session.text().contains("Ctrl-Space opens mahi's palette"));
        session.type_keys(b"\0");
        session.wait_for_screen("╭─ mahi");
        session.type_keys(b"abc");
        session.wait_for_screen("› abc");
        session.type_keys(b"\x1b");
        Session::pause_between_keys();
        session.type_keys(b"hello\r");
        let (code, text) = session.finish();
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("got:hello"), "{text}");
        assert!(!text.contains("got:abc"), "{text}");
    }

    #[test]
    fn output_held_while_the_palette_is_open_is_shown_when_the_agent_ends() {
        let fixture = fixture();
        let mut session = Session::start(
            &fixture,
            &[
                "run",
                "sh",
                "-c",
                "printf 'ready\\n'; sleep 1; printf 'late-output\\n'",
            ],
        );
        session.wait_for("ready");
        session.type_keys(b"\0");
        session.wait_for_screen("╭─ mahi");
        let (code, text) = session.finish();
        assert_eq!(code, 0, "{text}");
        let box_at = text.find('╭').unwrap();
        let late_at = text.find("late-output").expect(&text);
        assert!(late_at > box_at, "{text}");
    }

    #[test]
    fn palette_key_in_config_toml_changes_the_key_and_a_bad_one_stops_the_run() {
        let fixture = fixture();
        let settings = config_dir(&fixture.home).settings_file();
        std::fs::write(&settings, "palette-key = \"f5\"\n").unwrap();
        let mut session = Session::start(
            &fixture,
            &[
                "run",
                "sh",
                "-c",
                "printf 'ready\\n'; read first; read line; echo \"got:$line\"",
            ],
        );
        session.wait_for("ready");
        assert!(session.text().contains("F5 opens mahi's palette"));
        session.type_keys(b"\0\r");
        session.wait_for("^@");
        session.type_keys(b"\x1b[15~");
        session.wait_for_screen("╭─ mahi");
        session.type_keys(b"\x1b[15~");
        session.type_keys(b"x\r");
        let (code, text) = session.finish();
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("ready\r\n^@"), "{text:?}");
        assert!(text.contains("got:\x1b[15~x"), "{text:?}");

        std::fs::write(&settings, "palette-key = \"ctrl-m\"\n").unwrap();
        let output = fixture.mahi(&[&["run"][..], &ECHO_AGENT].concat());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_ne!(output.status.code(), Some(0), "{stderr}");
        assert!(stderr.contains("palette-key"), "{stderr}");
        assert!(stderr.contains("config.toml"), "{stderr}");
    }

    fn snapshot_head(fixture: &Fixture, thread: &str) -> gix::ObjectId {
        gix::open(&fixture.repo)
            .unwrap()
            .find_reference(format!("refs/threads/{thread}/agents/tester.sh/snapshots").as_str())
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .id
    }

    #[test]
    fn resume_reopens_the_worktree_and_continues_snapshots_and_turns() {
        let fixture = fixture();
        save_identity(&fixture);
        let first = fixture.mahi(&[
            "run",
            "sh",
            "-c",
            "echo one > notes; printf first | \"$MAHI_BIN\" hook prompt; \
             \"$MAHI_BIN\" hook turn-end < /dev/null",
        ]);
        let stderr = String::from_utf8_lossy(&first.stderr);
        assert_eq!(first.status.code(), Some(0), "{stderr}");
        let worktree = worktree_of(&stderr);
        let thread = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        let before = snapshot_head(&fixture, &thread);

        let (code, output) = in_terminal(
            &fixture,
            &[
                "resume",
                &thread,
                "--",
                "sh",
                "-c",
                "echo seen=$(cat notes); echo two >> notes; \
                 printf second | \"$MAHI_BIN\" hook prompt; pwd",
            ],
            Some(PASSPHRASE),
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("seen=one"), "{output}");
        assert!(output.contains(&worktree.display().to_string()), "{output}");
        assert_eq!(
            fs::read_to_string(worktree.join("notes")).unwrap(),
            "one\ntwo\n"
        );

        let repository = gix::open(&fixture.repo).unwrap();
        let after = snapshot_head(&fixture, &thread);
        let head = repository.find_commit(after).unwrap();
        assert_eq!(head.parent_ids().next().unwrap().detach(), before);
        let notes = head
            .tree()
            .unwrap()
            .find_entry("notes")
            .unwrap()
            .object()
            .unwrap();
        assert_eq!(notes.data, b"one\ntwo\n");

        let thread_id: ThreadId = thread.parse().unwrap();
        let store = Store::open(&fixture.repo).unwrap();
        let meta = load_meta(&store, thread_id, &fixture.owner, 0).unwrap();
        let tester = ParticipantName::new("tester").unwrap();
        let key = meta.thread_key(&tester, fixture.identity.as_age()).unwrap();
        let slot = AgentSlot::new(tester, AgentName::new("sh").unwrap());
        let turns = read_turns(&store, &key, thread_id, &slot, 10).unwrap();
        assert_eq!(turns.len(), 2, "{output}");
        assert_eq!(turns[1].turn(), 1);
        assert_eq!(turns[1].events()[0].payload(), b"prompt\nsecond");
    }

    const WORKING_CLAUDE: &str = r#"#!/bin/sh
printf '{"prompt":"build the parser"}' | "$MAHI_BIN" hook prompt
printf '{"tool_name":"Write","tool_input":{"file_path":"parser.rs"}}' | "$MAHI_BIN" hook tool
echo 'fn parse() {}' > parser.rs
project="$CLAUDE_CONFIG_DIR/projects/$(pwd -P | sed 's/[^a-zA-Z0-9]/-/g')"
mkdir -p "$project"
printf '%s\n' '{"type":"assistant","timestamp":"2026-09-30T00:00:00Z","message":{"content":[{"type":"text","text":"Parser done; tests pass."}]}}' > "$project/s.jsonl"
"$MAHI_BIN" hook turn-end < /dev/null
"#;

    const TAKER: &str = r#"#!/bin/sh
echo "args=$*"
echo "notes=$MAHI_HANDOFF"
ls -l "$MAHI_HANDOFF" | cut -c1-10
tr '\n' '|' < "$MAHI_HANDOFF"
echo
cat parser.rs
"#;

    fn script(fixture: &Fixture, directory: &str, name: &str, text: &str) -> PathBuf {
        let tools = fixture.root.join(directory);
        fs::create_dir_all(&tools).unwrap();
        let path = tools.join(name);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn worked_thread(fixture: &Fixture) -> (String, PathBuf) {
        save_identity(fixture);
        let claude = script(fixture, "working", "claude", WORKING_CLAUDE);
        let first = fixture
            .command(&["run", claude.to_str().unwrap()])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&first.stderr);
        assert_eq!(first.status.code(), Some(0), "{stderr}");
        let thread = worktree_of(&stderr)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        (thread, claude)
    }

    #[test]
    fn a_handoff_needs_no_worktree_a_new_agent_and_a_listed_source_with_work() {
        let fixture = fixture();
        let (thread, claude) = worked_thread(&fixture);
        let taker = script(&fixture, "taking", "codex", TAKER);
        let taker = taker.to_str().unwrap();

        let (code, output) = in_terminal(
            &fixture,
            &["handoff", &thread, "--from", "tester.claude", "--", taker],
            None,
        );
        assert_eq!(code, 1, "{output}");
        assert!(
            output.contains("record and remove it with mahi end"),
            "{output}"
        );
        assert!(fixture.mahi(&["end", &thread]).status.success());
        let (code, output) = in_terminal(
            &fixture,
            &[
                "handoff",
                &thread,
                "--from",
                "tester.claude",
                "--",
                claude.to_str().unwrap(),
            ],
            None,
        );
        assert_eq!(code, 1, "{output}");
        assert!(
            output.contains("already have an agent called claude"),
            "{output}"
        );
        let (code, output) = in_terminal(
            &fixture,
            &["handoff", &thread, "--from", "mallory.claude", "--", taker],
            None,
        );
        assert_eq!(code, 1, "{output}");
        assert!(
            output.contains("does not list a participant called mallory"),
            "{output}"
        );
        let (code, output) = in_terminal(
            &fixture,
            &["handoff", &thread, "--from", "tester.nothing", "--", taker],
            None,
        );
        assert_eq!(code, 1, "{output}");
        assert!(
            output.contains("tester.nothing has no snapshot here"),
            "{output}"
        );
    }

    #[test]
    fn another_agent_takes_over_with_the_work_and_a_briefing_of_it() {
        let fixture = fixture();
        let (thread, _claude) = worked_thread(&fixture);
        assert!(fixture.mahi(&["end", &thread]).status.success());
        let taker = script(&fixture, "taking", "codex", TAKER);
        let taker = taker.to_str().unwrap();

        let (code, output) = in_terminal(
            &fixture,
            &["handoff", &thread, "--from", "tester.claude", "--", taker],
            Some(PASSPHRASE),
        );
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains("handing tester.claude's work over to codex"),
            "{output}"
        );
        assert!(
            output.contains("tell the agent: Read the handoff notes at"),
            "{output}"
        );
        assert!(output.contains("mahi-handoff.md"), "{output}");
        for expected in [
            "> build the parser",
            "- ` Write parser.rs `",
            "- added ` parser.rs `",
            "- Previous agent: ` tester.claude `",
            "fn parse() {}",
            "-rw-------",
            "> Parser done; tests pass.",
        ] {
            assert!(output.contains(expected), "{expected}: {output}");
        }
        let store = Store::open(&fixture.repo).unwrap();
        let handed = ThreadRef::new(
            thread.parse().unwrap(),
            RefKind::Snapshots(AgentSlot::new(
                ParticipantName::new("tester").unwrap(),
                AgentName::new("codex").unwrap(),
            )),
        );
        all_signed_by(&store, &handed, &fixture.owner);
        let repository = gix::open(&fixture.repo).unwrap();
        let tree = repository
            .find_reference(handed.to_string().as_str())
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .tree()
            .unwrap();
        assert!(tree.find_entry("parser.rs").is_some());
    }

    #[test]
    fn claude_taking_over_starts_with_the_prompt_to_read_the_notes() {
        let fixture = fixture();
        save_identity(&fixture);
        let first = fixture
            .command(&["run", "sh", "-c", "echo work > work.txt"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&first.stderr);
        assert_eq!(first.status.code(), Some(0), "{stderr}");
        let thread = worktree_of(&stderr)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(fixture.mahi(&["end", &thread]).status.success());
        let claude = fake_claude(&fixture);
        let (code, output) = in_terminal(
            &fixture,
            &[
                "handoff",
                &thread,
                "--from",
                "tester.sh",
                "--",
                claude.to_str().unwrap(),
            ],
            Some(PASSPHRASE),
        );
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains("args=-- Read the handoff notes at "),
            "{output}"
        );
        assert!(!output.contains("tell the agent"), "{output}");
    }

    #[test]
    fn claudes_session_is_recorded_and_restored_once_its_state_is_gone() {
        let fixture = fixture();
        save_identity(&fixture);
        let claude = fake_claude(&fixture);
        let first = fixture
            .command(&["run", claude.to_str().unwrap()])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&first.stderr);
        assert_eq!(first.status.code(), Some(0), "{stderr}");
        assert!(!stderr.contains("session was not"), "{stderr}");
        let thread = worktree_of(&stderr)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let session = ThreadRef::new(
            thread.parse().unwrap(),
            RefKind::Session(AgentSlot::new(
                ParticipantName::new("tester").unwrap(),
                AgentName::new("claude").unwrap(),
            )),
        );
        let store = Store::open(&fixture.repo).unwrap();
        all_signed_by(&store, &session, &fixture.owner);
        let ended = fixture.mahi(&["end", &thread]);
        assert_eq!(ended.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&ended.stderr).contains("removed the agents' state"));

        let (code, output) = in_terminal(
            &fixture,
            &["resume", &thread, "--", claude.to_str().unwrap()],
            Some(PASSPHRASE),
        );
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains("restored the agent's session (1 file)"),
            "{output}"
        );
        assert!(
            output.contains(&format!("session=turn in {thread}|")),
            "{output}"
        );
        let (code, output) = in_terminal(
            &fixture,
            &["resume", &thread, "--", claude.to_str().unwrap()],
            Some(PASSPHRASE),
        );
        assert_eq!(code, 0, "{output}");
        assert!(!output.contains("restored"), "{output}");
        assert!(
            output.contains(&format!("session=turn in {thread}|turn in {thread}|")),
            "{output}"
        );
    }

    #[test]
    fn resuming_claude_continues_its_conversation_in_the_same_state() {
        let fixture = fixture();
        save_identity(&fixture);
        let claude = fake_claude(&fixture);
        let first = fixture
            .command(&["run", claude.to_str().unwrap()])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&first.stderr);
        assert_eq!(first.status.code(), Some(0), "{stderr}");
        let thread = worktree_of(&stderr)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let state = fs::canonicalize(
            fixture
                .repo
                .join(".git/mahi/state")
                .join(&thread)
                .join("tester.claude"),
        )
        .unwrap();
        fs::write(state.join("settings.json"), "{}").unwrap();

        let tools = claude.parent().unwrap().display().to_string();
        let command = PtyCommand::new(
            Path::new(env!("CARGO_BIN_EXE_mahi")),
            &fixture.repo,
            WindowSize {
                rows: 24,
                cols: 200,
            },
        )
        .arg("resume")
        .arg(&thread)
        .env("PATH", format!("{tools}:/usr/bin:/bin:/usr"))
        .env("HOME", &fixture.home)
        .env("XDG_CONFIG_HOME", fixture.home.join(".config"))
        .env("SSH_AUTH_SOCK", &fixture.socket)
        .env("USER", "tester")
        .env("MAHI_LIVE", "off");
        let (code, output) = in_terminal_with(command, Some(PASSPHRASE));
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("args=--continue"), "{output}");
        assert!(
            output.contains(&format!("config={}", state.display())),
            "{output}"
        );
        assert!(output.contains("hooks=ok"), "{output}");
        assert_eq!(fs::read_to_string(state.join("written")).unwrap(), "kept\n");

        let elsewhere = fixture.root.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::remove_dir_all(&state).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &state).unwrap();
        let (code, output) = in_terminal(
            &fixture,
            &["resume", &thread, "--", claude.to_str().unwrap()],
            Some(PASSPHRASE),
        );
        assert_eq!(code, 1, "{output}");
        assert!(output.contains("is not a private directory"), "{output}");
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        assert_eq!(fixture.threads().len(), 4);
        assert!(
            fixture
                .thread_worktrees()
                .iter()
                .any(|worktree| worktree.ends_with(&thread))
        );
    }

    #[test]
    fn end_records_the_last_changes_and_removes_the_worktree_and_state() {
        let fixture = fixture();
        let claude = fake_claude(&fixture);
        let run = fixture
            .command(&["run", claude.to_str().unwrap()])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert_eq!(run.status.code(), Some(0), "{stderr}");
        let worktree = worktree_of(&stderr);
        let thread = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        let state = fixture.repo.join(".git/mahi/state").join(&thread);
        assert!(state.exists());
        let lock = config_dir(&fixture.home).path().join("locks").join(&thread);
        assert!(lock.exists());
        fs::write(worktree.join("late"), "written after the agent\n").unwrap();

        let ended = fixture.mahi(&["end", &thread]);
        let report = String::from_utf8_lossy(&ended.stderr);
        assert_eq!(ended.status.code(), Some(0), "{report}");
        assert!(
            report.contains("recorded the worktree's last changes"),
            "{report}"
        );
        assert!(!worktree.exists());
        assert!(!state.exists());
        assert!(!lock.exists());
        assert!(fixture.thread_worktrees().is_empty());
        let repository = gix::open(&fixture.repo).unwrap();
        let last = repository
            .find_reference(
                format!("refs/threads/{thread}/agents/tester.claude/snapshots").as_str(),
            )
            .unwrap()
            .peel_to_commit()
            .unwrap();
        let late = last
            .tree()
            .unwrap()
            .find_entry("late")
            .unwrap()
            .object()
            .unwrap();
        assert_eq!(late.data, b"written after the agent\n");
        let snapshots = ThreadRef::new(
            thread.parse().unwrap(),
            RefKind::Snapshots(AgentSlot::new(
                ParticipantName::new("tester").unwrap(),
                AgentName::new("claude").unwrap(),
            )),
        );
        all_signed_by(
            &Store::open(&fixture.repo).unwrap(),
            &snapshots,
            &fixture.owner,
        );
        assert_eq!(fixture.threads().len(), 4);
        let listed = fixture.mahi(&["threads"]);
        assert!(String::from_utf8_lossy(&listed.stdout).contains("no worktree"));

        let again = fixture.mahi(&["end", &thread]);
        assert_eq!(again.status.code(), Some(0));
        assert!(!String::from_utf8_lossy(&again.stderr).contains("recorded"));
    }

    fn ended_thread(fixture: &Fixture) -> (PathBuf, String) {
        let run = fixture.mahi(&["run", "true"]);
        let worktree = worktree_of(&String::from_utf8_lossy(&run.stderr));
        let thread = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        (worktree, thread)
    }

    #[test]
    fn end_without_changes_records_nothing_new() {
        let fixture = fixture();
        let (_, thread) = ended_thread(&fixture);
        let ended = fixture.mahi(&["end", &thread]);
        let report = String::from_utf8_lossy(&ended.stderr);
        assert_eq!(ended.status.code(), Some(0), "{report}");
        assert!(!report.contains("recorded"), "{report}");
        assert!(report.contains("removed the worktree"), "{report}");
    }

    #[test]
    fn end_leaves_a_worktree_that_no_longer_links_back_and_prunes_a_deleted_one() {
        let fixture = fixture();
        let (worktree, thread) = ended_thread(&fixture);
        fs::write(worktree.join(".git"), "gitdir: /elsewhere\n").unwrap();
        let broken = fixture.mahi(&["end", &thread]);
        assert_eq!(broken.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&broken.stderr).contains("no longer links back"));
        assert!(worktree.exists());

        let (worktree, thread) = ended_thread(&fixture);
        fs::remove_dir_all(&worktree).unwrap();
        let pruned = fixture.mahi(&["end", &thread]);
        let report = String::from_utf8_lossy(&pruned.stderr);
        assert_eq!(pruned.status.code(), Some(0), "{report}");
        assert!(report.contains("already gone"), "{report}");
        assert!(!fixture.repo.join(".git/worktrees").join(&thread).exists());
    }

    #[test]
    fn end_refuses_to_lose_unrecorded_files_unless_forced() {
        let fixture = fixture();
        let (worktree, thread) = ended_thread(&fixture);
        let secret = worktree.join("unreadable");
        fs::write(&secret, "x").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
        let refused = fixture.mahi(&["end", &thread]);
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(refused.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("leaves out unreadable"), "{stderr}");
        assert!(worktree.exists());
        let forced = fixture.mahi(&["end", "--force", &thread]);
        assert_eq!(forced.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&forced.stderr)
                .contains("discarded what the snapshot left out: unreadable")
        );
        assert!(!worktree.exists());
    }

    #[test]
    fn resume_refuses_a_thread_signed_by_another_key_before_the_passphrase() {
        let fixture = fixture();
        let first = fixture.mahi(&["run", "true"]);
        let worktree = worktree_of(&String::from_utf8_lossy(&first.stderr));
        let thread = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        let config = config_dir(&fixture.home);
        fs::remove_file(config.signing_key_file()).unwrap();
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        SigningKey::try_from(other.public_key().clone())
            .unwrap()
            .save(&config.signing_key_file())
            .unwrap();
        let refused = fixture.mahi(&["resume", &thread, "--", "true"]);
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(refused.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("only a thread you started"), "{stderr}");
        assert!(!stderr.contains("Passphrase"), "{stderr}");
        let ending = fixture.mahi(&["end", &thread]);
        assert_eq!(ending.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&ending.stderr).contains("only a thread you started"));
        assert!(worktree.exists());
    }

    #[test]
    fn resume_and_end_need_the_signing_key_in_ssh_agent() {
        let fixture = fixture();
        let first = fixture.mahi(&["run", "true"]);
        let worktree = worktree_of(&String::from_utf8_lossy(&first.stderr));
        let thread = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        let elsewhere = fixture.root.join("other-agent.sock");
        serve_signatures(
            &elsewhere,
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
            None,
        );
        for arguments in [
            &["resume", &thread, "--", "sh", "-c", "echo ran > ran.txt"][..],
            &["end", &thread],
        ] {
            let refused = fixture
                .command(arguments)
                .env("SSH_AUTH_SOCK", &elsewhere)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&refused.stderr);
            assert_eq!(refused.status.code(), Some(1), "{stderr}");
            assert!(
                stderr.contains("does not hold your signing key"),
                "{stderr}"
            );
            assert!(!stderr.contains("Passphrase"), "{stderr}");
        }
        assert!(!worktree.join("ran.txt").exists());
        assert!(worktree.exists());
        let threads = fixture.threads().len();
        let run = fixture
            .command(&["run", "true"])
            .env("SSH_AUTH_SOCK", &elsewhere)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert_eq!(run.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("does not hold your signing key"),
            "{stderr}"
        );
        assert_eq!(fixture.threads().len(), threads);
        let repository = gix::open(&fixture.repo).unwrap();
        let tester = repository
            .find_reference(format!("refs/threads/{thread}/agents/tester.true/snapshots").as_str())
            .unwrap()
            .id()
            .detach();
        repository
            .reference(
                format!("refs/threads/{thread}/agents/mallory.true/snapshots").as_str(),
                tester,
                gix::refs::transaction::PreviousValue::MustNotExist,
                "test",
            )
            .unwrap();
        let someone_else = fixture
            .command(&["resume", &thread, "--", "true"])
            .env("USER", "mallory")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&someone_else.stderr);
        assert_eq!(someone_else.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("does not list your signing key for mallory"),
            "{stderr}"
        );
    }

    #[test]
    fn taking_a_thread_from_the_remote_checks_the_key_first_and_needs_the_thread_there() {
        let fixture = fixture();
        let thread = "0123456789abcdef0123456789abcdef";
        let elsewhere = fixture.root.join("other-agent.sock");
        serve_signatures(
            &elsewhere,
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
            None,
        );
        let config = fixture.repo.join(".git/config");
        let mut text = fs::read_to_string(&config).unwrap();
        text.push_str("[remote \"origin\"]\n\turl = ssh://127.0.0.1:1/unreachable.git\n");
        fs::write(&config, text).unwrap();
        let refused = fixture
            .command(&["resume", "--take-remote", thread, "--", "true"])
            .env("SSH_AUTH_SOCK", &elsewhere)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(refused.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("does not hold your signing key"),
            "{stderr}"
        );
        assert!(!stderr.contains("fetching"), "{stderr}");
        let missing = fixture.mahi(&["resume", "--take-remote", thread, "--", "true"]);
        let stderr = String::from_utf8_lossy(&missing.stderr);
        assert_eq!(missing.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("fetching the thread from origin"),
            "{stderr}"
        );
        assert!(stderr.contains("has no agent of yours"), "{stderr}");

        let first = fixture.mahi(&["run", "true"]);
        let worktree = worktree_of(&String::from_utf8_lossy(&first.stderr));
        let here = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        let kept = fixture.mahi(&["resume", "--take-remote", &here, "--", "true"]);
        let stderr = String::from_utf8_lossy(&kept.stderr);
        assert_eq!(kept.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("record and remove it with mahi end"),
            "{stderr}"
        );
        assert!(!stderr.contains("fetching"), "{stderr}");
        assert!(fixture.mahi(&["end", &here]).status.success());
        let taken = fixture.mahi(&["resume", "--take-remote", &here, "--", "true"]);
        let stderr = String::from_utf8_lossy(&taken.stderr);
        assert!(
            stderr.contains("fetching the thread from origin"),
            "{stderr}"
        );
    }

    #[test]
    fn a_running_thread_cannot_be_resumed_by_another_mahi() {
        let fixture = fixture();
        let mut running = KillOnDrop(
            fixture
                .command(&["run", "sh", "-c", "sleep 30"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stderr = running.0.stderr.take().unwrap();
        let mut seen = Vec::new();
        let has_thread_line = |seen: &[u8]| {
            let text = String::from_utf8_lossy(seen);
            text.split_once("mahi: thread ")
                .is_some_and(|(_, rest)| rest.contains('\n'))
        };
        while !has_thread_line(&seen) {
            let mut chunk = [0_u8; 256];
            let read = stderr.read(&mut chunk).unwrap();
            assert_ne!(read, 0, "mahi run ended early");
            seen.extend_from_slice(&chunk[..read]);
        }
        let worktree = worktree_of(&String::from_utf8_lossy(&seen));
        let thread = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        let busy = fixture.mahi(&["resume", &thread, "--", "true"]);
        assert_eq!(busy.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&busy.stderr).contains("already running"));
        let ending = fixture.mahi(&["end", &thread]);
        assert_eq!(ending.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&ending.stderr).contains("stop it before ending"));
        assert!(worktree.exists());
    }

    #[test]
    fn resume_refuses_unknown_threads_and_wrong_passphrases_and_rebuilds_a_lost_worktree() {
        let fixture = fixture();
        save_identity(&fixture);
        let unknown = fixture.mahi(&["resume", "0123456789abcdef0123456789abcdef"]);
        assert_eq!(unknown.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&unknown.stderr).contains("no agent of yours"));

        let first = fixture.mahi(&["run", "sh", "-c", "echo recorded work > work.txt"]);
        let worktree = worktree_of(&String::from_utf8_lossy(&first.stderr));
        let thread = worktree.file_name().unwrap().to_str().unwrap().to_owned();
        let (code, output) = in_terminal(
            &fixture,
            &["resume", &thread, "--", "true"],
            Some("wrong passphrase"),
        );
        assert_eq!(code, 1, "{output}");
        assert!(output.contains("cannot unlock your mahi key"), "{output}");

        let recorded = gix::open(&fixture.repo)
            .unwrap()
            .find_reference(format!("refs/threads/{thread}/agents/tester.sh/snapshots").as_str())
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .tree()
            .unwrap()
            .find_entry("work.txt")
            .is_some();
        assert!(recorded, "{}", String::from_utf8_lossy(&first.stderr));
        fs::remove_dir_all(&worktree).unwrap();
        let (code, output) = in_terminal(
            &fixture,
            &["resume", &thread, "--", "cat", "work.txt"],
            Some(PASSPHRASE),
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("recorded work"), "{output}");
        assert!(worktree.join("README").is_file());
    }

    #[test]
    fn worktrees_go_to_the_data_directory_which_must_not_be_private() {
        let fixture = fixture();
        let run = fixture.mahi(&["run", "true"]);
        let worktree = worktree_of(&String::from_utf8_lossy(&run.stderr));
        let repository = worktree.parent().unwrap();
        assert!(
            repository
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("repo-")
        );
        assert_eq!(
            fs::metadata(repository).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let data = fixture.root.join("data");
        let run = fixture
            .command(&["run", "true"])
            .env("XDG_DATA_HOME", &data)
            .output()
            .unwrap();
        let worktree = worktree_of(&String::from_utf8_lossy(&run.stderr));
        assert!(
            worktree.starts_with(data.join("mahi/worktrees")),
            "{worktree:?}"
        );

        let threads = fixture.threads();
        let linked = fixture.root.join("linked-data");
        fs::create_dir_all(fixture.home.join(".ssh")).unwrap();
        std::os::unix::fs::symlink(fixture.home.join(".ssh"), &linked).unwrap();
        let through_link = fixture
            .command(&["run", "true"])
            .env("XDG_DATA_HOME", &linked)
            .output()
            .unwrap();
        assert_eq!(through_link.status.code(), Some(1));
        assert!(!fixture.home.join(".ssh/mahi").exists());
        fs::remove_dir(fixture.home.join(".ssh")).unwrap();
        let private = fixture.home.join(".ssh");
        let refused = fixture
            .command(&["run", "true"])
            .env("XDG_DATA_HOME", &private)
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("holds private files"));
        assert!(!private.exists());
        assert_eq!(fixture.threads(), threads);
    }

    fn credential(fixture: &Fixture, arguments: &[&str], input: &[u8]) -> Output {
        let mut child = fixture
            .command(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn a_stored_credential_reaches_claude_instead_of_the_shells_token() {
        let fixture = fixture();
        let added = credential(
            &fixture,
            &["credential", "add", "claude"],
            b"stored-token\n",
        );
        assert_eq!(added.status.code(), Some(0));
        let again = credential(&fixture, &["credential", "add", "claude"], b"other\n");
        assert_eq!(again.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&again.stderr).contains("remove it first"));
        let listed = fixture.mahi(&["credential", "list"]);
        assert_eq!(String::from_utf8_lossy(&listed.stdout), "claude\n");

        let claude = fake_claude(&fixture);
        let output = fixture
            .command(&["run", claude.to_str().unwrap()])
            .env("CLAUDE_CODE_OAUTH_TOKEN", "shell-token")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{stdout}");
        assert!(stdout.contains("token=stored-token"), "{stdout}");
        assert!(!stdout.contains("shell-token"), "{stdout}");

        let removed = fixture.mahi(&["credential", "remove", "claude"]);
        assert_eq!(removed.status.code(), Some(0));
        let listed = fixture.mahi(&["credential", "list"]);
        assert!(listed.stdout.is_empty());
    }

    #[test]
    fn any_agent_gets_a_named_credential_given_one_way() {
        let fixture = fixture();
        let added = credential(&fixture, &["credential", "add", "service"], b"s3cret");
        assert_eq!(added.status.code(), Some(0));
        let long = vec![b'a'; 16 * 1024 + 3];
        let too_long = credential(&fixture, &["credential", "add", "long"], &long);
        assert_eq!(too_long.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&too_long.stderr).contains("larger than 16 KiB"));
        let output = fixture.mahi(&[
            "run",
            "--credential",
            "service=SERVICE_TOKEN",
            "sh",
            "-c",
            "echo token=$SERVICE_TOKEN",
        ]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{stdout}");
        assert!(stdout.contains("token=s3cret"), "{stdout}");
        let threads = fixture.threads();

        let missing = fixture.mahi(&["run", "--credential", "absent=TOKEN", "true"]);
        assert_eq!(missing.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("mahi credential add absent"));
        let twice = fixture
            .command(&[
                "run",
                "--credential",
                "service=SERVICE_TOKEN",
                "--pass-env",
                "SERVICE_TOKEN",
                "true",
            ])
            .env("SERVICE_TOKEN", "x")
            .output()
            .unwrap();
        assert_eq!(twice.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&twice.stderr).contains("more than one way"));
        for clash in ["service=PATH", "service=CLAUDE_CONFIG_DIR"] {
            let claude = fake_claude(&fixture);
            let refused = fixture.mahi(&["run", "--credential", clash, claude.to_str().unwrap()]);
            assert_eq!(refused.status.code(), Some(1), "{clash}");
            assert!(
                String::from_utf8_lossy(&refused.stderr).contains("more than one way"),
                "{clash}"
            );
        }
        assert_eq!(fixture.threads(), threads);
    }

    #[test]
    fn the_agent_cannot_write_to_the_checkout_or_the_git_directory() {
        let fixture = fixture();
        let outside = fixture.root.join("outside");
        let script = format!(
            "echo x > {outside} 2>/dev/null; echo outside=$?; \
             echo x >> {readme} 2>/dev/null; echo checkout=$?; \
             echo x > {hook} 2>/dev/null; echo git=$?; \
             admin=$(sed 's/^gitdir: //' .git); \
             echo x >> \"$admin/HEAD\" 2>/dev/null; echo admin=$?; \
             echo x >> .git 2>/dev/null; echo link=$?; \
             rm -f .git 2>/dev/null; echo unlink=$?",
            outside = outside.display(),
            readme = fixture.repo.join("README").display(),
            hook = fixture.repo.join(".git/hooks/pre-commit").display(),
        );
        let output = fixture.mahi(&["run", "sh", "-c", &script]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{stdout}");
        for place in ["outside", "checkout", "git", "admin", "link", "unlink"] {
            assert!(stdout.contains(&format!("{place}=")), "{stdout}");
            assert!(!stdout.contains(&format!("{place}=0")), "{place}: {stdout}");
        }
        assert!(!outside.exists());
        assert_eq!(
            fs::read_to_string(fixture.repo.join("README")).unwrap(),
            "hello from the repository\n"
        );
        assert!(!fixture.repo.join(".git/hooks/pre-commit").exists());
        let worktree = worktree_of(&String::from_utf8_lossy(&output.stderr));
        let admin = fixture
            .repo
            .join(".git/worktrees")
            .join(worktree.file_name().unwrap());
        assert_eq!(
            fs::read_to_string(admin.join("HEAD")).unwrap(),
            format!("{}\n", fixture.base)
        );
        assert!(
            fs::read_to_string(worktree.join(".git"))
                .unwrap()
                .starts_with("gitdir: ")
        );
    }

    #[test]
    fn a_file_that_is_not_a_program_is_refused_before_a_thread_starts() {
        let fixture = fixture();
        let agent = fixture.root.join("tools").join("broken-agent");
        fs::create_dir(agent.parent().unwrap()).unwrap();
        fs::write(&agent, b"\x00\x01\x02 not a program").unwrap();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
        let output = fixture.mahi(&["run", agent.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("is not a program"), "{stderr}");
        assert!(fixture.threads().is_empty());
        assert!(fixture.thread_worktrees().is_empty());
    }

    #[test]
    fn a_stop_signal_while_the_thread_is_created_leaves_nothing_behind() {
        let (asked, asked_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let fixture = fixture_with(Some(Hold {
            asked,
            release: release_rx,
        }));
        let mut child = KillOnDrop(
            fixture
                .command(&["run", "true"])
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        );
        asked_rx.recv_timeout(Duration::from_secs(20)).unwrap();
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.0.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        thread::sleep(Duration::from_millis(200));
        release.send(()).unwrap();
        let mut status = None;
        wait_until("mahi to exit", || {
            status = child.0.try_wait().unwrap();
            status.is_some()
        });
        assert_eq!(status.unwrap().signal(), Some(libc::SIGTERM));
        assert!(fixture.threads().is_empty());
        assert!(fixture.thread_worktrees().is_empty());
        assert_eq!(
            fs::read_dir(fixture.repo.join(".git/worktrees")).map_or(0, Iterator::count),
            0
        );
    }

    #[test]
    fn a_second_stop_signal_ends_mahi_while_the_ssh_agent_waits() {
        let (asked, asked_rx) = mpsc::channel();
        let (_release, release_rx) = mpsc::channel();
        let fixture = fixture_with(Some(Hold {
            asked,
            release: release_rx,
        }));
        let mut child = KillOnDrop(
            fixture
                .command(&["run", "true"])
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        );
        asked_rx.recv_timeout(Duration::from_secs(20)).unwrap();
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.0.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        thread::sleep(Duration::from_millis(200));
        assert!(child.0.try_wait().unwrap().is_none());
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let mut status = None;
        wait_until("mahi to exit", || {
            status = child.0.try_wait().unwrap();
            status.is_some()
        });
        assert_eq!(status.unwrap().signal(), Some(libc::SIGTERM));
        assert!(fixture.threads().is_empty());
    }

    #[test]
    fn a_failure_before_the_agent_starts_leaves_no_thread_or_worktree() {
        let fixture = fixture();
        let output = fixture
            .command(&["run", "true"])
            .env("TMPDIR", fixture.root.join("missing"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("private directories"), "{stderr}");
        assert!(fixture.threads().is_empty());
        assert!(fixture.thread_worktrees().is_empty());
        assert!(!fixture.repo.join(".git/worktrees").exists());
    }

    #[derive(Debug)]
    struct AdmitsHost(mahi_thread::NodeId);

    impl mahi_live::Peers for AdmitsHost {
        fn admits(&self, node: &mahi_thread::NodeId) -> bool {
            node == &self.0
        }

        fn meta_for(&self, _thread: ThreadId, _node: &mahi_thread::NodeId) -> Option<Vec<u8>> {
            None
        }
    }

    fn running_thread(fixture: &Fixture) -> (ThreadId, mahi_crypto::ThreadKey) {
        wait_until("the thread", || {
            fixture.threads().iter().any(|name| name.ends_with("/meta"))
        });
        let thread: ThreadId = fixture
            .threads()
            .iter()
            .find_map(|name| name.strip_suffix("/meta"))
            .and_then(|name| name.strip_prefix("refs/threads/"))
            .unwrap()
            .parse()
            .unwrap();
        let store = Store::open(&fixture.repo).unwrap();
        let tester = ParticipantName::new("tester").unwrap();
        let key = load_meta(&store, thread, &fixture.owner, 0)
            .unwrap()
            .thread_key(&tester, fixture.identity.as_age())
            .unwrap();
        (thread, key)
    }

    fn invite_bob(fixture: &Fixture, thread: ThreadId, key: &mahi_crypto::ThreadKey) -> NodeKey {
        let bob_node_key = NodeKey::generate().unwrap();
        let bob_ssh = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let bob = mahi_thread::Participant::new(
            ParticipantName::new("bob").unwrap(),
            ParticipantKey::from_public_key(bob_ssh.public_key()).unwrap(),
            age::x25519::Identity::generate().to_public(),
            mahi_thread::NodeId::from_bytes(bob_node_key.public()).unwrap(),
        )
        .unwrap();
        let owner_ssh = ssh_key::PublicKey::from_openssh(fixture.owner.to_openssh()).unwrap();
        let signer = mahi_identity::AgentSigner::new(
            mahi_identity::SshAgent::new(&fixture.socket),
            owner_ssh,
        )
        .unwrap();
        let store = Store::open(&fixture.repo).unwrap();
        mahi_thread::add_participant(&store, thread, key, &signer, bob).unwrap();
        bob_node_key
    }

    fn local_host_address(fixture: &Fixture) -> mahi_live::HostAddress {
        let host_node = mahi_thread::NodeId::from_bytes(
            NodeKey::load(&config_dir(&fixture.home).node_key_file())
                .unwrap()
                .public(),
        )
        .unwrap();
        let port = mahi_live::stable_port(&host_node);
        mahi_live::HostAddress::new(
            host_node,
            None,
            vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))],
        )
        .unwrap()
    }

    fn wait_for_heartbeat(topic: &mahi_live::LiveTopic, receiver: &mut mahi_live::FrameReceiver) {
        let mut heartbeat = false;
        wait_until("a heartbeat from the quiet host", || {
            while let Some(frame) = topic.receive(Duration::from_millis(100)).unwrap() {
                heartbeat |= matches!(
                    receiver.open(&frame).map(|received| received.body),
                    Ok(mahi_live::Body::Heartbeat { .. })
                );
            }
            heartbeat
        });
    }

    #[test]
    fn an_invited_participant_watches_the_agent_live_over_the_local_network() {
        use mahi_live::{
            Body,
            FrameReceiver,
            FrameSender,
            LiveKeys,
            LiveNode,
            Relays,
        };

        let fixture = fixture();
        let mut command = fixture.command(&[
            "run",
            "sh",
            "-c",
            "printf 'first screen'; sleep 12; printf ' then live output'; sleep 10",
        ]);
        let mahi = KillOnDrop(
            command
                .env("MAHI_LIVE", "local")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let (thread, key) = running_thread(&fixture);
        let bob = invite_bob(&fixture, thread, &key);
        let address = local_host_address(&fixture);
        let published = config_dir(&fixture.home)
            .path()
            .join("live")
            .join(thread.to_string());
        wait_until("the host to publish its address", || published.exists());
        let host = mahi_live::HostAddress::from_bytes(&fs::read(&published).unwrap()).unwrap();
        assert_eq!(host.node(), address.node());
        let viewer = LiveNode::bind_live(
            bob.secret(),
            Relays::Disabled,
            Arc::new(AdmitsHost(*address.node())),
        )
        .unwrap();
        let mut document = None;
        wait_until("the host to serve meta to bob", || {
            document = viewer.fetch_meta(&address, thread).ok();
            if document.is_none() {
                thread::sleep(Duration::from_millis(500));
            }
            document.is_some()
        });
        let meta =
            mahi_thread::VerifiedMeta::decode(&document.unwrap(), thread, &fixture.owner).unwrap();
        let keys = || LiveKeys::derive(&key, thread).unwrap();
        let topic = viewer
            .join(
                keys().topic(),
                std::slice::from_ref(&address),
                Some(Duration::from_secs(10)),
            )
            .unwrap();
        let mut receiver = FrameReceiver::new(
            keys(),
            meta.participants()
                .map(|listed| (*listed.node(), listed.name().clone())),
        );
        let mut sender = FrameSender::new(keys(), bob.secret()).unwrap();
        let (mut screen, mut output) = (Vec::new(), Vec::new());
        let mut asked_at: Option<Instant> = None;
        wait_until("the screen and the live output", || {
            if screen.is_empty() && asked_at.is_none_or(|at| at.elapsed() > Duration::from_secs(1))
            {
                let request = receiver.request_screen().unwrap();
                topic.broadcast(sender.seal(&request).unwrap()).unwrap();
                asked_at = Some(Instant::now());
            }
            while let Some(frame) = topic.receive(Duration::from_millis(100)).unwrap() {
                match receiver.open(&frame).map(|received| received.body) {
                    Ok(Body::Screen { bytes, .. }) => screen.extend_from_slice(&bytes),
                    Ok(Body::Output { bytes, .. }) => output.extend_from_slice(&bytes),
                    _ => {}
                }
            }
            String::from_utf8_lossy(&output).contains("then live output")
        });
        assert!(String::from_utf8_lossy(&screen).contains("first screen"));
        wait_for_heartbeat(&topic, &mut receiver);
        viewer.close().unwrap();
        let mut mahi = mahi;
        let mut status = None;
        wait_until("mahi to exit after its agent", || {
            status = mahi.0.try_wait().unwrap();
            status.is_some()
        });
        assert!(status.unwrap().success());
        assert!(!published.exists());
    }

    #[test]
    fn mahi_ends_with_its_agent_when_teammates_can_watch_and_refuses_an_unknown_live_setting() {
        let fixture = fixture();
        let started = Instant::now();
        let output = fixture
            .command(&["run", "sh", "-c", "printf done"])
            .env("MAHI_LIVE", "local")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(started.elapsed() < Duration::from_secs(15));
        let refused = fixture
            .command(&["run", "true"])
            .env("MAHI_LIVE", "of")
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains("MAHI_LIVE must be off, local or public")
        );
    }

    struct Teammate {
        home: PathBuf,
        repo: PathBuf,
        socket: PathBuf,
        key: ParticipantKey,
    }

    fn teammate(fixture: &Fixture, name: &str) -> Teammate {
        let home = fixture.root.join(format!("{name}-home"));
        let repo = fixture.root.join(format!("{name}-repo"));
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&repo).unwrap();
        repository_on_main(&repo);
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        initialise(&home, &key)
            .save(
                &config_dir(&home).identity_file(),
                &SecretString::from(PASSPHRASE.to_owned()),
            )
            .unwrap();
        let socket = fixture.root.join(format!("{name}-agent.sock"));
        let participant = ParticipantKey::from_public_key(key.public_key()).unwrap();
        serve_signatures(&socket, key, None);
        Teammate {
            home,
            repo,
            socket,
            key: participant,
        }
    }

    fn teammate_env(command: &mut Command, teammate: &Teammate, name: &str) {
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr")
            .env("HOME", &teammate.home)
            .env("XDG_CONFIG_HOME", teammate.home.join(".config"))
            .env("SSH_AUTH_SOCK", &teammate.socket)
            .env("USER", name)
            .env("MAHI_LIVE", "local");
    }

    fn mahi_in_terminal(cwd: &Path, arguments: &[&str], env: &[(&str, &OsStr)]) -> PtyChild {
        let mut command = PtyCommand::new(
            Path::new(env!("CARGO_BIN_EXE_mahi")),
            cwd,
            WindowSize {
                rows: 24,
                cols: 200,
            },
        );
        for argument in arguments {
            command = command.arg(argument);
        }
        for (key, value) in env {
            command = command.env(key, value);
        }
        command.spawn().unwrap()
    }

    fn collect(child: &PtyChild) -> Arc<Mutex<Vec<u8>>> {
        let output = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&output);
        let mut reader = child.reader().unwrap();
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                collected.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        });
        output
    }

    fn exit_of(child: &mut PtyChild) -> i32 {
        let mut status = None;
        wait_until("mahi to finish", || {
            status = child.try_wait().unwrap();
            status.is_some()
        });
        exit_code(status.unwrap())
    }

    #[test]
    fn a_teammate_invited_with_their_card_joins_and_watches_the_agent_then_leaves() {
        let fixture = fixture();
        save_identity(&fixture);
        let mut host = fixture.command(&[
            "run",
            "sh",
            "-c",
            "printf 'first screen'; while [ ! -e go ]; do sleep 0.1; done; \
             printf ' then live output'; sleep 30",
        ]);
        let _host = KillOnDrop(
            host.env("MAHI_LIVE", "local")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let (thread, _key) = running_thread(&fixture);
        let bob = teammate(&fixture, "bob");
        let ticket = invite_teammate(&fixture, thread, &bob);

        let bob_config = bob.home.join(".config");
        let bob_env: Vec<(&str, &OsStr)> = vec![
            ("PATH", OsStr::new("/usr/bin:/bin:/usr")),
            ("HOME", bob.home.as_os_str()),
            ("XDG_CONFIG_HOME", bob_config.as_os_str()),
            ("USER", OsStr::new("bob")),
            ("MAHI_LIVE", OsStr::new("local")),
        ];
        let mut join = mahi_in_terminal(&bob.repo, &["join", &ticket], &bob_env);
        let watched = collect(&join);
        let mut keys = join.writer().unwrap();
        wait_until("bob's passphrase question", || {
            String::from_utf8_lossy(&watched.lock().unwrap()).contains("Passphrase")
        });
        keys.write_all(format!("{PASSPHRASE}\n").as_bytes())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(40);
        while !String::from_utf8_lossy(&watched.lock().unwrap()).contains("first screen") {
            assert!(
                Instant::now() < deadline,
                "{}",
                String::from_utf8_lossy(&watched.lock().unwrap())
            );
            thread::sleep(Duration::from_millis(50));
        }
        assert!(!String::from_utf8_lossy(&watched.lock().unwrap()).contains("live output"));
        let worktree = fixture.thread_worktrees().pop().unwrap();
        fs::write(worktree.join("go"), "").unwrap();
        while !String::from_utf8_lossy(&watched.lock().unwrap()).contains("live output") {
            assert!(
                Instant::now() < deadline,
                "{}",
                String::from_utf8_lossy(&watched.lock().unwrap())
            );
            thread::sleep(Duration::from_millis(50));
        }
        assert!(String::from_utf8_lossy(&watched.lock().unwrap()).contains("first screen"));
        keys.write_all(b"q").unwrap();
        assert_eq!(exit_of(&mut join), 0);
        assert!(String::from_utf8_lossy(&watched.lock().unwrap()).contains("left thread"));
    }

    #[test]
    fn a_teammate_sends_a_prompt_the_host_reads_and_accepts_into_the_agent() {
        let fixture = fixture();
        save_identity(&fixture);
        let mut host = Session::start_with(
            &fixture,
            &[
                "run",
                "sh",
                "-c",
                "printf 'ready\\n'; read line; echo \"got:$line\"; read end",
            ],
            "local",
        );
        host.wait_for("ready");
        let (thread, _key) = running_thread(&fixture);
        let bob = teammate(&fixture, "bob");
        let ticket = invite_teammate(&fixture, thread, &bob);
        let bob_config = bob.home.join(".config");
        let bob_env: Vec<(&str, &OsStr)> = vec![
            ("PATH", OsStr::new("/usr/bin:/bin:/usr")),
            ("HOME", bob.home.as_os_str()),
            ("XDG_CONFIG_HOME", bob_config.as_os_str()),
            ("USER", OsStr::new("bob")),
            ("MAHI_LIVE", OsStr::new("local")),
        ];
        let mut join = mahi_in_terminal(&bob.repo, &["join", &ticket], &bob_env);
        let watched = collect(&join);
        let seen = |text: &str| String::from_utf8_lossy(&watched.lock().unwrap()).contains(text);
        let mut keys = join.writer().unwrap();
        wait_until("bob's passphrase question", || seen("Passphrase"));
        keys.write_all(format!("{PASSPHRASE}\n").as_bytes())
            .unwrap();
        wait_until("bob to see the agent", || seen("ready"));
        keys.write_all(b"\0").unwrap();
        wait_until("bob's palette", || seen("Enter sends"));
        keys.write_all(b"run the tests\r").unwrap();
        wait_until("the host to queue bob's prompt", || seen("waiting"));

        host.wait_for(
            "\x1b]9;mahi: bob sent a prompt (Ctrl-Space to read it): run the tests\x07\x07",
        );
        host.type_keys(b"\0");
        host.wait_for_screen("run the tests");
        host.type_keys(b"\r");
        host.wait_for("got:run the tests");
        wait_until("bob to learn it was accepted", || seen("accepted"));
        keys.write_all(b"\x1b").unwrap();
        thread::sleep(Duration::from_millis(300));
        keys.write_all(b"q").unwrap();
        assert_eq!(exit_of(&mut join), 0);
        host.type_keys(b"end\r");
        let (code, text) = host.finish();
        assert_eq!(code, 0, "{text}");
    }

    fn all_signed_by(store: &Store, thread_ref: &ThreadRef, key: &ParticipantKey) {
        let mut next = store.head(thread_ref).unwrap();
        assert!(next.is_some(), "{thread_ref} is missing");
        while let Some(commit) = next {
            assert!(
                mahi_thread::signed_by(store, commit, key).unwrap(),
                "{thread_ref} {commit}"
            );
            next = store.parent(commit).unwrap();
        }
    }

    fn invite_teammate(fixture: &Fixture, thread: ThreadId, teammate: &Teammate) -> String {
        let mut id = Command::new(env!("CARGO_BIN_EXE_mahi"));
        id.arg("id");
        teammate_env(&mut id, teammate, "bob");
        let card = String::from_utf8(id.output().unwrap().stdout).unwrap();
        let config_home = fixture.home.join(".config");
        let owner_env: Vec<(&str, &OsStr)> = vec![
            ("PATH", OsStr::new("/usr/bin:/bin:/usr")),
            ("HOME", fixture.home.as_os_str()),
            ("XDG_CONFIG_HOME", config_home.as_os_str()),
            ("SSH_AUTH_SOCK", fixture.socket.as_os_str()),
            ("USER", OsStr::new("tester")),
            ("MAHI_LIVE", OsStr::new("local")),
        ];
        let thread_text = thread.to_string();
        let mut invite = mahi_in_terminal(
            &fixture.repo,
            &["invite", &thread_text, card.trim()],
            &owner_env,
        );
        let invited = collect(&invite);
        let mut answer = invite.writer().unwrap();
        wait_until("the owner's passphrase question", || {
            String::from_utf8_lossy(&invited.lock().unwrap()).contains("Passphrase")
        });
        answer
            .write_all(format!("{PASSPHRASE}\n").as_bytes())
            .unwrap();
        assert_eq!(exit_of(&mut invite), 0);
        String::from_utf8_lossy(&invited.lock().unwrap())
            .split_whitespace()
            .find(|word| word.starts_with("mahi1"))
            .unwrap()
            .to_owned()
    }

    fn teammate_in_terminal(teammate: &Teammate, name: &str, arguments: &[&str]) -> (i32, String) {
        let config = teammate.home.join(".config");
        let env: Vec<(&str, &OsStr)> = vec![
            ("PATH", OsStr::new("/usr/bin:/bin:/usr")),
            ("HOME", teammate.home.as_os_str()),
            ("XDG_CONFIG_HOME", config.as_os_str()),
            ("SSH_AUTH_SOCK", teammate.socket.as_os_str()),
            ("USER", OsStr::new(name)),
            ("MAHI_LIVE", OsStr::new("local")),
        ];
        let mut mahi = mahi_in_terminal(&teammate.repo, arguments, &env);
        let output = collect(&mahi);
        let mut keys = mahi.writer().unwrap();
        wait_until("the passphrase question", || {
            String::from_utf8_lossy(&output.lock().unwrap()).contains("Passphrase")
        });
        keys.write_all(format!("{PASSPHRASE}\n").as_bytes())
            .unwrap();
        let code = exit_of(&mut mahi);
        thread::sleep(Duration::from_millis(100));
        let text = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
        (code, text)
    }

    #[test]
    fn a_teammate_joins_with_their_agent_only_with_the_key_meta_lists() {
        let fixture = fixture();
        save_identity(&fixture);
        let mut host = fixture.command(&["run", "sh", "-c", "sleep 60"]);
        let _host = KillOnDrop(
            host.env("MAHI_LIVE", "local")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let (thread, _key) = running_thread(&fixture);
        let bob = teammate(&fixture, "bob");
        let ticket = invite_teammate(&fixture, thread, &bob);
        let join = |socket: &Path| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_mahi"));
            command
                .args(["join", &ticket, "--", "true"])
                .current_dir(&bob.repo);
            teammate_env(&mut command, &bob, "bob");
            let output = command
                .env("SSH_AUTH_SOCK", socket)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            (
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
        };
        let rotated = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let elsewhere = fixture.root.join("rotated-agent.sock");
        serve_signatures(&elsewhere, rotated.clone(), None);

        let (code, stderr) = join(&elsewhere);
        assert_eq!(code, Some(1), "{stderr}");
        assert!(
            stderr.contains("does not hold your signing key"),
            "{stderr}"
        );
        assert!(
            !stderr.contains("waiting for the thread's host"),
            "{stderr}"
        );

        let config = config_dir(&bob.home);
        fs::remove_file(config.signing_key_file()).unwrap();
        SigningKey::try_from(rotated.public_key().clone())
            .unwrap()
            .save(&config.signing_key_file())
            .unwrap();
        let (code, stderr) = join(&elsewhere);
        assert_eq!(code, Some(1), "{stderr}");
        assert!(
            stderr.contains("lists another signing key for you"),
            "{stderr}"
        );
        assert!(!stderr.contains("Passphrase"), "{stderr}");
    }

    #[test]
    fn a_teammate_runs_their_own_agent_in_the_owners_thread() {
        let fixture = fixture();
        save_identity(&fixture);
        let mut host = fixture.command(&["run", "sh", "-c", "sleep 60"]);
        let _host = KillOnDrop(
            host.env("MAHI_LIVE", "local")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let (thread, _key) = running_thread(&fixture);
        let bob = teammate(&fixture, "bob");
        let ticket = invite_teammate(&fixture, thread, &bob);
        assert_eq!(
            Store::open(&bob.repo).unwrap().head_commit().unwrap(),
            fixture.base,
            "repository_on_main writes the same base commit in both clones"
        );

        let (code, text) = teammate_in_terminal(
            &bob,
            "bob",
            &[
                "join",
                &ticket,
                "--",
                "sh",
                "-c",
                "printf 'bob agent in %s' \"$(basename \"$PWD\")\"; echo change > bob.txt",
            ],
        );
        assert_eq!(code, 0, "{text}");
        assert!(text.contains(&format!("bob agent in {thread}")), "{text}");

        let store = Store::open(&bob.repo).unwrap();
        let owner = mahi_thread::remembered_owner(&store, thread)
            .unwrap()
            .unwrap();
        assert_eq!(owner, fixture.owner);
        load_meta(&store, thread, &owner, 1).unwrap();
        let bob_git = gix::open(&bob.repo).unwrap();
        let snapshots = bob_git
            .find_reference(format!("refs/threads/{thread}/agents/bob.sh/snapshots").as_str())
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .tree()
            .unwrap();
        assert!(snapshots.find_entry("bob.txt").is_some());

        let thread_text = thread.to_string();
        let (code, text) = teammate_in_terminal(
            &bob,
            "bob",
            &[
                "resume",
                &thread_text,
                "--",
                "sh",
                "-c",
                "printf 'bob resumed'; echo more > more.txt",
            ],
        );
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("bob resumed"), "{text}");
        let resumed_tree = bob_git
            .find_reference(format!("refs/threads/{thread}/agents/bob.sh/snapshots").as_str())
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .tree()
            .unwrap();
        assert!(resumed_tree.find_entry("bob.txt").is_some());
        assert!(resumed_tree.find_entry("more.txt").is_some());
        let snapshots = ThreadRef::new(
            thread,
            RefKind::Snapshots(AgentSlot::new(
                ParticipantName::new("bob").unwrap(),
                AgentName::new("sh").unwrap(),
            )),
        );
        all_signed_by(&store, &snapshots, &bob.key);

        let mut end = Command::new(env!("CARGO_BIN_EXE_mahi"));
        end.args(["end", &thread_text]).current_dir(&bob.repo);
        teammate_env(&mut end, &bob, "bob");
        let ended = end.output().unwrap();
        assert_eq!(
            ended.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&ended.stderr)
        );
        let bob_store = Store::open(&bob.repo).unwrap();
        assert!(bob_store.worktree_dir(&thread_text).is_err());
        assert!(
            !bob_store
                .common_dir()
                .join("mahi/state")
                .join(&thread_text)
                .exists()
        );
        load_meta(&bob_store, thread, &fixture.owner, 1).unwrap();
    }

    #[test]
    fn run_needs_mahi_init_a_repository_and_a_branch() {
        let fixture = fixture();
        let uninitialised = fixture.root.join("fresh-home");
        fs::create_dir(&uninitialised).unwrap();
        let output = fixture
            .command(&["run", "true"])
            .env("HOME", &uninitialised)
            .env("XDG_CONFIG_HOME", uninitialised.join(".config"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("run mahi init first"));

        let node_key = config_dir(&fixture.home).node_key_file();
        let saved = fs::read(&node_key).unwrap();
        fs::remove_file(&node_key).unwrap();
        let output = fixture.command(&["run", "true"]).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("run mahi init first"));
        assert!(fixture.threads().is_empty());
        fs::write(&node_key, saved).unwrap();
        fs::set_permissions(&node_key, fs::Permissions::from_mode(0o600)).unwrap();

        let elsewhere = tempfile::tempdir().unwrap();
        let output = fixture
            .command(&["run", "true"])
            .current_dir(elsewhere.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot open the git repository"));

        fs::write(
            fixture.repo.join(".git/HEAD"),
            format!("{}\n", fixture.base),
        )
        .unwrap();
        let output = fixture.mahi(&["run", "true"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("not on a local branch"));
        assert!(fixture.threads().is_empty());
    }

    fn run_with_input(arguments: &[&str], input: &[u8]) -> (Option<i32>, String) {
        let fixture = fixture();
        let mut child = fixture
            .command(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                child.kill().unwrap();
                panic!("mahi run did not finish after its input ended");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    #[test]
    fn piped_input_reaches_the_agent_and_its_end_finishes_the_agent() {
        let (code, stdout) = run_with_input(
            &["run", "sh", "-c", "read line; echo got=$line; cat"],
            b"piped-line\nrest\n",
        );
        assert_eq!(code, Some(0), "{stdout}");
        assert!(stdout.contains("got=piped-line"), "{stdout}");
    }

    #[test]
    fn a_last_line_without_a_newline_still_ends_the_input() {
        let (code, stdout) = run_with_input(
            &["run", "sh", "-c", "cat > /dev/null; echo input-ended"],
            b"no newline at the end",
        );
        assert_eq!(code, Some(0), "{stdout}");
        assert!(stdout.contains("input-ended"), "{stdout}");
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    struct KillOnDrop(std::process::Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn a_closed_output_ends_mahi_and_the_agent() {
        let fixture = fixture();
        let mut child = KillOnDrop(
            fixture
                .command(&["run", "sh", "-c", "while :; do echo line; done"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut first = [0_u8; 5];
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_exact(&mut first)
            .unwrap();
        let mut status = None;
        wait_until("mahi to exit after its output closed", || {
            status = child.0.try_wait().unwrap();
            status.is_some()
        });
        assert_eq!(status.unwrap().code(), Some(141));
    }

    #[test]
    fn a_stop_signal_ends_the_agent_and_restores_the_terminal() {
        let fixture = fixture();
        let mut mahi = PtyCommand::new(
            Path::new(env!("CARGO_BIN_EXE_mahi")),
            &fixture.repo,
            WindowSize { rows: 24, cols: 80 },
        )
        .arg("run")
        .arg("sleep")
        .arg("60")
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &fixture.home)
        .env("XDG_CONFIG_HOME", fixture.home.join(".config"))
        .env("SSH_AUTH_SOCK", &fixture.socket)
        .env("USER", "tester")
        .env("MAHI_LIVE", "off")
        .spawn()
        .unwrap();
        let terminal = mahi.writer().unwrap();
        let canonical = |terminal: &fs::File| {
            rustix::termios::tcgetattr(terminal)
                .unwrap()
                .local_modes
                .contains(LocalModes::ICANON)
        };
        let mut reader = mahi.reader().unwrap();
        thread::spawn(move || {
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
        wait_until("raw mode", || !canonical(&terminal));
        let pid = rustix::process::Pid::from_raw(i32::try_from(mahi.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let mut status = None;
        wait_until("mahi to exit", || {
            status = mahi.try_wait().unwrap();
            status.is_some()
        });
        assert_eq!(exit_code(status.unwrap()), 128 + 15);
        assert!(canonical(&terminal));
    }

    #[test]
    fn a_stop_signal_without_a_terminal_makes_mahi_die_of_it() {
        let fixture = fixture();
        let mut child = KillOnDrop(
            fixture
                .command(&["run", "sh", "-c", "echo ready; exec sleep 60"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut output = child.0.stdout.take().unwrap();
        let mut seen = Vec::new();
        while !seen.windows(5).any(|window| window == b"ready") {
            let mut chunk = [0_u8; 64];
            let read = output.read(&mut chunk).unwrap();
            assert_ne!(read, 0, "the agent never became ready");
            seen.extend_from_slice(&chunk[..read]);
        }
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.0.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::HUP).unwrap();
        let mut status = None;
        wait_until("mahi to exit", || {
            status = child.0.try_wait().unwrap();
            status.is_some()
        });
        assert_eq!(status.unwrap().signal(), Some(libc::SIGHUP));
        drop(output);
    }

    #[test]
    fn usage_errors_and_missing_agents_are_reported_without_a_thread() {
        let fixture = fixture();
        let unknown = fixture.mahi(&["jump"]);
        assert_eq!(unknown.status.code(), Some(2));
        let unknown_error = String::from_utf8_lossy(&unknown.stderr);
        assert!(
            unknown_error.contains("unrecognized subcommand 'jump'"),
            "{unknown_error}"
        );
        assert!(unknown_error.contains("Usage: mahi"), "{unknown_error}");
        let missing = fixture.mahi(&["run", "no-such-agent-anywhere"]);
        assert_eq!(missing.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("cannot find"));
        assert!(fixture.threads().is_empty());
    }

    #[test]
    fn help_and_version_succeed() {
        let fixture = fixture();
        let help = fixture.mahi(&["--help"]);
        assert!(help.status.success());
        let help_text = String::from_utf8_lossy(&help.stdout);
        assert!(help_text.contains("Usage: mahi <COMMAND>"), "{help_text}");
        assert!(help_text.contains("Exit codes"), "{help_text}");
        let run_help = fixture.mahi(&["run", "--help"]);
        assert!(run_help.status.success());
        let run_help_text = String::from_utf8_lossy(&run_help.stdout);
        assert!(
            run_help_text.contains("Usage: mahi run [OPTIONS] <AGENT>"),
            "{run_help_text}"
        );
        let version = fixture.mahi(&["--version"]);
        assert!(String::from_utf8_lossy(&version.stdout).starts_with("mahi "));
    }
}
