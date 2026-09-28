//! Runs the `mahi` binary and checks what `mahi run` gives the agent.

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{
            Read,
            Write,
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
        sync::mpsc,
        thread,
        time::{
            Duration,
            Instant,
        },
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
    use mahi_identity::{
        ConfigDir,
        LocalIdentity,
        PublicIdentity,
        SigningKey,
    };
    use mahi_sandbox::{
        PtyCommand,
        WindowSize,
        exit_code,
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

    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        home: PathBuf,
        repo: PathBuf,
        socket: PathBuf,
        base: ObjectId,
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
        initialise(&home, &key);
        serve_signatures(&socket, key, hold);
        Fixture {
            _dir: dir,
            root,
            home,
            repo,
            socket,
            base,
        }
    }

    fn config_dir(home: &Path) -> ConfigDir {
        ConfigDir::resolve(Some(home), Some(&home.join(".config"))).unwrap()
    }

    fn initialise(home: &Path, key: &PrivateKey) {
        let config = config_dir(home);
        fs::create_dir_all(config.path()).unwrap();
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o700)).unwrap();
        PublicIdentity::from(&LocalIdentity::generate())
            .save(&config.recipient_file())
            .unwrap();
        SigningKey::try_from(key.public_key().clone())
            .unwrap()
            .save(&config.signing_key_file())
            .unwrap();
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
                .env("MAHI_TEST_SECRET", "secret-value");
            command
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
        assert!(worktree.starts_with(fixture.repo.join(".git/mahi/worktrees")));
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
        assert!(!fixture.repo.join(".git/mahi/worktrees").exists());
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
        for directory in [".git/mahi/worktrees", ".git/worktrees"] {
            assert_eq!(
                fs::read_dir(fixture.repo.join(directory)).map_or(0, Iterator::count),
                0,
                "{directory}"
            );
        }
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
        assert!(!fixture.repo.join(".git/mahi/worktrees").exists());
        assert!(!fixture.repo.join(".git/worktrees").exists());
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
            run_help_text.contains("Usage: mahi run <AGENT>"),
            "{run_help_text}"
        );
        let version = fixture.mahi(&["--version"]);
        assert!(String::from_utf8_lossy(&version.stdout).starts_with("mahi "));
    }
}
