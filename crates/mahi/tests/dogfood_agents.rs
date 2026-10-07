//! Runs the real Claude Code and Codex through mahi end to end: a thread, a handoff, a resume
//! and a landing, with the user's own sign-ins. `just dogfood` runs it; see the justfile.

#![cfg(unix)]

#[cfg(test)]
mod tests {
    use std::{
        env,
        fs,
        io::{
            Read,
            Write,
        },
        os::unix::fs::PermissionsExt,
        path::{
            Path,
            PathBuf,
        },
        process::{
            Child,
            Command,
            Stdio,
        },
        sync::mpsc,
        thread,
        time::{
            Duration,
            Instant,
        },
    };

    use mahi_sandbox::{
        PtyChild,
        PtyCommand,
        WindowSize,
        exit_code,
    };

    const PASSPHRASE: &str = "dogfood-passphrase";
    const PASSPHRASE_PROMPT: &str = "Passphrase for your mahi key:";
    const SIZE: WindowSize = WindowSize {
        rows: 50,
        cols: 160,
    };
    const CLAUDE_TASK: &str = "Add a subtract(a, b) function to calc.py, and a test_calc.py that \
                               checks add and subtract with plain asserts. Run it with python3 \
                               test_calc.py, then say in one sentence what you did.";
    const CODEX_TASK: &str = "Now add multiply(a, b) to calc.py with asserts for it in \
                              test_calc.py, and run python3 test_calc.py.";
    const KEY_GAP: Duration = Duration::from_secs(2);

    struct World {
        root: tempfile::TempDir,
        _agent: KillOnDrop,
    }

    struct KillOnDrop(Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    impl World {
        fn home(&self) -> PathBuf {
            self.root.path().join("home")
        }

        fn repo(&self) -> PathBuf {
            self.root.path().join("repo")
        }

        fn socket(&self) -> PathBuf {
            self.root.path().join("agent.sock")
        }

        fn command(&self, arguments: &[&str]) -> PtyCommand {
            let mut command = PtyCommand::new(&mahi_binary(), &self.repo(), SIZE);
            for argument in arguments {
                command = command.arg(argument);
            }
            command
                .env("PATH", required_env("PATH"))
                .env("HOME", self.home())
                .env("XDG_CONFIG_HOME", self.home().join(".config"))
                .env("SSH_AUTH_SOCK", self.socket())
                .env("USER", "tester")
                .env("TERM", "xterm-256color")
                .env("MAHI_LIVE", "off")
        }

        fn worktree(&self, thread: &str, agent: &str) -> PathBuf {
            let worktrees = self.home().join(".local/share/mahi/worktrees");
            let repository = fs::read_dir(&worktrees)
                .unwrap()
                .next()
                .expect("mahi made a worktree directory for the repository")
                .unwrap()
                .path();
            repository.join(format!("{thread}{agent}"))
        }

        fn state(&self, thread: &str, agent: &str) -> PathBuf {
            self.repo()
                .join(".git/mahi/state")
                .join(thread)
                .join(format!("tester.{agent}"))
        }
    }

    fn mahi_binary() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_mahi"))
    }

    fn required_env(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the dogfood test"))
    }

    fn require_program(name: &str) {
        let found = env::split_paths(&required_env("PATH"))
            .any(|dir| dir.join(name).metadata().is_ok_and(|meta| meta.is_file()));
        assert!(found, "the dogfood test needs {name} on PATH");
    }

    fn world() -> World {
        for program in [
            "claude",
            "codex",
            "ssh-agent",
            "ssh-keygen",
            "ssh-add",
            "python3",
            "git",
        ] {
            require_program(program);
        }
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        fs::create_dir_all(home.join(".config")).unwrap();
        let socket = root.path().join("agent.sock");
        let agent = KillOnDrop(
            Command::new("ssh-agent")
                .arg("-D")
                .arg("-a")
                .arg(&socket)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "ssh-agent did not start");
            thread::sleep(Duration::from_millis(50));
        }
        let key = root.path().join("id_dogfood");
        run(Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "dogfood", "-f"])
            .arg(&key));
        run(Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", &socket)
            .arg(&key)
            .stderr(Stdio::null()));
        let repo = root.path().join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("calc.py"), "def add(a, b):\n    return a + b\n").unwrap();
        fs::write(repo.join(".gitignore"), "__pycache__/\n").unwrap();
        for arguments in [
            &["init", "-q", "-b", "main"][..],
            &["config", "user.name", "Dogfood"],
            &["config", "user.email", "dogfood@mahi.social"],
            &["add", "."],
            &["commit", "-q", "-m", "Start a tiny calculator"],
        ] {
            run(Command::new("git")
                .args(arguments)
                .current_dir(&repo)
                .env("HOME", &home)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1"));
        }
        World {
            root,
            _agent: agent,
        }
    }

    fn run(command: &mut Command) {
        let status = command.status().unwrap();
        assert!(status.success(), "{command:?} failed");
    }

    struct Terminal {
        child: PtyChild,
        keys: std::fs::File,
        output: mpsc::Receiver<Vec<u8>>,
        parser: vt100::Parser,
        raw: Vec<u8>,
        changed: Instant,
        sent: Option<Instant>,
        ended: Option<i32>,
    }

    impl Terminal {
        fn start(command: PtyCommand) -> Self {
            let child = command.spawn().unwrap();
            let mut reader = child.reader().unwrap();
            let keys = child.writer().unwrap();
            let (sender, output) = mpsc::channel();
            thread::spawn(move || {
                let mut buffer = [0_u8; 8192];
                while let Ok(read) = reader.read(&mut buffer) {
                    if read == 0 || sender.send(buffer[..read].to_vec()).is_err() {
                        break;
                    }
                }
            });
            Self {
                child,
                keys,
                output,
                parser: vt100::Parser::new(SIZE.rows, SIZE.cols, 0),
                raw: Vec::new(),
                changed: Instant::now(),
                sent: None,
                ended: None,
            }
        }

        fn pump(&mut self) {
            while let Ok(chunk) = self.output.recv_timeout(Duration::from_millis(100)) {
                self.parser.process(&chunk);
                self.raw.extend_from_slice(&chunk);
                self.changed = Instant::now();
            }
            if self.ended.is_none()
                && let Some(status) = self.child.try_wait().unwrap()
            {
                self.ended = Some(exit_code(status));
            }
        }

        fn screen(&self) -> String {
            self.parser.screen().contents()
        }

        fn raw_text(&self) -> String {
            String::from_utf8_lossy(&self.raw).into_owned()
        }

        fn quiet_for(&self, time: Duration) -> bool {
            self.changed.elapsed() >= time
        }

        fn send(&mut self, keys: &str) -> bool {
            if self.sent.is_some_and(|sent| sent.elapsed() < KEY_GAP) {
                return false;
            }
            self.send_now(keys);
            true
        }

        fn send_now(&mut self, keys: &str) {
            for chunk in keys.as_bytes().chunks(8) {
                self.keys.write_all(chunk).unwrap();
                thread::sleep(Duration::from_millis(30));
            }
            self.sent = Some(Instant::now());
        }

        fn answer_dialogs(&mut self, passphrases: &mut usize) {
            let asked = self.raw_text().matches(PASSPHRASE_PROMPT).count();
            if asked > *passphrases && self.send(&format!("{PASSPHRASE}\r")) {
                *passphrases = asked;
            }
            let screen = self.screen();
            let selected = |label: &str| {
                screen.lines().any(|line| {
                    line.contains(label)
                        && (line.contains('\u{276f}') || line.trim_start().starts_with('\u{203a}'))
                })
            };
            let keys = if screen.contains("Yes, I trust this folder")
                && screen.contains("Enter to confirm")
            {
                Some(if selected("Yes, I trust this folder") {
                    "\r"
                } else {
                    "\x1b[B"
                })
            } else if screen.contains("Trust and continue") && selected("Trust and continue") {
                Some("\r")
            } else if screen.contains("Hooks need review") {
                Some(if selected("Trust all and continue") {
                    "\r"
                } else {
                    "2"
                })
            } else {
                None
            };
            if let Some(keys) = keys {
                self.send(keys);
            }
        }

        fn drive(&mut self, limit: Duration, mut done: impl FnMut(&mut Self) -> bool) {
            let deadline = Instant::now() + limit;
            let mut passphrases = 0;
            loop {
                self.pump();
                if done(self) || self.ended.is_some() {
                    return;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out; the screen was:\n{}",
                    self.screen()
                );
                self.answer_dialogs(&mut passphrases);
            }
        }

        fn quit(mut self, keys: &[&str]) -> String {
            for key in keys {
                self.send_now(key);
                thread::sleep(Duration::from_secs(1));
            }
            self.drive(Duration::from_secs(60), |_| false);
            assert_eq!(self.ended, Some(0), "the screen was:\n{}", self.screen());
            self.raw_text()
        }
    }

    fn thread_of(output: &str) -> String {
        output
            .split("mahi: thread ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("mahi names the thread")
            .to_owned()
    }

    fn contains(path: &Path, needle: &str) -> bool {
        fs::read_to_string(path).is_ok_and(|text| text.contains(needle))
    }

    fn rollout_text(state: &Path) -> String {
        let mut text = String::new();
        let mut dirs = vec![state.join("sessions")];
        while let Some(dir) = dirs.pop() {
            for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path
                    .extension()
                    .is_some_and(|extension| extension == "jsonl")
                {
                    text.push_str(&fs::read_to_string(&path).unwrap_or_default());
                }
            }
        }
        text
    }

    fn init_with_claude_token(world: &World, token: &[u8]) {
        let mut init = Terminal::start(world.command(&["init"]));
        let mut answered = 0;
        init.drive(Duration::from_secs(60), |terminal| {
            let text = terminal.raw_text();
            let asked =
                text.matches("New passphrase:").count() + text.matches("Repeat it:").count();
            if asked > answered
                && terminal.quiet_for(Duration::from_millis(300))
                && terminal.send(&format!("{PASSPHRASE}\r"))
            {
                answered = asked;
            }
            false
        });
        init.quit(&[]);
        let mut store = Command::new(mahi_binary())
            .args(["credential", "add", "claude"])
            .current_dir(world.repo())
            .env_clear()
            .env("PATH", required_env("PATH"))
            .env("HOME", world.home())
            .env("XDG_CONFIG_HOME", world.home().join(".config"))
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        store.stdin.take().unwrap().write_all(token).unwrap();
        assert!(store.wait().unwrap().success());
    }

    fn claude_works_in_a_new_thread(world: &World) -> String {
        let mut claude = Terminal::start(world.command(&["run", "claude", CLAUDE_TASK]));
        let mut thread = String::new();
        claude.drive(Duration::from_secs(600), |terminal| {
            if thread.is_empty() && terminal.raw_text().contains("mahi: thread ") {
                thread = thread_of(&terminal.raw_text());
            }
            !thread.is_empty()
                && contains(
                    &world.worktree(&thread, ".claude").join("test_calc.py"),
                    "subtract",
                )
                && terminal.quiet_for(Duration::from_secs(20))
        });
        claude.quit(&["/exit", "\r"]);
        thread
    }

    fn codex_takes_over_and_extends(world: &World, thread: &str, codex_auth: &Path) {
        let state = world.state(thread, "codex");
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(codex_auth, state.join("auth.json")).unwrap();
        fs::set_permissions(state.join("auth.json"), fs::Permissions::from_mode(0o600)).unwrap();
        let tree = world.worktree(thread, ".codex");
        let mut codex = Terminal::start(world.command(&[
            "handoff",
            thread,
            "--from",
            "tester.claude",
            "--",
            "codex",
        ]));
        let started = Instant::now();
        let mut asked = false;
        codex.drive(Duration::from_mins(15), |terminal| {
            let idle = terminal.screen().contains("Ask Codex to do anything")
                && terminal.quiet_for(Duration::from_secs(8))
                && started.elapsed() > Duration::from_secs(20);
            if !asked && idle {
                terminal.send_now(CODEX_TASK);
                thread::sleep(Duration::from_secs(1));
                terminal.send_now("\r");
                asked = true;
                return false;
            }
            asked && idle && contains(&tree.join("calc.py"), "multiply")
        });
        codex.quit(&["\x03", "\x03"]);
        assert!(
            rollout_text(&state).contains("The previous agent's latest replies"),
            "Codex read a briefing that quotes Claude's replies"
        );
    }

    fn codex_resumes_without_asking_about_hooks(world: &World, thread: &str) {
        let mut again = Terminal::start(world.command(&["resume", thread, "--agent", "codex"]));
        again.drive(Duration::from_mins(2), |terminal| {
            terminal.screen().contains("Ask Codex to do anything")
                && terminal.quiet_for(Duration::from_secs(5))
        });
        assert!(
            !again.raw_text().contains("Hooks need review"),
            "the hooks were approved once, so a resume does not ask again"
        );
        again.quit(&["\x03", "\x03"]);
    }

    fn both_land_cleanly(world: &World, thread: &str) {
        let output = Terminal::start(world.command(&["land", thread])).quit(&[]);
        assert!(!output.contains("conflict"), "{output}");
        let landing = world.worktree(thread, "@land");
        let tested = Command::new("python3")
            .arg("test_calc.py")
            .current_dir(&landing)
            .status()
            .unwrap();
        assert!(tested.success(), "the landed tests pass");
        for name in ["add", "subtract", "multiply"] {
            assert!(
                contains(&landing.join("calc.py"), &format!("def {name}(")),
                "{name}"
            );
        }
    }

    #[test]
    fn claude_hands_off_to_codex_which_resumes_and_both_land_cleanly() {
        let token = fs::read(required_env("MAHI_DOGFOOD_CLAUDE_TOKEN"))
            .expect("MAHI_DOGFOOD_CLAUDE_TOKEN names a readable file");
        let codex_auth = PathBuf::from(required_env("MAHI_DOGFOOD_CODEX_AUTH"));
        assert!(codex_auth.is_file(), "MAHI_DOGFOOD_CODEX_AUTH names a file");
        let world = world();
        init_with_claude_token(&world, &token);
        let thread = claude_works_in_a_new_thread(&world);
        codex_takes_over_and_extends(&world, &thread, &codex_auth);
        codex_resumes_without_asking_about_hooks(&world, &thread);
        both_land_cleanly(&world, &thread);
    }
}
