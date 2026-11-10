//! Runs the real Claude Code through mahi end to end: a thread and its landing, with the user's
//! own sign-in. `just dogfood` runs it; see the justfile.

#![cfg(unix)]

#[cfg(test)]
#[path = "../../mahi-ssh/tests/openssh/mod.rs"]
#[expect(dead_code, reason = "mahi-ssh's own tests use the rest of this helper")]
mod openssh;

#[cfg(test)]
mod tests {
    use std::{
        env,
        fs,
        io::{
            Read,
            Write,
        },
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

    use super::openssh;

    const PASSPHRASE: &str = "dogfood-passphrase";
    const PASSPHRASE_PROMPT: &str = "Passphrase for your mahi key:";
    const SIZE: WindowSize = WindowSize {
        rows: 50,
        cols: 160,
    };
    const CLAUDE_TASK: &str = "Add a subtract(a, b) function to calc.py, and a test_calc.py that \
                               checks add and subtract with plain asserts. Run it with python3 \
                               test_calc.py, then say in one sentence what you did.";
    const LAND_TASK: &str = "Add a subtract(a, b) function to calc.py. Then land the thread with \
                             mahi's land tool, as one commit with a short message, a title and a \
                             description, and say in one sentence what you did.";
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

        fn plain_command(&self, arguments: &[&str]) -> Command {
            let mut command = Command::new(mahi_binary());
            command
                .args(arguments)
                .current_dir(self.repo())
                .env_clear()
                .env("PATH", required_env("PATH"))
                .env("HOME", self.home())
                .env("XDG_CONFIG_HOME", self.home().join(".config"));
            command
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
            git(&repo, arguments);
        }
        World {
            root,
            _agent: agent,
        }
    }

    fn git(dir: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {arguments:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap()
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
        let mut store = world
            .plain_command(&["credential", "add", "claude"])
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

    fn serve_remote(world: &World, server: &openssh::OpenSsh) -> PathBuf {
        server.authorize(&fs::read_to_string(world.root.path().join("id_dogfood.pub")).unwrap());
        fs::create_dir_all(world.home().join(".ssh")).unwrap();
        fs::write(
            world.home().join(".ssh/known_hosts"),
            openssh::known_hosts_line(server.dir.path(), server.port),
        )
        .unwrap();
        let remote = world.root.path().join("remote.git");
        fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare", "-b", "main"]);
        git(
            &world.repo(),
            &["push", "-q", remote.to_str().unwrap(), "main"],
        );
        git(
            &world.repo(),
            &["remote", "add", "up", &server.url(&remote)],
        );
        let chosen = world
            .plain_command(&["remote", "up", "--private"])
            .status()
            .unwrap();
        assert!(chosen.success());
        remote
    }

    fn claude_lands_a_new_thread(world: &World) -> String {
        let mut claude = Terminal::start(world.command(&["run", "claude", LAND_TASK]));
        let mut thread = String::new();
        let (mut confirming, mut result, mut closed) = (None, None, false);
        claude.drive(Duration::from_mins(15), |terminal| {
            if thread.is_empty() && terminal.raw_text().contains("mahi: thread ") {
                thread = thread_of(&terminal.raw_text());
            }
            let screen = terminal.screen();
            assert!(
                !screen.contains("Not pushed:"),
                "the landing was not pushed; the screen was:\n{screen}"
            );
            if screen.contains("Enter pushes  Esc cancels") && shown_past_guard(&mut confirming) {
                terminal.send("\r");
            }
            let pushed = screen.contains("Pushed ") && screen.contains("Esc closes");
            if pushed && shown_past_guard(&mut result) {
                closed |= terminal.send("\x1b");
            }
            closed && terminal.quiet_for(Duration::from_secs(20))
        });
        assert!(
            !thread.is_empty(),
            "mahi named no thread; the screen was:\n{}",
            claude.screen()
        );
        claude.quit(&["/exit", "\r"]);
        thread
    }

    fn shown_past_guard(since: &mut Option<Instant>) -> bool {
        since.get_or_insert_with(Instant::now).elapsed() > Duration::from_secs(1)
    }

    fn its_work_passes_its_tests(world: &World, thread: &str) {
        let worktree = world.worktree(thread, ".claude");
        let tested = Command::new("python3")
            .arg("test_calc.py")
            .current_dir(&worktree)
            .status()
            .unwrap();
        assert!(tested.success(), "the agent's tests pass");
        for name in ["add", "subtract"] {
            assert!(
                contains(&worktree.join("calc.py"), &format!("def {name}(")),
                "{name}"
            );
        }
    }

    fn claude_token() -> Vec<u8> {
        let file = env::var_os("MAHI_DOGFOOD_CLAUDE_TOKEN").map_or_else(
            || PathBuf::from(required_env("HOME")).join(".config/mahi-test-token"),
            PathBuf::from,
        );
        fs::read(&file).unwrap_or_else(|error| {
            panic!(
                "cannot read a Claude Code setup token at {}: {error}; put one there with \
                 claude setup-token, or name its file in MAHI_DOGFOOD_CLAUDE_TOKEN",
                file.display()
            )
        })
    }

    #[test]
    fn claude_works_in_a_new_thread_whose_tests_pass() {
        let token = claude_token();
        let world = world();
        init_with_claude_token(&world, &token);
        let thread = claude_works_in_a_new_thread(&world);
        its_work_passes_its_tests(&world, &thread);
    }

    #[test]
    fn claude_lands_its_thread_through_the_land_tool() {
        let token = claude_token();
        let world = world();
        let server = openssh::start("ssh-ed25519", &[]);
        init_with_claude_token(&world, &token);
        let remote = serve_remote(&world, &server);
        let thread = claude_lands_a_new_thread(&world);
        let branch = format!("mahi/{thread}");
        let main = git(&remote, &["rev-parse", "main"]);
        assert_eq!(git(&remote, &["rev-parse", &format!("{branch}~1")]), main);
        let message = git(&remote, &["log", "-1", "--format=%B", &branch]);
        assert!(
            message.contains(&format!("Thread: {thread}\n")),
            "{message}"
        );
        assert!(message.contains("Agent: tester.claude\n"), "{message}");
        let landed = git(&remote, &["show", &format!("{branch}:calc.py")]);
        assert!(landed.contains("def subtract("), "{landed}");
    }
}
