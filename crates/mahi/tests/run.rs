//! Runs the `mahi` binary and checks what `mahi run` gives the agent.

#[cfg(test)]
mod tests {
    use std::{
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
            Command,
            Output,
            Stdio,
        },
        thread,
        time::{
            Duration,
            Instant,
        },
    };

    fn test_home() -> PathBuf {
        let home = Path::new(env!("CARGO_TARGET_TMPDIR")).join("test-home");
        fs::create_dir_all(&home).unwrap();
        fs::canonicalize(home).unwrap()
    }

    fn mahi_command(arguments: &[&str], cwd: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mahi"));
        command
            .args(arguments)
            .current_dir(cwd)
            .env("PATH", "/usr/bin:/bin:/usr")
            .env("HOME", test_home())
            .env("MAHI_TEST_SECRET", "secret-value");
        command
    }

    fn mahi(arguments: &[&str], cwd: &Path) -> Output {
        mahi_command(arguments, cwd).output().unwrap()
    }

    fn outside_tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        (dir, path)
    }

    #[test]
    fn run_starts_the_agent_in_the_current_directory_and_returns_its_exit_code() {
        let (_dir, cwd) = outside_tmp();
        let output = mahi(
            &[
                "run",
                "--",
                "sh",
                "-c",
                "echo agent-ran; pwd; echo written > file; \
                 echo home=$HOME; echo secret=$MAHI_TEST_SECRET; exit 3",
            ],
            &cwd,
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(3), "{stdout}");
        assert!(stdout.contains("agent-ran"), "{stdout}");
        assert!(stdout.contains(&cwd.display().to_string()), "{stdout}");
        assert!(stdout.contains("home=/"), "{stdout}");
        assert!(
            !stdout.contains(&format!("home={}", test_home().display())),
            "{stdout}"
        );
        assert!(!stdout.contains("secret-value"), "{stdout}");
        assert_eq!(fs::read_to_string(cwd.join("file")).unwrap(), "written\n");
    }

    #[test]
    fn the_agent_cannot_write_beside_the_current_directory_or_into_git() {
        let (_dir, root) = outside_tmp();
        let cwd = root.join("work");
        fs::create_dir_all(cwd.join(".git")).unwrap();
        let outside = root.join("outside");
        let output = mahi(
            &[
                "run",
                "sh",
                "-c",
                &format!(
                    "echo x > {outside} 2>/dev/null; echo outside=$?; \
                     echo x > .git/hook 2>/dev/null; echo git=$?",
                    outside = outside.display()
                ),
            ],
            &cwd,
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{stdout}");
        assert!(
            stdout.contains("outside=") && stdout.contains("git="),
            "{stdout}"
        );
        assert!(!stdout.contains("outside=0"), "{stdout}");
        assert!(!stdout.contains("git=0"), "{stdout}");
        assert!(!outside.exists());
        assert!(!cwd.join(".git/hook").exists());
    }

    #[test]
    fn the_home_directory_is_refused_as_the_working_directory() {
        let (_dir, home) = outside_tmp();
        let output = mahi_command(&["run", "true"], &home)
            .env("HOME", &home)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("holds private files"));
    }

    fn run_with_input(arguments: &[&str], input: &[u8]) -> (Option<i32>, String) {
        let (_dir, cwd) = outside_tmp();
        let mut child = mahi_command(arguments, &cwd)
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

    #[test]
    fn a_closed_output_ends_mahi_and_the_agent() {
        let (_dir, cwd) = outside_tmp();
        let mut child = mahi_command(&["run", "sh", "-c", "while :; do echo line; done"], &cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut first = [0_u8; 5];
        child.stdout.take().unwrap().read_exact(&mut first).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                panic!("mahi run kept going after its output closed");
            }
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(141));
    }

    #[test]
    fn usage_errors_and_missing_agents_are_reported() {
        let (_dir, cwd) = outside_tmp();
        let unknown = mahi(&["jump"], &cwd);
        assert_eq!(unknown.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&unknown.stderr).contains("usage: mahi run"));
        let missing = mahi(&["run", "no-such-agent-anywhere"], &cwd);
        assert_eq!(missing.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("cannot find"));
    }

    #[test]
    fn help_and_version_succeed() {
        let (_dir, cwd) = outside_tmp();
        let help = mahi(&["--help"], &cwd);
        assert!(help.status.success());
        assert!(String::from_utf8_lossy(&help.stdout).contains("usage: mahi run"));
        let version = mahi(&["--version"], &cwd);
        assert!(String::from_utf8_lossy(&version.stdout).starts_with("mahi "));
    }
}
