//! Runs programs in the macOS sandbox and checks what they can read, write and reach.

#![cfg(target_os = "macos")]

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Read,
        net::TcpListener,
        path::{
            Path,
            PathBuf,
        },
        process::Command,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use mahi_sandbox::{
        Access,
        PtyCommand,
        Sandbox,
        WindowSize,
        exit_code,
    };

    const SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };

    fn run(sandbox: Sandbox, cwd: &Path, script: &str) -> (i32, String) {
        run_command(
            PtyCommand::new(Path::new("/bin/sh"), cwd, SIZE)
                .arg("-c")
                .arg(script)
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .sandbox(sandbox),
        )
    }

    fn run_command(command: PtyCommand) -> (i32, String) {
        let mut child = command.spawn().unwrap();
        let mut reader = child.reader().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut output = Vec::new();
            let _ = reader.read_to_end(&mut output);
            let _ = sender.send(output);
        });
        let output = receiver
            .recv_timeout(Duration::from_secs(20))
            .expect("the program closes its terminal");
        let code = exit_code(child.wait().unwrap());
        (code, String::from_utf8_lossy(&output).into_owned())
    }

    fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        (dir, path)
    }

    fn system_with(binds: &[(&Path, Access)]) -> Sandbox {
        let mut sandbox = Sandbox::system().unwrap();
        for (path, access) in binds {
            sandbox.bind(path, *access).unwrap();
        }
        sandbox
    }

    #[test]
    fn system_programs_run_with_a_working_terminal() {
        let (_dir, work) = canonical_tempdir();
        let (code, output) = run(
            system_with(&[(&work, Access::ReadWrite)]),
            &work,
            "echo hello; echo size=$(stty size); echo x > /dev/null && echo null-ok; \
             head -c 4 /dev/urandom | wc -c | tr -d ' ' | sed 's/^/bytes=/'",
        );
        assert_eq!(code, 0, "{output}");
        for expected in ["hello", "size=24 80", "null-ok", "bytes=4"] {
            assert!(output.contains(expected), "{expected} missing: {output}");
        }
    }

    #[test]
    fn only_bound_paths_can_be_read_and_only_read_write_ones_written() {
        let (_dir, root) = canonical_tempdir();
        let docs = root.join("docs");
        let work = root.join("work");
        fs::create_dir_all(&docs).unwrap();
        fs::create_dir_all(&work).unwrap();
        fs::write(docs.join("readme"), "docs-content").unwrap();
        fs::write(root.join("secret"), "secret-content").unwrap();
        let script = format!(
            "cat {docs}/readme; cat {secret} 2>/dev/null || echo secret-denied; \
             echo new > {work}/file && echo rw-ok; \
             echo new > {docs}/other 2>/dev/null || echo ro-denied; \
             echo new > {root}/outside 2>/dev/null || echo outside-denied",
            docs = docs.display(),
            work = work.display(),
            root = root.display(),
            secret = root.join("secret").display(),
        );
        let (code, output) = run(
            system_with(&[(&docs, Access::ReadOnly), (&work, Access::ReadWrite)]),
            &work,
            &script,
        );
        assert_eq!(code, 0, "{output}");
        for expected in [
            "docs-content",
            "secret-denied",
            "rw-ok",
            "ro-denied",
            "outside-denied",
        ] {
            assert!(output.contains(expected), "{expected} missing: {output}");
        }
        assert!(!output.contains("secret-content"), "{output}");
        assert_eq!(fs::read_to_string(work.join("file")).unwrap(), "new\n");
        assert!(!docs.join("other").exists());
        assert!(!root.join("outside").exists());
    }

    #[test]
    fn local_socket_pairs_still_work() {
        let (code, output) = run(
            Sandbox::system().unwrap(),
            Path::new("/"),
            "/usr/bin/perl -MSocket -e 'socketpair(my $a, my $b, AF_UNIX, SOCK_STREAM, 0) \
             or die; print \"pair-ok\\n\"'",
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("pair-ok"), "{output}");
    }

    #[test]
    fn the_network_is_unreachable_even_on_localhost() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (code, output) = run(
            Sandbox::system().unwrap(),
            Path::new("/"),
            &format!(
                "/bin/bash -c 'echo bash-ok'; \
                 /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' 2>/dev/null || echo outside-denied; \
                 /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' 2>/dev/null || echo local-denied"
            ),
        );
        assert_eq!(code, 0, "{output}");
        for expected in ["bash-ok", "outside-denied", "local-denied"] {
            assert!(output.contains(expected), "{expected} missing: {output}");
        }
    }

    #[test]
    fn a_read_only_bind_inside_a_read_write_one_cannot_be_changed_or_moved() {
        let (_dir, work) = canonical_tempdir();
        fs::create_dir_all(work.join("a/ro")).unwrap();
        fs::write(work.join("a/ro/kept"), "original").unwrap();
        let (code, output) = run(
            system_with(&[
                (&work, Access::ReadWrite),
                (&work.join("a/ro"), Access::ReadOnly),
            ]),
            &work,
            "echo x > a/ro/file 2>/dev/null || echo write-denied; \
             mv a/ro moved 2>/dev/null || echo move-denied; \
             mv a b 2>/dev/null || echo parent-move-denied; \
             ln a/ro/kept linked 2>/dev/null; echo evil >> linked 2>/dev/null; \
             echo evil >> A/RO/kept 2>/dev/null; mv A B 2>/dev/null; \
             echo x > a/other && echo sibling-ok",
        );
        assert_eq!(code, 0, "{output}");
        for expected in [
            "write-denied",
            "move-denied",
            "parent-move-denied",
            "sibling-ok",
        ] {
            assert!(output.contains(expected), "{expected} missing: {output}");
        }
        assert!(work.join("a/ro").is_dir());
        assert_eq!(
            fs::read_to_string(work.join("a/ro/kept")).unwrap(),
            "original"
        );
        assert!(!work.join("a/ro/file").exists());
    }

    #[test]
    fn links_from_a_writable_path_do_not_reach_outside_files() {
        let (_dir, root) = canonical_tempdir();
        let work = root.join("work");
        fs::create_dir(&work).unwrap();
        fs::write(root.join("secret"), "secret-content").unwrap();
        let secret = root.join("secret");
        let (code, output) = run(
            system_with(&[(&work, Access::ReadWrite)]),
            &work,
            &format!(
                "ln -s {secret} soft; cat soft 2>/dev/null; \
                 ln {secret} hard 2>/dev/null; cat hard 2>/dev/null; \
                 cat /System/Volumes/Data{secret} 2>/dev/null; echo done",
                secret = secret.display()
            ),
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("done"), "{output}");
        assert!(!output.contains("secret-content"), "{output}");
    }

    struct KillOnDrop(std::process::Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn other_processes_cannot_be_inspected_or_signalled() {
        let outside = KillOnDrop(
            Command::new("/bin/sleep")
                .arg("30")
                .env("MAHI_MARKER", "marker-value")
                .spawn()
                .unwrap(),
        );
        let pid = i32::try_from(outside.0.id()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let visible = process_arguments(pid)
                .is_ok_and(|arguments| contains(&arguments, b"MAHI_MARKER=marker-value"));
            if visible {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the marker is not readable even outside the sandbox"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let exe = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let mut sandbox = Sandbox::system().unwrap();
        sandbox.bind(&exe, Access::ReadOnly).unwrap();
        let (code, output) = run_command(
            PtyCommand::new(&exe, Path::new("/"), SIZE)
                .arg("--exact")
                .arg("tests::other_processes_cannot_be_inspected_or_signalled_inner")
                .arg("--ignored")
                .arg("--nocapture")
                .env("MAHI_OUTSIDE_PID", pid.to_string())
                .sandbox(sandbox),
        );
        drop(outside);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("1 passed"), "{output}");
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    #[ignore = "run inside the sandbox by other_processes_cannot_be_inspected_or_signalled"]
    fn other_processes_cannot_be_inspected_or_signalled_inner() {
        let pid: i32 = std::env::var("MAHI_OUTSIDE_PID")
            .expect("this test only runs inside the sandbox")
            .parse()
            .unwrap();
        assert_eq!(process_arguments(pid), Err(libc::EPERM));
        let target = rustix::process::Pid::from_raw(pid).unwrap();
        assert_eq!(
            rustix::process::test_kill_process(target),
            Err(rustix::io::Errno::PERM)
        );
    }

    #[expect(
        unsafe_code,
        reason = "the test reads another process's arguments with the raw sysctl"
    )]
    fn process_arguments(pid: i32) -> Result<Vec<u8>, i32> {
        let mut name = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut buffer = vec![0_u8; 256 * 1024];
        let mut length = buffer.len();
        // SAFETY: `name` holds three valid MIB entries, `buffer` has `length` writable bytes,
        // and no new value is passed.
        let result = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                3,
                buffer.as_mut_ptr().cast(),
                &raw mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 {
            buffer.truncate(length);
            Ok(buffer)
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }
}
