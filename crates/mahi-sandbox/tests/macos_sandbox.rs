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
    fn probe_output_written_before_a_late_reader() {
        let (_dir, work) = canonical_tempdir();
        fs::write(work.join("work.txt"), "recorded work\n").unwrap();
        let mut table = Vec::new();
        for sandboxed in [false] {
            for program in ["cat"] {
                for delay in [150_u64, 400] {
                    let mut lost = 0;
                    let mut empty_eof = 0;
                    for _ in 0..80 {
                        let command = if program == "cat" {
                            PtyCommand::new(Path::new("/bin/cat"), &work, SIZE).arg("work.txt")
                        } else {
                            PtyCommand::new(Path::new("/bin/sh"), &work, SIZE)
                                .arg("-c")
                                .arg("cat work.txt")
                        };
                        let command = command.env("PATH", "/usr/bin:/bin");
                        let command = if sandboxed {
                            command.sandbox(system_with(&[(&work, Access::ReadWrite)]))
                        } else {
                            command
                        };
                        let mut child = command.spawn().unwrap();
                        let mut reader = child.reader().unwrap();
                        thread::sleep(Duration::from_millis(delay));
                        while child.try_wait().unwrap().is_none() {
                            thread::sleep(Duration::from_millis(5));
                        }
                        let (sender, receiver) = mpsc::channel();
                        thread::spawn(move || {
                            let mut output = Vec::new();
                            let _ = reader.read_to_end(&mut output);
                            let _ = sender.send(output);
                        });
                        thread::sleep(Duration::from_millis(20));
                        child.release_terminal();
                        let output = receiver.recv_timeout(Duration::from_secs(20)).unwrap();
                        let _ = child.wait();
                        if !String::from_utf8_lossy(&output).contains("recorded work") {
                            lost += 1;
                            if output.is_empty() {
                                empty_eof += 1;
                            }
                        }
                    }
                    table.push(format!(
                        "sandboxed={sandboxed} program={program} delay={delay}ms lost={lost}/80 held empty={empty_eof}"
                    ));
                }
            }
        }
        panic!("PROBE\n{}", table.join("\n"));
    }

    #[test]
    fn homebrew_programs_are_readable_but_its_service_data_is_not() {
        let homebrew = Path::new("/opt/homebrew");
        assert!(
            homebrew.join("bin").is_dir() && homebrew.join("var").is_dir(),
            "this test needs Homebrew in /opt/homebrew, as on GitHub's macOS runners"
        );
        let (_dir, work) = canonical_tempdir();
        let (code, output) = run(
            system_with(&[(&work, Access::ReadWrite)]),
            &work,
            "ls /opt/homebrew/bin > /dev/null && echo bin=ok; \
             ls /opt/homebrew/var > /dev/null 2>&1 && echo var=ok; echo done",
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("done"), "{output}");
        assert!(output.contains("bin=ok"), "{output}");
        assert!(!output.contains("var=ok"), "{output}");
    }

    #[test]
    fn only_the_opened_loopback_port_can_be_reached() {
        let (_dir, work) = canonical_tempdir();
        let opened = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let opened_port = opened.local_addr().unwrap().port();
        let closed_port = closed.local_addr().unwrap().port();
        let mut sandbox = system_with(&[(&work, Access::ReadWrite)]);
        sandbox.open_loopback_port(opened_port).unwrap();
        let script = format!(
            "nc -z -w 2 127.0.0.1 {opened_port} && echo opened=ok; \
             nc -z -w 2 127.0.0.1 {closed_port} && echo closed=ok; echo done"
        );
        let (code, output) = run(sandbox, &work, &script);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("done"), "{output}");
        assert!(output.contains("opened=ok"), "{output}");
        assert!(!output.contains("closed=ok"), "{output}");
    }

    #[test]
    fn only_the_allowed_unix_socket_can_be_reached() {
        let (_dir, root) = canonical_tempdir();
        let work = root.join("work");
        let outside = root.join("outside");
        fs::create_dir(&work).unwrap();
        fs::create_dir(&outside).unwrap();
        let allowed = work.join("allowed.sock");
        let other = work.join("other.sock");
        let host = outside.join("host.sock");
        let _allowed = std::os::unix::net::UnixListener::bind(&allowed).unwrap();
        let _other = std::os::unix::net::UnixListener::bind(&other).unwrap();
        let _host = std::os::unix::net::UnixListener::bind(&host).unwrap();
        let mut sandbox = system_with(&[(&work, Access::ReadWrite)]);
        sandbox.allow_connect(&allowed).unwrap();
        let script = format!(
            "echo x | nc -U -w 1 {allowed} && echo allowed=ok; \
             echo x | nc -U -w 1 {other} && echo other=ok; \
             rm {allowed} && ln {host} {allowed} 2>/dev/null && echo linked=ok; \
             echo x | nc -U -w 1 {allowed} && echo host=ok; echo done",
            allowed = allowed.display(),
            other = other.display(),
            host = host.display(),
        );
        let (code, output) = run(sandbox, &work, &script);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("done"), "{output}");
        assert!(output.contains("allowed=ok"), "{output}");
        assert!(!output.contains("other=ok"), "{output}");
        assert!(!output.contains("host=ok"), "{output}");
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
    fn unlisted_sysctls_and_outside_signals_are_refused() {
        let outside = KillOnDrop(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        let pid = outside.0.id();
        let exe = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let mut sandbox = Sandbox::system().unwrap();
        sandbox.bind(&exe, Access::ReadOnly).unwrap();
        let (code, output) = run_command(
            PtyCommand::new(&exe, Path::new("/"), SIZE)
                .arg("--exact")
                .arg("tests::unlisted_sysctls_and_outside_signals_are_refused_inner")
                .arg("--ignored")
                .arg("--nocapture")
                .env("MAHI_OUTSIDE_PID", pid.to_string())
                .sandbox(sandbox),
        );
        drop(outside);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("1 passed"), "{output}");
    }

    #[test]
    #[ignore = "run inside the sandbox by unlisted_sysctls_and_outside_signals_are_refused"]
    fn unlisted_sysctls_and_outside_signals_are_refused_inner() {
        let pid: i32 = std::env::var("MAHI_OUTSIDE_PID")
            .expect("this test only runs inside the sandbox")
            .parse()
            .unwrap();
        assert_eq!(read_by_name(c"kern.boottime"), Err(libc::EPERM));
        assert_eq!(read_by_name(c"hw.ncpu"), Ok(()));
        let target = rustix::process::Pid::from_raw(pid).unwrap();
        assert_eq!(
            rustix::process::test_kill_process(target),
            Err(rustix::io::Errno::PERM)
        );
    }

    #[expect(
        unsafe_code,
        reason = "the test checks the sysctl allowlist with the raw call"
    )]
    fn read_by_name(name: &std::ffi::CStr) -> Result<(), i32> {
        let mut buffer = [0_u8; 64];
        let mut length = buffer.len();
        // SAFETY: `name` is NUL-terminated, `buffer` has `length` writable bytes, and no new
        // value is passed.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                &raw mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }
}
