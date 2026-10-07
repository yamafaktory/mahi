//! Runs programs in the Linux sandbox and checks what they can see and change.

#![cfg(target_os = "linux")]

#[cfg(test)]
mod tests {
    use std::{
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
        os::unix::net::UnixListener,
        path::Path,
        process::Command,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use mahi_sandbox::{
        Access,
        PtyChild,
        PtyCommand,
        PtyError,
        Sandbox,
        WindowSize,
        exit_code,
    };
    use rustix::{
        event::{
            PollFd,
            PollFlags,
            Timespec,
        },
        io::Errno,
        process::PidfdFlags,
    };

    const SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };

    fn run(sandbox: Sandbox, cwd: &Path, script: &str) -> (i32, String) {
        let command = PtyCommand::new(Path::new("/bin/sh"), cwd, SIZE)
            .arg("-c")
            .arg(script);
        run_command(command.sandbox(sandbox))
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
            .recv_timeout(Duration::from_secs(10))
            .expect("the program closes its terminal");
        let code = exit_code(child.wait().unwrap());
        (code, String::from_utf8_lossy(&output).into_owned())
    }

    fn system_with(binds: &[(&Path, Access)]) -> Sandbox {
        let mut sandbox = Sandbox::system().unwrap();
        for (path, access) in binds {
            sandbox.bind(path, *access).unwrap();
        }
        sandbox
    }

    #[test]
    fn the_program_starts_in_its_working_directory_with_its_own_uid() {
        let work = tempfile::tempdir().unwrap();
        let uid = rustix::process::getuid().as_raw();
        let (code, output) = run(
            system_with(&[(work.path(), Access::ReadWrite)]),
            work.path(),
            "echo \"cwd=$(pwd) uid=$(id -u)\"",
        );
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains(&format!("cwd={} uid={uid}", work.path().display())),
            "{output}"
        );
    }

    #[test]
    fn paths_outside_the_sandbox_are_invisible() {
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(root.path().join("secret"), "s").unwrap();
        let home = std::env::var_os("HOME").unwrap();
        let script = format!(
            "test -e {secret} && echo leak; test -e {home:?} && echo home; test -e /var && echo var; \
             ls -A {root}; echo done",
            secret = root.path().join("secret").display(),
            root = root.path().display(),
        );
        let (code, output) = run(system_with(&[(&work, Access::ReadWrite)]), &work, &script);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("done"), "{output}");
        for leak in ["leak", "home", "var", "secret"] {
            assert!(!output.contains(leak), "{leak} is visible: {output}");
        }
    }

    #[test]
    fn writes_reach_read_write_paths_and_fail_elsewhere() {
        let root = tempfile::tempdir().unwrap();
        let docs = root.path().join("docs");
        let work = docs.join("work");
        fs::create_dir_all(&work).unwrap();
        let script = "echo new > work/file && echo ok-rw; \
                      echo new > readme 2>/dev/null || echo ro-denied; \
                      touch /newfile 2>/dev/null || echo root-denied; \
                      echo scratch > /tmp/x && echo tmp-ok";
        let (code, output) = run(
            system_with(&[(&docs, Access::ReadOnly), (&work, Access::ReadWrite)]),
            &docs,
            script,
        );
        assert_eq!(code, 0, "{output}");
        for expected in ["ok-rw", "ro-denied", "root-denied", "tmp-ok"] {
            assert!(output.contains(expected), "{expected} missing: {output}");
        }
        assert_eq!(fs::read_to_string(work.join("file")).unwrap(), "new\n");
        assert!(!docs.join("readme").exists());
    }

    #[test]
    fn a_single_file_can_be_bound() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("config");
        fs::write(&file, "contents").unwrap();
        let (code, output) = run(
            system_with(&[(&file, Access::ReadOnly)]),
            Path::new("/"),
            &format!("cat {}", file.display()),
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("contents"), "{output}");
    }

    #[test]
    fn a_symbolic_link_on_a_bound_path_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        for path in [link.clone(), link.join("inner")] {
            fs::create_dir_all(real.join("inner")).unwrap();
            let result = PtyCommand::new(Path::new("/bin/sh"), Path::new("/"), SIZE)
                .arg("-c")
                .arg("true")
                .sandbox(system_with(&[(&path, Access::ReadWrite)]))
                .spawn();
            assert_eq!(spawn_errno(result), Errno::LOOP, "{}", path.display());
        }
    }

    #[test]
    fn tmp_is_private_and_dev_is_minimal() {
        let marker = tempfile::NamedTempFile::new().unwrap();
        let script = format!(
            "test -e {marker} && echo host-tmp; ls -A /tmp | grep -q . && echo tmp-not-empty; \
             echo x > /dev/null && echo null-ok; echo \"bytes=$(head -c 4 /dev/urandom | wc -c)\"; \
             ls /dev; echo done",
            marker = marker.path().display(),
        );
        let (code, output) = run(Sandbox::system().unwrap(), Path::new("/"), &script);
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains("null-ok") && output.contains("bytes=4") && output.contains("done")
        );
        assert!(
            !output.contains("host-tmp") && !output.contains("tmp-not-empty"),
            "{output}"
        );
        for device in ["sda", "nvme", "kmsg", "mem"] {
            assert!(!output.contains(device), "{device} is visible: {output}");
        }
    }

    #[test]
    fn a_working_directory_outside_the_sandbox_is_a_spawn_error() {
        let outside = tempfile::tempdir().unwrap();
        let result = PtyCommand::new(Path::new("/bin/sh"), outside.path(), SIZE)
            .sandbox(Sandbox::system().unwrap())
            .spawn();
        assert_eq!(spawn_errno(result), Errno::NOENT);
    }

    #[test]
    fn read_only_holds_when_mahi_runs_as_root() {
        let output = Command::new("unshare")
            .arg("--map-root-user")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::read_only_holds_when_mahi_runs_as_root_inner",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .expect("unshare from util-linux runs the test as root in a user namespace");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run by read_only_holds_when_mahi_runs_as_root as root in a user namespace"]
    fn read_only_holds_when_mahi_runs_as_root_inner() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let docs = tempfile::tempdir().unwrap();
        let file = docs.path().join("f");
        fs::write(&file, "orig").unwrap();
        let script = format!(
            "echo uid=$(id -u); mount -o remount,rw,bind {docs} 2>&1; \
             mount -o remount,rw / 2>&1; umount {docs} 2>&1; \
             echo pwned > {file} 2>/dev/null || echo denied",
            docs = docs.path().display(),
            file = file.display(),
        );
        let (_, output) = run(
            system_with(&[(docs.path(), Access::ReadOnly)]),
            Path::new("/"),
            &script,
        );
        assert!(output.contains("uid=0"), "{output}");
        assert!(output.contains("denied"), "{output}");
        assert_eq!(fs::read_to_string(&file).unwrap(), "orig");
    }

    #[test]
    fn the_agent_is_alone_in_its_own_process_namespace() {
        let host_pid = std::process::id();
        assert!(host_pid > 10);
        let script = format!(
            "echo pid=$$; echo procs=$(ls /proc | grep -c '^[0-9][0-9]*$'); \
             test -e /proc/{host_pid} && echo host-visible; \
             ls /proc/1/root >/dev/null 2>&1 || echo init-hidden; \
             ls /proc/1/fd >/dev/null 2>&1 || echo init-fds-hidden"
        );
        let (code, output) = run(Sandbox::system().unwrap(), Path::new("/"), &script);
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("pid=2"), "{output}");
        assert!(output.contains("init-hidden"), "{output}");
        assert!(output.contains("init-fds-hidden"), "{output}");
        assert!(!output.contains("host-visible"), "{output}");
        let procs = output
            .split("procs=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|count| count.parse::<u32>().ok())
            .unwrap();
        assert!(procs <= 6, "{output}");
    }

    #[test]
    fn the_terminal_has_a_name_and_fds_are_listed() {
        let (code, output) = run(
            Sandbox::system().unwrap(),
            Path::new("/"),
            "tty; test -e /dev/fd/0 && echo fd-ok",
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("/dev/console"), "{output}");
        assert!(output.contains("fd-ok"), "{output}");
    }

    #[test]
    fn processes_left_behind_end_with_the_agent() {
        let (code, output) = run(
            Sandbox::system().unwrap(),
            Path::new("/"),
            "setsid sleep 60 & echo started",
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("started"), "{output}");
    }

    #[test]
    fn exit_codes_and_kills_come_through_the_watchers() {
        let (code, _) = run(Sandbox::system().unwrap(), Path::new("/"), "exit 7");
        assert_eq!(code, 7);

        let mut child = PtyCommand::new(Path::new("/bin/sh"), Path::new("/"), SIZE)
            .arg("-c")
            .arg("sleep 30")
            .sandbox(Sandbox::system().unwrap())
            .spawn()
            .unwrap();
        child.kill().unwrap();
        assert_eq!(exit_code(child.wait().unwrap()), 128 + 9);
    }

    #[test]
    fn an_interrupt_reaches_the_agent_and_not_its_watchers() {
        let mut child = PtyCommand::new(Path::new("/bin/sh"), Path::new("/"), SIZE)
            .arg("-c")
            .arg("trap 'echo caught; exit 5' INT; echo ready; while :; do sleep 0.1; done")
            .sandbox(Sandbox::system().unwrap())
            .spawn()
            .unwrap();
        let mut reader = child.reader().unwrap();
        let mut seen = Vec::new();
        while !String::from_utf8_lossy(&seen).contains("ready") {
            let mut chunk = [0u8; 64];
            let read = reader.read(&mut chunk).unwrap();
            assert_ne!(read, 0, "the agent never became ready");
            seen.extend_from_slice(&chunk[..read]);
        }
        child.writer().unwrap().write_all(b"\x03").unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = reader.read_to_end(&mut rest);
            let _ = sender.send(rest);
        });
        let rest = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(String::from_utf8_lossy(&rest).contains("caught"));
        assert_eq!(exit_code(child.wait().unwrap()), 5);
    }

    #[test]
    fn kernel_controls_in_proc_are_read_only_or_hidden() {
        let script = "awk '$5 == \"/proc/sys\" || $5 == \"/proc/sysrq-trigger\" \
                      { split($6, o, \",\"); print $5 \"=\" o[1] }' /proc/self/mountinfo; \
                      test -s /proc/kcore && echo kcore-readable; echo done";
        let (code, output) = run(Sandbox::system().unwrap(), Path::new("/"), script);
        assert_eq!(code, 0, "{output}");
        for expected in ["/proc/sys=ro", "/proc/sysrq-trigger=ro", "done"] {
            assert!(output.contains(expected), "{expected} missing: {output}");
        }
        assert!(!output.contains("kcore-readable"), "{output}");
    }

    #[test]
    fn the_agent_leads_its_own_session_apart_from_its_watchers() {
        let (code, output) = run(
            Sandbox::system().unwrap(),
            Path::new("/"),
            "echo session=$(awk '{print $6}' /proc/$$/stat); trap '' TERM; kill -TERM 0; exit 3",
        );
        assert!(output.contains("session=2"), "{output}");
        assert_eq!(code, 3, "{output}");
    }

    #[test]
    fn a_sandbox_ignoring_hangup_ends_when_mahi_goes_away() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::a_sandbox_ignoring_hangup_ends_when_mahi_goes_away_inner",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}"
        );
        let watcher = stdout
            .split("watcher=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|pid| pid.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
            .unwrap_or_else(|| panic!("no watcher pid in {stdout}"));
        let watcher = match rustix::process::pidfd_open(watcher, PidfdFlags::empty()) {
            Ok(watcher) => watcher,
            Err(Errno::SRCH) => return,
            Err(error) => panic!("cannot watch the watcher: {error}"),
        };
        let mut fds = [PollFd::new(&watcher, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 15,
            tv_nsec: 0,
        };
        let ready = rustix::event::poll(&mut fds, Some(&timeout)).unwrap();
        assert_eq!(ready, 1, "the sandbox outlived its terminal");
    }

    #[test]
    #[ignore = "run by a_sandbox_ignoring_hangup_ends_when_mahi_goes_away, which outlives it"]
    fn a_sandbox_ignoring_hangup_ends_when_mahi_goes_away_inner() {
        let child = PtyCommand::new(Path::new("/bin/sh"), Path::new("/"), SIZE)
            .arg("-c")
            .arg("trap '' HUP; echo ready; while :; do sleep 0.1; done")
            .sandbox(Sandbox::system().unwrap())
            .spawn()
            .unwrap();
        let mut reader = child.reader().unwrap();
        let mut seen = Vec::new();
        while !String::from_utf8_lossy(&seen).contains("ready") {
            let mut chunk = [0u8; 64];
            let read = reader.read(&mut chunk).unwrap();
            assert_ne!(read, 0);
            seen.extend_from_slice(&chunk[..read]);
        }
        println!("watcher={}", child.id());
        std::mem::forget(child);
    }

    #[test]
    fn the_agent_has_loopback_and_no_other_network() {
        let host = tempfile::tempdir().unwrap();
        let socket = host.path().join("host.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut sandbox = Sandbox::system().unwrap();
        sandbox.bind(&exe, Access::ReadOnly).unwrap();
        let (code, output) = run_command(
            PtyCommand::new(&exe, Path::new("/"), SIZE)
                .arg("--exact")
                .arg("tests::the_agent_has_loopback_and_no_other_network_inner")
                .arg("--ignored")
                .arg("--nocapture")
                .env("MAHI_HOST_SOCKET", &socket)
                .sandbox(sandbox),
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("1 passed"), "{output}");
    }

    #[test]
    #[ignore = "run inside the sandbox by the_agent_has_loopback_and_no_other_network"]
    fn the_agent_has_loopback_and_no_other_network_inner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let outside = TcpStream::connect_timeout(
            &SocketAddr::from(([1, 1, 1, 1], 53)),
            Duration::from_secs(2),
        );
        assert_eq!(
            outside.unwrap_err().kind(),
            std::io::ErrorKind::NetworkUnreachable
        );
        let interfaces = fs::read_to_string("/proc/net/dev").unwrap();
        assert!(
            interfaces
                .lines()
                .any(|line| line.trim_start().starts_with("lo:")),
            "{interfaces}"
        );
        let routes = fs::read_to_string("/proc/net/route").unwrap();
        assert_eq!(routes.lines().count(), 1, "{routes}");
        let host_socket =
            std::env::var("MAHI_HOST_SOCKET").expect("this test only runs inside the sandbox");
        let unix = fs::read_to_string("/proc/net/unix").unwrap();
        assert!(!unix.contains(&host_socket), "{unix}");
    }

    const OPENED_PORT: u16 = 3128;

    #[test]
    fn the_caller_accepts_the_agents_connections_on_the_opened_loopback_port() {
        let exe = std::env::current_exe().unwrap();
        let mut sandbox = Sandbox::system().unwrap();
        sandbox.bind(&exe, Access::ReadOnly).unwrap();
        sandbox.open_loopback_port(OPENED_PORT).unwrap();
        let mut child = PtyCommand::new(&exe, Path::new("/"), SIZE)
            .arg("--exact")
            .arg("tests::the_caller_accepts_the_agents_connections_on_the_opened_loopback_port_inner")
            .arg("--ignored")
            .arg("--nocapture")
            .sandbox(sandbox)
            .spawn()
            .unwrap();
        let listener = child.take_loopback_listener().unwrap();
        assert!(child.take_loopback_listener().is_none());
        assert_eq!(listener.local_addr().unwrap().port(), OPENED_PORT);
        let answered = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut ping = [0_u8; 4];
            stream.read_exact(&mut ping).unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").unwrap();
        });
        let mut reader = child.reader().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut output = Vec::new();
            let _ = reader.read_to_end(&mut output);
            let _ = sender.send(output);
        });
        let output = receiver.recv_timeout(Duration::from_secs(20)).unwrap();
        let output = String::from_utf8_lossy(&output);
        assert_eq!(exit_code(child.wait().unwrap()), 0, "{output}");
        assert!(output.contains("1 passed"), "{output}");
        answered.join().unwrap();
    }

    #[test]
    #[ignore = "run inside the sandbox by the_caller_accepts_the_agents_connections_on_the_opened_loopback_port"]
    fn the_caller_accepts_the_agents_connections_on_the_opened_loopback_port_inner() {
        for entry in fs::read_dir("/proc/self/fd").unwrap() {
            let target = fs::read_link(entry.unwrap().path()).unwrap_or_default();
            assert!(
                !target.to_string_lossy().starts_with("socket:"),
                "the agent inherited {}",
                target.display()
            );
        }
        for address in ["127.0.0.1", "0.0.0.0"] {
            assert_eq!(
                TcpListener::bind((address, OPENED_PORT))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::AddrInUse,
                "{address}"
            );
        }
        let mut stream = TcpStream::connect(("127.0.0.1", OPENED_PORT)).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut pong = [0_u8; 4];
        stream.read_exact(&mut pong).unwrap();
        assert_eq!(&pong, b"pong");
    }

    #[test]
    fn without_an_opened_port_there_is_no_loopback_listener() {
        let mut child = PtyCommand::new(Path::new("/bin/sh"), Path::new("/"), SIZE)
            .arg("-c")
            .arg("true")
            .sandbox(Sandbox::system().unwrap())
            .spawn()
            .unwrap();
        assert!(child.take_loopback_listener().is_none());
        let _ = child.wait();
    }

    #[test]
    fn the_agent_cannot_create_nested_user_namespaces() {
        let (code, output) = run(
            Sandbox::system().unwrap(),
            Path::new("/"),
            "command -v unshare >/dev/null || echo missing-unshare; \
             unshare --user true 2>&1 && echo nested-userns; echo done",
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("done"), "{output}");
        assert!(!output.contains("missing-unshare"), "{output}");
        assert!(!output.contains("nested-userns"), "{output}");
        assert!(output.contains("Operation not permitted"), "{output}");
    }

    #[test]
    fn landlock_refuses_device_nodes_and_keeps_proc_and_the_terminal_usable() {
        let (code, output) = run(
            Sandbox::system().unwrap(),
            Path::new("/"),
            "mknod /tmp/device c 1 3 2>&1; echo 1000 > /proc/self/oom_score_adj && echo proc-ok; \
             echo to-stdout > /dev/stdout; echo to-stderr > /dev/stderr; \
             echo size=$(stty size)",
        );
        assert_eq!(code, 0, "{output}");
        for expected in [
            "/tmp/device: Permission denied",
            "proc-ok",
            "to-stdout",
            "to-stderr",
            "size=24 80",
        ] {
            assert!(output.contains(expected), "{expected} missing: {output}");
        }
    }

    #[test]
    fn everyday_file_work_still_succeeds_in_writable_paths() {
        let work = tempfile::tempdir().unwrap();
        let script = "mkdir a b c && echo data > a/f && mv a/f b/f && ln b/f c/hard && \
                      mv c a/c && : > b/f && ln -s f b/link && mkfifo /tmp/fifo && rm -r a && \
                      cp /usr/bin/true ./tool && ./tool && echo all-ok";
        let (code, output) = run(
            system_with(&[(work.path(), Access::ReadWrite)]),
            work.path(),
            script,
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("all-ok"), "{output}");
        assert!(work.path().join("b/f").exists());
    }

    #[test]
    fn a_read_write_file_can_be_bound_and_appended_to() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("settings.json");
        fs::write(&file, "one\n").unwrap();
        let (code, output) = run(
            system_with(&[(&file, Access::ReadWrite)]),
            Path::new("/"),
            &format!("echo two >> {}", file.display()),
        );
        assert_eq!(code, 0, "{output}");
        assert_eq!(fs::read_to_string(&file).unwrap(), "one\ntwo\n");
    }

    #[test]
    fn the_filter_refuses_dangerous_system_calls() {
        let exe = std::env::current_exe().unwrap();
        let mut sandbox = Sandbox::system().unwrap();
        sandbox.bind(&exe, Access::ReadOnly).unwrap();
        let (code, output) = run_command(
            PtyCommand::new(&exe, Path::new("/"), SIZE)
                .arg("--exact")
                .arg("tests::the_filter_refuses_dangerous_system_calls_inner")
                .arg("--ignored")
                .arg("--nocapture")
                .sandbox(sandbox),
        );
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("1 passed"), "{output}");
    }

    #[test]
    #[ignore = "run inside the sandbox by the_filter_refuses_dangerous_system_calls"]
    fn the_filter_refuses_dangerous_system_calls_inner() {
        let flags = usize::try_from(libc::CLONE_NEWUSER).unwrap();
        let high_flags = flags | (1 << 32);
        let tiocsti = usize::try_from(libc::TIOCSTI).unwrap();
        let high_tiocsti = tiocsti | (1 << 32);
        let byte = *b"x";
        let byte = byte.as_ptr() as usize;
        let vsock = usize::try_from(libc::AF_VSOCK).unwrap();
        let high_vsock = vsock | (1 << 32);
        let stream = usize::try_from(libc::SOCK_STREAM).unwrap();
        let denied = [
            ("unshare", raw_syscall(libc::SYS_unshare, [flags, 0, 0])),
            ("keyctl", raw_syscall(libc::SYS_keyctl, [0, 0, 0])),
            (
                "perf_event_open",
                raw_syscall(libc::SYS_perf_event_open, [0, 0, 0]),
            ),
            ("mount", raw_syscall(libc::SYS_mount, [0, 0, 0])),
            (
                "clone with a namespace",
                raw_syscall(libc::SYS_clone, [flags, 0, 0]),
            ),
            ("TIOCSTI", raw_syscall(libc::SYS_ioctl, [0, tiocsti, byte])),
            (
                "clone with high bits",
                raw_syscall(libc::SYS_clone, [high_flags, 0, 0]),
            ),
            (
                "TIOCSTI with high bits",
                raw_syscall(libc::SYS_ioctl, [0, high_tiocsti, byte]),
            ),
            (
                "vsock socket",
                raw_syscall(libc::SYS_socket, [vsock, stream, 0]),
            ),
            (
                "vsock socket with high bits",
                raw_syscall(libc::SYS_socket, [high_vsock, stream, 0]),
            ),
        ];
        for (name, result) in denied {
            assert_eq!(result, Err(libc::EPERM), "{name}");
        }
        let missing = [
            (
                "io_uring_setup",
                raw_syscall(libc::SYS_io_uring_setup, [1, 0, 0]),
            ),
            ("clone3", raw_syscall(libc::SYS_clone3, [0, 0, 0])),
        ];
        for (name, result) in missing {
            assert_eq!(result, Err(libc::ENOSYS), "{name}");
        }
        let clone_fs = usize::try_from(libc::CLONE_FS).unwrap();
        assert_eq!(raw_syscall(libc::SYS_unshare, [clone_fs, 0, 0]), Ok(0));
        assert_eq!(
            fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap(),
            "0\n"
        );
        let unix = usize::try_from(libc::AF_UNIX).unwrap();
        assert!(raw_syscall(libc::SYS_socket, [unix, stream, 0]).is_ok());
        assert!(rustix::termios::tcgetwinsize(std::io::stdin()).is_ok());
        thread::spawn(|| 7).join().unwrap();
        assert!(Command::new("/bin/true").status().unwrap().success());
    }

    #[expect(
        unsafe_code,
        reason = "the test makes raw system calls to check what the filter lets through"
    )]
    fn raw_syscall(nr: libc::c_long, args: [usize; 3]) -> Result<libc::c_long, i32> {
        let [first, second, third] = args;
        // SAFETY: every call is one the filter must refuse before the kernel reads its
        // arguments, or one that fails on the null or zero arguments given; none writes memory.
        let result = unsafe { libc::syscall(nr, first, second, third) };
        if result == -1 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        } else {
            Ok(result)
        }
    }

    fn spawn_errno(result: Result<PtyChild, PtyError>) -> Errno {
        match result {
            Err(PtyError::Spawn(_, error)) => Errno::from_io_error(&error).unwrap(),
            other => panic!("expected a spawn error, got {other:?}"),
        }
    }
}
