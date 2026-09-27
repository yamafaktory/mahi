//! Runs `mahi init` in a terminal and checks the files it creates.

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{
            Read,
            Write,
        },
        os::unix::{
            net::UnixListener,
            process::ExitStatusExt,
        },
        path::Path,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use mahi_sandbox::{
        PtyCommand,
        PtyReader,
        WindowSize,
        exit_code,
    };
    use rustix::termios::LocalModes;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    fn serve_one_key(socket: &Path) {
        let listener = UnixListener::bind(socket).unwrap();
        let blob = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_bytes()
            .unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut request = [0_u8; 5];
                if stream.read_exact(&mut request).is_err() {
                    continue;
                }
                let mut body = vec![12, 0, 0, 0, 1];
                body.extend_from_slice(&u32::try_from(blob.len()).unwrap().to_be_bytes());
                body.extend_from_slice(&blob);
                body.extend_from_slice(&0_u32.to_be_bytes());
                let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
                frame.extend_from_slice(&body);
                let _ = stream.write_all(&frame);
            }
        });
    }

    fn read_until(reader: &mut PtyReader, seen: &mut Vec<u8>, text: &str) {
        while !String::from_utf8_lossy(seen).contains(text) {
            let mut chunk = [0_u8; 256];
            let read = reader.read(&mut chunk).unwrap();
            assert_ne!(
                read,
                0,
                "{text:?} never came: {}",
                String::from_utf8_lossy(seen)
            );
            seen.extend_from_slice(&chunk[..read]);
        }
    }

    #[test]
    fn a_stop_signal_at_the_passphrase_prompt_turns_echo_back_on() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        let mut mahi = PtyCommand::new(
            Path::new(env!("CARGO_BIN_EXE_mahi")),
            dir.path(),
            WindowSize { rows: 24, cols: 80 },
        )
        .arg("init")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .spawn()
        .unwrap();
        let mut reader = mahi.reader().unwrap();
        let terminal = mahi.writer().unwrap();
        let mut seen = Vec::new();
        read_until(&mut reader, &mut seen, "New passphrase: ");
        let echo = |terminal: &fs::File| {
            rustix::termios::tcgetattr(terminal)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        };
        assert!(!echo(&terminal));
        let pid = rustix::process::Pid::from_raw(i32::try_from(mahi.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = reader.read_to_end(&mut rest);
            let _ = sender.send(rest);
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = mahi.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() > deadline {
                let report = diagnose(mahi.id(), &receiver);
                mahi.kill().unwrap();
                panic!("mahi kept running after SIGTERM\n{report}");
            }
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert!(echo(&terminal));
    }

    fn diagnose(pid: u32, output: &mpsc::Receiver<Vec<u8>>) -> String {
        let run = |program: &str, arguments: &[&str]| {
            std::process::Command::new(program)
                .args(arguments)
                .output()
                .map_or_else(
                    |error| format!("{program} failed: {error}"),
                    |output| {
                        format!(
                            "{}{}",
                            String::from_utf8_lossy(&output.stdout),
                            String::from_utf8_lossy(&output.stderr)
                        )
                    },
                )
        };
        let pid = pid.to_string();
        let (threads, stacks) = if cfg!(target_os = "macos") {
            (run("ps", &["-M", "-p", &pid]), run("sample", &[&pid, "1"]))
        } else {
            (
                run("ps", &["-L", "-o", "pid,lwp,stat,wchan", "-p", &pid]),
                run("cat", &[&format!("/proc/{pid}/wchan")]),
            )
        };
        let printed = output.try_recv().map_or_else(
            |_| "(the terminal is still open)".to_owned(),
            |bytes| String::from_utf8_lossy(&bytes).into_owned(),
        );
        format!("threads:\n{threads}\nstacks:\n{stacks}\nprinted after the signal:\n{printed}")
    }

    #[test]
    fn init_asks_for_a_passphrase_and_writes_the_identity_files() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        let socket = dir.path().join("agent.sock");
        serve_one_key(&socket);
        let mut mahi = PtyCommand::new(
            Path::new(env!("CARGO_BIN_EXE_mahi")),
            dir.path(),
            WindowSize { rows: 24, cols: 80 },
        )
        .arg("init")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SSH_AUTH_SOCK", &socket)
        .spawn()
        .unwrap();
        let mut reader = mahi.reader().unwrap();
        let mut writer = mahi.writer().unwrap();
        let mut seen = Vec::new();
        read_until(&mut reader, &mut seen, "New passphrase: ");
        writer.write_all(b"correct horse battery\n").unwrap();
        read_until(&mut reader, &mut seen, "Repeat it: ");
        writer.write_all(b"correct horse battery\n").unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = reader.read_to_end(&mut rest);
            let _ = sender.send(rest);
        });
        let rest = receiver.recv_timeout(Duration::from_secs(60)).unwrap();
        seen.extend_from_slice(&rest);
        let output = String::from_utf8_lossy(&seen);
        assert_eq!(exit_code(mahi.wait().unwrap()), 0, "{output}");
        assert!(!output.contains("correct horse"), "{output}");
        assert!(output.contains("mahi key:    age1"), "{output}");
        assert!(output.contains("signing key: SHA256:"), "{output}");
        let config = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/mahi")
        } else {
            home.join(".config/mahi")
        };
        for name in ["identity.age", "identity.pub", "signing-key.pub"] {
            assert!(config.join(name).is_file(), "{name} is missing");
        }
    }
}
