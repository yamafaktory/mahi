//! Runs programs in the Linux sandbox and checks what they can see and change.

#![cfg(target_os = "linux")]

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Read,
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
    use rustix::io::Errno;

    const SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };

    fn run(sandbox: Sandbox, cwd: &Path, script: &str) -> (i32, String) {
        let mut child = PtyCommand::new(Path::new("/bin/sh"), cwd, SIZE)
            .arg("-c")
            .arg(script)
            .sandbox(sandbox)
            .spawn()
            .unwrap();
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

    fn spawn_errno(result: Result<PtyChild, PtyError>) -> Errno {
        match result {
            Err(PtyError::Spawn(_, error)) => Errno::from_io_error(&error).unwrap(),
            other => panic!("expected a spawn error, got {other:?}"),
        }
    }
}
