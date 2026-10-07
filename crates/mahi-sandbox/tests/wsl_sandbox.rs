//! Runs a Windows program through WSL 2's interop, outside the Linux sandbox and inside it.

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
        time::{
            Duration,
            Instant,
        },
    };

    use mahi_sandbox::{
        Access,
        PtyCommand,
        Sandbox,
        WindowSize,
        exit_code,
    };

    const WINDOWS_SHELL: &str = "/mnt/c/Windows/System32/cmd.exe";
    const RAN: &str = "ran-Windows_NT";
    const SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };

    fn in_terminal(work: &Path, program: &Path, sandbox: Option<Sandbox>) -> (Option<i32>, String) {
        let mut command = PtyCommand::new(program, work, SIZE)
            .arg("/c")
            .arg("echo ran-%OS%");
        if let Some(interop) = std::env::var_os("WSL_INTEROP") {
            command = command.env("WSL_INTEROP", interop);
        }
        if let Some(sandbox) = sandbox {
            command = command.sandbox(sandbox);
        }
        let mut child = command.spawn().unwrap();
        let mut reader = child.reader().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 || sender.send(buffer[..read].to_vec()).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut output = Vec::new();
        let mut code = None;
        while Instant::now() < deadline && !String::from_utf8_lossy(&output).contains(RAN) {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(chunk) => output.extend_from_slice(&chunk),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if let Some(status) = child.try_wait().unwrap() {
                code = Some(exit_code(status));
                while let Ok(chunk) = receiver.recv_timeout(Duration::from_secs(1)) {
                    output.extend_from_slice(&chunk);
                }
                break;
            }
        }
        if code.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        (code, String::from_utf8_lossy(&output).into_owned())
    }

    #[test]
    fn a_windows_program_runs_outside_the_sandbox_and_not_inside_it() {
        let work = tempfile::tempdir().unwrap();
        let program = work.path().join("cmd.exe");
        fs::copy(WINDOWS_SHELL, &program).expect("WSL 2 with the C: drive mounted");
        let outside = Command::new(&program)
            .args(["/c", "echo ran-%OS%"])
            .current_dir(work.path())
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&outside.stdout).contains(RAN),
            "interop must work outside the sandbox: {outside:?}"
        );
        let (_, output) = in_terminal(work.path(), &program, None);
        assert!(
            output.contains(RAN),
            "interop must work in a terminal: {output}"
        );
        let mut sandbox = Sandbox::system().unwrap();
        sandbox.bind(work.path(), Access::ReadOnly).unwrap();
        let (code, output) = in_terminal(work.path(), &program, Some(sandbox));
        eprintln!("in the sandbox: {code:?} {output:?}");
        assert_ne!(code, Some(0), "{output}");
        assert!(!output.contains(RAN), "{output}");
    }
}
