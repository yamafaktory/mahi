use std::{
    fmt::Write as _,
    net::{
        TcpListener,
        TcpStream,
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
    time::{
        Duration,
        Instant,
    },
};

use mahi_ssh::{
    KnownHosts,
    SshRemote,
};

pub(crate) struct OpenSsh {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) port: u16,
    pub(crate) known_hosts: KnownHosts,
    pub(crate) agent: PathBuf,
    pub(crate) user: String,
    sshd: Child,
    ssh_agent: Child,
}

impl Drop for OpenSsh {
    fn drop(&mut self) {
        let _ = self.sshd.kill();
        let _ = self.ssh_agent.kill();
        let _ = self.sshd.wait();
        let _ = self.ssh_agent.wait();
    }
}

fn sshd_program() -> PathBuf {
    ["/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .expect("OpenSSH's sshd is installed (openssh-server)")
}

fn run(program: &str, args: &[&str], env: &[(&str, &Path)]) -> String {
    let mut command = Command::new(program);
    command.args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{program} is installed: {error}"));
    assert!(output.status.success(), "{program} {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

fn wait_for(what: &str, ready: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "{what} did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn write_keys(dir: &Path, host_key_type: &str) {
    let host_key = dir.join("host_key");
    let mut keygen = vec!["-q", "-N", "", "-f", host_key.to_str().unwrap()];
    match host_key_type {
        "ecdsa-sha2-nistp256" => keygen.extend(["-t", "ecdsa", "-b", "256"]),
        "ecdsa-sha2-nistp384" => keygen.extend(["-t", "ecdsa", "-b", "384"]),
        _ => keygen.extend(["-t", "ed25519"]),
    }
    run("ssh-keygen", &keygen, &[]);
    let user_key = dir.join("user_key");
    run(
        "ssh-keygen",
        &[
            "-q",
            "-N",
            "",
            "-t",
            "ed25519",
            "-f",
            user_key.to_str().unwrap(),
        ],
        &[],
    );
    let forced = dir.join("forced.sh");
    std::fs::write(
        &forced,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$GIT_PROTOCOL\" >> '{}'\nexec /bin/sh -c \"$SSH_ORIGINAL_COMMAND\"\n",
            dir.join("protocols").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&forced, std::fs::Permissions::from_mode(0o755)).unwrap();
    let user_public = std::fs::read_to_string(user_key.with_extension("pub")).unwrap();
    std::fs::write(
        dir.join("authorized_keys"),
        format!("command=\"{}\" {user_public}", forced.display()),
    )
    .unwrap();
}

fn write_config(dir: &Path, port: u16, options: &[(&str, &str)]) {
    let path = |name: &str| dir.join(name).to_str().unwrap().to_owned();
    let mut config = String::new();
    for (name, value) in options.iter().copied().chain([
        ("ListenAddress", "127.0.0.1"),
        ("Port", &port.to_string()),
        ("HostKey", &path("host_key")),
        ("PidFile", &path("sshd.pid")),
        ("AuthorizedKeysFile", &path("authorized_keys")),
        ("UsePAM", "no"),
        ("StrictModes", "no"),
        ("PasswordAuthentication", "no"),
        ("KbdInteractiveAuthentication", "no"),
        ("AcceptEnv", "GIT_PROTOCOL"),
        ("SetEnv", "SSH_AUTH_SOCK=/nonexistent/mahi-test"),
        ("LogLevel", "VERBOSE"),
    ]) {
        writeln!(config, "{name} {value}").unwrap();
    }
    std::fs::write(dir.join("sshd_config"), config).unwrap();
}

pub(crate) fn start(host_key_type: &str, options: &[(&str, &str)]) -> OpenSsh {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    write_keys(dir.path(), host_key_type);
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    write_config(dir.path(), port, options);
    let log = std::fs::File::create(path("sshd.log")).unwrap();
    let sshd = Command::new(sshd_program())
        .args(["-D", "-e", "-f"])
        .arg(path("sshd_config"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("sshd starts");
    let agent = path("agent.sock");
    let ssh_agent = Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&agent)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("ssh-agent is installed");
    wait_for("ssh-agent", || agent.exists());
    let user_key = path("user_key");
    run(
        "ssh-add",
        &["-q", user_key.to_str().unwrap()],
        &[("SSH_AUTH_SOCK", &agent)],
    );
    wait_for("sshd", || TcpStream::connect(("127.0.0.1", port)).is_ok());
    let host_public = std::fs::read_to_string(path("host_key.pub")).unwrap();
    let known_hosts = KnownHosts::parse(&format!("[127.0.0.1]:{port} {host_public}"));
    let user = run("id", &["-un"], &[]).trim().to_owned();
    OpenSsh {
        dir,
        port,
        known_hosts,
        agent,
        user,
        sshd,
        ssh_agent,
    }
}

impl OpenSsh {
    pub(crate) fn url(&self, path: &Path) -> String {
        format!(
            "ssh://{}@127.0.0.1:{}{}",
            self.user,
            self.port,
            path.display()
        )
    }

    pub(crate) fn remote(&self, path: &Path) -> SshRemote {
        SshRemote::parse(&self.url(path)).unwrap()
    }

    pub(crate) fn protocols(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join("protocols"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    pub(crate) fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("sshd.log")).unwrap_or_default()
    }
}
