//! Runs mahi's SSH client against OpenSSH's `sshd` and `ssh-agent` in every combination of key
//! exchange, cipher and host key it supports, through rekeys and large transfers; it needs
//! OpenSSH, and runs with `just test-git`.

#[cfg(test)]
#[path = "openssh/mod.rs"]
mod openssh;

#[cfg(test)]
mod tests {
    use std::{
        io::{
            Read,
            Write,
        },
        path::Path,
    };

    use mahi_ssh::{
        RemoteFailure,
        SshSession,
    };
    use tokio::runtime::Runtime;

    use crate::openssh::{
        self,
        OpenSsh,
    };

    fn runtime() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn connect(runtime: &Runtime, server: &OpenSsh) -> SshSession {
        runtime
            .block_on(SshSession::connect(
                &server.remote(Path::new("/repo")),
                &server.known_hosts,
                &server.agent,
                "nobody",
                None,
            ))
            .unwrap_or_else(|error| panic!("{error}: {}", server.log()))
    }

    fn output_of(
        runtime: &Runtime,
        session: &SshSession,
        command: &str,
    ) -> std::io::Result<Vec<u8>> {
        let (mut output, mut input) = runtime
            .block_on(session.exec(command, &[]))
            .unwrap()
            .split();
        input.finish()?;
        let mut said = Vec::new();
        output.read_to_end(&mut said)?;
        Ok(said)
    }

    #[test]
    fn every_key_exchange_cipher_and_host_key_works_with_openssh() {
        let runtime = runtime();
        let offered = std::process::Command::new("ssh")
            .args(["-Q", "kex"])
            .output()
            .expect("OpenSSH's ssh is installed");
        let offered = String::from_utf8(offered.stdout).unwrap();
        let offered: Vec<&str> = offered.lines().collect();
        assert!(offered.contains(&"curve25519-sha256"), "{offered:?}");
        let methods = [
            "mlkem768x25519-sha256",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
        ];
        for kex in methods.into_iter().filter(|kex| offered.contains(kex)) {
            for cipher in [
                "chacha20-poly1305@openssh.com",
                "aes256-gcm@openssh.com",
                "aes128-gcm@openssh.com",
            ] {
                for host_key in ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384"] {
                    let server = openssh::start(
                        host_key,
                        &[
                            ("KexAlgorithms", kex),
                            ("Ciphers", cipher),
                            ("HostKeyAlgorithms", host_key),
                        ],
                    );
                    let session = connect(&runtime, &server);
                    let said = output_of(&runtime, &session, "echo hello")
                        .unwrap_or_else(|error| panic!("{error}: {}", server.log()));
                    assert_eq!(said, b"hello\n", "{kex} {cipher} {host_key}");
                    runtime.block_on(session.close()).unwrap();
                }
            }
        }
    }

    #[test]
    fn megabytes_round_trip_while_the_server_rekeys() {
        let runtime = runtime();
        let server = openssh::start(
            "ssh-ed25519",
            &[("RekeyLimit", "64K"), ("LogLevel", "DEBUG1")],
        );
        let session = connect(&runtime, &server);
        let (mut output, mut input) = runtime.block_on(session.exec("cat", &[])).unwrap().split();
        let sent: Vec<u8> = (0..4_000_000u32)
            .map(|i| (i.wrapping_mul(7) % 251) as u8)
            .collect();
        let writer = {
            let sent = sent.clone();
            std::thread::spawn(move || {
                for piece in sent.chunks(65_000) {
                    input.write_all(piece).unwrap();
                }
                input.finish().unwrap();
            })
        };
        let mut received = Vec::new();
        output
            .read_to_end(&mut received)
            .unwrap_or_else(|error| panic!("{error}: {}", server.log()));
        writer.join().unwrap();
        assert!(
            received == sent,
            "{} of {} bytes",
            received.len(),
            sent.len()
        );
        assert!(
            server.log().matches("rekey").count() > 1,
            "{}",
            server.log()
        );
    }

    fn failure(
        runtime: &Runtime,
        (session, server): (&SshSession, &OpenSsh),
        command: &str,
    ) -> RemoteFailure {
        let error = output_of(runtime, session, command).unwrap_err();
        let shown = format!("{error:?}");
        *error
            .into_inner()
            .and_then(|inner| inner.downcast::<RemoteFailure>().ok())
            .unwrap_or_else(|| panic!("{shown}: {}", server.log()))
    }

    #[test]
    fn exit_statuses_and_errors_come_back_from_openssh() {
        let runtime = runtime();
        let server = openssh::start("ssh-ed25519", &[]);
        let session = connect(&runtime, &server);
        assert_eq!(
            failure(&runtime, (&session, &server), "exit 7"),
            RemoteFailure::Status(7)
        );
        assert_eq!(
            failure(
                &runtime,
                (&session, &server),
                "echo 'no such repository' >&2; exit 1"
            ),
            RemoteFailure::Said("no such repository".to_owned())
        );
        assert_eq!(output_of(&runtime, &session, "true").unwrap(), b"");
        assert_eq!(server.protocols().len(), 3);
    }
}
