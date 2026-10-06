//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing` or, to lint them,
//! the `fuzzing` feature: each takes untrusted bytes as an SSH server could send them, and must
//! neither panic nor use more than its bounds allow.

use crate::{
    exec,
    proto::{
        auth::{
            Auth,
            Progress,
        },
        channel::{
            Connection,
            Event,
        },
        cipher::{
            CipherName,
            Opener,
        },
        kex::HostKeyAlgorithm,
        message::Message,
        packet::Inbound,
        transport::{
            Poll,
            Transport,
        },
    },
};

/// Decodes `data` as the payload of an SSH message and checks that encoding what was decoded
/// decodes to the same message.
///
/// # Panics
///
/// Panics if a decoded message does not survive the round trip.
pub fn message(data: &[u8]) {
    let Ok(message) = Message::decode(data) else {
        return;
    };
    let mut encoded = Vec::with_capacity(data.len());
    message
        .encode(&mut encoded)
        .expect("a decoded message fits in a u32-length string");
    assert_eq!(Message::decode(&encoded), Ok(message));
}

/// Reads `data` as a stream of packets from the server, first in the clear and then under each
/// cipher with a fixed key, as far as they open.
///
/// # Panics
///
/// Panics if a fixed key has the wrong length for its cipher.
pub fn packets(data: &[u8]) {
    let mut openers = vec![Opener::clear()];
    for cipher in CipherName::ALL {
        let key = vec![7; cipher.key_len()];
        let iv = vec![1; cipher.iv_len()];
        openers.push(Opener::new(cipher, &key, &iv).expect("the key fits the cipher"));
    }
    for mut opener in openers {
        let mut inbound = Inbound::default();
        let mut sequence = 0u32;
        for chunk in data.chunks(4099) {
            if inbound.push(chunk).is_err() {
                break;
            }
            while let Ok(Some(payload)) = inbound.next(&mut opener, sequence) {
                let _ = Message::decode(payload);
                sequence = sequence.wrapping_add(1);
            }
        }
    }
}

/// Feeds `data` to a new client connection as the server's bytes, in pieces, from the
/// identification line through the key exchange, as far as it gets.
///
/// # Panics
///
/// Panics if a new connection cannot be started, which needs only random bytes.
pub fn transport(data: &[u8]) {
    let mut transport = Transport::new(&HostKeyAlgorithm::ALL).expect("a new connection starts");
    for chunk in data.chunks(1031) {
        let sent = transport.output().len();
        transport.advance_output(sent);
        if transport.receive(chunk).is_err() {
            return;
        }
        loop {
            match transport.poll() {
                Ok(Poll::Message) => {
                    let _ = Message::decode(transport.message());
                }
                Ok(Poll::HostKey) => {
                    if transport.accept_host_key().is_err() {
                        return;
                    }
                }
                Ok(Poll::Pending) => break,
                Err(_) => return,
            }
        }
    }
}

fn established() -> Transport {
    Transport::established().expect("a new connection starts")
}

fn messages(
    transport: &mut Transport,
    data: &[u8],
    mut handle: impl FnMut(&mut Transport, &[u8]) -> bool,
) {
    for chunk in data.chunks(1031) {
        let sent = transport.output().len();
        transport.advance_output(sent);
        if transport.receive(chunk).is_err() {
            return;
        }
        loop {
            match transport.poll() {
                Ok(Poll::Message) => {
                    let payload = transport.message().to_vec();
                    if !handle(transport, &payload) {
                        return;
                    }
                }
                Ok(Poll::Pending) => break,
                Ok(Poll::HostKey) | Err(_) => return,
            }
        }
    }
}

/// Feeds `data` as clear packets from the server to the login of an established connection,
/// signing whatever it is asked to sign with a fixed byte string.
///
/// # Panics
///
/// Panics if a new connection cannot be started, which needs only random bytes.
pub fn login(data: &[u8]) {
    let mut transport = established();
    let key = ssh_key::PublicKey::from_openssh(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    )
    .expect("a fixed key parses");
    let Ok(mut auth) = Auth::start(&mut transport, "git", [key.clone(), key]) else {
        return;
    };
    messages(&mut transport, data, |transport, payload| {
        match auth.handle(transport, payload) {
            Ok(Progress::Sign(_)) => {
                auth.signed(transport, b"\0\0\0\x0bssh-ed25519\0\0\0\0")
                    .is_ok()
                    || auth.sign_refused(transport).is_ok()
            }
            Ok(_) => true,
            Err(_) => false,
        }
    });
}

/// Feeds `data` as clear packets from the server to the channels of an established connection
/// with one session channel opened, reading and sending as a command would.
///
/// # Panics
///
/// Panics if a new connection cannot be started, which needs only random bytes.
pub fn connection(data: &[u8]) {
    let mut transport = established();
    let mut connection = Connection::default();
    let Ok(id) = connection.open_session(&mut transport) else {
        return;
    };
    let _ = connection.keepalive(&mut transport);
    messages(
        &mut transport,
        data,
        |transport, payload| match connection.handle(transport, payload) {
            Ok(Event::Data(channel, data) | Event::Errors(channel, data)) => {
                let length = data.len();
                connection.consumed(transport, channel, length).is_ok()
            }
            Ok(Event::Opened(channel) | Event::WindowOpened(channel)) => {
                let _ = connection.exec(transport, channel, "git-upload-pack 'repo'");
                connection
                    .send_data(transport, channel, &vec![0; 40_000])
                    .is_ok()
            }
            Ok(Event::Eof(channel)) => connection.close(transport, channel).is_ok(),
            Ok(_) => true,
            Err(_) => false,
        },
    );
    let _ = connection.send_eof(&mut transport, id);
}

/// Shows `data` as mahi shows what a remote command wrote to its error stream: nothing that
/// could drive or disguise the terminal is left, and every line after the first is marked as
/// the remote's.
///
/// # Panics
///
/// Panics if a hidden character is left or a later line is not marked, the bug looked for.
pub fn exec_output(data: &[u8]) {
    let shown = exec::printable(data);
    assert!(
        shown
            .chars()
            .all(|c| c == '\n' || c == '\t' || !(c.is_control() || mahi_core::is_invisible(c))),
        "{shown:?}"
    );
    for line in shown.split('\n').skip(1) {
        assert!(line.starts_with("remote: "), "{shown:?}");
    }
    assert!(shown.len() <= data.len() * 11);
}
