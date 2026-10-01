//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`: each takes
//! untrusted bytes as an SSH server could send them, and must neither panic nor use more than
//! its bounds allow.

use crate::proto::{
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
