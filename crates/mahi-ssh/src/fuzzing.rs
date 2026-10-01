//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`: each takes
//! untrusted bytes as an SSH server could send them, and must neither panic nor use more than
//! its bounds allow.

use crate::proto::message::Message;

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
