//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`: each takes
//! untrusted bytes as a peer could send them, and must neither panic nor use more than its
//! bounds allow.

use std::str::FromStr;

use crate::{
    HostAddress,
    Ticket,
    frame,
};

/// Parses `data` as a remembered host address, as a ticket's text and as a ticket's payload,
/// and checks that what decodes encodes and decodes again to the same.
///
/// # Panics
///
/// Panics if a decoded address or ticket does not survive encoding, the bug looked for.
pub fn ticket(data: &[u8]) {
    if let Ok(host) = HostAddress::from_bytes(data) {
        let bytes = host.to_bytes().expect("a decoded address encodes");
        assert_eq!(HostAddress::from_bytes(&bytes).ok(), Some(host));
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Ticket::from_str(text);
    }
    if let Ok(ticket) = Ticket::from_payload(data) {
        let text = ticket.encode().expect("a decoded ticket encodes");
        assert!(text.len() <= 1023);
        assert_eq!(Ticket::from_str(&text).ok(), Some(ticket));
    }
}

/// Decodes `data` as a live frame's plaintext and its body.
pub fn frame_plaintext(data: &[u8]) {
    frame::fuzz_plaintext(data);
}

/// Decodes `data` as a message from another of the user's mahis, and checks that what decodes
/// encodes and decodes again to the same.
///
/// # Panics
///
/// Panics if a decoded message does not survive encoding, the bug looked for.
pub fn local_message(data: &[u8]) {
    if let Ok(message) = crate::LocalMessage::decode(data) {
        let mut frame = Vec::new();
        message
            .encode(&mut frame)
            .expect("a decoded message encodes");
        assert_eq!(
            crate::LocalMessage::decode(frame.get(4..).unwrap_or_default()).ok(),
            Some(message)
        );
    }
}
