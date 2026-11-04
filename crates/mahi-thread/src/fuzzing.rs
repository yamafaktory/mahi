//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing` or, to lint them,
//! the `fuzzing` feature: each takes untrusted bytes as a peer, a remote or an agent could send
//! them, and must neither panic nor use more than its bounds allow.

use std::{
    collections::HashSet,
    str::FromStr,
};

use ed25519_dalek::SigningKey;
use mahi_core::ThreadId;
use mahi_store::ObjectId;
use ssh_key::{
    PublicKey,
    public::Ed25519PublicKey,
};

pub use self::fetched::fetched;
use crate::{
    ParticipantCard,
    ParticipantKey,
    VerifiedMeta,
    session_files,
    transcript,
};

mod fetched;

fn owner() -> Option<ParticipantKey> {
    let point = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    ParticipantKey::from_public_key(&PublicKey::from(Ed25519PublicKey(point))).ok()
}

fn null() -> ObjectId {
    ObjectId::null(gix_hash::Kind::Sha1)
}

/// Decodes `data` as a signed `meta` document.
pub fn meta(data: &[u8]) {
    if let Some(owner) = owner() {
        let _ = VerifiedMeta::decode(data, ThreadId::from_bytes([1; 16]), &owner);
    }
}

/// Decodes `data` as the body of a `meta` document whose signature checked out.
pub fn meta_body(data: &[u8]) {
    if let Some(owner) = owner() {
        let _ = VerifiedMeta::decode_body(data, ThreadId::from_bytes([1; 16]), &owner);
    }
    let _ = crate::Tombstone::decode_body(data, ThreadId::from_bytes([1; 16]));
}

/// Parses `data` as a participant card.
pub fn card(data: &str) {
    let _ = ParticipantCard::from_str(data);
}

/// Decodes `data` as a transcript turn's plaintext, and checks that a decoded turn encodes
/// and decodes again to the same.
///
/// # Panics
///
/// Panics if a decoded turn does not survive encoding, the bug looked for.
pub fn transcript_turn(data: &[u8]) {
    if let Ok(decoded) = transcript::decode(data, null()) {
        let encoded = decoded
            .record
            .encode(decoded.last_seq)
            .expect("a decoded turn encodes");
        let again = transcript::decode(&encoded, null()).expect("an encoded turn decodes");
        assert!(again.record == decoded.record && again.last_seq == decoded.last_seq);
    }
}

/// Decodes `data` as a session manifest's plaintext, and checks that a decoded manifest
/// encodes and decodes again to the same.
///
/// # Panics
///
/// Panics if a decoded manifest does not survive encoding, the bug looked for.
pub fn session_manifest(data: &[u8]) {
    if let Ok(manifest) = session_files::decode_manifest(data, null()) {
        let encoded = postcard::to_allocvec(&manifest).expect("a decoded manifest encodes");
        let again =
            session_files::decode_manifest(&encoded, null()).expect("an encoded manifest decodes");
        assert!(again == manifest);
    }
}

/// Decodes `data` as a session manifest and, when it decodes, checks the files a reader would
/// accept from it with every piece present: each a relative path with no empty, `.` or `..`
/// component, in strictly increasing order, none the same as another once ASCII case is
/// folded nor a directory of another, within the file and byte limits.
///
/// # Panics
///
/// Panics if the reader accepts a file list that breaks one of these, the bug looked for.
pub fn session_files(data: &[u8]) {
    let Ok(manifest) = session_files::decode_manifest(data, null()) else {
        return;
    };
    let Ok(files) = session_files::accepted_files(&manifest, |_| true, null()) else {
        return;
    };
    assert!(files.len() <= session_files::MAX_SESSION_FILES);
    let mut folded = HashSet::new();
    let mut directories = HashSet::new();
    let mut total: u64 = 0;
    let mut previous: Option<&str> = None;
    for file in &files {
        let path = file.path.as_str();
        assert!(
            path.split('/').all(|part| !part.is_empty()
                && part != "."
                && part != ".."
                && !part.contains('\0')),
            "{path:?}"
        );
        assert!(previous.is_none_or(|previous| previous < path), "{path:?}");
        previous = Some(path);
        let lower = path.to_ascii_lowercase();
        let mut at = 0;
        while let Some(slash) = lower[at..].find('/') {
            directories.insert(lower[..at + slash].to_owned());
            at += slash + 1;
        }
        assert!(folded.insert(lower), "{path:?}");
        total += file.len;
    }
    assert!(total <= session_files::MAX_SESSION_BYTES);
    assert!(folded.iter().all(|path| !directories.contains(path)));
}
