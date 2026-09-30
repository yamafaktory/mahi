//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`: each takes
//! untrusted bytes as a peer, a remote or an agent could send them, and must neither panic nor
//! use more than its bounds allow.

use std::str::FromStr;

use ed25519_dalek::SigningKey;
use mahi_core::ThreadId;
use mahi_store::{
    Change,
    Changes,
    ObjectId,
};
use ssh_key::{
    PublicKey,
    public::Ed25519PublicKey,
};

use crate::{
    Briefing,
    MAX_BRIEFING_BYTES,
    ParticipantCard,
    ParticipantKey,
    VerifiedMeta,
    session_files,
    transcript,
};

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

/// Renders a briefing from records cut out of `data` at zero bytes, each repeated as many times
/// as `data`'s first byte says so that records can reach their limits, and checks its size.
///
/// # Panics
///
/// Panics if the briefing is larger than [`MAX_BRIEFING_BYTES`], which is the bug looked for.
pub fn briefing(data: &[u8]) {
    let repeat = usize::from(data.first().copied().unwrap_or_default()) + 1;
    let mut parts = data
        .split(|byte| *byte == 0)
        .map(|part| String::from_utf8_lossy(part).repeat(repeat));
    let mut next = || parts.next().unwrap_or_default();
    let title = next();
    let branch = next();
    let from = next();
    let rest: Vec<String> = std::iter::from_fn(|| Some(next()))
        .take_while(|part| !part.is_empty())
        .collect();
    let third = rest.len() / 3;
    let briefing = Briefing {
        title,
        branch,
        from,
        prompts: rest.get(..third).unwrap_or_default().to_vec(),
        omitted_prompts: data.len(),
        transcript_cut: data.first().is_some_and(|byte| byte % 2 == 1),
        changes: Changes {
            paths: rest
                .iter()
                .skip(third)
                .take(third)
                .map(|path| (path.clone(), Change::Modified))
                .collect(),
            truncated: data.len().is_multiple_of(2),
        },
        tools: rest.iter().skip(2 * third).cloned().collect(),
        replies: rest.iter().rev().take(4).cloned().collect(),
    };
    assert!(briefing.render().len() <= MAX_BRIEFING_BYTES);
}
