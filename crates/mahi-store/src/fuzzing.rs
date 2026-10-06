//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`: each takes
//! untrusted bytes as a remote, a teammate's tree or an agent's worktree could hold them, and
//! must neither panic nor use more than its bounds allow.

use std::{
    collections::HashSet,
    io,
};

use gix::{
    ObjectId,
    bstr::ByteSlice,
    objs::tree::EntryKind,
};
use mahi_core::{
    RefKind,
    ThreadId,
    ThreadRef,
};

pub use self::{
    scratch::{
        scratch_store,
        set_ref,
    },
    trees::trees,
};
use crate::{
    merge,
    push,
    snapshot,
    store,
    worktree,
};

mod scratch;
mod temp;
mod trees;

fn lines(data: &[u8]) -> impl FnMut(&mut String) -> io::Result<usize> + '_ {
    let mut rest = data.split(|byte| *byte == b'\n');
    move |line: &mut String| {
        Ok(rest.next().map_or(0, |next| {
            line.push_str(&String::from_utf8_lossy(next));
            line.push('\n');
            next.len() + 1
        }))
    }
}

/// Reads the rest of `data`, split at newlines, as a remote's ref advertisement for a push of
/// one thread's `meta` when its first byte is even, or else as its report on that push.
pub fn send_pack(data: &[u8]) {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let meta = ThreadRef::new(ThreadId::from_bytes([1; 16]), RefKind::Meta);
    let names: HashSet<String> = HashSet::from([meta.to_string()]);
    if selector.is_multiple_of(2) {
        let _ =
            push::parse_advertisement(&mut lines(rest), &|name| names.contains(name), &|name| {
                name.starts_with("refs/threads/")
            });
    } else {
        let _ = push::read_report(&mut lines(rest), &names);
    }
}

const HFS_IGNORED: [char; 16] = [
    '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
    '\u{202e}', '\u{206a}', '\u{206b}', '\u{206c}', '\u{206d}', '\u{206e}', '\u{206f}', '\u{feff}',
];

fn harmless(name: &[u8]) -> bool {
    let shown: String = String::from_utf8_lossy(name)
        .chars()
        .filter(|c| !HFS_IGNORED.contains(c))
        .collect();
    !name.is_empty()
        && !name.contains(&b'/')
        && !name.contains(&0)
        && name != b"."
        && name != b".."
        && !name.eq_ignore_ascii_case(b".git")
        && !name.eq_ignore_ascii_case(b"git~1")
        && !shown.eq_ignore_ascii_case(".git")
}

/// Checks `data` with every check mahi makes on a name: the names a snapshot records, a merge
/// writes, a tree entry is given and a worktree is called, none of which, once accepted, can
/// leave its directory or reach `.git`, and the branch names, which must stay the branch they
/// name under `refs/heads/`.
///
/// # Panics
///
/// Panics if a check accepts a name that could leave its directory, reach `.git` or name
/// another branch.
pub fn names(data: &[u8]) {
    if snapshot::safe_name(data) {
        assert!(harmless(data), "{:?}", data.as_bstr());
    }
    if snapshot::safe_link_name(data) {
        assert!(
            harmless(data) && !data.eq_ignore_ascii_case(b".gitmodules"),
            "{:?}",
            data.as_bstr()
        );
    }
    let blob = (
        EntryKind::Blob.into(),
        ObjectId::null(gix::hash::Kind::Sha1),
    );
    let link = (
        EntryKind::Link.into(),
        ObjectId::null(gix::hash::Kind::Sha1),
    );
    for entry in [None, Some(blob), Some(link)] {
        if merge::safe_name(data.as_bstr(), entry) {
            assert!(harmless(data), "{:?}", data.as_bstr());
        }
    }
    if merge::safe_name(data.as_bstr(), Some(link)) {
        assert!(!data.eq_ignore_ascii_case(b".gitmodules"));
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for kind in [EntryKind::Blob, EntryKind::Link, EntryKind::Tree] {
        if store::validate_entry_name(text, kind).is_ok() {
            assert!(harmless(data) && data.len() <= 255, "{text:?}");
            if kind == EntryKind::Link {
                assert!(!text.eq_ignore_ascii_case(".gitmodules"), "{text:?}");
            }
        }
    }
    if worktree::validate_name(text).is_ok() {
        assert!(
            harmless(data) && !text.starts_with('.') && data.len() <= 128,
            "{text:?}"
        );
    }
    if let Ok(branch) = store::branch_ref(text) {
        assert_eq!(
            branch.as_bstr().strip_prefix(b"refs/heads/"),
            Some(data),
            "{text:?}"
        );
        assert!(
            !text.starts_with('-') && !text.starts_with("refs/") && text != "HEAD" && text != "@",
            "{text:?}"
        );
    }
}
