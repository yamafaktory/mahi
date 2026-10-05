//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`: each takes
//! untrusted bytes as a remote could send them, and must neither panic nor use more than its
//! bounds allow.

use std::{
    collections::HashSet,
    io,
};

use mahi_core::{
    RefKind,
    ThreadId,
    ThreadRef,
};

use crate::push;

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
        let _ = push::parse_advertisement(&mut lines(rest), &names, &|name| {
            name.starts_with("refs/threads/")
        });
    } else {
        let _ = push::read_report(&mut lines(rest), &names);
    }
}
