#![no_main]

use mahi_term::{
    BackgroundReply,
    ReplySplit,
};

fn split(chunks: &[&[u8]]) -> (BackgroundReply, Vec<u8>) {
    let mut split = ReplySplit::default();
    let mut keys = Vec::new();
    let mut told = BackgroundReply::Incomplete;
    for chunk in chunks {
        told = split.read(chunk, &mut keys);
    }
    split.give_up(&mut keys);
    (told, keys)
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&cut, stream)) = data.split_first() else {
        return;
    };
    let (first, second) = stream.split_at(usize::from(cut).min(stream.len()));
    let whole = split(&[stream]);
    let parts = split(&[first, second]);
    assert_eq!(whole.1, parts.1);
    if whole.0 != BackgroundReply::Incomplete && parts.0 != BackgroundReply::Incomplete {
        assert_eq!(whole.0, parts.0);
    }
    assert!(whole.1.len() <= stream.len());
});
