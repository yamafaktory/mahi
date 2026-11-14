#![no_main]

use mahi_term::{
    Background,
    BackgroundReply,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&split, input)) = data.split_first() else {
        return;
    };
    let (reply, more) = input.split_at(usize::from(split).min(input.len()));
    let first = Background::from_reply(reply);
    if let BackgroundReply::Told(_) = first {
        let mut longer = reply.to_vec();
        longer.extend_from_slice(more);
        assert_eq!(Background::from_reply(&longer), first);
    }
});
