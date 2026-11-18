#![no_main]

use mahi_term::{
    is_terminal_answer,
    starts_answer,
    string_end,
    terminal_answer_at,
};

const ESC: u8 = 0x1b;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let starts = data.iter().enumerate().filter(|(_, byte)| **byte == ESC);
    for (at, _) in starts {
        let Some(end) = terminal_answer_at(data, at) else {
            continue;
        };
        assert!(at < end && end <= data.len());
        let cut = data
            .get(end)
            .is_some_and(|&byte| byte < 0x20 && byte != 0x07 && byte != ESC);
        if !cut {
            assert_eq!(terminal_answer_at(&data[..end], at), Some(end));
            assert!(is_terminal_answer(&data[at..end]));
            assert!(!starts_answer(&data[at..end]));
        }
    }
    if !data.iter().any(|&byte| byte < 0x20 || byte == b'\\') {
        assert_eq!(string_end(data, 0), None);
    }
});
