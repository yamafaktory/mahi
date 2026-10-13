#![no_main]

use mahi_term::{
    AgentScreen,
    OutputTracker,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&split, input)) = data.split_first() else {
        return;
    };
    let mut screen = AgentScreen::new(u16::from(split % 40).max(1), u16::from(split).max(1));
    let mut passed = Vec::new();
    let mut replies = Vec::new();
    for piece in input.chunks(usize::from(split).max(1)) {
        if let [rows, columns, ..] = piece {
            screen.set_size(u16::from(*rows % 50), u16::from(*columns));
        }
        screen.feed(piece);
        screen.take_passed(&mut passed);
        screen.take_replies(&mut replies);
    }
    screen.set_size(u16::from(split % 7).max(1), u16::from(split % 13).max(1));
    screen.undo(&mut passed);
    let mut tracker = OutputTracker::default();
    tracker.feed(&passed);
    assert!(tracker.is_ground(), "{passed:?}");
    for pair in passed.windows(2) {
        assert!(pair != b"\x1bP" && pair != b"\x1b_", "{passed:?}");
    }
    assert!(
        replies
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'\x1b' | b'[' | b';' | b'R' | b'n')),
        "{replies:?}"
    );
});
