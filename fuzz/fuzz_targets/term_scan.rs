#![no_main]

use mahi_term::{
    KeyScanner,
    PaletteKey,
    Segment,
};

const KEYS: [&str; 6] = ["ctrl-space", "ctrl-a", "ctrl-^", "ctrl-_", "f1", "f5"];

fn is_dropped_event(gap: &[u8]) -> bool {
    gap.starts_with(b"\x1b[")
        && matches!(gap.last(), Some(b'u' | b'~' | b'P'..=b'S'))
        && gap.contains(&b':')
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&choice, rest)) = data.split_first() else {
        return;
    };
    let Some((&split, input)) = rest.split_first() else {
        return;
    };
    let key: PaletteKey = KEYS[usize::from(choice) % KEYS.len()].parse().unwrap();
    let mut scanner = KeyScanner::new(key);
    let (first, second) = input.split_at(usize::from(split).min(input.len()));
    for chunk in [first, second] {
        let base = chunk.as_ptr() as usize;
        let mut next = 0;
        for segment in scanner.scan(chunk) {
            let (Segment::Pass(bytes) | Segment::Palette(bytes)) = segment;
            assert!(!bytes.is_empty());
            let start = bytes.as_ptr() as usize - base;
            assert!(start >= next);
            if start > next {
                assert!(is_dropped_event(&chunk[next..start]));
            }
            next = start + bytes.len();
            assert!(next <= chunk.len());
        }
        if next < chunk.len() {
            assert!(is_dropped_event(&chunk[next..]));
        }
    }
});
