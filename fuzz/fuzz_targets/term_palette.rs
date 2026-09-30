#![no_main]

use mahi_term::{
    OutputTracker,
    PaletteInput,
    PaletteItem,
    PaletteKeys,
    PaletteView,
    Preview,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&split, input)) = data.split_first() else {
        return;
    };
    let (first, second) = input.split_at(usize::from(split).min(input.len()));
    let mut keys = PaletteKeys::default();
    let mut filter = String::new();
    for chunk in [first, second] {
        let used = keys.read(chunk, |key| {
            if let PaletteInput::Text(c) = key {
                assert!(!c.is_control());
                filter.push(c);
            }
            true
        });
        assert_eq!(used, chunk.len());
    }
    let body: Vec<u8> = input.iter().copied().filter(|&byte| byte != 0x1b).collect();
    let pasted = [&b"\x1b[200~"[..], &body].concat();
    let cut = usize::from(split).min(pasted.len());
    let mut keys = PaletteKeys::default();
    let mut escaped = false;
    for chunk in [&pasted[..cut], &pasted[cut..]] {
        keys.read(chunk, |key| {
            match key {
                PaletteInput::Text(_) => {}
                PaletteInput::Escape if cut == 1 => escaped = true,
                _ => assert!(escaped, "a key inside a paste: {key:?}"),
            }
            true
        });
    }
    let mut tracker = OutputTracker::default();
    let followed = tracker.feed_until_drawable(first);
    assert!(followed <= first.len());
    tracker.feed(second);
    let text = String::from_utf8_lossy(input);
    let items = [PaletteItem {
        label: &text,
        detail: &filter,
    }];
    let view = PaletteView {
        title: &text,
        filter: &filter,
        items: &items,
        selected: usize::from(split),
        empty: &text,
        hint: &text,
        preview: Some(Preview {
            text: &text,
            scroll: usize::from(split),
        }),
    };
    let rows = u16::from(split % 64);
    let columns = u16::from(split);
    let mut out = Vec::new();
    let drawn = view.draw(rows, columns, &mut out).unwrap();
    assert!(drawn.page <= drawn.lines);
    let mut drawn = OutputTracker::default();
    drawn.feed(&out);
    assert!(drawn.can_draw());
    assert!(!out.windows(2).any(|pair| pair == b"\x1b]" || pair == b"\x1bP"));
});
