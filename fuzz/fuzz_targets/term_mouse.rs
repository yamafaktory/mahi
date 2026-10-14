#![no_main]

use mahi_term::{
    MouseEncoding,
    MouseMode,
    Typed,
    cut_report,
    split_mouse,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut keys = Vec::with_capacity(data.len());
    let mut reports = 0;
    let mut out = Vec::new();
    for piece in split_mouse(data) {
        match piece {
            Typed::Keys(bytes) => {
                assert!(!bytes.is_empty());
                keys.extend_from_slice(bytes);
            }
            Typed::Mouse(event) => {
                reports += 1;
                for encoding in [MouseEncoding::X10, MouseEncoding::Utf8, MouseEncoding::Sgr] {
                    out.clear();
                    assert!(!event.encode((MouseMode::Off, encoding), (0, 0), &mut out));
                    for mode in [
                        MouseMode::Press,
                        MouseMode::PressRelease,
                        MouseMode::ButtonMotion,
                        MouseMode::AnyMotion,
                    ] {
                        out.clear();
                        event.encode((mode, encoding), (event.column, event.row), &mut out);
                    }
                }
                out.clear();
                if event.encode(
                    (MouseMode::AnyMotion, MouseEncoding::Sgr),
                    (event.column, event.row),
                    &mut out,
                ) {
                    let again: Vec<Typed<'_>> = split_mouse(&out).collect();
                    assert_eq!(again, [Typed::Mouse(event)]);
                }
            }
        }
    }
    assert!(keys.len() + reports * 9 <= data.len());
    assert!(cut_report(data) <= data.len());
});
