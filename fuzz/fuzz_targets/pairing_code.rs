#![no_main]

use mahi_live::{
    MAX_SLOT,
    PairingCode,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(code) = text.parse::<PairingCode>() else {
        return;
    };
    assert!((1..=MAX_SLOT).contains(&code.slot()));
    let written = code.to_string();
    assert_eq!(written, written.to_ascii_lowercase());
    assert_eq!(*code.password(), written);
    assert_eq!(written.parse::<PairingCode>().unwrap().to_string(), written);
    assert_eq!(format!("{code:?}"), format!("PairingCode({}-..)", code.slot()));
});
