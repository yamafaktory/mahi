#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mahi_thread::fuzzing::session_manifest(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = mahi_thread::SessionPath::new(text);
    }
});
