#![no_main]

libfuzzer_sys::fuzz_target!(|text: &str| {
    mahi_thread::fuzzing::card(text);
    let _ = mahi_thread::ParticipantKey::from_openssh(text);
});
