#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mahi_live::fuzzing::ticket(data);
});
