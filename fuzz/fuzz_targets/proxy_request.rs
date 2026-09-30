#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mahi_proxy::fuzzing::request(data);
});
