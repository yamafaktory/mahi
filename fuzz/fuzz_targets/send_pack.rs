#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mahi_store::fuzzing::send_pack(data);
});
