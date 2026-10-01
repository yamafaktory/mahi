#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| mahi_ssh::fuzzing::transport(data));
