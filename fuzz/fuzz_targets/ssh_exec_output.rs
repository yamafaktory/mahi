#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mahi_ssh::fuzzing::exec_output(data);
});
