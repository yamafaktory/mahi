#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mahi_identity::fuzzing::agent_answer(data);
});
