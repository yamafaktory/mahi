#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use mahi_agent::hook;
    if let Some(message) = hook::decode(data) {
        assert!(message.payload.len() <= hook::MAX_PAYLOAD_BYTES);
        let again = hook::encode(message.kind, &message.payload).unwrap();
        assert_eq!(again, data);
    }
});
