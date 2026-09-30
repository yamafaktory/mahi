#![no_main]

use std::sync::OnceLock;

use mahi_crypto::ThreadKey;

static KEY: OnceLock<ThreadKey> = OnceLock::new();

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let key = KEY.get_or_init(ThreadKey::generate);
    if let Ok(plaintext) = key.open(data, 1 << 20) {
        assert!(plaintext.len() <= 1 << 20);
    }
    let sealed = key.seal(data).unwrap();
    assert_eq!(key.open(&sealed, data.len()).unwrap(), data);
    assert!(key.open(&sealed, data.len().saturating_sub(1)).is_err() || data.is_empty());
    let identity = age::x25519::Identity::generate();
    let _ = ThreadKey::from_wrapped(data, &identity);
});
