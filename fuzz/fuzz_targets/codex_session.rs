#![no_main]

use mahi_agent::codex;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(path) = std::str::from_utf8(data)
        && codex::is_session_log(path)
    {
        assert_eq!(path.split('/').count(), 4);
        assert!(
            path.split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
        );
    }
});
