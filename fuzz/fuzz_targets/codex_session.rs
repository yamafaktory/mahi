#![no_main]

use mahi_agent::codex;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Some(line) = codex::log_line(data) {
        assert!(
            line.reply
                .is_none_or(|reply| reply.chars().count() <= 4000 && !reply.trim().is_empty())
        );
        assert!(line.timestamp.is_none_or(|time| time.chars().count() <= 64));
    }
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
