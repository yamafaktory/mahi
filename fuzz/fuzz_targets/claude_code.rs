#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use mahi_agent::claude_code;
    if let Some(line) = claude_code::log_line(data) {
        assert!(line.reply.is_none_or(|reply| reply.chars().count() <= 4000));
        assert!(line.timestamp.is_none_or(|time| time.chars().count() <= 64));
    }
    assert!(claude_code::prompt_text(data).chars().count() <= 4000);
    assert!(claude_code::tool_text(data).chars().count() <= 4000);
    if let Ok(path) = std::str::from_utf8(data) {
        if let Some(dir) = claude_code::session_dir(std::path::Path::new(path)) {
            let name = dir.strip_prefix("projects/").unwrap();
            assert!(name.len() <= 200);
            assert!(name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'));
        }
    }
});
