#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use mahi_agent::claude_code;
    assert!(mahi_agent::payload::prompt_text(data).chars().count() <= 4000);
    assert!(mahi_agent::payload::tool_text(data).chars().count() <= 4000);
    if let Ok(path) = std::str::from_utf8(data) {
        if let Some(dir) = claude_code::session_dir(std::path::Path::new(path)) {
            let name = dir.strip_prefix("projects/").unwrap();
            assert!(name.len() <= 200);
            assert!(
                name.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            );
        }
    }
});
