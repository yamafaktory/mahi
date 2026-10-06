#![no_main]

use mahi_agent::profile::{
    MAX_PROFILE_BYTES,
    Piece,
    Placeholder,
    Template,
    UserProfile,
    template,
};

fn written_back(template: &Template) -> String {
    let mut text = String::new();
    for piece in template.pieces() {
        match piece {
            Piece::Text(literal) => {
                text.push_str(&literal.replace('{', "{{").replace('}', "}}"));
            }
            Piece::Value(Placeholder::StateDir) => text.push_str("{state_dir}"),
            Piece::Value(Placeholder::MahiBin) => text.push_str("{mahi_bin}"),
            Piece::Value(Placeholder::McpSocket) => text.push_str("{mcp_socket}"),
        }
    }
    text
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = template("fuzz", text) {
        for pair in parsed.pieces().windows(2) {
            assert!(!matches!(pair, [Piece::Text(_), Piece::Text(_)]));
        }
        assert!(!parsed.pieces().contains(&Piece::Text(String::new())));
        let written = written_back(&parsed);
        if written.len() <= MAX_PROFILE_BYTES {
            let again = template("fuzz", &written).expect("a written template parses");
            assert_eq!(again, parsed);
        }
    }
    let Ok(profile) = UserProfile::parse(text) else {
        return;
    };
    assert!(!profile.program.is_empty() && !profile.program.contains('/'));
    let folded: Vec<String> = profile
        .files
        .iter()
        .map(|file| file.path.join("/").to_ascii_lowercase())
        .collect();
    for (index, path) in folded.iter().enumerate() {
        for (other, against) in folded.iter().enumerate() {
            if index != other {
                assert_ne!(path, against);
                assert!(!against.starts_with(&format!("{path}/")));
            }
        }
    }
    for file in &profile.files {
        assert!(!file.path.is_empty() && file.path.len() <= 8);
        for component in &file.path {
            assert!(component != "." && component != ".." && (1..=200).contains(&component.len()));
            assert!(component.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'@')));
        }
    }
});
