//! The JSON payloads agents' hooks send mahi, in the shape Claude Code's and Codex's share: a
//! prompt's `prompt`, and a tool call's `tool_name` and `tool_input`.

use serde_json::Value;

const MAX_KEPT_CHARS: usize = 4000;
const NO_TEXT: &str = "(a prompt without text)";
const TOOL_DETAILS: [&str; 7] = [
    "file_path",
    "path",
    "command",
    "pattern",
    "url",
    "query",
    "description",
];

/// Returns the prompt a `UserPromptSubmit` hook payload holds, at most 4000 characters: its
/// `prompt`, a note when it has none, or the payload itself when it is not JSON.
#[must_use]
pub fn prompt_text(payload: &[u8]) -> String {
    match serde_json::from_slice::<Value>(payload) {
        Ok(value) => value
            .get("prompt")
            .and_then(Value::as_str)
            .map_or_else(|| NO_TEXT.to_owned(), kept),
        Err(_) => lossy(payload),
    }
}

/// Describes the tool call a `PostToolUse` hook payload holds, at most 4000 characters: the
/// tool's name and the first of its input's file, path, command, pattern, URL, query or
/// description, or the payload itself when it is not JSON.
#[must_use]
pub fn tool_text(payload: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(payload) else {
        return lossy(payload);
    };
    let name = value
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("tool");
    let detail = value.get("tool_input").and_then(|input| {
        TOOL_DETAILS
            .iter()
            .find_map(|field| input.get(*field).and_then(Value::as_str))
    });
    match detail {
        Some(detail) => name
            .chars()
            .chain(std::iter::once(' '))
            .chain(detail.chars())
            .take(MAX_KEPT_CHARS)
            .collect(),
        None => kept(name),
    }
}

fn lossy(payload: &[u8]) -> String {
    kept(&String::from_utf8_lossy(payload))
}

fn kept(text: &str) -> String {
    text.chars().take(MAX_KEPT_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_and_tool_calls_are_read_from_hook_payloads() {
        assert_eq!(
            prompt_text(br#"{"session_id":"s","prompt":"Add a login page"}"#),
            "Add a login page"
        );
        assert_eq!(prompt_text(b"plain text"), "plain text");
        assert_eq!(
            prompt_text(br#"{"cwd":"/home/bob","session_id":"s"}"#),
            NO_TEXT
        );
        assert_eq!(
            tool_text(
                br#"{"tool_name":"Edit","tool_input":{"file_path":"src/a.rs","old_string":"x"}}"#
            ),
            "Edit src/a.rs"
        );
        assert_eq!(
            tool_text(br#"{"tool_name":"Bash","tool_input":{"command":"cargo test"}}"#),
            "Bash cargo test"
        );
        assert_eq!(
            tool_text(br#"{"tool_name":"TodoWrite","tool_input":{}}"#),
            "TodoWrite"
        );
        let long = format!(
            "{{\"tool_name\":\"{}\",\"tool_input\":{{\"command\":\"ls\"}}}}",
            "n".repeat(MAX_KEPT_CHARS + 10)
        );
        assert_eq!(tool_text(long.as_bytes()).chars().count(), MAX_KEPT_CHARS);
        assert_eq!(prompt_text(&[b'x'; 10_000]).chars().count(), MAX_KEPT_CHARS);
    }
}
