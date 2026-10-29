//! The JSON payloads agents' hooks send mahi, in the shape Claude Code's and Codex's share: a
//! prompt's `prompt`, a tool call's `tool_name` and `tool_input`, and Claude Code's
//! notification's `notification_type`.

use std::borrow::Cow;

use serde::Deserialize;
use serde_json::Value;

const MAX_KEPT_CHARS: usize = 4000;
const NO_TEXT: &str = "(a prompt without text)";
const QUESTIONS: [&str; 2] = ["permission_prompt", "elicitation_dialog"];
const TOOL_DETAILS: [&str; 7] = [
    "file_path",
    "path",
    "command",
    "pattern",
    "url",
    "query",
    "description",
];

/// The fields of a prompt's or a tool call's hook payload, read whole and without the others,
/// such as a tool's response.
#[derive(Debug, Default, Deserialize)]
pub struct HookFields<'payload> {
    /// A prompt's text.
    #[serde(borrow, default)]
    pub prompt: Option<Cow<'payload, str>>,
    /// The name of the tool a tool call used.
    #[serde(borrow, default)]
    pub tool_name: Option<Cow<'payload, str>>,
    /// The input a tool call gave its tool.
    #[serde(default)]
    pub tool_input: Option<Value>,
}

impl<'payload> HookFields<'payload> {
    /// Reads the fields of `payload`, or `None` when it is not a JSON object.
    #[must_use]
    pub fn parse(payload: &'payload [u8]) -> Option<Self> {
        serde_json::from_slice(payload).ok()
    }
}

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

/// Returns whether a `Notification` hook payload says the agent asks the user something: a
/// permission request or a question, not its reminder that it waits for input.
#[must_use]
pub fn asks_user(payload: &[u8]) -> bool {
    serde_json::from_slice::<Value>(payload).is_ok_and(|value| {
        value
            .get("notification_type")
            .and_then(Value::as_str)
            .is_some_and(|kind| QUESTIONS.contains(&kind))
    })
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

    #[test]
    fn hook_fields_are_read_whole_and_the_others_are_skipped() {
        let long = "x".repeat(MAX_KEPT_CHARS + 10);
        let payload = format!(
            "{{\"prompt\":\"{long}\",\"tool_response\":{{\"stdout\":\"big\"}},\"tool_input\":[1]}}"
        );
        let fields = HookFields::parse(payload.as_bytes()).unwrap();
        assert_eq!(fields.prompt.as_deref(), Some(long.as_str()));
        assert_eq!(fields.tool_name, None);
        assert_eq!(fields.tool_input, Some(serde_json::json!([1])));
        assert!(
            HookFields::parse(br#"{"tool_name":"Bash"}"#)
                .unwrap()
                .prompt
                .is_none()
        );
        assert!(HookFields::parse(b"plain text").is_none());
        assert!(HookFields::parse(br#""a string""#).is_none());
        assert!(HookFields::parse(br#"{"prompt":7}"#).is_none());
    }

    #[test]
    fn only_a_permission_request_or_a_question_asks_the_user() {
        assert!(asks_user(
            br#"{"message":"Claude needs your permission to use Bash","notification_type":"permission_prompt"}"#
        ));
        assert!(asks_user(br#"{"notification_type":"elicitation_dialog"}"#));
        assert!(!asks_user(
            br#"{"message":"Claude is waiting for your input","notification_type":"idle_prompt"}"#
        ));
        assert!(!asks_user(br#"{"notification_type":"auth_success"}"#));
        assert!(!asks_user(
            br#"{"message":"Claude needs your permission to use Bash"}"#
        ));
        assert!(!asks_user(br#"{"notification_type":7}"#));
        assert!(!asks_user(b"permission_prompt"));
    }
}
