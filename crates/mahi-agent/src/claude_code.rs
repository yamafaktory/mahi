//! Claude Code: where it keeps an agent's sessions, and what its session log says.

use std::{
    borrow::Cow,
    fmt,
    path::Path,
};

use serde::{
    Deserialize,
    Deserializer,
    de::{
        self,
        IgnoredAny,
        SeqAccess,
        Visitor,
    },
};

const CLAUDE_CODE_LONGEST_PROJECT: usize = 200;
const MAX_LOG_TEXT_CHARS: usize = 4000;
pub(crate) const MAX_LOG_TIME_CHARS: usize = 64;
const MAX_LOG_PARTS: usize = 1000;

/// One line of an agent's own session log, as its profile reads it: when it was written, and
/// the agent's reply it holds, if any.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LogLine {
    /// When the line was written, as the log says.
    pub timestamp: Option<String>,
    /// The agent's reply the line holds, if any.
    pub reply: Option<String>,
}

#[derive(Deserialize)]
struct ClaudeEntry<'a> {
    #[serde(rename = "type", borrow, default)]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    timestamp: Option<Cow<'a, str>>,
    #[serde(rename = "isSidechain", default)]
    sidechain: bool,
    #[serde(rename = "isApiErrorMessage", default)]
    api_error: bool,
    #[serde(borrow, default)]
    message: Option<ClaudeMessage<'a>>,
}

#[derive(Deserialize)]
struct ClaudeMessage<'a> {
    #[serde(borrow, default)]
    model: Option<Cow<'a, str>>,
    #[serde(borrow, default, deserialize_with = "content_parts")]
    content: Vec<ContentPart<'a>>,
}

/// One part of a message's content: its type and its text.
#[derive(Deserialize)]
pub(crate) struct ContentPart<'a> {
    #[serde(rename = "type", borrow, default)]
    pub(crate) kind: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    pub(crate) text: Option<Cow<'a, str>>,
}

/// Reads a message's content parts, at most [`MAX_LOG_PARTS`] of them, and none from content
/// that is text rather than a list.
pub(crate) fn content_parts<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ContentPart<'de>>, D::Error> {
    deserializer.deserialize_any(ContentParts)
}

struct ContentParts;

impl<'de> Visitor<'de> for ContentParts {
    type Value = Vec<ContentPart<'de>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a list of content parts, or text")
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut parts = Vec::new();
        while parts.len() < MAX_LOG_PARTS {
            match seq.next_element()? {
                Some(part) => parts.push(part),
                None => return Ok(parts),
            }
        }
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(parts)
    }
}

pub(crate) fn cut_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Reads a line of Claude Code's session log: the text parts of an `assistant` entry of the
/// main conversation are its reply; a subagent's (`isSidechain`), an API error's and one
/// Claude Code made up itself (model `<synthetic>`) are not.
#[must_use]
pub fn log_line(line: &[u8]) -> Option<LogLine> {
    let entry: ClaudeEntry<'_> = serde_json::from_slice(line).ok()?;
    let timestamp = entry
        .timestamp
        .as_deref()
        .map(|time| cut_chars(time, MAX_LOG_TIME_CHARS));
    let genuine =
        entry.kind.as_deref() == Some("assistant") && !entry.sidechain && !entry.api_error;
    let reply = entry
        .message
        .filter(|message| genuine && message.model.as_deref() != Some("<synthetic>"))
        .map(|message| {
            joined(
                message
                    .content
                    .iter()
                    .filter(|part| part.kind.as_deref() == Some("text"))
                    .filter_map(|part| part.text.as_deref()),
            )
        })
        .filter(|text| !text.trim().is_empty());
    Some(LogLine { timestamp, reply })
}

/// Joins the text `parts` of a reply with newlines, at most 4000 characters in all.
pub(crate) fn joined<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    let mut text = String::new();
    let mut left = MAX_LOG_TEXT_CHARS;
    for part in parts {
        if left == 0 {
            break;
        }
        if !text.is_empty() {
            text.push('\n');
            left -= 1;
        }
        for character in part.chars().take(left) {
            text.push(character);
            left -= 1;
        }
    }
    text
}

/// Returns whether the file at `path`, relative to Claude Code's session directory, is the log
/// of a session of the main conversation: a `.jsonl` file at its top, as a subagent's log is
/// in a directory of its own.
#[must_use]
pub fn is_session_log(path: &str) -> bool {
    !path.contains('/')
        && Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
}

/// Returns where Claude Code keeps the sessions of an agent working in `worktree`, inside its
/// config directory: `projects/` and the worktree's path with every character other than an
/// ASCII letter or digit replaced by `-`, one for each UTF-16 unit, as Claude Code names it.
/// A name Claude Code would shorten, past 200 characters, gives `None`.
#[must_use]
pub fn session_dir(worktree: &Path) -> Option<String> {
    let mut name = String::new();
    for character in worktree.to_str()?.chars() {
        if character.is_ascii_alphanumeric() {
            name.push(character);
        } else {
            name.extend(std::iter::repeat_n('-', character.len_utf16()));
        }
    }
    (name.len() <= CLAUDE_CODE_LONGEST_PROJECT).then(|| format!("projects/{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_code_sessions_are_found_under_the_worktree_path_it_names() {
        assert_eq!(
            session_dir(Path::new(
                "/home/u/.local/share/mahi/worktrees/app-1f2e/0123abcd"
            ))
            .as_deref(),
            Some("projects/-home-u--local-share-mahi-worktrees-app-1f2e-0123abcd")
        );
        let long = format!("/{}", "a".repeat(199));
        assert!(session_dir(Path::new(&long)).is_some());
        let longer = format!("/{}", "a".repeat(200));
        assert_eq!(session_dir(Path::new(&longer)), None);
        assert_eq!(
            session_dir(Path::new("/tmp/é")).as_deref(),
            Some("projects/-tmp--")
        );
        assert_eq!(
            session_dir(Path::new("/tmp/\u{1f600}")).as_deref(),
            Some("projects/-tmp---")
        );
    }

    #[test]
    fn claude_codes_log_gives_its_own_text_replies_and_times() {
        let reply = br#"{"type":"assistant","timestamp":"2026-09-30T10:00:00Z","message":{"content":[{"type":"thinking","thinking":"hidden"},{"type":"text","text":"Done."},{"type":"tool_use","name":"Edit"},{"type":"text","text":"Tests pass."}]}}"#;
        assert_eq!(
            log_line(reply),
            Some(LogLine {
                timestamp: Some("2026-09-30T10:00:00Z".to_owned()),
                reply: Some("Done.\nTests pass.".to_owned()),
            })
        );
        let user = br#"{"type":"user","timestamp":"t","message":{"content":"hi"}}"#;
        assert_eq!(
            log_line(user),
            Some(LogLine {
                timestamp: Some("t".to_owned()),
                reply: None,
            })
        );
        let tools_only = br#"{"type":"assistant","message":{"content":[{"type":"tool_use"}]}}"#;
        assert_eq!(log_line(tools_only).and_then(|line| line.reply), None);
        assert_eq!(log_line(b"not json"), None);
        for other in [
            &br#"{"type":"assistant","isSidechain":true,"message":{"content":[{"type":"text","text":"sub"}]}}"#[..],
            br#"{"type":"assistant","isApiErrorMessage":true,"message":{"content":[{"type":"text","text":"API Error"}]}}"#,
            br#"{"type":"assistant","message":{"model":"<synthetic>","content":[{"type":"text","text":"No response requested."}]}}"#,
            br#"{"type":"assistant","message":{"content":"plain"}}"#,
        ] {
            assert_eq!(log_line(other).and_then(|line| line.reply), None);
        }
        let many = format!(
            "{{\"type\":\"assistant\",\"message\":{{\"content\":[{}{{\"type\":\"text\",\"text\":\"late\"}}]}}}}",
            "{},".repeat(MAX_LOG_PARTS)
        );
        assert_eq!(log_line(many.as_bytes()).and_then(|line| line.reply), None);
    }
}
