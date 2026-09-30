use std::collections::VecDeque;

use mahi_core::AgentSlot;
use mahi_crypto::ThreadKey;
use mahi_store::{
    ObjectId,
    Store,
    StoreError,
};
use mahi_thread::{
    BRIEFED_PROMPTS,
    Briefing,
    MetaError,
    TranscriptError,
    VerifiedMeta,
    walk_turns,
};
use serde_json::Value;
use thiserror::Error;

use crate::hook::HookKind;

const MAX_TURNS: usize = 10_000;
const NO_TEXT: &str = "(a prompt without text)";
const MAX_CHANGED_FILES: usize = 1000;
const RECENT_TOOLS: usize = 20;
const MAX_KEPT_CHARS: usize = 4000;
const TOOL_DETAILS: [&str; 7] = [
    "file_path",
    "path",
    "command",
    "pattern",
    "url",
    "query",
    "description",
];

/// The prompt a new agent is started with to read its briefing at `path`.
pub(crate) fn first_prompt(path: &str) -> String {
    format!("Read the handoff notes at {path} and continue the work they describe.")
}

#[derive(Debug, Error)]
pub(crate) enum HandoffError {
    #[error("cannot read the thread's title")]
    Meta(#[source] MetaError),
    #[error("cannot read the previous agent's transcript")]
    Transcript(#[source] TranscriptError),
    #[error("cannot list the files the previous agent changed")]
    Store(#[from] StoreError),
}

/// What the previous agent's transcript tells a new one: its first prompt, its latest prompts
/// and tool calls, and how many prompts came in between.
#[derive(Debug, Default)]
struct Gathered {
    oldest: Option<Vec<u8>>,
    latest: VecDeque<String>,
    prompts: usize,
    tools: VecDeque<String>,
    turns: usize,
}

impl Gathered {
    fn visit(&mut self, kind: HookKind, payload: &[u8]) {
        match kind {
            HookKind::Prompt => {
                self.prompts += 1;
                if self.latest.len() < BRIEFED_PROMPTS {
                    self.latest.push_front(prompt_text(payload));
                } else {
                    self.oldest = Some(payload.to_vec());
                }
            }
            HookKind::Tool if self.tools.len() < RECENT_TOOLS => {
                self.tools.push_front(tool_text(payload));
            }
            HookKind::Tool | HookKind::TurnEnd => {}
        }
    }

    fn into_prompts(self) -> (Vec<String>, usize) {
        let omitted = self
            .prompts
            .saturating_sub(self.latest.len() + usize::from(self.oldest.is_some()));
        let mut prompts: Vec<String> = self
            .oldest
            .map(|oldest| prompt_text(&oldest))
            .into_iter()
            .collect();
        prompts.extend(self.latest);
        (prompts, omitted)
    }
}

/// Writes the briefing for the user's new agent taking over `from`'s work in `thread`: its
/// thread title and branch, its prompts and tool calls, walked newest first through at most
/// 10,000 turns, and the files `snapshot`, its latest snapshot's tree, changed from `base`.
pub(crate) fn briefing(
    store: &Store,
    key: &ThreadKey,
    meta: &VerifiedMeta,
    from: &AgentSlot,
    (base, snapshot): (ObjectId, ObjectId),
) -> Result<Briefing, HandoffError> {
    let private = meta.private(key).map_err(HandoffError::Meta)?;
    let mut gathered = Gathered::default();
    let walked = walk_turns(store, key, meta.thread(), from, MAX_TURNS, |turn| {
        gathered.turns += 1;
        for event in turn.events().iter().rev() {
            let Some((name, payload)) = split_event(event.payload()) else {
                continue;
            };
            if let Some(kind) = HookKind::parse(name) {
                gathered.visit(kind, payload);
            }
        }
    });
    let reached_start = walked.is_ok() && gathered.turns < MAX_TURNS;
    let transcript_cut = !reached_start && gathered.prompts > 0;
    if walked.is_err() && gathered.turns == 0 {
        walked.map_err(HandoffError::Transcript)?;
    }
    let changes = store.changed_paths(store.commit_tree(base)?, snapshot, MAX_CHANGED_FILES)?;
    let tools = gathered.tools.iter().cloned().collect();
    let (prompts, omitted_prompts) = gathered.into_prompts();
    Ok(Briefing {
        title: private.title().to_owned(),
        branch: private.landing_branch().to_owned(),
        from: from.to_string(),
        prompts,
        omitted_prompts,
        transcript_cut,
        changes,
        tools,
        replies: Vec::new(),
    })
}

fn split_event(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = payload.iter().position(|byte| *byte == b'\n')?;
    Some((payload.get(..at)?, payload.get(at + 1..)?))
}

fn prompt_text(payload: &[u8]) -> String {
    match serde_json::from_slice::<Value>(payload) {
        Ok(value) => value
            .get("prompt")
            .and_then(Value::as_str)
            .map_or_else(|| NO_TEXT.to_owned(), kept),
        Err(_) => lossy(payload),
    }
}

fn tool_text(payload: &[u8]) -> String {
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
        Some(detail) => kept(&format!("{name} {detail}")),
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

    fn visit(gathered: &mut Gathered, kind: HookKind, payload: &str) {
        gathered.visit(kind, payload.as_bytes());
    }

    #[test]
    fn prompts_and_tool_calls_are_read_from_claude_codes_hook_payloads() {
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
        assert_eq!(prompt_text(&[b'x'; 10_000]).chars().count(), MAX_KEPT_CHARS);
        assert_eq!(
            split_event(b"prompt\n{}"),
            Some((&b"prompt"[..], &b"{}"[..]))
        );
        assert_eq!(split_event(b"no newline"), None);
    }

    #[test]
    fn the_first_prompt_and_the_latest_ones_are_kept_newest_first_walk() {
        let mut gathered = Gathered::default();
        for index in (1..=100).rev() {
            visit(&mut gathered, HookKind::Tool, &format!("tool {index}"));
            visit(&mut gathered, HookKind::Prompt, &format!("prompt {index}"));
        }
        let tools: Vec<String> = gathered.tools.iter().cloned().collect();
        assert_eq!(tools.len(), RECENT_TOOLS);
        assert_eq!(tools.first().map(String::as_str), Some("tool 81"));
        assert_eq!(tools.last().map(String::as_str), Some("tool 100"));
        let (prompts, omitted) = gathered.into_prompts();
        assert_eq!(prompts.first().map(String::as_str), Some("prompt 1"));
        assert_eq!(prompts.get(1).map(String::as_str), Some("prompt 71"));
        assert_eq!(prompts.last().map(String::as_str), Some("prompt 100"));
        assert_eq!(prompts.len(), BRIEFED_PROMPTS + 1);
        assert_eq!(omitted, 100 - BRIEFED_PROMPTS - 1);

        let mut few = Gathered::default();
        visit(&mut few, HookKind::Prompt, "second");
        visit(&mut few, HookKind::Prompt, "first");
        assert_eq!(
            few.into_prompts(),
            (vec!["first".to_owned(), "second".to_owned()], 0)
        );
    }
}
