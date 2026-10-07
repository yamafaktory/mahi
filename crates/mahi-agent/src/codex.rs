//! Codex: where it keeps an agent's sessions, what its session log says, and the approvals it
//! records for mahi's hooks, which mahi carries from one thread to the next so the user
//! approves them once.

use std::{
    borrow::Cow,
    fmt::Write as _,
    path::Path,
    str::FromStr,
};

use serde::Deserialize;
use thiserror::Error;
use toml::{
    Table,
    Value,
};

use crate::claude_code::{
    ContentPart,
    LogLine,
    MAX_LOG_TIME_CHARS,
    content_parts,
    cut_chars,
    joined,
};

/// The directory in Codex's home that holds its sessions, one log a session.
pub const SESSION_DIR: &str = "sessions";

/// The events of mahi's hooks, as Codex names them in its approval records, in the order a
/// [`HookTrust`] keeps them.
pub const HOOK_EVENTS: [&str; 3] = ["user_prompt_submit", "post_tool_use", "stop"];

/// The most bytes of a Codex `config.toml` mahi reads or writes.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// The most bytes of the file mahi keeps approvals in.
pub const MAX_SAVED_BYTES: usize = 4096;

const HASH_PREFIX: &str = "sha256:";
const HASH_DIGITS: usize = 64;
const LOG_PREFIX: &str = "rollout-";

#[derive(Deserialize)]
struct CodexEntry<'a> {
    #[serde(rename = "type", borrow, default)]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    timestamp: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    payload: Option<CodexPayload<'a>>,
}

#[derive(Deserialize)]
struct CodexPayload<'a> {
    #[serde(rename = "type", borrow, default)]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    role: Option<Cow<'a, str>>,
    #[serde(borrow, default, deserialize_with = "content_parts")]
    content: Vec<ContentPart<'a>>,
}

/// Returns where Codex keeps the sessions of an agent, inside its home: [`SESSION_DIR`],
/// whatever the worktree, since each thread's agent has a home of its own.
#[must_use]
pub fn session_dir(_worktree: &Path) -> Option<String> {
    Some(SESSION_DIR.to_owned())
}

/// Returns whether the file at `path`, relative to [`SESSION_DIR`], is a session log as Codex
/// names it: `YYYY/MM/DD/rollout-….jsonl`. A log Codex has compressed is not.
#[must_use]
pub fn is_session_log(path: &str) -> bool {
    let mut parts = path.split('/');
    let digits = |part: Option<&str>, count: usize| {
        part.is_some_and(|part| {
            part.len() == count && part.bytes().all(|byte| byte.is_ascii_digit())
        })
    };
    digits(parts.next(), 4)
        && digits(parts.next(), 2)
        && digits(parts.next(), 2)
        && parts.next().is_some_and(|name| {
            name.starts_with(LOG_PREFIX)
                && Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
        })
        && parts.next().is_none()
}

/// Reads a line of a Codex session log: the `output_text` parts of an assistant `message`
/// response item are its reply. Codex also writes each reply as an `item_completed` event,
/// which is left out so a reply is read once; this form is the same in logs Codex wrote
/// before and after it began writing those events.
#[must_use]
pub fn log_line(line: &[u8]) -> Option<LogLine> {
    let entry: CodexEntry<'_> = serde_json::from_slice(line).ok()?;
    let timestamp = entry
        .timestamp
        .as_deref()
        .map(|time| cut_chars(time, MAX_LOG_TIME_CHARS));
    let reply = entry
        .payload
        .filter(|payload| {
            entry.kind.as_deref() == Some("response_item")
                && payload.kind.as_deref() == Some("message")
                && payload.role.as_deref() == Some("assistant")
        })
        .map(|payload| {
            joined(
                payload
                    .content
                    .iter()
                    .filter(|part| part.kind.as_deref() == Some("output_text"))
                    .filter_map(|part| part.text.as_deref()),
            )
        })
        .filter(|text| !text.trim().is_empty());
    Some(LogLine { timestamp, reply })
}

/// A hash Codex records for an approved hook: `sha256:` and 64 lowercase hexadecimal digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookHash(String);

/// A hook hash that is not in the form Codex writes.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("not a hook hash")]
pub struct HookHashError;

impl FromStr for HookHash {
    type Err = HookHashError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let digits = text.strip_prefix(HASH_PREFIX).ok_or(HookHashError)?;
        let hex = digits.len() == HASH_DIGITS
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        hex.then(|| Self(text.to_owned())).ok_or(HookHashError)
    }
}

impl HookHash {
    /// Returns the hash as Codex writes it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The approvals of mahi's hooks, one for each of [`HOOK_EVENTS`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookTrust([Option<HookHash>; 3]);

impl HookTrust {
    /// Reads the approvals Codex recorded in the `config.toml` text `config` for mahi's hooks
    /// in the file `hooks_json`; none when the text is too long or does not parse.
    #[must_use]
    pub fn recorded(config: &str, hooks_json: &str) -> Self {
        let Some(table) = parsed(config) else {
            return Self::default();
        };
        let state = table
            .get("hooks")
            .and_then(|hooks| hooks.get("state"))
            .and_then(Value::as_table);
        Self(HOOK_EVENTS.map(|event| {
            state?
                .get(&key(hooks_json, event))?
                .get("trusted_hash")?
                .as_str()?
                .parse()
                .ok()
        }))
    }

    /// Reads approvals mahi saved with [`HookTrust::to_saved`]; none of those that are missing
    /// or not hashes.
    #[must_use]
    pub fn from_saved(text: &str) -> Self {
        let table = (text.len() <= MAX_SAVED_BYTES)
            .then(|| text.parse::<Table>().ok())
            .flatten();
        Self(HOOK_EVENTS.map(|event| table.as_ref()?.get(event)?.as_str()?.parse().ok()))
    }

    /// Returns the approvals as the text of the file mahi keeps them in.
    #[must_use]
    pub fn to_saved(&self) -> String {
        let mut text = String::new();
        for (event, hash) in HOOK_EVENTS.iter().zip(&self.0) {
            if let Some(hash) = hash {
                let _ = writeln!(text, "{event} = \"{}\"", hash.as_str());
            }
        }
        text
    }

    /// Returns the approvals, one for each of [`HOOK_EVENTS`].
    #[must_use]
    pub fn hashes(&self) -> &[Option<HookHash>; 3] {
        &self.0
    }

    /// Returns whether every hook has an approval.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.0.iter().all(Option::is_some)
    }

    /// Returns `config` with an approval record added for each of mahi's hooks in the file
    /// `hooks_json` that has none yet, leaving any record Codex or the user wrote as it is;
    /// `None` when there is nothing to add, `config` does not parse, `hooks_json` cannot be
    /// written as a key, or the result would not parse.
    #[must_use]
    pub fn added_to(&self, config: &str, hooks_json: &str) -> Option<String> {
        if hooks_json.contains(['"', '\\']) || hooks_json.chars().any(char::is_control) {
            return None;
        }
        let table = parsed(config)?;
        let state = table
            .get("hooks")
            .and_then(|hooks| hooks.get("state"))
            .and_then(Value::as_table);
        let mut out = config.to_owned();
        let mut added = false;
        for (event, hash) in HOOK_EVENTS.iter().zip(&self.0) {
            let Some(hash) = hash else {
                continue;
            };
            let key = key(hooks_json, event);
            if state.is_some_and(|state| state.contains_key(&key)) {
                continue;
            }
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            let _ = write!(
                out,
                "\n[hooks.state.\"{key}\"]\ntrusted_hash = \"{}\"\n",
                hash.as_str()
            );
            added = true;
        }
        (added && parsed(&out).is_some()).then_some(out)
    }
}

fn key(hooks_json: &str, event: &str) -> String {
    format!("{hooks_json}:{event}:0:0")
}

fn parsed(config: &str) -> Option<Table> {
    (config.len() <= MAX_CONFIG_BYTES)
        .then(|| config.parse::<Table>().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOOKS: &str = "/state/t/alice.codex/hooks.json";

    fn hash(digit: char) -> HookHash {
        format!("sha256:{}", digit.to_string().repeat(64))
            .parse()
            .unwrap()
    }

    fn trust() -> HookTrust {
        HookTrust([Some(hash('1')), Some(hash('2')), Some(hash('3'))])
    }

    #[test]
    fn hook_hashes_are_only_codexs_sha256_form() {
        assert!(
            format!("sha256:{}", "a".repeat(64))
                .parse::<HookHash>()
                .is_ok()
        );
        for bad in [
            String::new(),
            "sha256:".to_owned(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("sha512:{}", "a".repeat(64)),
            format!("sha256:{}\"", "a".repeat(63)),
        ] {
            assert_eq!(bad.parse::<HookHash>(), Err(HookHashError), "{bad}");
        }
    }

    #[test]
    fn approvals_codex_recorded_for_mahis_hooks_are_read_and_others_ignored() {
        let config = format!(
            "[projects.\"/repo\"]\ntrust_level = \"trusted\"\n\n[hooks.state]\n\n\
             [hooks.state.\"{HOOKS}:post_tool_use:0:0\"]\ntrusted_hash = \"{}\"\n\n\
             [hooks.state.\"{HOOKS}:stop:0:0\"]\ntrusted_hash = \"not a hash\"\n\n\
             [hooks.state.\"/other/hooks.json:user_prompt_submit:0:0\"]\ntrusted_hash = \"{}\"\n",
            hash('2').as_str(),
            hash('9').as_str(),
        );
        let recorded = HookTrust::recorded(&config, HOOKS);
        assert_eq!(recorded, HookTrust([None, Some(hash('2')), None]));
        assert!(!recorded.is_complete());
        assert_eq!(
            HookTrust::recorded("not = [toml", HOOKS),
            HookTrust::default()
        );
        let long = format!("# {}\n", "x".repeat(MAX_CONFIG_BYTES));
        assert_eq!(HookTrust::recorded(&long, HOOKS), HookTrust::default());
    }

    #[test]
    fn saved_approvals_read_back_and_bad_ones_are_dropped() {
        let saved = trust().to_saved();
        assert_eq!(HookTrust::from_saved(&saved), trust());
        assert!(HookTrust::from_saved(&saved).is_complete());
        let partial = format!("stop = \"{}\"\npost_tool_use = 3\n", hash('3').as_str());
        assert_eq!(
            HookTrust::from_saved(&partial),
            HookTrust([None, None, Some(hash('3'))])
        );
        assert_eq!(HookTrust::from_saved("= broken"), HookTrust::default());
    }

    #[test]
    fn approvals_are_added_to_a_new_threads_config_as_codex_reads_them() {
        let config = "[tui]\nscreen_reader_detection_done = true";
        let added = trust().added_to(config, HOOKS).unwrap();
        assert!(added.starts_with(config));
        assert_eq!(HookTrust::recorded(&added, HOOKS), trust());
        assert_eq!(
            HookTrust::recorded(&trust().added_to("", HOOKS).unwrap(), HOOKS),
            trust()
        );
    }

    #[test]
    fn existing_records_are_kept_and_nothing_is_written_when_nothing_is_missing() {
        let mine = format!("[hooks.state.\"{HOOKS}:stop:0:0\"]\nenabled = false\n");
        let added = trust().added_to(&mine, HOOKS).unwrap();
        assert_eq!(added.matches(":stop:0:0").count(), 1);
        assert!(added.contains("enabled = false"));
        let recorded = HookTrust::recorded(&added, HOOKS);
        assert_eq!(
            recorded,
            HookTrust([Some(hash('1')), Some(hash('2')), None])
        );
        let full = trust().added_to("", HOOKS).unwrap();
        assert_eq!(trust().added_to(&full, HOOKS), None);
        assert_eq!(HookTrust::default().added_to("", HOOKS), None);
    }

    #[test]
    fn a_config_or_path_that_would_break_codexs_file_is_left_alone() {
        assert_eq!(trust().added_to("broken = [", HOOKS), None);
        assert_eq!(trust().added_to("hooks = { state = {} }\n", HOOKS), None);
        for path in ["/a\"b/hooks.json", "/a\\b/hooks.json", "/a\nb/hooks.json"] {
            assert_eq!(trust().added_to("", path), None, "{path:?}");
        }
    }

    #[test]
    fn codex_replies_are_read_once_from_response_items_in_old_and_new_logs() {
        let reply = br#"{"timestamp":"2026-10-06T20:42:00.042Z","ordinal":23,"type":"response_item","payload":{"type":"message","id":"m","role":"assistant","content":[{"type":"output_text","text":"Created bye.txt."},{"type":"output_text","text":"Done."}],"phase":"final_answer"}}"#;
        assert_eq!(
            log_line(reply),
            Some(LogLine {
                timestamp: Some("2026-10-06T20:42:00.042Z".to_owned()),
                reply: Some("Created bye.txt.\nDone.".to_owned()),
            })
        );
        let older = br#"{"timestamp":"2025-06-01T10:00:00Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"old reply"}]}}"#;
        assert_eq!(log_line(older).unwrap().reply.as_deref(), Some("old reply"));
        let event = br#"{"timestamp":"2026-10-06T20:42:00.040Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"AgentMessage","content":[{"type":"Text","text":"Created bye.txt."}]}}}"#;
        let user = br#"{"timestamp":"t","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"make it"}]}}"#;
        let developer = br#"{"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"rules"}]}}"#;
        let call = br#"{"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","input":"ls"}}"#;
        let blank = br#"{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"  "}]}}"#;
        for line in [&event[..], user, developer, call, blank] {
            assert_eq!(log_line(line).unwrap().reply, None);
        }
        assert_eq!(
            log_line(event).unwrap().timestamp.as_deref(),
            Some("2026-10-06T20:42:00.040Z")
        );
        assert_eq!(log_line(b"not json"), None);
        let long = format!(
            r#"{{"type":"response_item","payload":{{"type":"message","role":"assistant","content":[{{"type":"output_text","text":"{}"}}]}}}}"#,
            "x".repeat(10_000)
        );
        assert_eq!(
            log_line(long.as_bytes())
                .unwrap()
                .reply
                .unwrap()
                .chars()
                .count(),
            4000
        );
    }

    #[test]
    fn only_codexs_dated_rollout_logs_are_session_logs() {
        assert_eq!(
            session_dir(Path::new("/any/worktree")).as_deref(),
            Some("sessions")
        );
        assert!(is_session_log(
            "2026/10/06/rollout-2026-10-06T22-41-35-01a1.jsonl"
        ));
        for other in [
            "rollout-x.jsonl",
            "2026/10/06/rollout-x.jsonl.zst",
            "2026/10/06/history.jsonl",
            "2026/10/6/rollout-x.jsonl",
            "2026/1a/06/rollout-x.jsonl",
            "2026/10/06/x/rollout-x.jsonl",
            "",
        ] {
            assert!(!is_session_log(other), "{other}");
        }
    }
}
