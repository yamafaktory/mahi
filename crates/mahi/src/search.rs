use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    fs,
    io,
    ops::ControlFlow,
};

use age::secrecy::SecretString;
use mahi_agent::{
    hook::HookKind,
    payload::HookFields,
};
use mahi_core::{
    AgentSlot,
    ThreadId,
    is_invisible,
};
use mahi_identity::{
    ConfigDir,
    ConfigError,
    IdentityError,
};
use mahi_store::{
    Store,
    StoreError,
};
use mahi_thread::{
    ParticipantKey,
    load_meta,
    walk_turns_while,
};
use serde::{
    Serialize,
    Serializer,
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    environment::Environment,
    handoff,
    prompt::{
        Prompt as _,
        TerminalPrompt,
    },
    session,
    threads::{
        self,
        AsText,
        Format,
    },
    unlocked,
};

const MAX_SEARCHED_TURNS: usize = 100_000;
const MAX_MATCHES: usize = 200;
const CHARS_BEFORE: usize = 60;
const MAX_EXCERPT_CHARS: usize = 200;
const MAX_TOOL_NAME_CHARS: usize = 64;
const CUT: char = '…';
const NO_TOOL_NAME: &str = "tool";

#[derive(Debug, Error)]
pub(crate) enum SearchError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot read the repository's threads")]
    Store(#[from] StoreError),
    #[error("mahi is not set up; run mahi init")]
    NotSetUp,
    #[error("cannot find mahi's configuration")]
    Config(#[from] ConfigError),
    #[error("cannot ask for the passphrase")]
    Terminal(#[source] io::Error),
    #[error("cannot unlock your mahi key")]
    Unlock(#[source] IdentityError),
    #[error("cannot write the matches as JSON")]
    Json(#[source] serde_json::Error),
}

/// What a search found: the matches to print, and what it could not read, to report.
#[derive(Debug)]
pub(crate) struct Searched {
    /// The matching turns, as the format prints them.
    pub(crate) found: String,
    /// One line for each thread that could not be read, and one when matches were left out.
    pub(crate) unread: String,
}

/// Where a match is in a turn: what the user asked, or a tool the agent used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Asked,
    Used,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Asked => "asked",
            Self::Used => "used",
        }
    }
}

impl Serialize for Kind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One turn event that holds the text.
#[derive(Debug, Serialize)]
struct Match<'searched> {
    thread: AsText<'searched, ThreadId>,
    agent: AsText<'searched, AgentSlot>,
    turn: u64,
    kind: Kind,
    text: String,
}

/// Searches the prompts and tool calls of every thread of the repository around the current
/// directory for `text`, ignoring case, and prints the matches in `format`: threads in the
/// order `mahi threads` lists them, each agent's turns newest first, at most
/// [`MAX_MATCHES`]. Asks once for the passphrase of the user's mahi key, which opens every
/// thread they are in, when a thread lists them.
pub(crate) fn search(
    text: &str,
    format: Format,
    environment: &Environment,
) -> Result<Searched, SearchError> {
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(SearchError::CurrentDirectory)?;
    let store = Store::discover(&cwd)?;
    let own = threads::own_key(environment).ok_or(SearchError::NotSetUp)?;
    let searched = threads::searchable(&store, Some(&own))?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let needle = needle_of(text);
    let mut matches = Vec::new();
    let mut unread = String::new();
    let more = find_all(
        (&store, &own, &config),
        &searched,
        &needle,
        (&mut matches, &mut unread),
    )?;
    if more.is_break() {
        let _ = writeln!(
            unread,
            "mahi: more turns match; only the first {MAX_MATCHES} are shown"
        );
    }
    let found = match format {
        Format::Text => found_text(&matches),
        Format::Json => {
            let mut found = serde_json::to_string(&matches).map_err(SearchError::Json)?;
            found.push('\n');
            found
        }
    };
    Ok(Searched { found, unread })
}

/// Finds the turns of the `searched` threads whose events hold `needle`, into `matches`, and
/// reports into `unread` what cannot be read; breaks once one more match than
/// [`MAX_MATCHES`] is found. Unlocks the user's mahi key, kept in `config`, at the first
/// thread that lists the user, whose key is `own`.
fn find_all<'searched>(
    (store, own, config): (&Store, &ParticipantKey, &ConfigDir),
    searched: &'searched [(ThreadId, BTreeSet<AgentSlot>)],
    needle: &[char],
    (matches, unread): (&mut Vec<Match<'searched>>, &mut String),
) -> Result<ControlFlow<()>, SearchError> {
    let mut identity = None;
    let mut cleaned = String::new();
    for (thread, agents) in searched {
        let meta = session::thread_owner(store, *thread, own.clone())
            .map_err(|error| crate::describe(&error))
            .and_then(|owner| {
                load_meta(store, *thread, &owner, 0).map_err(|error| crate::describe(&error))
            });
        let listed = meta.and_then(|meta| {
            let me = meta
                .participants()
                .find(|participant| participant.key() == own)
                .map(|participant| participant.name().clone())
                .ok_or_else(|| "it does not list you".to_owned())?;
            Ok((meta, me))
        });
        let (meta, me) = match listed {
            Ok(listed) => listed,
            Err(error) => {
                let _ = writeln!(unread, "mahi: cannot read thread {thread}: {error}");
                continue;
            }
        };
        if identity.is_none() {
            identity = Some(unlocked::identity(
                &config.identity_file(),
                ask_passphrase,
                SearchError::Unlock,
            )?);
        }
        let Some(identity) = identity.as_ref() else {
            continue;
        };
        let key = match meta.thread_key(&me, identity.as_age()) {
            Ok(key) => key,
            Err(error) => {
                let _ = writeln!(
                    unread,
                    "mahi: cannot read thread {thread}: {}",
                    crate::describe(&error)
                );
                continue;
            }
        };
        for agent in agents {
            let mut more = ControlFlow::Continue(());
            let mut turns = 0;
            let walked = walk_turns_while(
                store,
                &key,
                *thread,
                agent,
                MAX_SEARCHED_TURNS + 1,
                |turn| {
                    if turns == MAX_SEARCHED_TURNS {
                        let _ = writeln!(
                            unread,
                            "mahi: only the newest {MAX_SEARCHED_TURNS} turns of {agent} in \
                             thread {thread} are searched"
                        );
                        return ControlFlow::Break(());
                    }
                    turns += 1;
                    for event in turn.events() {
                        let Some((kind, text)) = matched(event.payload(), needle, &mut cleaned)
                        else {
                            continue;
                        };
                        if matches.len() == MAX_MATCHES {
                            more = ControlFlow::Break(());
                            return more;
                        }
                        matches.push(Match {
                            thread: AsText(thread),
                            agent: AsText(agent),
                            turn: turn.turn(),
                            kind,
                            text,
                        });
                    }
                    ControlFlow::Continue(())
                },
            );
            if let Err(error) = walked {
                let _ = writeln!(
                    unread,
                    "mahi: cannot read every turn of {agent} in thread {thread}: {}",
                    crate::describe(&error)
                );
            }
            if more.is_break() {
                return Ok(more);
            }
        }
    }
    Ok(ControlFlow::Continue(()))
}

fn ask_passphrase() -> Result<SecretString, SearchError> {
    TerminalPrompt::open()
        .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
        .map_err(SearchError::Terminal)
}

fn found_text(matches: &[Match<'_>]) -> String {
    if matches.is_empty() {
        return "no turn matches\n".to_owned();
    }
    let mut found = String::new();
    for found_match in matches {
        let _ = writeln!(
            found,
            "{}  {}  turn {}  {}: {}",
            found_match.thread.0,
            found_match.agent.0,
            found_match.turn,
            found_match.kind.as_str(),
            found_match.text
        );
    }
    found
}

/// Returns what the event `payload` is and the excerpt around the first place it holds
/// `needle`, folded to lower case, once cleaned into `cleaned`; or `None` when the event is
/// neither a prompt nor a tool call, or does not hold it.
///
/// A prompt is searched whole. A tool call is searched in its tool's name and in every text
/// of its input, and shown as its tool's name and the excerpt of the text that holds it.
fn matched(payload: &[u8], needle: &[char], cleaned: &mut String) -> Option<(Kind, String)> {
    let (name, details) = handoff::split_event(payload)?;
    let kind = match HookKind::parse(name)? {
        HookKind::Prompt => Kind::Asked,
        HookKind::Tool => Kind::Used,
        HookKind::TurnEnd | HookKind::Asks => return None,
    };
    let Some(fields) = HookFields::parse(details) else {
        return excerpt_of(&String::from_utf8_lossy(details), needle, cleaned)
            .map(|shown| (kind, shown));
    };
    if kind == Kind::Asked {
        return excerpt_of(fields.prompt.as_deref()?, needle, cleaned).map(|shown| (kind, shown));
    }
    let tool = fields.tool_name.as_deref();
    let mut shown = String::new();
    push_cleaned(
        &mut shown,
        tool.unwrap_or(NO_TOOL_NAME),
        MAX_TOOL_NAME_CHARS,
    );
    if tool.is_some_and(|tool| excerpt_of(tool, needle, cleaned).is_some()) {
        return Some((kind, shown));
    }
    let inside = find_in(fields.tool_input.as_ref()?, needle, cleaned)?;
    shown.push(' ');
    shown.push_str(&inside);
    Some((kind, shown))
}

/// Returns the excerpt of the first text inside `value`, depth first, that holds `needle`.
fn find_in(value: &Value, needle: &[char], cleaned: &mut String) -> Option<String> {
    match value {
        Value::String(text) => excerpt_of(text, needle, cleaned),
        Value::Array(values) => values
            .iter()
            .find_map(|value| find_in(value, needle, cleaned)),
        Value::Object(fields) => fields
            .values()
            .find_map(|value| find_in(value, needle, cleaned)),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

/// Cleans `text` into `cleaned` as it is shown, and returns the excerpt of it around the
/// first place it holds `needle`.
fn excerpt_of(text: &str, needle: &[char], cleaned: &mut String) -> Option<String> {
    cleaned.clear();
    push_cleaned(cleaned, text, usize::MAX);
    let at = find_folded(cleaned, needle)?;
    Some(excerpt(cleaned, at))
}

/// Returns the characters of `text` as they are shown on one line: each run of white space
/// as one space, without control or invisible characters.
fn cleaned_chars(text: &str) -> impl Iterator<Item = char> + '_ {
    let mut after_space = false;
    text.chars().filter_map(move |character| {
        if character.is_whitespace() {
            let first = !after_space;
            after_space = true;
            return first.then_some(' ');
        }
        if character.is_control() || is_invisible(character) {
            return None;
        }
        after_space = false;
        Some(character)
    })
}

/// Appends at most `most` of `characters` to `out`, marked where they are cut.
fn push_most(out: &mut String, characters: impl Iterator<Item = char>, most: usize) {
    let numbered = characters.enumerate();
    for (kept, character) in numbered {
        if kept == most {
            out.push(CUT);
            return;
        }
        out.push(character);
    }
}

fn push_cleaned(out: &mut String, text: &str, most: usize) {
    push_most(out, cleaned_chars(text), most);
}

/// Returns `text` as a search looks for it: cleaned as a transcript's text is, then folded to
/// lower case.
fn needle_of(text: &str) -> Vec<char> {
    let mut cleaned = String::new();
    push_cleaned(&mut cleaned, text, usize::MAX);
    folded(&cleaned).collect()
}

fn folded(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars().flat_map(char::to_lowercase)
}

/// Returns the byte offset in `haystack` of the first character from which it holds `needle`,
/// both folded to lower case.
fn find_folded(haystack: &str, needle: &[char]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let starts = haystack.char_indices().map(|(at, _)| at);
    for at in starts {
        let rest = haystack.get(at..)?;
        let mut held = folded(rest);
        if needle.iter().all(|wanted| held.next() == Some(*wanted)) {
            return Some(at);
        }
    }
    None
}

/// Returns up to [`MAX_EXCERPT_CHARS`] characters of the cleaned `text`, starting up to
/// [`CHARS_BEFORE`] characters before the byte offset `at`, marked where it is cut.
fn excerpt(text: &str, at: usize) -> String {
    let before = text.get(..at).unwrap_or_default();
    let start = before
        .char_indices()
        .rev()
        .nth(CHARS_BEFORE - 1)
        .map_or(0, |(start, _)| start);
    let mut shown = String::new();
    if start > 0 {
        shown.push(CUT);
    }
    let rest = text.get(start..).unwrap_or_default();
    push_most(&mut shown, rest.chars(), MAX_EXCERPT_CHARS);
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(payload: &[u8], text: &str) -> Option<(Kind, String)> {
        matched(payload, &needle_of(text), &mut String::new())
    }

    #[test]
    fn a_prompt_or_a_tool_call_matches_in_any_case_and_other_events_never_do() {
        assert_eq!(
            found(b"prompt\n{\"prompt\":\"Add the Sign-In page\"}", "sign-in"),
            Some((Kind::Asked, "Add the Sign-In page".to_owned()))
        );
        assert_eq!(
            found(
                br#"tool
{"tool_name":"Bash","tool_input":{"command":"cargo test login"}}"#,
                "LOGIN"
            ),
            Some((Kind::Used, "Bash cargo test login".to_owned()))
        );
        assert_eq!(
            found(
                br#"tool
{"tool_name":"WebFetch","tool_input":{}}"#,
                "fetch"
            ),
            Some((Kind::Used, "WebFetch".to_owned()))
        );
        assert_eq!(
            found(b"prompt\nplain login", "login"),
            Some((Kind::Asked, "plain login".to_owned()))
        );
        assert_eq!(found(b"prompt\nnothing here", "login"), None);
        assert_eq!(found(b"prompt\n{\"cwd\":\"login\"}", "login"), None);
        assert_eq!(found(b"turn-end\nlogin", "login"), None);
        assert_eq!(found(b"asks\nlogin", "login"), None);
        assert_eq!(found(b"prompt login", "login"), None);
        assert_eq!(
            found(
                br#"tool
{"tool_input":{"command":"ls"}}"#,
                "tool"
            ),
            None
        );
        assert_eq!(
            found(
                br#"tool
{"tool_input":{"command":"ls"}}"#,
                "ls"
            ),
            Some((Kind::Used, "tool ls".to_owned()))
        );
        assert_eq!(found(b"prompt\nlogin", ""), None);
    }

    #[test]
    fn a_long_prompt_and_every_text_of_a_tools_input_are_searched() {
        let prompt = format!("{{\"prompt\":\"{} needle\"}}", "x".repeat(5000));
        let (kind, shown) = found(format!("prompt\n{prompt}").as_bytes(), "NEEDLE").unwrap();
        assert_eq!(kind, Kind::Asked);
        assert!(shown.ends_with("x needle"), "{shown}");
        let edit = br#"tool
{"tool_name":"Edit","tool_input":{"file_path":"src/a.rs","edits":[{"new_string":"fn login() {}"}]}}"#;
        assert_eq!(
            found(edit, "fn login"),
            Some((Kind::Used, "Edit fn login() {}".to_owned()))
        );
    }

    #[test]
    fn hidden_characters_and_line_breaks_do_not_keep_a_text_from_matching() {
        assert_eq!(
            found(
                b"prompt\n{\"prompt\":\"log\\u200bin\\r\\n\\n page\\u001b[2J\"}",
                "login page"
            ),
            Some((Kind::Asked, "login page[2J".to_owned()))
        );
        assert_eq!(
            found(b"prompt\nthe login page", "\tLOGIN\u{200b}\n PAGE"),
            Some((Kind::Asked, "the login page".to_owned()))
        );
        assert_eq!(found(b"prompt\nthe login page", "\u{200b}"), None);
    }

    #[test]
    fn a_match_found_in_folded_text_points_into_the_original_text() {
        let needle = |text: &str| -> Vec<char> { folded(text).collect() };
        let text = "İstanbul and Straße";
        assert_eq!(find_folded(text, &needle("STRASSE")), None);
        let at = find_folded(text, &needle("straße")).unwrap();
        assert_eq!(text.get(at..), Some("Straße"));
        let at = find_folded(text, &needle("and")).unwrap();
        assert_eq!(text.get(at..), Some("and Straße"));
    }

    #[test]
    fn an_excerpt_starts_before_the_match_and_is_cut_on_both_sides() {
        let text = format!("{}needle{}", "a".repeat(100), "b".repeat(300));
        let at = text.find("needle").unwrap();
        let shown = excerpt(&text, at);
        assert!(
            shown.starts_with(&format!("…{}needle", "a".repeat(60))),
            "{shown}"
        );
        assert!(shown.ends_with("b…"), "{shown}");
        assert_eq!(shown.chars().count(), 1 + MAX_EXCERPT_CHARS + 1);
        assert_eq!(excerpt("short needle", 6), "short needle");
    }

    #[test]
    fn a_tools_name_is_cleaned_and_cut() {
        let name = format!(
            "{{\"tool_name\":\"{}\\u001b\",\"tool_input\":{{\"x\":\"hit\"}}}}",
            "n".repeat(100)
        );
        let (_, shown) = found(format!("tool\n{name}").as_bytes(), "hit").unwrap();
        assert_eq!(shown, format!("{}… hit", "n".repeat(MAX_TOOL_NAME_CHARS)));
    }
}
