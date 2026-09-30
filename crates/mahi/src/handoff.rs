use std::{
    collections::VecDeque,
    io::{
        self,
        Write,
    },
    path::Path,
};

use mahi_core::{
    AgentSlot,
    ThreadId,
};
use mahi_crypto::ThreadKey;
use mahi_store::{
    ObjectId,
    Store,
    StoreError,
};
use mahi_thread::{
    BRIEFED_PROMPTS,
    BRIEFED_REPLIES,
    Briefing,
    MetaError,
    ParticipantKey,
    SessionReader,
    TranscriptError,
    VerifiedMeta,
    session_ref,
    signed_by,
    walk_turns,
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    hook::HookKind,
    profile::Profile,
};

const MAX_TURNS: usize = 10_000;
const MAX_LOG_LINE_BYTES: usize = 4 * 1024 * 1024;
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
    let replies = meta
        .participants()
        .find(|listed| listed.name() == from.participant())
        .map(|listed| replies(store, key, meta.thread(), from, listed.key()))
        .unwrap_or_default();
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
        replies,
    })
}

/// Returns the latest replies of `from`'s agent, oldest first, from the newest session log its
/// recorded session holds, when its profile can read one and the session is signed by `writer`,
/// the key `meta` lists for its participant. Anything that cannot be read gives no replies.
pub(crate) fn replies(
    store: &Store,
    key: &ThreadKey,
    thread: ThreadId,
    from: &AgentSlot,
    writer: &ParticipantKey,
) -> Vec<String> {
    let Some(read_line) =
        Profile::for_agent(from.agent().as_str().as_ref()).and_then(|profile| profile.log_line)
    else {
        return Vec::new();
    };
    let Ok(Some(head)) = store.head(&session_ref(thread, from)) else {
        return Vec::new();
    };
    if !signed_by(store, head, writer).unwrap_or(false) {
        return Vec::new();
    }
    let Ok(reader) = SessionReader::open(store, key, head) else {
        return Vec::new();
    };
    let mut newest: Option<(Option<String>, VecDeque<String>)> = None;
    for (index, file) in reader.files().iter().enumerate() {
        let path = file.path.as_str();
        let log = Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"));
        if path.contains('/') || !log {
            continue;
        }
        let mut last = None;
        let mut latest = VecDeque::new();
        let mut lines = Lines::new(|line| {
            let Some(read) = read_line(line) else {
                return;
            };
            if read.timestamp.is_some() {
                last = read.timestamp;
            }
            if let Some(reply) = read.reply {
                if latest.len() == BRIEFED_REPLIES {
                    latest.pop_front();
                }
                latest.push_back(reply);
            }
        });
        if reader.copy(index, &mut lines).is_err() {
            return Vec::new();
        }
        lines.finish();
        if newest.as_ref().is_none_or(|(time, _)| last > *time) {
            newest = Some((last, latest));
        }
    }
    newest.map(|(_, latest)| latest.into()).unwrap_or_default()
}

/// Splits what is written to it into lines and hands each to `visit`, leaving out lines longer
/// than 4 MiB without holding them.
struct Lines<F: FnMut(&[u8])> {
    partial: Vec<u8>,
    skipping: bool,
    visit: F,
}

impl<F: FnMut(&[u8])> Lines<F> {
    fn new(visit: F) -> Self {
        Self {
            partial: Vec::new(),
            skipping: false,
            visit,
        }
    }

    fn end_line(&mut self) {
        if !self.skipping && !self.partial.is_empty() {
            (self.visit)(&self.partial);
        }
        self.partial.clear();
        self.skipping = false;
    }

    fn finish(mut self) {
        self.end_line();
    }
}

impl<F: FnMut(&[u8])> Write for Lines<F> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut rest = buffer;
        while !rest.is_empty() {
            let (piece, ends) = match rest.iter().position(|byte| *byte == b'\n') {
                Some(at) => (rest.get(..at).unwrap_or_default(), Some(at + 1)),
                None => (rest, None),
            };
            if ends.is_some() && self.partial.is_empty() && !self.skipping {
                if !piece.is_empty() && piece.len() <= MAX_LOG_LINE_BYTES {
                    (self.visit)(piece);
                }
            } else if !self.skipping {
                if self.partial.len() + piece.len() > MAX_LOG_LINE_BYTES {
                    self.skipping = true;
                    self.partial.clear();
                } else {
                    self.partial.extend_from_slice(piece);
                }
            }
            match ends {
                Some(next) => {
                    self.end_line();
                    rest = rest.get(next..).unwrap_or_default();
                }
                None => rest = &[],
            }
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
    use mahi_core::{
        AgentName,
        ParticipantName,
    };
    use mahi_thread::{
        GitSigner,
        SessionPath,
        SessionWriter,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

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
        let long = format!(
            "{{\"tool_name\":\"{}\",\"tool_input\":{{\"command\":\"ls\"}}}}",
            "n".repeat(MAX_KEPT_CHARS + 10)
        );
        assert_eq!(tool_text(long.as_bytes()).chars().count(), MAX_KEPT_CHARS);
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

    #[test]
    fn lines_are_split_across_writes_and_overlong_ones_left_out() {
        let mut seen = Vec::new();
        let mut lines = Lines::new(|line| seen.push(line.to_vec()));
        lines.write_all(b"one\ntw").unwrap();
        lines.write_all(b"o\n\nthree").unwrap();
        lines
            .write_all(&vec![b'x'; MAX_LOG_LINE_BYTES + 1])
            .unwrap();
        lines.write_all(b"\nfour\n").unwrap();
        lines.write_all(&vec![b'k'; MAX_LOG_LINE_BYTES]).unwrap();
        lines.write_all(b"\n").unwrap();
        lines
            .write_all(&vec![b's'; MAX_LOG_LINE_BYTES - 1])
            .unwrap();
        lines.write_all(b"ss\nfive").unwrap();
        lines.finish();
        assert_eq!(
            seen,
            [
                b"one".to_vec(),
                b"two".to_vec(),
                b"four".to_vec(),
                vec![b'k'; MAX_LOG_LINE_BYTES],
                b"five".to_vec(),
            ]
        );
    }

    fn log(time: &str, text: &str) -> String {
        format!(
            "{{\"type\":\"assistant\",\"timestamp\":\"{time}\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{text}\"}}]}}}}\n"
        )
    }

    #[test]
    fn replies_come_from_the_newest_log_of_a_session_its_participant_signed() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = ThreadKey::generate();
        let thread = mahi_core::ThreadId::random().unwrap();
        let from = AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("claude").unwrap(),
        );
        let alice = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let alice_key = ParticipantKey::from_public_key(alice.public_key()).unwrap();
        let older = [log("2026-01-01T00:00:00Z", "old")].concat();
        let hidden = [log("2027-01-01T00:00:00Z", "hidden")].concat();
        let newer = [
            log("2026-02-01T00:00:00Z", "one"),
            log("2026-02-01T00:00:01Z", "two"),
            "{\"type\":\"user\"}\n".to_owned(),
            log("2026-02-01T00:00:02Z", "three"),
            log("2026-02-01T00:00:03Z", "four"),
        ]
        .concat();
        let mut writer = SessionWriter::new(&store, &key, &alice_key, None).unwrap();
        for (name, text) in [
            ("a.jsonl", &newer),
            ("b.jsonl", &older),
            ("b/c.jsonl", &hidden),
            ("notes.txt", &hidden),
        ] {
            writer
                .add(SessionPath::new(name).unwrap(), &mut text.as_bytes())
                .unwrap();
        }
        let signer = GitSigner(alice);
        let head = writer.commit(thread, &from, &signer).unwrap();
        assert_eq!(
            replies(&store, &key, thread, &from, &alice_key),
            ["two", "three", "four"]
        );
        let bob = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let bob_key = ParticipantKey::from_public_key(bob.public_key()).unwrap();
        assert!(replies(&store, &key, thread, &from, &bob_key).is_empty());
        let mut entries = store.commit_blobs(head).unwrap();
        let garbage = store.write_sealed(&key, b"not the piece").unwrap();
        for (_, blob) in entries.iter_mut().filter(|(name, _)| name != "manifest") {
            *blob = garbage;
        }
        let named: Vec<(&str, mahi_store::EntryKind, ObjectId)> = entries
            .iter()
            .map(|(name, blob)| (name.as_str(), mahi_store::EntryKind::Blob, *blob))
            .collect();
        let tree = store.write_tree(&named).unwrap();
        store
            .append_signed(
                &session_ref(thread, &from),
                Some(head),
                tree,
                "session",
                &signer,
            )
            .unwrap();
        assert!(replies(&store, &key, thread, &from, &alice_key).is_empty());
        let codex = AgentSlot::new(
            ParticipantName::new("alice").unwrap(),
            AgentName::new("codex").unwrap(),
        );
        assert!(replies(&store, &key, thread, &codex, &alice_key).is_empty());
    }
}
