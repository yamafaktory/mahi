use std::fmt::Write;

use gix::bstr::{
    BStr,
    BString,
    ByteSlice,
};
use mahi_core::{
    AgentSlot,
    ThreadId,
};

const CHERRY_PICKED: &[u8] = b"(cherry picked from commit ";
const SIGNED_OFF_BY: &[u8] = b"Signed-off-by";
const LANDED_THREAD: &str = "Thread: ";
const LANDED_AGENT: &str = "Agent: ";
const MAX_LANDED_NAMES: usize = 64;

/// A thread a landed commit names in its trailers, with the agents named after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Landed {
    /// The thread.
    pub thread: ThreadId,
    /// The agents named after it, each once.
    pub agents: Vec<AgentSlot>,
}

/// Returns the trailers a landing of `thread` by `agents` writes on its commit.
#[must_use]
pub fn landing_trailers(thread: ThreadId, agents: &[AgentSlot]) -> String {
    let mut trailers = format!("{LANDED_THREAD}{thread}\n");
    for slot in agents {
        let _ = writeln!(trailers, "{LANDED_AGENT}{slot}");
    }
    trailers
}

/// Reads the threads a landed commit's `message` names, each with the agents named after it.
/// The lines may be anywhere and indented, since a squash merge can copy the messages of several
/// landings into one. A value that does not parse is left out, and so is an agent named before
/// any thread or after a thread line that does not parse, and any name past the 64th of its
/// kind, threads or one thread's agents.
#[must_use]
pub fn landed_from(message: &[u8]) -> Vec<Landed> {
    let mut landed: Vec<Landed> = Vec::new();
    let mut current = None;
    let lines = message
        .lines()
        .filter_map(|line| line.to_str().ok())
        .map(str::trim_start);
    for line in lines {
        if let Some(id) = line.strip_prefix(LANDED_THREAD) {
            current = id
                .parse()
                .ok()
                .and_then(|thread| named_at(&mut landed, thread));
        } else if let Some(slot) = line
            .strip_prefix(LANDED_AGENT)
            .and_then(|slot| slot.parse().ok())
            && let Some(named) = current.and_then(|at| landed.get_mut(at))
        {
            push_once(&mut named.agents, slot);
        }
    }
    landed
}

fn named_at(landed: &mut Vec<Landed>, thread: ThreadId) -> Option<usize> {
    if let Some(at) = landed.iter().position(|named| named.thread == thread) {
        return Some(at);
    }
    (landed.len() < MAX_LANDED_NAMES).then(|| {
        landed.push(Landed {
            thread,
            agents: Vec::new(),
        });
        landed.len() - 1
    })
}

fn push_once<T: PartialEq>(names: &mut Vec<T>, name: T) {
    if !names.contains(&name) && names.len() < MAX_LANDED_NAMES {
        names.push(name);
    }
}

/// Returns `message` with `trailers`, lines of `Key: value` each ending in a newline, joined to
/// its trailer block, or starting one when its last paragraph is not one, as git reads trailers.
#[must_use]
pub fn appended_trailers(message: &BStr, trailers: &str) -> BString {
    let body = message.trim_end();
    let eol: &[u8] = if body.find(b"\r\n").is_some() {
        b"\r\n"
    } else {
        b"\n"
    };
    let block = last_paragraph(body).filter(|block| is_trailer_block(block));
    let mut out = BString::from(Vec::with_capacity(
        body.len() + trailers.len() * 2 + 2 * eol.len(),
    ));
    out.extend_from_slice(body);
    out.extend_from_slice(eol);
    if block.is_none() {
        out.extend_from_slice(eol);
    }
    for line in trailers.as_bytes().lines() {
        out.extend_from_slice(line);
        out.extend_from_slice(eol);
    }
    out
}

fn last_paragraph(body: &[u8]) -> Option<&[u8]> {
    let mut start = None;
    let mut offset = 0;
    for line in body.lines_with_terminator() {
        offset += line.len();
        if line.trim().is_empty() {
            start = Some(offset);
        }
    }
    start.and_then(|at| body.get(at..))
}

fn is_trailer_block(block: &[u8]) -> bool {
    let mut trailers = 0_usize;
    let mut others = 0_usize;
    let mut generated = false;
    let mut after_trailer = false;
    for line in block.lines() {
        if after_trailer
            && line
                .first()
                .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            continue;
        }
        after_trailer = false;
        if line.starts_with(CHERRY_PICKED) {
            trailers += 1;
            generated = true;
        } else if let Some(key) = trailer_key(line) {
            trailers += 1;
            after_trailer = true;
            generated |= key.eq_ignore_ascii_case(SIGNED_OFF_BY);
        } else {
            others += 1;
        }
    }
    trailers > 0 && (others == 0 || (generated && trailers.saturating_mul(3) >= others))
}

fn trailer_key(line: &[u8]) -> Option<&[u8]> {
    let colon = line.find_byte(b':')?;
    let key = line.get(..colon)?.trim_end();
    let valid = !key.is_empty()
        && key
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
    valid.then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_landing_reads_back_each_thread_with_its_agents_from_anywhere_in_a_message() {
        let thread = ThreadId::random().unwrap();
        let other = ThreadId::random().unwrap();
        let alice: AgentSlot = "alice.claude".parse().unwrap();
        let bob: AgentSlot = "bob.codex".parse().unwrap();
        let landed = landing_trailers(thread, &[alice.clone(), bob.clone()]);
        let squashed = format!(
            "Squashed\n\nAgent: carol.claude\n* Change a\n\n{landed}\n    * Change b\n\n    Thread: {other}\n    Agent: alice.claude\nThread: not-an-id\nAgent: no slot\n"
        );
        assert_eq!(
            landed_from(squashed.as_bytes()),
            [
                Landed {
                    thread,
                    agents: vec![alice.clone(), bob],
                },
                Landed {
                    thread: other,
                    agents: vec![alice],
                },
            ]
        );
        assert_eq!(landed_from(b"Plain commit\n"), []);
    }

    #[test]
    fn an_agent_after_a_thread_line_that_does_not_parse_belongs_to_no_thread() {
        let thread = ThreadId::random().unwrap();
        let message =
            format!("Thread: {thread}\nAgent: alice.claude\nThread: not-an-id\nAgent: bob.codex\n");
        assert_eq!(
            landed_from(message.as_bytes()),
            [Landed {
                thread,
                agents: vec!["alice.claude".parse().unwrap()],
            }]
        );
    }

    #[test]
    fn at_most_64_threads_and_64_agents_of_a_thread_are_read_from_one_message() {
        let mut message = String::new();
        for _ in 0..70 {
            let _ = writeln!(message, "Thread: {}", ThreadId::random().unwrap());
        }
        assert_eq!(landed_from(message.as_bytes()).len(), 64);
        let mut message = format!("Thread: {}\n", ThreadId::random().unwrap());
        for agent in 0..70 {
            let _ = writeln!(message, "Agent: alice.agent{agent}");
        }
        assert_eq!(landed_from(message.as_bytes())[0].agents.len(), 64);
    }

    #[test]
    fn trailers_join_an_existing_block_or_start_one() {
        let trailers = "Thread: t\nAgent: alice.claude\n";
        let cases: [(&str, &str); 11] = [
            ("subject", "subject\n\n{}"),
            ("subject\n", "subject\n\n{}"),
            ("subject\n\nbody text\n\n", "subject\n\nbody text\n\n{}"),
            (
                "subject\n\nbody\n\nSigned-off-by: a <a@b>\n",
                "subject\n\nbody\n\nSigned-off-by: a <a@b>\n{}",
            ),
            ("subject\n\nThread: other\n", "subject\n\nThread: other\n{}"),
            ("Thread: t\n", "Thread: t\n\n{}"),
            (
                "s\n\nSigned-off-by: a <a@b>\n(cherry picked from commit abc)\n",
                "s\n\nSigned-off-by: a <a@b>\n(cherry picked from commit abc)\n{}",
            ),
            (
                "s\n\nCo-authored-by: a\n  folded <a@b>\nReviewed-by:b\n",
                "s\n\nCo-authored-by: a\n  folded <a@b>\nReviewed-by:b\n{}",
            ),
            (
                "s\n\nsome prose\nmore prose\nSigned-off-by: a <a@b>\n",
                "s\n\nsome prose\nmore prose\nSigned-off-by: a <a@b>\n{}",
            ),
            (
                "s\n\nNote: this is prose\nthat goes on\n",
                "s\n\nNote: this is prose\nthat goes on\n\n{}",
            ),
            (
                "s\r\n\r\nSigned-off-by: a <a@b>\r\n",
                "s\r\n\r\nSigned-off-by: a <a@b>\r\nThread: t\r\nAgent: alice.claude\r\n",
            ),
        ];
        for (message, expected) in cases {
            assert_eq!(
                appended_trailers(message.into(), trailers),
                BString::from(expected.replace("{}", trailers)),
                "{message:?}"
            );
        }
    }
}
