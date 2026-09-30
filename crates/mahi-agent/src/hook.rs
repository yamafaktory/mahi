//! The messages an agent's hooks send the `mahi run` that started it: the event's name, a
//! newline, the payload's length as four big-endian bytes, and the payload.

use mahi_thread::MAX_EVENT_BYTES;

const LONGEST_NAME: usize = 16;
const LENGTH_BYTES: usize = 4;

/// The largest payload a hook can report: an event holds its name, a newline, and the payload.
pub const MAX_PAYLOAD_BYTES: usize = MAX_EVENT_BYTES - LONGEST_NAME - 1;

/// The largest message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = LONGEST_NAME + 1 + LENGTH_BYTES + MAX_PAYLOAD_BYTES;

/// What an agent's hook reports to the `mahi run` that started the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookKind {
    /// The user sent the agent a prompt.
    Prompt,
    /// The agent used a tool, which may have changed the worktree.
    Tool,
    /// The agent finished its turn.
    TurnEnd,
}

/// One event an agent's hook reported, with the payload it read from its standard input.
#[derive(Debug, PartialEq, Eq)]
pub struct HookMessage {
    /// What happened.
    pub kind: HookKind,
    /// What the agent told the hook about it.
    pub payload: Vec<u8>,
}

impl HookKind {
    /// Returns the event's name, as a message and a transcript event carry it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Tool => "tool",
            Self::TurnEnd => "turn-end",
        }
    }

    /// Returns every event, in the order `mahi hook` lists them.
    #[must_use]
    pub fn all() -> [Self; 3] {
        [Self::Prompt, Self::Tool, Self::TurnEnd]
    }

    /// Says what the event means, for `mahi hook --help`.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Prompt => "The user sent the agent a prompt",
            Self::Tool => "The agent used a tool, which may have changed the worktree",
            Self::TurnEnd => "The agent finished its turn",
        }
    }

    /// Returns the event named `name`, if it is one.
    #[must_use]
    pub fn parse(name: &[u8]) -> Option<Self> {
        Self::all()
            .into_iter()
            .find(|kind| kind.as_str().as_bytes() == name)
    }
}

/// Writes the message for `kind` with `payload`, or `None` when the payload is larger than
/// [`MAX_PAYLOAD_BYTES`].
#[must_use]
pub fn encode(kind: HookKind, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    let length = u32::try_from(payload.len()).ok()?;
    let name = kind.as_str().as_bytes();
    let mut message = Vec::with_capacity(name.len() + 1 + LENGTH_BYTES + payload.len());
    message.extend_from_slice(name);
    message.push(b'\n');
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(payload);
    Some(message)
}

/// Reads a whole message, or `None` when it is not one: an unknown or overlong name, a length
/// that does not match the payload, or a payload over [`MAX_PAYLOAD_BYTES`].
#[must_use]
pub fn decode(received: &[u8]) -> Option<HookMessage> {
    if received.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    let end = received
        .iter()
        .take(LONGEST_NAME + 1)
        .position(|&byte| byte == b'\n')?;
    let kind = HookKind::parse(received.get(..end)?)?;
    let rest = received.get(end + 1..)?;
    let (length, payload) = rest.split_first_chunk::<LENGTH_BYTES>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    (length == payload.len() && length <= MAX_PAYLOAD_BYTES).then(|| HookMessage {
        kind,
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_decode_to_what_was_encoded_and_nothing_else_decodes() {
        for kind in [HookKind::Prompt, HookKind::Tool, HookKind::TurnEnd] {
            let message = encode(kind, b"payload").unwrap();
            assert_eq!(
                decode(&message),
                Some(HookMessage {
                    kind,
                    payload: b"payload".to_vec(),
                })
            );
            assert_eq!(HookKind::parse(kind.as_str().as_bytes()), Some(kind));
        }
        let message = encode(HookKind::Tool, b"abc").unwrap();
        assert_eq!(decode(message.get(..message.len() - 1).unwrap()), None);
        let mut longer = message.clone();
        longer.push(b'x');
        assert_eq!(decode(&longer), None);
        assert_eq!(decode(b"unknown\n\0\0\0\0"), None);
        assert_eq!(decode(b""), None);
        assert!(encode(HookKind::Prompt, &vec![0; MAX_PAYLOAD_BYTES + 1]).is_none());
        let largest = encode(HookKind::TurnEnd, &vec![0; MAX_PAYLOAD_BYTES]).unwrap();
        assert!(largest.len() <= MAX_MESSAGE_BYTES);
        assert!(decode(&largest).is_some());
    }
}
