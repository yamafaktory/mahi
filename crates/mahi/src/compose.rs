use std::{
    collections::VecDeque,
    io::{
        self,
        Write,
    },
};

use mahi_core::AgentSlot;
use mahi_live::{
    MAX_PROMPT_BYTES,
    PROMPT_ID_BYTES,
    PromptOutcome,
};
use mahi_term::{
    KeyScanner,
    PaletteInput,
    PaletteItem,
    PaletteKey,
    PaletteKeys,
    PaletteView,
    Segment,
};

const QUIT_KEYS: [u8; 3] = [b'q', 0x03, 0x04];
const MOST_SENT: usize = 32;
const SHOWN_CHARS: usize = 200;
const EMPTY: &str = "Type a prompt for the agent; Enter sends it to its host";
const HINT: &str = "Enter sends · ↑↓ and Enter on an empty line switch agents · Esc closes";
const NOT_SENT: &str = "not sent";

/// What a watching teammate writes to the followed agent: the palette they compose a prompt in,
/// and the prompts they sent with what their host answered.
#[derive(Debug)]
pub(crate) struct Composer {
    scanner: KeyScanner,
    keys: PaletteKeys,
    open: bool,
    text: String,
    sent: VecDeque<Sent>,
    title: String,
    follows: String,
    agents: Vec<AgentSlot>,
    watching: Option<AgentSlot>,
    selected: usize,
}

#[derive(Debug)]
struct Sent {
    id: Option<[u8; PROMPT_ID_BYTES]>,
    text: String,
    outcome: Option<PromptOutcome>,
}

/// What the keys a watching teammate typed asked for.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Typed {
    /// Leave the thread.
    pub(crate) quit: bool,
    /// The palette opened, closed or changed, so the screen is drawn again.
    pub(crate) changed: bool,
    /// Send this prompt.
    pub(crate) send: Option<String>,
    /// Watch this agent instead.
    pub(crate) switch: Option<AgentSlot>,
}

impl Composer {
    /// Starts a closed palette, opened with `key`, for prompts to `follows`'s agent.
    pub(crate) fn new(key: PaletteKey, follows: &str) -> Self {
        Self {
            scanner: KeyScanner::new(key),
            keys: PaletteKeys::default(),
            open: false,
            text: String::new(),
            sent: VecDeque::new(),
            title: format!("Prompt for {follows}'s agent"),
            follows: follows.to_owned(),
            agents: Vec::new(),
            watching: None,
            selected: 0,
        }
    }

    /// Lists `agents`, the followed participant's agents the viewer heard from, with the one it
    /// shows, `watching`; returns whether the list changed.
    pub(crate) fn set_agents<'a>(
        &mut self,
        agents: impl Iterator<Item = &'a AgentSlot> + Clone,
        watching: Option<&AgentSlot>,
    ) -> bool {
        if self.agents.iter().eq(agents.clone()) && watching == self.watching.as_ref() {
            return false;
        }
        self.agents.clear();
        self.agents.extend(agents.cloned());
        self.watching = watching.cloned();
        self.title = match &self.watching {
            Some(slot) => format!("Prompt for {slot}"),
            None => format!("Prompt for {}'s agent", self.follows),
        };
        if let Some(watched) = self
            .watching
            .as_ref()
            .and_then(|slot| self.agents.iter().position(|agent| agent == slot))
        {
            self.selected = watched;
        }
        self.selected = self.selected.min(self.agents.len().saturating_sub(1));
        true
    }

    /// Returns whether the palette is open.
    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    /// Takes `chunk`, the keys the teammate typed.
    pub(crate) fn typed(&mut self, chunk: &[u8]) -> Typed {
        let mut typed = Typed::default();
        let Self {
            scanner,
            keys,
            open,
            text,
            agents,
            watching,
            selected,
            ..
        } = self;
        for segment in scanner.scan(chunk) {
            match segment {
                Segment::Palette(_) => {
                    *open = !*open;
                    *keys = PaletteKeys::default();
                    typed.changed = true;
                }
                Segment::Pass(bytes) if !*open => {
                    typed.quit |= bytes.iter().any(|byte| QUIT_KEYS.contains(byte));
                }
                Segment::Pass(bytes) => {
                    let used = keys.read(bytes, |input| {
                        match input {
                            PaletteInput::Text(character)
                                if text.len() + character.len_utf8() <= MAX_PROMPT_BYTES =>
                            {
                                text.push(character);
                                typed.changed = true;
                            }
                            PaletteInput::Backspace => typed.changed |= text.pop().is_some(),
                            PaletteInput::Enter if !text.trim().is_empty() => {
                                typed.send = Some(std::mem::take(text));
                                typed.changed = true;
                            }
                            PaletteInput::Enter => {
                                let chosen = agents.get(*selected);
                                if chosen.is_some() && chosen != watching.as_ref() {
                                    typed.switch = chosen.cloned();
                                    typed.changed = true;
                                }
                            }
                            PaletteInput::Up if *selected > 0 => {
                                *selected -= 1;
                                typed.changed = true;
                            }
                            PaletteInput::Down if *selected + 1 < agents.len() => {
                                *selected += 1;
                                typed.changed = true;
                            }
                            PaletteInput::Escape => {
                                *open = false;
                                typed.changed = true;
                            }
                            PaletteInput::Text(_)
                            | PaletteInput::Tab
                            | PaletteInput::Reject
                            | PaletteInput::Up
                            | PaletteInput::Down
                            | PaletteInput::PageUp
                            | PaletteInput::PageDown => {}
                        }
                        *open
                    });
                    let rest = bytes.get(used..).unwrap_or_default();
                    typed.quit |= rest.iter().any(|byte| QUIT_KEYS.contains(byte));
                }
            }
        }
        typed
    }

    /// Notes that `text` was sent as the prompt `id`, or could not be sent when `id` is `None`.
    pub(crate) fn sent(&mut self, id: Option<[u8; PROMPT_ID_BYTES]>, text: &str) {
        if self.sent.len() == MOST_SENT {
            self.sent.pop_back();
        }
        self.sent.push_front(Sent {
            id,
            text: text.chars().take(SHOWN_CHARS).collect(),
            outcome: None,
        });
    }

    /// Notes what the host answered for the prompt `id`, and returns whether it was one of
    /// ours.
    pub(crate) fn answered(&mut self, id: [u8; PROMPT_ID_BYTES], outcome: PromptOutcome) -> bool {
        let Some(sent) = self.sent.iter_mut().find(|sent| sent.id == Some(id)) else {
            return false;
        };
        sent.outcome = Some(outcome);
        true
    }

    /// Draws the open palette on a screen of `rows` by `columns`.
    ///
    /// # Errors
    ///
    /// Returns the error `out` gives.
    pub(crate) fn draw(&self, rows: u16, columns: u16, out: &mut impl Write) -> io::Result<()> {
        if !self.open {
            return Ok(());
        }
        let agents = self.agents.iter().map(|agent| PaletteItem {
            label: if Some(agent) == self.watching.as_ref() {
                "watching"
            } else {
                "agent"
            },
            detail: agent.agent().as_str(),
        });
        let sent = self.sent.iter().map(|sent| PaletteItem {
            label: status(sent),
            detail: &sent.text,
        });
        let items: Vec<PaletteItem<'_>> = agents.chain(sent).collect();
        let view = PaletteView {
            title: &self.title,
            filter: &self.text,
            items: &items,
            selected: self.selected,
            empty: EMPTY,
            hint: HINT,
            preview: None,
        };
        view.draw(rows, columns, out).map(|_| ())
    }
}

fn status(sent: &Sent) -> &'static str {
    match (sent.id, sent.outcome) {
        (None, _) => NOT_SENT,
        (Some(_), None) => "sent",
        (Some(_), Some(PromptOutcome::Queued)) => "waiting",
        (Some(_), Some(PromptOutcome::Accepted)) => "accepted",
        (Some(_), Some(PromptOutcome::Rejected)) => "rejected",
        (Some(_), Some(PromptOutcome::Dropped)) => "dropped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(agent: &str) -> AgentSlot {
        format!("alice.{agent}").parse().unwrap()
    }

    fn composer() -> Composer {
        Composer::new(PaletteKey::CTRL_SPACE, "alice")
    }

    #[test]
    fn q_leaves_only_while_the_palette_is_closed() {
        let mut composer = composer();
        assert!(composer.typed(b"q").quit);
        assert!(composer.typed(b"\x03").quit);
        assert!(!composer.typed(b"x").quit);
        assert!(composer.typed(b"\0").changed);
        assert!(composer.is_open());
        assert!(!composer.typed(b"quit").quit);
        assert_eq!(composer.text, "quit");
    }

    #[test]
    fn keys_after_the_palette_closes_in_the_same_read_still_count() {
        let mut composer = composer();
        composer.typed(b"\0");
        assert!(composer.typed(b"\x1b[27uq").quit);
        composer.typed(b"\0");
        let typed = composer.typed(b"\x03");
        assert!(!typed.quit && !composer.is_open());
    }

    #[test]
    fn enter_sends_what_was_typed_and_escape_closes() {
        let mut composer = composer();
        composer.typed(b"\0");
        assert_eq!(composer.typed(b"  \r").send, None);
        let typed = composer.typed(b"fix the test\x7f\x7f\x7f\x7fbuild\r");
        assert_eq!(typed.send.as_deref(), Some("  fix the build"));
        assert!(composer.text.is_empty());
        assert!(composer.is_open());
        composer.typed(b"\x1b");
        assert!(!composer.is_open());
        composer.typed(b"\0");
        composer.typed(b"\0");
        assert!(!composer.is_open());
    }

    #[test]
    fn a_pasted_newline_does_not_send_and_the_text_stays_within_a_prompt() {
        let mut composer = composer();
        composer.typed(b"\0");
        let typed = composer.typed(b"\x1b[200~one\rtwo\x1b[201~");
        assert_eq!(typed.send, None);
        assert_eq!(composer.text, "one\ntwo");
        composer.text.clear();
        composer.typed(&vec![b'x'; MAX_PROMPT_BYTES + 10]);
        assert_eq!(composer.text.len(), MAX_PROMPT_BYTES);
    }

    #[test]
    fn the_agents_are_listed_and_enter_on_an_empty_line_switches_to_the_chosen_one() {
        let mut composer = composer();
        let (claude, codex) = (slot("claude"), slot("codex"));
        let both = [claude.clone(), codex.clone()];
        assert!(composer.set_agents(both.iter(), Some(&claude)));
        assert!(!composer.set_agents(both.iter(), Some(&claude)));
        composer.typed(b"\0");
        assert_eq!(composer.typed(b"\r").switch, None);
        assert!(composer.typed(b"\x1b[B").changed);
        assert!(!composer.typed(b"\x1b[B").changed);
        assert_eq!(composer.typed(b"\r").switch, Some(codex.clone()));
        let typed = composer.typed(b"look\r");
        assert_eq!(typed.send.as_deref(), Some("look"));
        assert_eq!(typed.switch, None);
        assert!(composer.set_agents(both.iter(), Some(&codex)));
        assert_eq!(composer.selected, 1);
        assert!(composer.typed(b"\x1b[A").changed);
        let mut out = Vec::new();
        composer.draw(24, 80, &mut out).unwrap();
        let drawn = String::from_utf8_lossy(&out);
        assert!(drawn.contains("Prompt for alice.codex"), "{drawn}");
        assert!(drawn.contains("watching"), "{drawn}");
        assert!(drawn.contains("claude"), "{drawn}");
        assert!(composer.set_agents([claude.clone()].iter(), Some(&claude)));
        assert_eq!(composer.selected, 0);
    }

    #[test]
    fn answers_update_what_was_sent_and_the_list_shows_them() {
        let mut composer = composer();
        composer.sent(Some([1; 16]), "first");
        composer.sent(None, "second");
        assert!(composer.answered([1; 16], PromptOutcome::Accepted));
        assert!(!composer.answered([9; 16], PromptOutcome::Rejected));
        let mut out = Vec::new();
        composer.draw(24, 80, &mut out).unwrap();
        assert!(out.is_empty());
        composer.typed(b"\0");
        composer.draw(24, 80, &mut out).unwrap();
        let drawn = String::from_utf8_lossy(&out);
        assert!(drawn.contains("Prompt for alice's agent"), "{drawn}");
        assert!(drawn.contains("accepted"), "{drawn}");
        assert!(drawn.contains(NOT_SENT), "{drawn}");
        for id in 0..40 {
            composer.sent(Some([id; 16]), "more");
        }
        assert_eq!(composer.sent.len(), MOST_SENT);
    }
}
