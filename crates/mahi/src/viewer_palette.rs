use std::io::{
    self,
    Write,
};

use mahi_core::AgentSlot;
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
const TITLE: &str = "Agents";
const HINT: &str = "↑↓ and Enter switch agents · Esc closes";

/// The palette a watching teammate opens in the viewer to switch between the followed
/// participant's agents.
#[derive(Debug)]
pub(crate) struct ViewerPalette {
    scanner: KeyScanner,
    keys: PaletteKeys,
    open: bool,
    agents: Vec<AgentSlot>,
    watching: Option<AgentSlot>,
    selected: usize,
}

/// What the keys a watching teammate typed asked for.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Typed {
    /// Leave the thread.
    pub(crate) quit: bool,
    /// The palette opened, closed or changed, so the screen is drawn again.
    pub(crate) changed: bool,
    /// Watch this agent instead.
    pub(crate) switch: Option<AgentSlot>,
}

impl ViewerPalette {
    /// Starts a closed palette, opened with `key`.
    pub(crate) fn new(key: PaletteKey) -> Self {
        Self {
            scanner: KeyScanner::new(key),
            keys: PaletteKeys::default(),
            open: false,
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
            agents,
            watching,
            selected,
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
                            | PaletteInput::Pasted(_)
                            | PaletteInput::Backspace
                            | PaletteInput::Tab
                            | PaletteInput::Reject
                            | PaletteInput::Up
                            | PaletteInput::Down
                            | PaletteInput::Left
                            | PaletteInput::Right
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

    /// Draws the open palette on a screen of `rows` by `columns`.
    ///
    /// # Errors
    ///
    /// Returns the error `out` gives.
    pub(crate) fn draw(&self, rows: u16, columns: u16, out: &mut impl Write) -> io::Result<()> {
        if !self.open {
            return Ok(());
        }
        let items: Vec<PaletteItem<'_>> = self
            .agents
            .iter()
            .map(|agent| PaletteItem {
                label: if Some(agent) == self.watching.as_ref() {
                    "watching"
                } else {
                    "agent"
                },
                detail: agent.agent().as_str(),
            })
            .collect();
        let view = PaletteView {
            title: TITLE,
            filter: "",
            items: &items,
            selected: self.selected,
            empty: crate::join::WAITING_FOR_HOST,
            hint: HINT,
            preview: None,
            true_color: crate::ui::true_color(),
        };
        view.draw(rows, columns, out).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(agent: &str) -> AgentSlot {
        format!("alice.{agent}").parse().unwrap()
    }

    fn palette() -> ViewerPalette {
        ViewerPalette::new(PaletteKey::CTRL_SPACE)
    }

    #[test]
    fn q_leaves_only_while_the_palette_is_closed() {
        let mut palette = palette();
        assert!(palette.typed(b"q").quit);
        assert!(palette.typed(b"\x03").quit);
        assert!(!palette.typed(b"x").quit);
        assert!(palette.typed(b"\0").changed);
        assert!(palette.is_open());
        assert!(!palette.typed(b"quit").quit);
        assert!(palette.is_open());
    }

    #[test]
    fn keys_after_the_palette_closes_in_the_same_read_still_count() {
        let mut palette = palette();
        palette.typed(b"\0");
        assert!(palette.typed(b"\x1b[27uq").quit);
        palette.typed(b"\0");
        let typed = palette.typed(b"\x03");
        assert!(!typed.quit && !palette.is_open());
    }

    #[test]
    fn escape_or_the_palette_key_closes_it() {
        let mut palette = palette();
        palette.typed(b"\0");
        palette.typed(b"\x1b");
        assert!(!palette.is_open());
        palette.typed(b"\0");
        palette.typed(b"\0");
        assert!(!palette.is_open());
    }

    #[test]
    fn the_agents_are_listed_and_enter_switches_to_the_chosen_one() {
        let mut palette = palette();
        let (claude, codex) = (slot("claude"), slot("codex"));
        let both = [claude.clone(), codex.clone()];
        assert!(palette.set_agents(both.iter(), Some(&claude)));
        assert!(!palette.set_agents(both.iter(), Some(&claude)));
        palette.typed(b"\0");
        assert_eq!(palette.typed(b"\r").switch, None);
        assert!(palette.typed(b"\x1b[B").changed);
        assert!(!palette.typed(b"\x1b[B").changed);
        assert!(!palette.typed(b"look").changed);
        assert_eq!(palette.typed(b"\r").switch, Some(codex.clone()));
        assert!(palette.set_agents(both.iter(), Some(&codex)));
        assert_eq!(palette.selected, 1);
        assert!(palette.typed(b"\x1b[A").changed);
        let mut out = Vec::new();
        palette.draw(24, 80, &mut out).unwrap();
        let drawn = String::from_utf8_lossy(&out);
        assert!(drawn.contains(TITLE), "{drawn}");
        assert!(drawn.contains("watching"), "{drawn}");
        assert!(drawn.contains("claude"), "{drawn}");
        assert!(palette.set_agents([claude.clone()].iter(), Some(&claude)));
        assert_eq!(palette.selected, 0);
    }

    #[test]
    fn a_closed_palette_draws_nothing_and_an_empty_one_says_what_it_waits_for() {
        let mut palette = palette();
        let mut out = Vec::new();
        palette.draw(24, 80, &mut out).unwrap();
        assert!(out.is_empty());
        palette.typed(b"\0");
        palette.draw(24, 80, &mut out).unwrap();
        let drawn = String::from_utf8_lossy(&out);
        assert!(drawn.contains(crate::join::WAITING_FOR_HOST), "{drawn}");
    }
}
