use std::time::Instant;

use mahi_core::{
    AgentSlot,
    ParticipantName,
};
use mahi_live::Body;
use unicode_width::UnicodeWidthChar;

use crate::{
    join::{
        ASK_EVERY,
        HOST_SILENCE,
        STUCK_SCREEN,
    },
    rebuilding::{
        Part,
        Rebuilding,
    },
};

const MOST_WATCHED: usize = 16;
const MOST_CELLS: u32 = 100_000;
const TAB_STOP: usize = 8;

/// The agents of a thread's other participants, as the workspace watches them: a screen for
/// each agent whose frames it accepted, rebuilt as a viewer rebuilds one, from which only
/// contents and cursor are ever drawn.
#[derive(Debug)]
pub(crate) struct Teammates {
    own: ParticipantName,
    agents: Vec<Teammate>,
    lost: bool,
    asked_at: Option<Instant>,
    started: Option<Instant>,
}

/// A teammate's agent the workspace watches.
#[derive(Debug)]
struct Teammate {
    slot: AgentSlot,
    presence: Presence,
    screen: Watched,
    rebuilding: Option<Rebuilding>,
}

impl Teammate {
    /// Forgets the agent's screen, and any on its way, since it is now too large to be kept;
    /// returns whether it was kept until now.
    fn grew_too_large(&mut self) -> bool {
        self.rebuilding = None;
        let was = matches!(self.screen, Watched::TooLarge);
        self.screen = Watched::TooLarge;
        !was
    }
}

/// Whether a teammate's agent's host is heard from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// Heard from last at this time, within [`HOST_SILENCE`].
    Online(Instant),
    /// Not heard from for [`HOST_SILENCE`], since this time, or never.
    Offline(Option<Instant>),
}

impl Teammate {
    fn was_heard(&self) -> bool {
        !matches!(self.presence, Presence::Offline(None))
    }
}

impl Presence {
    fn is_online(self) -> bool {
        matches!(self, Self::Online(_))
    }
}

/// What the workspace has of a teammate's agent's screen.
enum Watched {
    Waiting,
    Drawn(Box<vt100::Parser>),
    TooLarge,
    Record(Box<vt100::Parser>),
}

impl std::fmt::Debug for Watched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Waiting => "Waiting",
            Self::Drawn(_) => "Drawn",
            Self::TooLarge => "TooLarge",
            Self::Record(_) => "Record",
        })
    }
}

impl Teammates {
    /// Starts watching the agents of every participant of a thread but `own`, the user.
    pub(crate) fn new(own: ParticipantName) -> Self {
        Self {
            own,
            agents: Vec::new(),
            lost: false,
            asked_at: None,
            started: None,
        }
    }

    /// Applies what `participant`, whose node sent it, sent at `now`; returns whether an
    /// agent's screen or the list of agents changed.
    pub(crate) fn apply(
        &mut self,
        participant: &ParticipantName,
        body: Body,
        now: Instant,
    ) -> bool {
        if participant == &self.own {
            return false;
        }
        match body {
            Body::Heartbeat { slot } => self.seen(&slot, now).is_some_and(|(_, new)| new),
            Body::Output { slot, bytes } => {
                let Some((teammate, new)) = self.seen(&slot, now) else {
                    return false;
                };
                match &mut teammate.screen {
                    Watched::Drawn(screen) => {
                        screen.process(&bytes);
                        true
                    }
                    Watched::Waiting | Watched::TooLarge | Watched::Record(_) => new,
                }
            }
            Body::Resize {
                slot,
                rows,
                columns,
            } => {
                let Some((teammate, new)) = self.seen(&slot, now) else {
                    return false;
                };
                if !fits(rows, columns) {
                    return teammate.grew_too_large() || new;
                }
                match &mut teammate.screen {
                    Watched::Drawn(screen) => {
                        mahi_term::resize_screen(screen.as_mut(), rows, columns);
                        true
                    }
                    Watched::TooLarge => {
                        teammate.screen = Watched::Waiting;
                        true
                    }
                    Watched::Waiting | Watched::Record(_) => new,
                }
            }
            Body::Screen {
                slot,
                rows,
                columns,
                challenge,
                part,
                parts,
                bytes,
            } => {
                let Some((teammate, new)) = self.seen(&slot, now) else {
                    return false;
                };
                if !fits(rows, columns) {
                    return teammate.grew_too_large() || new;
                }
                let part = Part {
                    slot,
                    challenge,
                    rows,
                    columns,
                    index: part,
                    parts,
                    bytes,
                };
                let Some((_, screen)) = Rebuilding::add(&mut teammate.rebuilding, part, now) else {
                    return new;
                };
                teammate.screen = Watched::Drawn(Box::new(screen));
                true
            }
            Body::ScreenRequest { .. }
            | Body::Claims { .. }
            | Body::TurnEnded(_)
            | Body::State(_) => false,
        }
    }

    /// Notes that frames were dropped, or came from a run not anchored yet, so the screens
    /// are asked for again.
    pub(crate) fn lose(&mut self) {
        self.lost = true;
    }

    /// Says whether to ask for the agents' screens at `now`, at most once every
    /// [`ASK_EVERY`]: frames were dropped, an agent online has no screen and none on its way,
    /// one waited too long for its missing parts, or no agent was heard yet within
    /// [`HOST_SILENCE`] of the first call, then at most once every [`STUCK_SCREEN`], so a slow
    /// answer still meets the challenge it echoes. When it says so, the screens are taken as
    /// asked for.
    pub(crate) fn take_wants_screen(&mut self, now: Instant) -> bool {
        let started = *self.started.get_or_insert(now);
        if self
            .asked_at
            .is_some_and(|at| now.saturating_duration_since(at) < ASK_EVERY)
        {
            return false;
        }
        let unheard = !self.agents.iter().any(Teammate::was_heard)
            && now.saturating_duration_since(started) < HOST_SILENCE
            && self
                .asked_at
                .is_none_or(|at| now.saturating_duration_since(at) >= STUCK_SCREEN);
        let wanted = self.lost
            || unheard
            || self.agents.iter().any(|teammate| {
                teammate.presence.is_online()
                    && match &teammate.rebuilding {
                        Some(rebuilding) => rebuilding.waited_longer_than(STUCK_SCREEN, now),
                        None => matches!(teammate.screen, Watched::Waiting),
                    }
            });
        if wanted {
            self.lost = false;
            self.asked_at = Some(now);
        }
        wanted
    }

    /// Lists the agents not heard from for [`HOST_SILENCE`] at `now` as offline, and forgets
    /// their screens; returns whether one went offline.
    pub(crate) fn expire(&mut self, now: Instant) -> bool {
        let mut changed = false;
        for teammate in &mut self.agents {
            if let Presence::Online(heard) = teammate.presence
                && now.saturating_duration_since(heard) > HOST_SILENCE
            {
                teammate.presence = Presence::Offline(Some(heard));
                teammate.screen = Watched::Waiting;
                teammate.rebuilding = None;
                changed = true;
            }
        }
        changed
    }

    /// Lists as offline the agents of `slots` that are not the user's and not listed yet,
    /// while the list has room: those the thread's refs name, whose hosts were not heard from;
    /// returns whether one was listed.
    pub(crate) fn add_offline<'a>(
        &mut self,
        slots: impl IntoIterator<Item = &'a AgentSlot>,
    ) -> bool {
        let mut added = false;
        for slot in slots {
            if self.agents.len() >= MOST_WATCHED {
                break;
            }
            if slot.participant() == &self.own {
                continue;
            }
            if let Err(index) = self
                .agents
                .binary_search_by(|teammate| teammate.slot.cmp(slot))
            {
                self.agents.insert(
                    index,
                    Teammate {
                        slot: slot.clone(),
                        presence: Presence::Offline(None),
                        screen: Watched::Waiting,
                        rebuilding: None,
                    },
                );
                added = true;
            }
        }
        added
    }

    /// Returns the agents watched, in slot order, and whether each is online.
    pub(crate) fn agents(&self) -> impl ExactSizeIterator<Item = (&AgentSlot, bool)> {
        self.agents
            .iter()
            .map(|teammate| (&teammate.slot, teammate.presence.is_online()))
    }

    /// Returns the screen of `slot`'s agent, once one arrived and while it is online.
    pub(crate) fn screen(&self, slot: &AgentSlot) -> Option<&vt100::Screen> {
        let teammate = self.agents.iter().find(|teammate| &teammate.slot == slot)?;
        match &teammate.screen {
            Watched::Drawn(screen) | Watched::Record(screen) => Some(screen.screen()),
            Watched::Waiting | Watched::TooLarge => None,
        }
    }

    /// Says whether `slot`'s agent is offline and shows no record of its work yet.
    pub(crate) fn wants_record(&self, slot: &AgentSlot) -> bool {
        self.agents.iter().any(|teammate| {
            &teammate.slot == slot
                && !teammate.presence.is_online()
                && matches!(teammate.screen, Watched::Waiting)
        })
    }

    /// Shows `text`, the record of the work of `slot`'s agent while it is offline, on a screen
    /// of `rows` by `columns`, from its top, as a teammate's screen is shown.
    pub(crate) fn set_record(&mut self, slot: &AgentSlot, text: &str, (rows, columns): (u16, u16)) {
        let Some(teammate) = self
            .agents
            .iter_mut()
            .find(|teammate| &teammate.slot == slot && !teammate.presence.is_online())
        else {
            return;
        };
        let mut screen = vt100::Parser::new(rows.max(1), columns.max(1), 0);
        draw_from_top(&mut screen, text);
        teammate.screen = Watched::Record(Box::new(screen));
    }

    /// Forgets the records of the offline agents' work, so they are read again at another
    /// size.
    pub(crate) fn forget_records(&mut self) {
        for teammate in &mut self.agents {
            if matches!(teammate.screen, Watched::Record(_)) {
                teammate.screen = Watched::Waiting;
            }
        }
    }

    /// Notes that `slot`'s agent was heard from at `now`, listing it if it is new, in the place
    /// of the agent offline the longest when the list is full; returns the agent and whether
    /// it is new or came back online.
    fn seen(&mut self, slot: &AgentSlot, now: Instant) -> Option<(&mut Teammate, bool)> {
        let index = match self
            .agents
            .binary_search_by(|teammate| teammate.slot.cmp(slot))
        {
            Ok(index) => {
                let teammate = self.agents.get_mut(index)?;
                let back = !teammate.presence.is_online();
                teammate.presence = Presence::Online(now);
                if back {
                    teammate.screen = Watched::Waiting;
                }
                return Some((teammate, back));
            }
            Err(index) if self.agents.len() < MOST_WATCHED => index,
            Err(_) => {
                let silent = self
                    .agents
                    .iter()
                    .enumerate()
                    .filter_map(|(index, teammate)| match teammate.presence {
                        Presence::Offline(heard) => Some((index, heard)),
                        Presence::Online(_) => None,
                    })
                    .min_by_key(|&(_, heard)| heard)
                    .map(|(index, _)| index)?;
                self.agents.remove(silent);
                self.agents
                    .binary_search_by(|teammate| teammate.slot.cmp(slot))
                    .err()?
            }
        };
        self.agents.insert(
            index,
            Teammate {
                slot: slot.clone(),
                presence: Presence::Online(now),
                screen: Watched::Waiting,
                rebuilding: None,
            },
        );
        Some((self.agents.get_mut(index)?, true))
    }
}

/// Says whether a screen `rows` by `columns` is small enough to be kept.
fn fits(rows: u16, columns: u16) -> bool {
    u32::from(rows) * u32::from(columns) <= MOST_CELLS
}

/// Writes `text` into `screen` from its top, wrapping its long lines, and leaves out its
/// control characters, which could move the cursor, its characters wider than the screen,
/// and what does not fit, so the screen never scrolls.
fn draw_from_top(screen: &mut vt100::Parser, text: &str) {
    let (rows, columns) = screen.screen().size();
    let columns = usize::from(columns);
    let mut row = 0;
    let mut encoded = [0; 4];
    let mut next_row = |screen: &mut vt100::Parser| {
        row += 1;
        if row >= rows {
            return false;
        }
        screen.process(b"\r\n");
        true
    };
    for (index, line) in text.lines().enumerate() {
        if index > 0 && !next_row(screen) {
            return;
        }
        let mut width = 0;
        let drawn = |&c: &char| (c == '\t' || !c.is_control()) && c.width().unwrap_or(0) <= columns;
        for character in line.chars().filter(drawn) {
            if width > 0 && width + char_width(character, width, columns) > columns {
                if !next_row(screen) {
                    return;
                }
                width = 0;
            }
            screen.process(character.encode_utf8(&mut encoded).as_bytes());
            width += char_width(character, width, columns);
        }
    }
}

/// Returns how many columns `character` takes when written `width` columns into a row of
/// `columns`, where a tab stops at the last column.
fn char_width(character: char, width: usize, columns: usize) -> usize {
    if character == '\t' {
        (TAB_STOP - width % TAB_STOP).min(columns.saturating_sub(width + 1))
    } else {
        character.width().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    struct Clock(Instant);

    impl Clock {
        fn new() -> Self {
            Self(Instant::now())
        }

        fn asks(&mut self, teammates: &mut Teammates) -> bool {
            self.0 += ASK_EVERY;
            teammates.take_wants_screen(self.0)
        }
    }

    fn bob() -> ParticipantName {
        "bob".parse().unwrap()
    }

    fn slot(slot: &str) -> AgentSlot {
        slot.parse().unwrap()
    }

    fn screen(slot: &str, (rows, columns): (u16, u16), bytes: &[u8]) -> Body {
        Body::Screen {
            slot: self::slot(slot),
            rows,
            columns,
            challenge: [7; 16],
            part: 0,
            parts: 1,
            bytes: bytes.to_vec(),
        }
    }

    fn output(slot: &str, bytes: &[u8]) -> Body {
        Body::Output {
            slot: self::slot(slot),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn a_teammates_agent_is_listed_asked_for_and_drawn_from_its_screen_and_output() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let mut clock = Clock::new();
        let now = Instant::now();
        assert!(clock.asks(&mut teammates));
        assert!(teammates.apply(&bob(), output("bob.claude", b"lost"), now));
        assert!(teammates.screen(&slot("bob.claude")).is_none());
        assert!(clock.asks(&mut teammates));
        assert!(teammates.apply(&bob(), screen("bob.claude", (2, 20), b"hello"), now));
        assert!(!clock.asks(&mut teammates));
        assert!(teammates.apply(&bob(), output("bob.claude", b" world"), now));
        assert_eq!(
            teammates.screen(&slot("bob.claude")).unwrap().contents(),
            "hello world"
        );
        assert!(!teammates.apply(
            &bob(),
            Body::Heartbeat {
                slot: slot("bob.claude")
            },
            now
        ));
        assert_eq!(
            teammates
                .agents()
                .map(|(slot, online)| (slot.to_string(), online))
                .collect::<Vec<_>>(),
            [("bob.claude".to_owned(), true)]
        );
    }

    #[test]
    fn a_new_watcher_asks_until_it_hears_an_agent_for_at_most_the_host_silence() {
        let start = Instant::now();
        let mut teammates = Teammates::new("alice".parse().unwrap());
        assert!(teammates.take_wants_screen(start));
        assert!(!teammates.take_wants_screen(start + ASK_EVERY));
        assert!(teammates.take_wants_screen(start + STUCK_SCREEN));
        teammates.add_offline([&slot("bob.claude")]);
        let later = start + STUCK_SCREEN * 2;
        assert!(teammates.take_wants_screen(later));
        assert!(teammates.apply(&bob(), screen("bob.claude", (2, 20), b"hi"), later));
        assert!(!teammates.take_wants_screen(start + STUCK_SCREEN * 3));
        let mut unanswered = Teammates::new("alice".parse().unwrap());
        assert!(unanswered.take_wants_screen(start));
        assert!(!unanswered.take_wants_screen(start + HOST_SILENCE));
    }

    #[test]
    fn the_users_own_agents_are_not_watched_and_a_lost_frame_asks_again_once() {
        let mut teammates = Teammates::new(bob());
        let mut clock = Clock::new();
        assert!(!teammates.apply(&bob(), screen("bob.claude", (2, 20), b"me"), Instant::now()));
        assert_eq!(teammates.agents().count(), 0);
        assert!(clock.asks(&mut teammates));
        clock.0 += HOST_SILENCE;
        teammates.lose();
        assert!(clock.asks(&mut teammates));
        assert!(!clock.asks(&mut teammates));
    }

    #[test]
    fn a_silent_agent_goes_offline_without_its_screen_and_comes_back_when_heard() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let mut clock = Clock::new();
        let then = Instant::now();
        teammates.apply(&bob(), screen("bob.claude", (2, 20), b"hi"), then);
        let later = then + HOST_SILENCE + Duration::from_secs(1);
        assert!(!teammates.expire(then));
        assert!(teammates.expire(later));
        assert!(!teammates.expire(later));
        assert!(teammates.screen(&slot("bob.claude")).is_none());
        assert!(!clock.asks(&mut teammates));
        assert_eq!(
            teammates.agents().next().map(|(_, online)| online),
            Some(false)
        );
        assert!(teammates.apply(
            &bob(),
            Body::Heartbeat {
                slot: slot("bob.claude")
            },
            later
        ));
        assert!(clock.asks(&mut teammates));
    }

    #[test]
    fn a_screen_too_large_is_not_kept_nor_asked_for_again() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let mut clock = Clock::new();
        let now = Instant::now();
        assert!(teammates.apply(&bob(), screen("bob.claude", (1000, 1000), b"big"), now));
        assert!(teammates.screen(&slot("bob.claude")).is_none());
        assert!(!clock.asks(&mut teammates));
        teammates.apply(&bob(), screen("bob.claude", (2, 20), b"small"), now);
        assert!(teammates.screen(&slot("bob.claude")).is_some());
        let resize = Body::Resize {
            slot: slot("bob.claude"),
            rows: 1000,
            columns: 1000,
        };
        assert!(teammates.apply(&bob(), resize, now));
        assert!(teammates.screen(&slot("bob.claude")).is_none());
        assert!(!teammates.apply(&bob(), screen("bob.claude", (1000, 1000), b"big"), now));
        let fitting = Body::Resize {
            slot: slot("bob.claude"),
            rows: 2,
            columns: 20,
        };
        assert!(teammates.apply(&bob(), fitting, now));
        assert!(clock.asks(&mut teammates));
    }

    #[test]
    fn the_parts_of_two_agents_screens_may_interleave() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let now = Instant::now();
        let part = |slot: &str, index: u16, bytes: &[u8]| Body::Screen {
            slot: self::slot(slot),
            rows: 2,
            columns: 20,
            challenge: [7; 16],
            part: index,
            parts: 2,
            bytes: bytes.to_vec(),
        };
        teammates.apply(&bob(), part("bob.claude", 0, b"one "), now);
        teammates.apply(&bob(), part("bob.codex", 0, b"two "), now);
        teammates.apply(&bob(), part("bob.claude", 1, b"claude"), now);
        teammates.apply(&bob(), part("bob.codex", 1, b"codex"), now);
        assert_eq!(
            teammates.screen(&slot("bob.claude")).unwrap().contents(),
            "one claude"
        );
        assert_eq!(
            teammates.screen(&slot("bob.codex")).unwrap().contents(),
            "two codex"
        );
    }

    #[test]
    fn a_new_agent_takes_the_place_of_the_longest_silent_one_when_the_list_is_full() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let then = Instant::now();
        for agent in 0..MOST_WATCHED {
            let heartbeat = Body::Heartbeat {
                slot: slot(&format!("bob.agent{agent:02}")),
            };
            teammates.apply(&bob(), heartbeat, then + Duration::from_secs(agent as u64));
        }
        let later = then + HOST_SILENCE + Duration::from_secs(60);
        teammates.expire(later);
        assert!(teammates.apply(
            &bob(),
            Body::Heartbeat {
                slot: slot("bob.new")
            },
            later
        ));
        let listed: Vec<String> = teammates
            .agents()
            .map(|(slot, _)| slot.to_string())
            .collect();
        assert_eq!(listed.len(), MOST_WATCHED);
        assert!(listed.contains(&"bob.new".to_owned()));
        assert!(!listed.contains(&"bob.agent00".to_owned()));
        assert!(listed.contains(&"bob.agent01".to_owned()));
    }

    #[test]
    fn screens_are_asked_for_at_most_once_a_second_and_again_for_one_stuck() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let then = Instant::now();
        let first = Body::Screen {
            slot: slot("bob.claude"),
            rows: 2,
            columns: 20,
            challenge: [7; 16],
            part: 0,
            parts: 2,
            bytes: b"half".to_vec(),
        };
        teammates.apply(&bob(), output("bob.claude", b"x"), then);
        assert!(teammates.take_wants_screen(then));
        teammates.lose();
        assert!(!teammates.take_wants_screen(then + ASK_EVERY / 2));
        assert!(teammates.take_wants_screen(then + ASK_EVERY));
        teammates.apply(&bob(), first, then);
        assert!(!teammates.take_wants_screen(then + ASK_EVERY * 2));
        let stuck = then + STUCK_SCREEN + Duration::from_millis(1);
        assert!(teammates.take_wants_screen(stuck));
    }

    #[test]
    fn a_screen_on_its_way_when_the_agent_grew_too_large_is_not_drawn() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let now = Instant::now();
        let part = |index: u16| Body::Screen {
            slot: slot("bob.claude"),
            rows: 2,
            columns: 20,
            challenge: [7; 16],
            part: index,
            parts: 2,
            bytes: b"old ".to_vec(),
        };
        teammates.apply(&bob(), part(0), now);
        let resize = Body::Resize {
            slot: slot("bob.claude"),
            rows: 1000,
            columns: 1000,
        };
        assert!(teammates.apply(&bob(), resize, now));
        teammates.apply(&bob(), part(1), now);
        assert!(teammates.screen(&slot("bob.claude")).is_none());
    }

    #[test]
    fn agents_of_the_threads_refs_are_listed_offline_until_heard_and_go_first_when_full() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let known = [
            slot("alice.claude"),
            slot("bob.codex"),
            slot("carol.claude"),
        ];
        assert!(teammates.add_offline(&known));
        assert!(!teammates.add_offline(&known));
        let listed: Vec<(String, bool)> = teammates
            .agents()
            .map(|(slot, online)| (slot.to_string(), online))
            .collect();
        assert_eq!(
            listed,
            [
                ("bob.codex".to_owned(), false),
                ("carol.claude".to_owned(), false)
            ]
        );
        let mut clock = Clock::new();
        assert!(clock.asks(&mut teammates));
        clock.0 += HOST_SILENCE;
        assert!(!clock.asks(&mut teammates));
        let now = Instant::now();
        assert!(teammates.apply(
            &bob(),
            Body::Heartbeat {
                slot: slot("bob.codex")
            },
            now
        ));
        for agent in 0..MOST_WATCHED - 2 {
            let heartbeat = Body::Heartbeat {
                slot: slot(&format!("bob.agent{agent:02}")),
            };
            teammates.apply(&bob(), heartbeat, now);
        }
        assert!(teammates.apply(
            &bob(),
            Body::Heartbeat {
                slot: slot("bob.new")
            },
            now
        ));
        let listed: Vec<String> = teammates
            .agents()
            .map(|(slot, _)| slot.to_string())
            .collect();
        assert!(!listed.contains(&"carol.claude".to_owned()));
        assert!(listed.contains(&"bob.codex".to_owned()));
        assert!(!teammates.add_offline(&known));
    }

    #[test]
    fn a_record_of_an_offline_agents_work_shows_only_until_its_host_is_heard() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let codex = slot("bob.codex");
        teammates.add_offline([&codex]);
        assert!(teammates.wants_record(&codex));
        teammates.set_record(&codex, "Turn 1:\n  asked: fix it", (4, 30));
        assert!(!teammates.wants_record(&codex));
        assert_eq!(
            teammates.screen(&codex).map(vt100::Screen::contents),
            Some("Turn 1:\n  asked: fix it".to_owned())
        );
        teammates.forget_records();
        assert!(teammates.wants_record(&codex));
        teammates.set_record(&codex, "again", (4, 30));
        let now = Instant::now();
        assert!(teammates.apply(
            &bob(),
            Body::Heartbeat {
                slot: codex.clone()
            },
            now
        ));
        assert!(teammates.screen(&codex).is_none());
        assert!(!teammates.wants_record(&codex));
        teammates.set_record(&codex, "online", (4, 30));
        assert!(teammates.screen(&codex).is_none());
    }

    #[test]
    fn a_record_shows_from_its_top_with_long_lines_wrapped_and_no_control_characters() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let codex = slot("bob.codex");
        teammates.add_offline([&codex]);
        teammates.set_record(&codex, "first\n123456789\nthird\nfourth\nfifth", (4, 5));
        assert_eq!(
            teammates.screen(&codex).map(vt100::Screen::contents),
            Some("first\n12345\n6789\nthird".to_owned())
        );
        teammates.forget_records();
        teammates.set_record(&codex, "a\tb\n界界界", (3, 5));
        assert_eq!(
            teammates.screen(&codex).map(vt100::Screen::contents),
            Some("a   b\n界界\n界".to_owned())
        );
        teammates.forget_records();
        teammates.set_record(&codex, "a\x1b[2Jb\x07\u{9b}Hc\r\nd", (3, 10));
        assert_eq!(
            teammates.screen(&codex).map(vt100::Screen::contents),
            Some("a[2JbHc\nd".to_owned())
        );
        for (text, size, shown) in [
            ("a界b", (3, 1), "a\nb"),
            ("abcd界x", (3, 5), "abcd\n界x"),
            ("abc\tx", (3, 4), "abcx"),
            ("abc\ndef\nghi", (2, 3), "abc\ndef"),
        ] {
            teammates.forget_records();
            teammates.set_record(&codex, text, size);
            assert_eq!(
                teammates.screen(&codex).map(vt100::Screen::contents),
                Some(shown.to_owned()),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_teammates_screen_narrowed_past_a_wide_character_or_one_row_high_still_draws() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let now = Instant::now();
        let claude = slot("bob.claude");
        assert!(teammates.apply(
            &bob(),
            screen("bob.claude", (3, 4), "\x1b[1;3H界".as_bytes()),
            now
        ));
        let narrower = Body::Resize {
            slot: claude.clone(),
            rows: 3,
            columns: 3,
        };
        assert!(teammates.apply(&bob(), narrower, now));
        assert!(teammates.apply(&bob(), output("bob.claude", b"\x1b[1;3Hx"), now));
        assert_eq!(teammates.screen(&claude).unwrap().contents(), "  x");
        assert!(teammates.apply(&bob(), screen("bob.claude", (1, 4), b""), now));
        assert!(teammates.apply(&bob(), output("bob.claude", b"abcdef"), now));
        let shown = teammates.screen(&claude).unwrap();
        assert_eq!(shown.size(), (2, 4));
        assert_eq!(shown.contents(), "abcdef");
    }

    #[test]
    fn at_most_sixteen_agents_are_watched() {
        let mut teammates = Teammates::new("alice".parse().unwrap());
        let now = Instant::now();
        for agent in 0..20 {
            let heartbeat = Body::Heartbeat {
                slot: slot(&format!("bob.agent{agent:02}")),
            };
            teammates.apply(&bob(), heartbeat, now);
        }
        assert_eq!(teammates.agents().count(), MOST_WATCHED);
        let listed: Vec<String> = teammates
            .agents()
            .map(|(slot, _)| slot.to_string())
            .collect();
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(listed, sorted);
    }
}
