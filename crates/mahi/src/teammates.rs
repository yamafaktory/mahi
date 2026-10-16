use std::time::Instant;

use mahi_core::{
    AgentSlot,
    ParticipantName,
};
use mahi_live::Body;

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

/// The agents of a thread's other participants, as the workspace watches them: a screen for
/// each agent whose frames it accepted, rebuilt as a viewer rebuilds one, from which only
/// contents and cursor are ever drawn.
#[derive(Debug)]
pub(crate) struct Teammates {
    own: ParticipantName,
    agents: Vec<Teammate>,
    lost: bool,
    asked_at: Option<Instant>,
}

/// A teammate's agent the workspace watches.
#[derive(Debug)]
struct Teammate {
    slot: AgentSlot,
    heard: Instant,
    online: bool,
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

/// What the workspace has of a teammate's agent's screen.
enum Watched {
    Waiting,
    Drawn(Box<vt100::Parser>),
    TooLarge,
}

impl std::fmt::Debug for Watched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Waiting => "Waiting",
            Self::Drawn(_) => "Drawn",
            Self::TooLarge => "TooLarge",
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
                    Watched::Waiting | Watched::TooLarge => new,
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
                        screen.screen_mut().set_size(rows, columns);
                        true
                    }
                    Watched::TooLarge => {
                        teammate.screen = Watched::Waiting;
                        true
                    }
                    Watched::Waiting => new,
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
            | Body::Prompt { .. }
            | Body::PromptAnswer { .. }
            | Body::Claims { .. } => false,
        }
    }

    /// Notes that frames were dropped, or came from a run not anchored yet, so the screens
    /// are asked for again.
    pub(crate) fn lose(&mut self) {
        self.lost = true;
    }

    /// Says whether to ask for the agents' screens at `now`, at most once every
    /// [`ASK_EVERY`]: frames were dropped, an agent online has no screen and none on its way,
    /// or one waited too long for its missing parts. When it says so, the screens are taken as asked for.
    pub(crate) fn take_wants_screen(&mut self, now: Instant) -> bool {
        if self
            .asked_at
            .is_some_and(|at| now.saturating_duration_since(at) < ASK_EVERY)
        {
            return false;
        }
        let wanted = self.lost
            || self.agents.iter().any(|teammate| {
                teammate.online
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
            if teammate.online && now.saturating_duration_since(teammate.heard) > HOST_SILENCE {
                teammate.online = false;
                teammate.screen = Watched::Waiting;
                teammate.rebuilding = None;
                changed = true;
            }
        }
        changed
    }

    /// Returns the agents watched, in slot order, and whether each is online.
    pub(crate) fn agents(&self) -> impl Iterator<Item = (&AgentSlot, bool)> {
        self.agents
            .iter()
            .map(|teammate| (&teammate.slot, teammate.online))
    }

    /// Returns the screen of `slot`'s agent, once one arrived and while it is online.
    pub(crate) fn screen(&self, slot: &AgentSlot) -> Option<&vt100::Screen> {
        let teammate = self.agents.iter().find(|teammate| &teammate.slot == slot)?;
        match &teammate.screen {
            Watched::Drawn(screen) => Some(screen.screen()),
            Watched::Waiting | Watched::TooLarge => None,
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
                teammate.heard = now;
                let back = !teammate.online;
                teammate.online = true;
                return Some((teammate, back));
            }
            Err(index) if self.agents.len() < MOST_WATCHED => index,
            Err(_) => {
                let silent = self
                    .agents
                    .iter()
                    .enumerate()
                    .filter(|(_, teammate)| !teammate.online)
                    .min_by_key(|(_, teammate)| teammate.heard)
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
                heard: now,
                online: true,
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
        assert!(!clock.asks(&mut teammates));
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
    fn the_users_own_agents_are_not_watched_and_a_lost_frame_asks_again_once() {
        let mut teammates = Teammates::new(bob());
        let mut clock = Clock::new();
        assert!(!teammates.apply(&bob(), screen("bob.claude", (2, 20), b"me"), Instant::now()));
        assert_eq!(teammates.agents().count(), 0);
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
