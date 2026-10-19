use std::time::{
    Duration,
    Instant,
};

use mahi_core::AgentSlot;

/// One part of an agent's screen, as a `Screen` frame carries it.
#[derive(Debug)]
pub(crate) struct Part {
    pub(crate) slot: AgentSlot,
    pub(crate) challenge: [u8; 16],
    pub(crate) rows: u16,
    pub(crate) columns: u16,
    pub(crate) index: u16,
    pub(crate) parts: u16,
    pub(crate) bytes: Vec<u8>,
}

/// The parts of one agent's screen that arrived, until all of them did.
#[derive(Debug)]
pub(crate) struct Rebuilding {
    slot: AgentSlot,
    challenge: [u8; 16],
    rows: u16,
    columns: u16,
    parts: Vec<Option<Vec<u8>>>,
    since: Instant,
}

impl Rebuilding {
    /// Adds `part`, which arrived at `now`, to the screen `rebuilding` holds, or starts another
    /// with it when it belongs to another screen; returns the screen and its agent once every
    /// part arrived.
    pub(crate) fn add(
        rebuilding: &mut Option<Self>,
        part: Part,
        now: Instant,
    ) -> Option<(AgentSlot, vt100::Parser)> {
        let same = rebuilding.as_ref().is_some_and(|screen| {
            screen.slot == part.slot
                && screen.challenge == part.challenge
                && (screen.rows, screen.columns) == (part.rows, part.columns)
                && screen.parts.len() == usize::from(part.parts)
        });
        if !same {
            *rebuilding = Some(Self {
                slot: part.slot,
                challenge: part.challenge,
                rows: part.rows,
                columns: part.columns,
                parts: vec![None; usize::from(part.parts)],
                since: now,
            });
        }
        let screen = rebuilding.as_mut()?;
        *screen.parts.get_mut(usize::from(part.index))? = Some(part.bytes);
        if screen.parts.iter().any(Option::is_none) {
            return None;
        }
        let screen = rebuilding.take()?;
        let mut parser = mahi_term::new_screen(screen.rows, screen.columns);
        for bytes in screen.parts.into_iter().flatten() {
            parser.process(&bytes);
        }
        Some((screen.slot, parser))
    }

    /// Says whether the screen has waited for its missing parts for longer than `wait` at
    /// `now`.
    pub(crate) fn waited_longer_than(&self, wait: Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.since) > wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(slot: &str, challenge: u8, (part, parts): (u16, u16), bytes: &[u8]) -> Part {
        Part {
            slot: slot.parse().unwrap(),
            challenge: [challenge; 16],
            rows: 2,
            columns: 10,
            index: part,
            parts,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn a_screen_is_rebuilt_once_its_parts_arrived_in_any_order() {
        let mut rebuilding = None;
        assert!(
            Rebuilding::add(
                &mut rebuilding,
                part("bob.claude", 1, (1, 2), b"there"),
                Instant::now(),
            )
            .is_none()
        );
        let (slot, screen) = Rebuilding::add(
            &mut rebuilding,
            part("bob.claude", 1, (0, 2), b"hi "),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(slot.to_string(), "bob.claude");
        assert_eq!(screen.screen().contents(), "hi there");
        assert!(rebuilding.is_none());
    }

    #[test]
    fn a_part_of_another_screen_starts_over_and_one_out_of_range_is_dropped() {
        let mut rebuilding = None;
        assert!(
            Rebuilding::add(
                &mut rebuilding,
                part("bob.claude", 1, (0, 2), b"old"),
                Instant::now(),
            )
            .is_none()
        );
        assert!(
            Rebuilding::add(
                &mut rebuilding,
                part("bob.claude", 2, (1, 2), b"new"),
                Instant::now(),
            )
            .is_none()
        );
        assert!(
            Rebuilding::add(
                &mut rebuilding,
                part("bob.claude", 2, (5, 2), b"x"),
                Instant::now(),
            )
            .is_none()
        );
        let (_, screen) = Rebuilding::add(
            &mut rebuilding,
            part("bob.claude", 2, (0, 2), b"a "),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(screen.screen().contents(), "a new");
        assert!(
            Rebuilding::add(
                &mut rebuilding,
                part("bob.codex", 3, (0, 2), b"b"),
                Instant::now(),
            )
            .is_none()
        );
        assert_eq!(rebuilding.as_ref().unwrap().slot.to_string(), "bob.codex");
        assert!(
            !rebuilding
                .as_ref()
                .unwrap()
                .waited_longer_than(Duration::from_secs(60), Instant::now())
        );
    }
}
