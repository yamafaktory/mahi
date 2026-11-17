use std::{
    fmt::Write,
    time::{
        Duration,
        Instant,
        SystemTime,
    },
};

use jiff::{
    SignedDuration,
    Timestamp,
    tz::TimeZone,
};
use serde::{
    Serialize,
    Serializer,
};

use crate::palette::push_age;

const SAID_AGO_FOR: SignedDuration = SignedDuration::from_hours(24);

/// Returns the time now, unless the clock is outside what a timestamp holds.
pub(crate) fn now() -> Option<Timestamp> {
    Timestamp::try_from(SystemTime::now()).ok()
}

/// Returns the instant of this run's clock at which `time` was, given that `now` is `at`; `at`
/// itself when `time` is not before `now`, or lies further back than the clock reaches.
pub(crate) fn instant_of(time: Timestamp, (now, at): (Timestamp, Instant)) -> Instant {
    Duration::try_from(now.duration_since(time))
        .ok()
        .and_then(|ago| at.checked_sub(ago))
        .unwrap_or(at)
}

/// When a teammate's snapshot that waits began: when its turn ended, or, while that time is
/// not known, when this run first saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Since {
    /// When its turn ended.
    TurnEnded(Instant),
    /// When this run first saw it.
    FirstSeen(Instant),
}

impl Since {
    /// Returns what `known` becomes now that `dated` may give its turn's end: a turn's end
    /// stays as it is, without asking `dated`, and a time `dated` gives replaces when it was
    /// first seen, which is `now` when it was not seen yet.
    pub(crate) fn settle(
        known: Option<Self>,
        dated: impl FnOnce() -> Option<Instant>,
        now: Instant,
    ) -> Self {
        if let Some(Self::TurnEnded(at)) = known {
            return Self::TurnEnded(at);
        }
        let first_seen = known.map_or(now, Self::instant);
        dated().map_or(Self::FirstSeen(first_seen), Self::TurnEnded)
    }

    /// Returns the instant it began.
    pub(crate) fn instant(self) -> Instant {
        match self {
            Self::TurnEnded(at) | Self::FirstSeen(at) => at,
        }
    }
}

/// What recorded times are shown against: the time now, when known, and the time zone, when
/// known.
#[derive(Debug, Clone, Default)]
pub(crate) struct Clock {
    now: Option<Timestamp>,
    zone: Option<TimeZone>,
    year: Option<i16>,
}

impl Clock {
    /// Returns the clock that shows times against `now` in `zone`.
    pub(crate) fn new(now: Option<Timestamp>, zone: Option<TimeZone>) -> Self {
        let year = now.map(|now| shown_in(zone.as_ref()).to_datetime(now).year());
        Self { now, zone, year }
    }

    /// Writes when `time` was: how long ago within a day, such as `3m ago`; otherwise its day
    /// and time in the zone, such as `Nov 14 14:05`, with the year unless it is now's, or in
    /// UTC with `UTC` after it when the zone is not known.
    pub(crate) fn push(&self, out: &mut String, time: Timestamp) {
        if let Some(ago) = self.now.map(|now| now.duration_since(time))
            && ago < SAID_AGO_FOR
            && let Ok(age) = Duration::try_from(ago)
        {
            push_age(out, age);
            out.push_str(" ago");
            return;
        }
        let then = shown_in(self.zone.as_ref()).to_datetime(time);
        let format = if self.year == Some(then.year()) {
            "%b %-d %H:%M"
        } else {
            "%b %-d %Y %H:%M"
        };
        let _ = write!(out, "{}", then.strftime(format));
        if self.zone.is_none() {
            out.push_str(" UTC");
        }
    }
}

/// A recorded time, written in RFC 3339 in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeText(pub(crate) Timestamp);

impl Serialize for TimeText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

fn shown_in(zone: Option<&TimeZone>) -> &TimeZone {
    zone.unwrap_or(&UTC)
}

static UTC: TimeZone = TimeZone::UTC;

#[cfg(test)]
mod tests {
    use super::*;

    fn when(time: Timestamp, now: Timestamp, zone: Option<&TimeZone>) -> String {
        let mut out = String::new();
        Clock::new(Some(now), zone.cloned()).push(&mut out, time);
        out
    }

    #[test]
    fn a_time_within_a_day_says_how_long_ago_and_an_older_one_its_day_and_time() {
        let now: Timestamp = "2026-11-16T13:05:00Z".parse().unwrap();
        let paris = TimeZone::posix("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        let at = |text: &str| -> Timestamp { text.parse().unwrap() };
        assert_eq!(
            when(at("2026-11-16T13:04:30Z"), now, Some(&paris)),
            "30s ago"
        );
        assert_eq!(
            when(at("2026-11-16T12:02:00Z"), now, Some(&paris)),
            "1h ago"
        );
        assert_eq!(
            when(at("2026-11-15T13:05:01Z"), now, Some(&paris)),
            "23h ago"
        );
        assert_eq!(
            when(at("2026-11-15T13:05:00Z"), now, Some(&paris)),
            "Nov 15 14:05"
        );
        assert_eq!(
            when(at("2026-11-04T08:30:00Z"), now, Some(&paris)),
            "Nov 4 09:30"
        );
        assert_eq!(
            when(at("2025-07-01T08:30:00Z"), now, Some(&paris)),
            "Jul 1 2025 10:30"
        );
        assert_eq!(
            when(at("2026-11-04T08:30:00Z"), now, None),
            "Nov 4 08:30 UTC"
        );
    }

    #[test]
    fn a_time_after_now_shows_its_day_and_time() {
        let now: Timestamp = "2026-11-16T13:05:00Z".parse().unwrap();
        let later: Timestamp = "2026-11-16T13:07:00Z".parse().unwrap();
        assert_eq!(when(later, now, None), "Nov 16 13:07 UTC");
    }

    #[test]
    fn without_the_time_now_a_time_shows_its_whole_date() {
        let then: Timestamp = "2026-11-16T13:04:00Z".parse().unwrap();
        let mut out = String::new();
        Clock::default().push(&mut out, then);
        assert_eq!(out, "Nov 16 2026 13:04 UTC");
    }

    #[test]
    fn a_past_time_falls_as_far_back_on_the_runs_clock_and_a_later_one_at_now() {
        let now: Timestamp = "2026-11-16T13:05:00Z".parse().unwrap();
        let at = Instant::now();
        let earlier: Timestamp = "2026-11-16T13:02:00Z".parse().unwrap();
        assert_eq!(
            at.duration_since(instant_of(earlier, (now, at))),
            Duration::from_secs(180)
        );
        let later: Timestamp = "2026-11-16T13:07:00Z".parse().unwrap();
        assert_eq!(instant_of(later, (now, at)), at);
    }
}
