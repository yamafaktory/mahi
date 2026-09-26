use std::{
    sync::{
        Arc,
        Condvar,
        Mutex,
        MutexGuard,
        PoisonError,
    },
    time::{
        Duration,
        Instant,
    },
};

use thiserror::Error;

const LONGEST: Duration = Duration::from_hours(24);

/// How often to snapshot a worktree, with and without pokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    min_interval: Duration,
    max_interval: Duration,
    settle: Duration,
}

/// A [`Schedule`] whose durations do not fit together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScheduleError {
    /// The minimum interval is zero, which would snapshot without pause.
    #[error("the minimum interval must be more than zero")]
    ZeroInterval,
    /// The maximum interval is shorter than the minimum.
    #[error("the maximum interval is shorter than the minimum")]
    MaxBelowMin,
    /// The settle time is longer than the minimum interval.
    #[error("the settle time is longer than the minimum interval")]
    SettleTooLong,
    /// An interval is longer than a day.
    #[error("intervals are limited to one day")]
    TooLong,
}

impl Schedule {
    /// Creates a schedule.
    ///
    /// `min_interval` is both the timer interval while the worktree keeps changing and the
    /// shortest time between two snapshots, poked or not. The timer doubles up to
    /// `max_interval` while nothing changes. After a poke, the scheduler waits for `settle` to
    /// pass without another poke, so a burst of edits is one snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError`] if `min_interval` is zero or longer than `max_interval`, if
    /// `settle` is longer than `min_interval`, or if `max_interval` is longer than a day.
    pub fn new(
        min_interval: Duration,
        max_interval: Duration,
        settle: Duration,
    ) -> Result<Self, ScheduleError> {
        if min_interval.is_zero() {
            return Err(ScheduleError::ZeroInterval);
        }
        if max_interval < min_interval {
            return Err(ScheduleError::MaxBelowMin);
        }
        if settle > min_interval {
            return Err(ScheduleError::SettleTooLong);
        }
        if max_interval > LONGEST {
            return Err(ScheduleError::TooLong);
        }
        Ok(Self {
            min_interval,
            max_interval,
            settle,
        })
    }
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(30),
            settle: Duration::from_millis(150),
        }
    }
}

/// Why [`Scheduler::wait`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Something, such as an agent hook, reported a change.
    Poked,
    /// The interval elapsed.
    Timer,
    /// The scheduler was closed, or every [`Poker`] was dropped; stop snapshotting.
    Closed,
}

#[derive(Debug, Default)]
struct State {
    poked: bool,
    closed: bool,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait_until<'a>(
        &self,
        state: MutexGuard<'a, State>,
        until: Instant,
    ) -> MutexGuard<'a, State> {
        let left = until.saturating_duration_since(Instant::now());
        self.wake
            .wait_timeout(state, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }

    fn close(&self) {
        self.lock().closed = true;
        self.wake.notify_all();
    }
}

#[derive(Debug)]
struct Handles(Arc<Shared>);

impl Drop for Handles {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Decides when to snapshot one worktree.
///
/// A snapshot is due when a [`Poker`] reports a change, such as an agent hook after a tool ran,
/// and otherwise on a timer that runs at the schedule's minimum interval while the worktree
/// keeps changing and doubles up to its maximum while it does not. The timer is the safety net
/// that catches changes no hook reported. However often it is poked, snapshots are never
/// closer together than the minimum interval, and the scheduler holds two flags, so its
/// memory never grows.
#[derive(Debug)]
pub struct Scheduler {
    shared: Arc<Shared>,
    schedule: Schedule,
    interval: Duration,
    last: Option<Instant>,
}

/// A handle that reports changes to a [`Scheduler`] from any thread.
///
/// When the last handle is dropped, the scheduler closes.
#[derive(Debug, Clone)]
pub struct Poker {
    handles: Arc<Handles>,
}

impl Scheduler {
    /// Creates a scheduler following `schedule`, and a handle to poke it.
    #[must_use]
    pub fn new(schedule: Schedule) -> (Self, Poker) {
        let shared = Arc::new(Shared::default());
        let poker = Poker {
            handles: Arc::new(Handles(Arc::clone(&shared))),
        };
        let scheduler = Self {
            shared,
            schedule,
            interval: schedule.min_interval,
            last: None,
        };
        (scheduler, poker)
    }

    /// Blocks until a snapshot is due, and says why.
    ///
    /// After a poke it waits for the settle time to pass without another poke, and never
    /// returns sooner than the minimum interval after its previous return. This blocks the
    /// calling thread, so async code must call it from a dedicated thread or through
    /// `spawn_blocking`.
    #[must_use]
    pub fn wait(&mut self) -> Trigger {
        let trigger = self.wait_inner();
        self.last = Some(Instant::now());
        trigger
    }

    fn wait_inner(&self) -> Trigger {
        let now = Instant::now();
        let timer = now.checked_add(self.interval).unwrap_or(now + LONGEST);
        let mut state = self.shared.lock();
        loop {
            if state.closed {
                return Trigger::Closed;
            }
            if state.poked {
                break;
            }
            if Instant::now() >= timer {
                return Trigger::Timer;
            }
            state = self.shared.wait_until(state, timer);
        }

        let earliest = self
            .last
            .map_or(now, |last| last + self.schedule.min_interval);
        let latest = Instant::now().max(earliest) + self.schedule.min_interval;
        loop {
            state.poked = false;
            let quiet = (Instant::now() + self.schedule.settle)
                .max(earliest)
                .min(latest);
            loop {
                if state.closed {
                    return Trigger::Closed;
                }
                if state.poked || Instant::now() >= quiet {
                    break;
                }
                state = self.shared.wait_until(state, quiet);
            }
            if !state.poked || Instant::now() >= latest {
                state.poked = false;
                return Trigger::Poked;
            }
        }
    }

    /// Records whether the snapshot just taken found a change, which sets the next interval.
    pub fn record(&mut self, changed: bool) {
        self.interval = if changed {
            self.schedule.min_interval
        } else {
            self.interval
                .saturating_mul(2)
                .min(self.schedule.max_interval)
        };
    }

    /// Returns how long the next [`Scheduler::wait`] waits when nothing pokes it.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }
}

impl Poker {
    /// Reports that the worktree may have changed.
    pub fn poke(&self) {
        let shared = &self.handles.0;
        shared.lock().poked = true;
        shared.wake.notify_all();
    }

    /// Stops the scheduler: its current and every later [`Scheduler::wait`] returns
    /// [`Trigger::Closed`].
    pub fn close(&self) {
        self.handles.0.close();
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    fn schedule(min_ms: u64, max_ms: u64, settle_ms: u64) -> Schedule {
        Schedule::new(
            Duration::from_millis(min_ms),
            Duration::from_millis(max_ms),
            Duration::from_millis(settle_ms),
        )
        .unwrap()
    }

    fn quick() -> Schedule {
        schedule(200, 800, 50)
    }

    fn slow_timer() -> Schedule {
        schedule(60_000, 60_000, 50)
    }

    #[test]
    fn schedules_are_validated() {
        let ms = Duration::from_millis;
        assert_eq!(
            Schedule::new(ms(0), ms(10), ms(0)),
            Err(ScheduleError::ZeroInterval)
        );
        assert_eq!(
            Schedule::new(ms(10), ms(5), ms(1)),
            Err(ScheduleError::MaxBelowMin)
        );
        assert_eq!(
            Schedule::new(ms(10), ms(20), ms(11)),
            Err(ScheduleError::SettleTooLong)
        );
        assert_eq!(
            Schedule::new(ms(10), Duration::MAX, ms(1)),
            Err(ScheduleError::TooLong)
        );
        assert!(Schedule::new(ms(10), LONGEST, ms(10)).is_ok());
    }

    #[test]
    fn the_timer_fires_when_nothing_pokes() {
        let (mut scheduler, _poker) = Scheduler::new(quick());
        let started = Instant::now();
        assert_eq!(scheduler.wait(), Trigger::Timer);
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn a_poke_wins_over_a_long_interval_after_settling() {
        let (mut scheduler, poker) = Scheduler::new(slow_timer());
        let started = Instant::now();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            poker.poke();
            poker
        });
        assert_eq!(scheduler.wait(), Trigger::Poked);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(100), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        drop(handle.join().unwrap());
    }

    #[test]
    fn a_poke_before_waiting_is_not_lost() {
        let (mut scheduler, poker) = Scheduler::new(slow_timer());
        poker.poke();
        assert_eq!(scheduler.wait(), Trigger::Poked);
    }

    #[test]
    fn a_poke_during_a_snapshot_is_taken_by_the_next_wait() {
        let (mut scheduler, poker) = Scheduler::new(schedule(200, 60_000, 50));
        poker.poke();
        assert_eq!(scheduler.wait(), Trigger::Poked);
        poker.poke();
        let started = Instant::now();
        assert_eq!(scheduler.wait(), Trigger::Poked);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(150), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn a_poke_during_settling_extends_it() {
        let (mut scheduler, poker) = Scheduler::new(schedule(2000, 2000, 400));
        let poking = poker.clone();
        let started = Instant::now();
        let handle = thread::spawn(move || {
            for _ in 0..5 {
                poking.poke();
                thread::sleep(Duration::from_millis(100));
            }
        });
        assert_eq!(scheduler.wait(), Trigger::Poked);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(800), "{elapsed:?}");
        handle.join().unwrap();
        drop(poker);
    }

    #[test]
    fn a_burst_of_pokes_is_one_snapshot() {
        let (mut scheduler, poker) = Scheduler::new(schedule(2000, 2000, 50));
        for _ in 0..1000 {
            poker.poke();
        }
        assert_eq!(scheduler.wait(), Trigger::Poked);
        scheduler.record(true);
        let started = Instant::now();
        assert_eq!(scheduler.wait(), Trigger::Timer);
        assert!(started.elapsed() >= Duration::from_secs(2));
    }

    #[test]
    fn pokes_never_bring_snapshots_closer_than_the_minimum_interval() {
        let (mut scheduler, poker) = Scheduler::new(schedule(400, 400, 50));
        let poking = poker.clone();
        let handle = thread::spawn(move || {
            for _ in 0..30 {
                poking.poke();
                thread::sleep(Duration::from_millis(60));
            }
        });
        assert_eq!(scheduler.wait(), Trigger::Poked);
        let first = Instant::now();
        assert_eq!(scheduler.wait(), Trigger::Poked);
        let gap = first.elapsed();
        assert!(gap >= Duration::from_millis(399), "{gap:?}");
        handle.join().unwrap();
        drop(poker);
    }

    #[test]
    fn continuous_pokes_still_yield_a_snapshot() {
        let (mut scheduler, poker) = Scheduler::new(quick());
        let poking = poker.clone();
        let handle = thread::spawn(move || {
            for _ in 0..40 {
                poking.poke();
                thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        assert_eq!(scheduler.wait(), Trigger::Poked);
        assert!(started.elapsed() < Duration::from_secs(1));
        handle.join().unwrap();
        drop(poker);
    }

    #[test]
    fn the_interval_backs_off_while_idle_and_resets_on_change() {
        let (mut scheduler, _poker) = Scheduler::new(quick());
        assert_eq!(scheduler.interval(), Duration::from_millis(200));
        scheduler.record(false);
        assert_eq!(scheduler.interval(), Duration::from_millis(400));
        for _ in 0..5 {
            scheduler.record(false);
        }
        assert_eq!(scheduler.interval(), Duration::from_millis(800));
        scheduler.record(true);
        assert_eq!(scheduler.interval(), Duration::from_millis(200));
    }

    #[test]
    fn closing_stops_a_waiting_scheduler_and_every_later_wait() {
        let (mut scheduler, poker) = Scheduler::new(slow_timer());
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            poker.close();
        });
        assert_eq!(scheduler.wait(), Trigger::Closed);
        assert_eq!(scheduler.wait(), Trigger::Closed);
        handle.join().unwrap();
    }

    #[test]
    fn closing_during_settling_wins() {
        let (mut scheduler, poker) = Scheduler::new(schedule(2000, 2000, 1000));
        poker.poke();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            poker.close();
        });
        assert_eq!(scheduler.wait(), Trigger::Closed);
        handle.join().unwrap();
    }

    #[test]
    fn dropping_every_poker_closes_the_scheduler() {
        let (mut scheduler, poker) = Scheduler::new(slow_timer());
        let second = poker.clone();
        drop(poker);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(second);
        });
        assert_eq!(scheduler.wait(), Trigger::Closed);
        handle.join().unwrap();
    }

    #[test]
    fn a_poisoned_lock_does_not_stop_the_scheduler() {
        let (mut scheduler, poker) = Scheduler::new(slow_timer());
        let shared = Arc::clone(&poker.handles.0);
        let _ = thread::spawn(move || {
            let _guard = shared.state.lock();
            panic!("poison the lock");
        })
        .join();
        poker.poke();
        assert_eq!(scheduler.wait(), Trigger::Poked);
    }
}
