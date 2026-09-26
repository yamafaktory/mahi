//! When to snapshot an agent's worktree: on a poke from its hooks, or on an adaptive timer.

mod scheduler;

pub use scheduler::{
    Poker,
    Schedule,
    ScheduleError,
    Scheduler,
    Trigger,
};
