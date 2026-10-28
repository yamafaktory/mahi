use std::{
    io::Write,
    sync::{
        Mutex,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mahi_agent::{
    hook::HookKind,
    payload::asks_user,
};
use mahi_live::TurnState;
use mahi_term::Report;

use crate::hub::OutputTap;

const INTERRUPT: u8 = 0x03;
const KILL_LINE: u8 = 0x15;
const ESC: u8 = 0x1b;

/// How work that waits for the agent paces itself: how long the agent and the user must be
/// quiet, and how often it looks.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pace {
    pub(crate) quiet: Duration,
    pub(crate) look_every: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            quiet: Duration::from_secs(2),
            look_every: Duration::from_millis(200),
        }
    }
}

/// What the agent and the user did last, to tell when the agent is idle: its turn ended, as
/// its hook reports, or was interrupted, the user's own input line is empty, and nothing was
/// written or typed for a while. Its changes happen one at a time, so the states it tells
/// arrive in the order they happen.
#[derive(Debug)]
pub(crate) struct Activity {
    turn_open: AtomicBool,
    turn_ended: AtomicBool,
    asking: AtomicBool,
    line_empty: AtomicBool,
    last: Mutex<Instant>,
    tap: Option<OutputTap>,
    changing: Mutex<()>,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            turn_open: AtomicBool::new(false),
            turn_ended: AtomicBool::new(true),
            asking: AtomicBool::new(false),
            line_empty: AtomicBool::new(true),
            last: Mutex::new(Instant::now()),
            tap: None,
            changing: Mutex::new(()),
        }
    }
}

impl Activity {
    /// Starts with nothing done yet, telling each change of the agent's state to `tap` too,
    /// when there is one, for the teammates.
    pub(crate) fn telling(tap: Option<OutputTap>) -> Self {
        Self {
            tap,
            ..Self::default()
        }
    }

    fn tell(&self, state: TurnState) {
        crate::report::send(&match state {
            TurnState::Working => Report::Working,
            TurnState::Done => Report::Done,
            TurnState::Asks => Report::Asks,
        });
        if let Some(tap) = &self.tap {
            tap.turn(state);
        }
    }

    /// Notes output from the agent or keys from the user.
    pub(crate) fn touched(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = Instant::now();
        }
    }

    /// Notes `bytes` the user typed, or the terminal answered, that went to the agent: text
    /// leaves the line unfinished, Enter, Ctrl-C, Ctrl-U or Escape alone empties it, and Ctrl-C
    /// or Escape interrupts a turn; other sequences, such as arrows or the terminal's answers,
    /// change neither. Text or Enter answers the agent's question, if it asked one.
    pub(crate) fn keys(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.touched();
        let effect = line_effect(bytes);
        let Ok(_changing) = self.changing.lock() else {
            return;
        };
        if effect.interrupts {
            self.asking.store(false, Ordering::SeqCst);
            if self.turn_open.swap(false, Ordering::SeqCst) {
                self.turn_ended.store(false, Ordering::SeqCst);
                self.tell(TurnState::Done);
            }
        }
        if let Some(empty) = effect.line_empty {
            self.line_empty.store(empty, Ordering::SeqCst);
            if !effect.interrupts && self.asking.swap(false, Ordering::SeqCst) {
                self.tell(TurnState::Working);
            }
        }
    }

    /// Notes what the agent's hook reported, with the `payload` it read.
    pub(crate) fn saw(&self, kind: HookKind, payload: &[u8]) {
        let Ok(_changing) = self.changing.lock() else {
            return;
        };
        match kind {
            HookKind::Prompt => {
                self.turn_open.store(true, Ordering::SeqCst);
                self.turn_ended.store(false, Ordering::SeqCst);
                self.asking.store(false, Ordering::SeqCst);
                self.tell(TurnState::Working);
            }
            HookKind::TurnEnd => {
                self.turn_open.store(false, Ordering::SeqCst);
                self.turn_ended.store(true, Ordering::SeqCst);
                self.asking.store(false, Ordering::SeqCst);
                self.tell(TurnState::Done);
            }
            HookKind::Tool => {
                if self.asking.swap(false, Ordering::SeqCst) {
                    self.tell(TurnState::Working);
                }
            }
            HookKind::Asks => {
                if asks_user(payload) && !self.asking.swap(true, Ordering::SeqCst) {
                    self.tell(TurnState::Asks);
                }
            }
        }
        self.touched();
    }

    fn is_idle(&self, pace: &Pace) -> bool {
        let Ok(quiet_for) = self.last.lock().map(|last| last.elapsed()) else {
            return false;
        };
        if self.asking.load(Ordering::SeqCst) {
            return false;
        }
        !self.turn_open.load(Ordering::SeqCst)
            && self.line_empty.load(Ordering::SeqCst)
            && quiet_for >= pace.quiet
    }

    /// Says whether the agent is idle after a turn its turn-end hook reported, or since it
    /// started: an interrupt does not count.
    fn is_idle_after_turn_end(&self, pace: &Pace) -> bool {
        self.turn_ended.load(Ordering::SeqCst) && self.is_idle(pace)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LineEffect {
    line_empty: Option<bool>,
    interrupts: bool,
}

impl LineEffect {
    fn empties(&mut self, interrupts: bool) {
        self.line_empty = Some(true);
        self.interrupts |= interrupts;
    }
}

fn line_effect(bytes: &[u8]) -> LineEffect {
    let mut effect = LineEffect::default();
    if bytes == [ESC] {
        effect.empties(true);
        return effect;
    }
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        at += 1;
        match byte {
            b'\r' | b'\n' | KILL_LINE => effect.empties(false),
            INTERRUPT => effect.empties(true),
            ESC => at = escape(bytes, at, &mut effect),
            0x00..=0x1f | 0x7f => {}
            _ => effect.line_empty = Some(false),
        }
    }
    effect
}

fn escape(bytes: &[u8], at: usize, effect: &mut LineEffect) -> usize {
    match bytes.get(at) {
        Some(b'[') => {
            let mut end = at + 1;
            while bytes
                .get(end)
                .is_some_and(|byte| (0x20..=0x3f).contains(byte))
            {
                end += 1;
            }
            if bytes.get(end) == Some(&b'u') {
                kitty_key(bytes.get(at + 1..end).unwrap_or_default(), effect);
            }
            end + 1
        }
        Some(b'O') => at + 2,
        Some(b']' | b'P' | b'_' | b'^' | b'X') => {
            let mut end = at + 1;
            while let Some(&byte) = bytes.get(end) {
                end += 1;
                if byte == 0x07 || (byte == b'\\' && bytes.get(end - 2) == Some(&ESC)) {
                    break;
                }
            }
            end
        }
        Some(_) => {
            effect.line_empty = Some(false);
            at + 1
        }
        None => at,
    }
}

fn kitty_key(params: &[u8], effect: &mut LineEffect) {
    let mut fields = params.split(|&byte| byte == b';');
    let code = fields
        .next()
        .and_then(|field| field.split(|&byte| byte == b':').next())
        .and_then(|digits| std::str::from_utf8(digits).ok()?.parse::<u32>().ok());
    let mut modifier = fields
        .next()
        .unwrap_or_default()
        .split(|&byte| byte == b':');
    let modifiers = modifier
        .next()
        .and_then(|digits| std::str::from_utf8(digits).ok()?.parse::<u32>().ok())
        .map_or(0, |value| value.saturating_sub(1) & !(64 | 128));
    let released = modifier.next() == Some(b"3");
    if released {
        return;
    }
    match (code, modifiers) {
        (Some(27), 0) | (Some(99), 4) => effect.empties(true),
        (Some(13), 0) | (Some(117), 4) => effect.empties(false),
        (Some(code), 0 | 1) if code >= 32 && code != 127 && !(57344..=63743).contains(&code) => {
            effect.line_empty = Some(false);
        }
        _ => {}
    }
}

/// The agent's side of what waits for it: whether mahi's palette is open.
pub(crate) trait AgentInput {
    /// Returns whether the palette is open, when nothing is given to the agent.
    fn palette_open(&self) -> bool;
}

/// What the agent must have done before an action runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness {
    /// Be idle with its turn closed, by its turn-end hook or an interrupt, not only gone quiet.
    TurnClosed,
    /// Be idle after a turn its turn-end hook reported, or since it started.
    AfterTurnEnd,
}

/// Runs `act` once the agent is as `readiness` says and the palette closed, holding the agent's
/// input while it runs, so no key of the user's comes in between;
/// returns `None` if `running` is cleared first.
pub(crate) fn when_ready<T>(
    activity: &Activity,
    agent: &impl AgentInput,
    writer: &Mutex<impl Write>,
    (running, pace, readiness): (&AtomicBool, Pace, Readiness),
    act: impl FnOnce() -> T,
) -> Option<T> {
    while running.load(Ordering::SeqCst) {
        thread::sleep(pace.look_every);
        let Ok(input) = writer.lock() else {
            return None;
        };
        let ready = match readiness {
            Readiness::TurnClosed => activity.is_idle(&pace),
            Readiness::AfterTurnEnd => activity.is_idle_after_turn_end(&pace),
        };
        if agent.palette_open() || !ready {
            continue;
        }
        let done = act();
        drop(input);
        return Some(done);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn fast() -> Pace {
        Pace {
            quiet: Duration::from_millis(100),
            look_every: Duration::from_millis(10),
        }
    }

    #[test]
    fn a_turn_keeps_the_agent_busy_until_it_ends_or_is_interrupted_however_long_it_stays_quiet() {
        let pace = fast();
        let activity = Activity::default();
        assert!(!activity.is_idle(&pace));
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.saw(HookKind::Prompt, b"");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.saw(HookKind::Prompt, b"");
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.saw(HookKind::Prompt, b"");
        thread::sleep(pace.quiet * 4);
        assert!(!activity.is_idle(&pace));
    }

    #[test]
    fn only_a_reported_turn_end_or_the_start_lets_a_merge_in() {
        let pace = fast();
        let activity = Activity::default();
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        activity.saw(HookKind::Prompt, b"");
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        assert!(!activity.is_idle_after_turn_end(&pace));
        activity.saw(HookKind::Prompt, b"");
        thread::sleep(pace.quiet * 4);
        assert!(!activity.is_idle_after_turn_end(&pace));
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        activity.keys(b"half typed");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle_after_turn_end(&pace));
    }

    #[test]
    fn a_turn_closed_by_its_hook_or_an_interrupt_counts_but_one_only_gone_quiet_does_not() {
        let pace = fast();
        let activity = Activity::default();
        activity.saw(HookKind::Prompt, b"");
        thread::sleep(pace.quiet * 4);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn an_escape_between_turns_keeps_merges_coming() {
        let pace = fast();
        let activity = Activity::default();
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
    }

    #[test]
    fn the_workspace_hears_of_turns_questions_and_interrupts_once_each() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        crate::report::connect(std::os::fd::IntoRawFd::into_raw_fd(writer));
        let permission = br#"{"notification_type":"permission_prompt"}"#;
        let activity = Activity::default();
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::Asks, br#"{"notification_type":"idle_prompt"}"#);
        activity.saw(HookKind::Asks, permission);
        activity.saw(HookKind::Asks, permission);
        activity.saw(HookKind::Tool, b"");
        activity.saw(HookKind::Tool, b"");
        activity.saw(HookKind::Asks, permission);
        activity.keys(b"\x1b[A");
        activity.keys(b"\r");
        activity.keys(b"\r");
        activity.saw(HookKind::Asks, permission);
        activity.keys(b"\x1b");
        activity.keys(b"\x1b");
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        let mut read = [0_u8; 256];
        let length = rustix::io::read(&reader, &mut read).unwrap();
        let mut reports = Vec::new();
        mahi_term::ReportReader::default().feed(&read[..length], |report| reports.push(report));
        assert_eq!(
            reports,
            [
                Report::Working,
                Report::Asks,
                Report::Working,
                Report::Asks,
                Report::Working,
                Report::Asks,
                Report::Done,
                Report::Working,
                Report::Done,
            ]
        );
    }

    #[test]
    fn a_question_outside_a_turn_keeps_merges_out_however_long_it_waits_until_the_user_answers() {
        let pace = fast();
        let activity = Activity::default();
        activity.saw(
            HookKind::Asks,
            br#"{"notification_type":"permission_prompt"}"#,
        );
        thread::sleep(pace.quiet * 4);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\x1b[B");
        thread::sleep(pace.quiet * 4);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\r");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn a_line_the_user_left_unfinished_keeps_merges_out() {
        let pace = fast();
        let activity = Activity::default();
        activity.keys(b"half a thou");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"ght\r");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.keys(b"again");
        activity.keys(b"\x15");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.keys(b"typed during the turn");
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\x1b[117;5u");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.keys(b"");
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn the_line_state_comes_from_keys_not_from_sequences() {
        let effect = |bytes: &[u8]| line_effect(bytes);
        let text = LineEffect {
            line_empty: Some(false),
            interrupts: false,
        };
        let emptied = LineEffect {
            line_empty: Some(true),
            interrupts: false,
        };
        let interrupted = LineEffect {
            line_empty: Some(true),
            interrupts: true,
        };
        assert_eq!(effect(b"abc"), text);
        assert_eq!(effect(b"abc\r"), emptied);
        assert_eq!(effect(b"abc\x03"), interrupted);
        assert_eq!(effect(b"\x1b"), interrupted);
        assert_eq!(effect(b"\x1b[27u"), interrupted);
        assert_eq!(effect(b"\x1b[99;5u"), interrupted);
        assert_eq!(effect(b"x\x1b[117;5u"), emptied);
        assert_eq!(effect(b"\x1b[13u"), emptied);
        assert_eq!(effect(b"\x1b[97u"), text);
        assert_eq!(effect(b"\x1bx"), text);
        for neutral in [
            &b"\x1b[12;40R"[..],
            b"\x1b[?62;22c",
            b"\x1b[?1u",
            b"\x1b[I",
            b"\x1b[O",
            b"\x1b[A\x1bOB",
            b"\x1b[5~",
            b"\x1b]11;rgb:0000/0000/0000\x07",
            b"\x1bP1+r544e\x1b\\",
            b"\x1b[27;1:3u",
            b"\x1b[57441u",
            b"\x7f",
        ] {
            assert_eq!(effect(neutral), LineEffect::default(), "{neutral:?}");
        }
        assert_eq!(effect(b"\r\x1b[12;40R"), emptied);
    }

    struct FakeAgent {
        palette_open: AtomicBool,
    }

    impl AgentInput for FakeAgent {
        fn palette_open(&self) -> bool {
            self.palette_open.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn work_waits_for_the_agents_closed_turn_and_holds_its_input_or_gives_up_when_the_run_ends() {
        let activity = Arc::new(Activity::default());
        let agent = Arc::new(FakeAgent {
            palette_open: AtomicBool::new(false),
        });
        let writer = Arc::new(Mutex::new(Vec::<u8>::new()));
        let running = Arc::new(AtomicBool::new(true));
        activity.keys(b"typing");
        let worker = {
            let (activity, agent, writer, running) = (
                Arc::clone(&activity),
                Arc::clone(&agent),
                Arc::clone(&writer),
                Arc::clone(&running),
            );
            thread::spawn(move || {
                let held = Arc::clone(&writer);
                when_ready(
                    &activity,
                    &*agent,
                    &writer,
                    (&running, fast(), Readiness::TurnClosed),
                    move || held.try_lock().is_err(),
                )
            })
        };
        thread::sleep(fast().quiet * 3);
        assert!(!worker.is_finished());
        activity.keys(b"\r");
        activity.saw(HookKind::Prompt, b"");
        thread::sleep(fast().quiet * 5);
        assert!(!worker.is_finished());
        activity.saw(HookKind::TurnEnd, b"");
        assert_eq!(worker.join().unwrap(), Some(true));

        agent.palette_open.store(true, Ordering::SeqCst);
        let worker = {
            let (activity, agent, writer, running) = (
                Arc::clone(&activity),
                Arc::clone(&agent),
                Arc::clone(&writer),
                Arc::clone(&running),
            );
            thread::spawn(move || {
                when_ready(
                    &activity,
                    &*agent,
                    &writer,
                    (&running, fast(), Readiness::TurnClosed),
                    || (),
                )
            })
        };
        thread::sleep(fast().quiet * 3);
        running.store(false, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), None);
    }
}
