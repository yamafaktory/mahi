use std::{
    io::{
        self,
        Write,
    },
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
    payload::{
        asks_user,
        starts_session,
    },
};
use mahi_live::TurnState;
use mahi_term::Report;

use crate::hub::OutputTap;

const ENTER_AFTER: Duration = Duration::from_millis(250);
const INTERRUPT: u8 = 0x03;
const KILL_LINE: u8 = 0x15;
const ESC: u8 = 0x1b;
const HELD_AT_MOST: usize = 4096;

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

/// Whether the agent's launch can open a dialog its hooks do not report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtLaunch {
    /// It can, so mahi types nothing into the agent until its hooks report it idle.
    MayAsk,
    /// It cannot, so the agent's first output counts as a reported turn end, unless a key
    /// came first.
    Ready,
}

/// What the agent and the user did last, to tell when the agent is idle: its turn ended, as
/// its hook reports, or was interrupted, the user's own input line is empty, and nothing was
/// written or typed for a while. Its changes happen one at a time, so the states it tells
/// arrive in the order they happen.
#[derive(Debug)]
pub(crate) struct Activity {
    turn_open: AtomicBool,
    turn_ended: AtomicBool,
    reported_untouched: AtomicBool,
    ready_on_output: AtomicBool,
    keyed: AtomicBool,
    asking: AtomicBool,
    line_empty: AtomicBool,
    unfinished: Mutex<Vec<u8>>,
    last: Mutex<Instant>,
    tap: Option<OutputTap>,
    changing: Mutex<()>,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            turn_open: AtomicBool::new(false),
            turn_ended: AtomicBool::new(true),
            reported_untouched: AtomicBool::new(false),
            ready_on_output: AtomicBool::new(false),
            keyed: AtomicBool::new(false),
            asking: AtomicBool::new(false),
            line_empty: AtomicBool::new(true),
            unfinished: Mutex::new(Vec::new()),
            last: Mutex::new(Instant::now()),
            tap: None,
            changing: Mutex::new(()),
        }
    }
}

impl Activity {
    /// Starts in the state `first`, when it is known, telling it at once, as each later
    /// change is told: to the workspace, and to `tap` too, when there is one, for the
    /// teammates. A run that starts working has its first turn open from the start, and the
    /// first output of a launch that is [`AtLaunch::Ready`] counts as a reported turn end,
    /// unless a key came first.
    pub(crate) fn telling(
        tap: Option<OutputTap>,
        first: Option<TurnState>,
        at_launch: AtLaunch,
    ) -> Self {
        let working = first == Some(TurnState::Working);
        let activity = Self {
            turn_open: AtomicBool::new(working),
            turn_ended: AtomicBool::new(!working),
            ready_on_output: AtomicBool::new(at_launch == AtLaunch::Ready),
            tap,
            ..Self::default()
        };
        if let Some(first) = first {
            activity.tell(first);
        }
        activity
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

    #[cfg(test)]
    pub(crate) fn is_turn_open(&self) -> bool {
        self.turn_open.load(Ordering::SeqCst)
    }

    /// Notes output from the agent: once it first writes, a launch that is
    /// [`AtLaunch::Ready`] counts as a reported turn end, unless the user typed a key.
    pub(crate) fn wrote(&self) {
        self.touched();
        if !self.ready_on_output.load(Ordering::SeqCst) {
            return;
        }
        let Ok(_changing) = self.changing.lock() else {
            return;
        };
        if self.ready_on_output.swap(false, Ordering::SeqCst) && !self.keyed.load(Ordering::SeqCst)
        {
            self.reported_untouched.store(true, Ordering::SeqCst);
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
    /// change neither. Text or Enter answers the agent's question, if it asked one. Only the
    /// terminal's answers, when they are all `bytes` hold, leave the agent untouched. An
    /// answer that `bytes` leave unfinished waits for the next `bytes`, unless they are Escape
    /// alone.
    pub(crate) fn keys(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.touched();
        let Ok(mut unfinished) = self.unfinished.lock() else {
            self.took(&line_effect(bytes));
            return;
        };
        let escaped = unfinished.as_slice() == [ESC] && bytes.first() == Some(&ESC);
        if escaped || bytes == [ESC] {
            unfinished.clear();
        }
        let joined = !unfinished.is_empty();
        if joined {
            unfinished.extend_from_slice(bytes);
        }
        let read = if joined { unfinished.as_slice() } else { bytes };
        let head = read.get(..unfinished_answer_at(read)).unwrap_or_default();
        let effect = (!is_terminal_answer(head)).then(|| line_effect(head));
        let finished = head.len();
        if joined {
            unfinished.drain(..finished);
        } else {
            unfinished.extend_from_slice(bytes.get(finished..).unwrap_or_default());
        }
        if unfinished.len() > HELD_AT_MOST {
            unfinished.clear();
        }
        drop(unfinished);
        if escaped {
            self.took(&line_effect(&[ESC]));
        }
        if let Some(effect) = effect {
            self.took(&effect);
        }
    }

    fn took(&self, effect: &LineEffect) {
        let changing = self.changing.lock();
        self.keyed.store(true, Ordering::SeqCst);
        self.reported_untouched.store(false, Ordering::SeqCst);
        let Ok(_changing) = changing else {
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
                let was_open = self.turn_open.swap(true, Ordering::SeqCst);
                self.turn_ended.store(false, Ordering::SeqCst);
                self.reported_untouched.store(false, Ordering::SeqCst);
                let was_asking = self.asking.swap(false, Ordering::SeqCst);
                if !was_open || was_asking {
                    self.tell(TurnState::Working);
                }
            }
            HookKind::TurnEnd => {
                self.turn_open.store(false, Ordering::SeqCst);
                self.turn_ended.store(true, Ordering::SeqCst);
                self.reported_untouched.store(true, Ordering::SeqCst);
                self.asking.store(false, Ordering::SeqCst);
                self.tell(TurnState::Done);
            }
            HookKind::Tool => {
                if self.asking.swap(false, Ordering::SeqCst) {
                    self.tell(TurnState::Working);
                }
            }
            HookKind::SessionStart => {
                if starts_session(payload) && !self.keyed.load(Ordering::SeqCst) {
                    self.reported_untouched.store(true, Ordering::SeqCst);
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

    /// Says whether the agent is idle after a turn end or a session start its hooks reported in
    /// this run, with no key of the user's since.
    fn is_untouched_after_turn_end(&self, pace: &Pace) -> bool {
        self.reported_untouched.load(Ordering::SeqCst) && self.is_idle(pace)
    }

    /// Takes in that mahi typed a prompt into the agent, so it types no other until the next
    /// turn end or session start its hooks report.
    pub(crate) fn typed_prompt(&self) {
        self.reported_untouched.store(false, Ordering::SeqCst);
        self.touched();
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

fn unfinished_answer_at(bytes: &[u8]) -> usize {
    let mut at = 0;
    while let Some(start) = bytes
        .get(at..)
        .and_then(|rest| rest.iter().position(|&byte| byte == ESC))
    {
        let start = at + start;
        if let Some(end) = terminal_answer_at(bytes, start) {
            at = end;
            continue;
        }
        let (before, tail) = bytes.split_at(start);
        if starts_answer(tail)
            || (tail == [ESC] && !before.is_empty() && is_terminal_answer(before))
        {
            return start;
        }
        at = start + 1;
    }
    bytes.len()
}

fn starts_answer(tail: &[u8]) -> bool {
    match tail {
        [ESC, b'[', _, ..] => {
            let csi = Csi::at(tail, 2);
            csi.last.is_none() && csi.end == tail.len()
        }
        [ESC, b']', rest @ ..] => {
            let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let after = rest.get(digits..).unwrap_or_default();
            digits > 0
                && (after.is_empty() || after.first() == Some(&b';'))
                && string_end(tail, 2).is_none()
        }
        [ESC, b'P', b'0'..=b'9' | b'>' | b'!', ..] => string_end(tail, 2).is_none(),
        _ => false,
    }
}

fn is_terminal_answer(bytes: &[u8]) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        let Some(end) = terminal_answer_at(bytes, at) else {
            return false;
        };
        at = end;
    }
    true
}

fn terminal_answer_at(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&ESC) {
        return None;
    }
    match bytes.get(at + 1)? {
        b'[' => {
            let csi = Csi::at(bytes, at + 2);
            let answers = match (csi.last?, csi.intermediates) {
                (b'R', b"") => is_position_report(csi.params),
                (b'c', b"") => matches!(csi.params.first(), Some(b'?' | b'>')),
                (b'u', b"") => csi.params.first() == Some(&b'?'),
                (b'I' | b'O', b"") => csi.params.is_empty(),
                (b'y', b"$") => two_numbers(csi.params.strip_prefix(b"?").unwrap_or(csi.params)),
                _ => false,
            };
            answers.then_some(csi.end + 1)
        }
        b']' | b'P' => string_end(bytes, at + 2),
        _ => None,
    }
}

fn is_position_report(params: &[u8]) -> bool {
    let modified_f3 = params.starts_with(b"1;") && params != b"1;1";
    !modified_f3 && two_numbers(params)
}

fn two_numbers(params: &[u8]) -> bool {
    let mut fields = params.split(|&byte| byte == b';');
    let number = |field: Option<&[u8]>| {
        field.is_some_and(|field| !field.is_empty() && field.iter().all(u8::is_ascii_digit))
    };
    number(fields.next()) && number(fields.next()) && fields.next().is_none()
}

struct Csi<'bytes> {
    params: &'bytes [u8],
    intermediates: &'bytes [u8],
    last: Option<u8>,
    end: usize,
}

impl<'bytes> Csi<'bytes> {
    fn at(bytes: &'bytes [u8], start: usize) -> Self {
        let in_range = |end: usize, range: std::ops::RangeInclusive<u8>| {
            bytes.get(end).is_some_and(|byte| range.contains(byte))
        };
        let mut end = start;
        while in_range(end, 0x30..=0x3f) {
            end += 1;
        }
        let middle = end;
        while in_range(end, 0x20..=0x2f) {
            end += 1;
        }
        Self {
            params: bytes.get(start..middle).unwrap_or_default(),
            intermediates: bytes.get(middle..end).unwrap_or_default(),
            last: bytes
                .get(end)
                .copied()
                .filter(|byte| (0x40..=0x7e).contains(byte)),
            end,
        }
    }
}

fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut end = start;
    while let Some(&byte) = bytes.get(end) {
        if byte < 0x20 && byte != 0x07 && byte != ESC {
            return Some(end);
        }
        end += 1;
        if byte == 0x07 || (byte == b'\\' && bytes.get(end.wrapping_sub(2)) == Some(&ESC)) {
            return Some(end);
        }
    }
    None
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
            let csi = Csi::at(bytes, at + 1);
            if csi.last == Some(b'u') && csi.intermediates.is_empty() {
                kitty_key(csi.params, effect);
            }
            csi.end + usize::from(csi.last.is_some())
        }
        Some(b'O') => at + 2,
        Some(b']' | b'P' | b'_' | b'^' | b'X') => string_end(bytes, at + 1).unwrap_or(bytes.len()),
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

/// Types `text` into the agent's `input` as a prompt: the text, then Enter once the agent took
/// it in; text holding a control character is refused, since it could act as a key.
pub(crate) fn type_prompt(input: &mut impl Write, text: &str) -> io::Result<()> {
    if text.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a typed prompt holds a control character",
        ));
    }
    input.write_all(text.as_bytes())?;
    input.flush()?;
    thread::sleep(ENTER_AFTER);
    input.write_all(b"\r")?;
    input.flush()
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
    /// Be idle after a turn end or a session start its hooks reported, with no key of the
    /// user's since, so no prompt, dialog or picker the hooks do not report may be open.
    UntouchedAfterTurnEnd,
}

/// Runs `act` once the agent is as `readiness` says and the palette closed, holding the agent's
/// input while it runs and handing it to `act`, so no key of the user's comes in between;
/// returns `None` if `running` is cleared first.
pub(crate) fn when_ready<W: Write, T>(
    activity: &Activity,
    agent: &impl AgentInput,
    writer: &Mutex<W>,
    (running, pace, readiness): (&AtomicBool, Pace, Readiness),
    act: impl FnOnce(&mut W) -> T,
) -> Option<T> {
    while running.load(Ordering::SeqCst) {
        thread::sleep(pace.look_every);
        let Ok(mut input) = writer.lock() else {
            return None;
        };
        if is_ready(activity, agent, pace, readiness) {
            let done = act(&mut input);
            drop(input);
            return Some(done);
        }
    }
    None
}

/// Runs `act` at once when the agent is as `readiness` says and the palette closed, holding the
/// agent's input while it runs and handing it to `act`; returns `None`, without waiting, when
/// it is not.
pub(crate) fn if_ready<W: Write, T>(
    activity: &Activity,
    agent: &impl AgentInput,
    writer: &Mutex<W>,
    (pace, readiness): (Pace, Readiness),
    act: impl FnOnce(&mut W) -> T,
) -> Option<T> {
    let mut input = writer.lock().ok()?;
    is_ready(activity, agent, pace, readiness).then(|| act(&mut input))
}

fn is_ready(
    activity: &Activity,
    agent: &impl AgentInput,
    pace: Pace,
    readiness: Readiness,
) -> bool {
    let ready = match readiness {
        Readiness::TurnClosed => activity.is_idle(&pace),
        Readiness::AfterTurnEnd => activity.is_idle_after_turn_end(&pace),
        Readiness::UntouchedAfterTurnEnd => activity.is_untouched_after_turn_end(&pace),
    };
    ready && !agent.palette_open()
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
    fn only_a_reported_turn_end_with_no_key_since_lets_a_prompt_in() {
        let pace = fast();
        let activity = Activity::default();
        thread::sleep(pace.quiet);
        assert!(!activity.is_untouched_after_turn_end(&pace));
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_untouched_after_turn_end(&pace));
        activity.keys(b"/model\r");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        assert!(!activity.is_untouched_after_turn_end(&pace));
        activity.saw(HookKind::TurnEnd, b"");
        activity.typed_prompt();
        thread::sleep(pace.quiet);
        assert!(!activity.is_untouched_after_turn_end(&pace));
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_untouched_after_turn_end(&pace));
    }

    #[test]
    fn a_reported_startup_or_resume_with_no_key_since_lets_a_prompt_in_before_any_turn() {
        let pace = fast();
        let (startup, resume) = (br#"{"source":"startup"}"#, br#"{"source":"resume"}"#);
        let activity = Activity::default();
        activity.saw(HookKind::SessionStart, startup);
        thread::sleep(pace.quiet);
        assert!(activity.is_untouched_after_turn_end(&pace));
        activity.keys(b"/clear\r");
        for source in [
            &br#"{"source":"clear"}"#[..],
            br#"{"source":"compact"}"#,
            b"",
        ] {
            activity.saw(HookKind::SessionStart, source);
        }
        thread::sleep(pace.quiet);
        assert!(!activity.is_untouched_after_turn_end(&pace));
        let resumed = Activity::default();
        resumed.saw(HookKind::SessionStart, resume);
        thread::sleep(pace.quiet);
        assert!(resumed.is_untouched_after_turn_end(&pace));
        resumed.typed_prompt();
        thread::sleep(pace.quiet);
        assert!(!resumed.is_untouched_after_turn_end(&pace));
    }

    #[test]
    fn the_terminals_answers_are_no_key() {
        let answers = [
            &b"\x1b[12;1R"[..],
            b"\x1b[1;1R",
            b"\x1b]11;rgb:0000/0000/0000\x07",
            b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\",
            b"\x1b[?62;22c",
            b"\x1b[>1;10;0c",
            b"\x1b[?0u",
            b"\x1b[I",
            b"\x1b[O",
            b"\x1b[?2026;2$y",
            b"\x1b[4;2$y",
            b"\x1bP1+r544e=787465726d\x1b\\",
            b"\x1b[12;1R\x1b[?0u",
        ];
        for answer in answers {
            assert!(is_terminal_answer(answer), "{answer:?}");
        }
        for key in [
            &b"\x1b[A"[..],
            b"x",
            b"\x1b[12;1Rx",
            b"\x1b[1;5D",
            b"\x1b[1;2R",
            b"\x1b[1;5R",
            b"\x1b[R",
            b"\x1b[2R",
            b"\x1b[1;2;3R",
            b"\x1b]11;rgb:0000",
            b"\x1b[2$y",
            b"\x1b[?$y",
            b"\x1b[?;;$y",
            b"\x1b[?2026;2;1$y",
            b"\x1b[99u",
        ] {
            assert!(!is_terminal_answer(key), "{key:?}");
        }
        let pace = fast();
        let activity = Activity::telling(None, None, AtLaunch::Ready);
        activity.wrote();
        for answer in answers {
            activity.keys(answer);
        }
        thread::sleep(pace.quiet);
        assert!(activity.is_untouched_after_turn_end(&pace));
        activity.keys(b"\x1b[A");
        thread::sleep(pace.quiet);
        assert!(!activity.is_untouched_after_turn_end(&pace));
    }

    #[test]
    fn an_answer_split_across_reads_is_no_key_and_leaves_the_line_empty() {
        let pace = fast();
        for (first, rest) in [
            (&b"\x1b[12;"[..], &b"1R"[..]),
            (b"\x1b]11;rgb:00", b"00/0000/0000\x07"),
            (b"\x1b]10;rgb:ffff/ffff/ffff\x1b", b"\\"),
            (b"\x1b[I\x1b", b"[O"),
            (b"\x1b[?62;22c\x1b", b"[12;1R"),
        ] {
            let activity = Activity::telling(None, None, AtLaunch::Ready);
            activity.wrote();
            activity.keys(first);
            activity.keys(rest);
            thread::sleep(pace.quiet);
            assert!(
                activity.is_untouched_after_turn_end(&pace),
                "{first:?} {rest:?}"
            );
        }
    }

    #[test]
    fn a_split_sequence_that_turns_out_a_key_still_counts() {
        let pace = fast();
        let activity = Activity::default();
        activity.keys(b"\x1b[9");
        activity.keys(b"9u");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\r");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.saw(HookKind::Prompt, b"");
        activity.keys(b"\x1b[12;");
        activity.keys(b"\x1b");
        assert!(!activity.is_turn_open());
    }

    #[test]
    fn an_alt_chord_that_starts_like_an_answer_leaves_later_keys_counting() {
        let pace = fast();
        for chord in [
            &b"\x1b]"[..],
            b"\x1bP",
            b"\x1b_",
            b"\x1b^",
            b"\x1bX",
            b"\x1b[",
            b"\x1bO",
        ] {
            let activity = Activity::default();
            activity.keys(chord);
            activity.keys(b"\r");
            activity.keys(b"a");
            thread::sleep(pace.quiet);
            assert!(!activity.is_idle(&pace), "{chord:?}");
            activity.saw(HookKind::Prompt, b"");
            activity.keys(chord);
            activity.keys(b"\x03");
            assert!(!activity.is_turn_open(), "{chord:?}");
        }
    }

    #[test]
    fn an_escape_held_after_an_answer_is_the_escape_key_when_a_sequence_follows() {
        let pace = fast();
        let activity = Activity::default();
        activity.keys(b"a");
        activity.saw(HookKind::Prompt, b"");
        activity.keys(b"\x1b[I\x1b");
        activity.keys(b"\x1b[O");
        assert!(!activity.is_turn_open());
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn a_control_key_after_a_held_answer_prefix_still_counts() {
        let pace = fast();
        for prefix in [&b"\x1b[1"[..], b"\x1b]1", b"\x1b]11;rgb", b"\x1bP1"] {
            let activity = Activity::default();
            activity.saw(HookKind::Prompt, b"");
            activity.keys(prefix);
            activity.keys(b"\x03");
            assert!(!activity.is_turn_open(), "{prefix:?}");
            activity.keys(b"a");
            activity.keys(prefix);
            activity.keys(b"\r");
            thread::sleep(pace.quiet);
            assert!(activity.is_idle(&pace), "{prefix:?}");
        }
    }

    #[test]
    fn an_unfinished_sequence_past_its_bound_is_dropped() {
        let pace = fast();
        let activity = Activity::default();
        let mut long = b"\x1b]11;rgb:".to_vec();
        long.resize(HELD_AT_MOST + 1, b'0');
        activity.keys(&long);
        activity.keys(b"x");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
    }

    #[test]
    fn a_session_start_after_a_key_lets_no_prompt_in() {
        let pace = fast();
        let activity = Activity::default();
        activity.keys(b"/model\r");
        activity.saw(HookKind::SessionStart, br#"{"source":"startup"}"#);
        thread::sleep(pace.quiet);
        assert!(!activity.is_untouched_after_turn_end(&pace));
    }

    #[test]
    fn a_launch_with_no_dialog_lets_a_prompt_in_once_the_agent_wrote_until_a_key() {
        let pace = fast();
        let activity = Activity::telling(None, None, AtLaunch::Ready);
        thread::sleep(pace.quiet);
        assert!(!activity.is_untouched_after_turn_end(&pace));
        activity.wrote();
        assert!(!activity.is_untouched_after_turn_end(&pace));
        thread::sleep(pace.quiet);
        assert!(activity.is_untouched_after_turn_end(&pace));
        let keyed_first = Activity::telling(None, None, AtLaunch::Ready);
        keyed_first.keys(b"h");
        keyed_first.keys(b"\x15");
        keyed_first.wrote();
        thread::sleep(pace.quiet);
        assert!(!keyed_first.is_untouched_after_turn_end(&pace));
        activity.keys(b"h");
        activity.keys(b"\x15");
        thread::sleep(pace.quiet);
        assert!(!activity.is_untouched_after_turn_end(&pace));
    }

    #[test]
    fn a_typed_prompt_is_its_text_then_enter() {
        let mut typed = Vec::new();
        type_prompt(&mut typed, "mahi merged bob.claude's work.").unwrap();
        assert_eq!(typed, b"mahi merged bob.claude's work.\r");
        let mut refused = Vec::new();
        assert!(type_prompt(&mut refused, "line\x1b[2J").is_err());
        assert!(refused.is_empty());
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
    fn a_run_that_starts_on_a_prompt_is_busy_until_its_turn_ends() {
        let pace = fast();
        let activity = Activity::telling(None, Some(TurnState::Working), AtLaunch::MayAsk);
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        let waiting = Activity::telling(None, Some(TurnState::Done), AtLaunch::MayAsk);
        thread::sleep(pace.quiet);
        assert!(waiting.is_idle_after_turn_end(&pace));
    }

    #[test]
    fn the_first_state_reaches_the_workspace_as_later_ones_do() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        crate::report::connect(std::os::fd::IntoRawFd::into_raw_fd(writer));
        let activity = Activity::telling(None, Some(TurnState::Working), AtLaunch::MayAsk);
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        let mut read = [0_u8; 64];
        let length = rustix::io::read(&reader, &mut read).unwrap();
        let mut reports = Vec::new();
        mahi_term::ReportReader::default().feed(&read[..length], |report| reports.push(report));
        assert_eq!(reports, [Report::Working, Report::Done]);
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

    #[test]
    fn only_a_tail_that_can_still_become_an_answer_is_held() {
        for (bytes, held) in [
            (&b"abc"[..], &b""[..]),
            (b"\x1b", b""),
            (b"\x1b[", b""),
            (b"\x1b]", b""),
            (b"\x1bP", b""),
            (b"\x1bO", b""),
            (b"\x1b_a", b""),
            (b"\x1b[A", b""),
            (b"a\x1b[12;", b"\x1b[12;"),
            (b"\x1b[?", b"\x1b[?"),
            (b"\x1b[?2026;2$", b"\x1b[?2026;2$"),
            (b"x\x1b]11;rgb:00", b"\x1b]11;rgb:00"),
            (b"\x1b]11;rgb:00\x1b", b"\x1b]11;rgb:00\x1b"),
            (b"\x1bP1+r\x1b", b"\x1bP1+r\x1b"),
            (b"\x1b]11;a\rb", b""),
            (b"\x1b]a", b""),
            (b"\x1b]1a", b""),
            (b"\x1bPh", b""),
            (b"\x1bP>", b"\x1bP>"),
            (b"\x1b[ 1", b""),
            (b"\x1b[1\x03", b""),
            (b"\r\x1b[12;40R\x1b[12", b"\x1b[12"),
            (b"\x1b[I\x1b", b"\x1b"),
            (b"\x1b[?62;22c\x1b", b"\x1b"),
            (b"x\x1b", b""),
            (b"\x1b[A\x1b", b""),
        ] {
            assert_eq!(&bytes[unfinished_answer_at(bytes)..], held, "{bytes:?}");
        }
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
                    move |_| held.try_lock().is_err(),
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
                    |_| (),
                )
            })
        };
        thread::sleep(fast().quiet * 3);
        running.store(false, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), None);
    }
}
