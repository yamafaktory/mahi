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
use mahi_term::{
    Csi,
    PASTE_START,
    PasteEnd,
    Report,
    is_terminal_answer,
    starts_answer,
    string_end,
    terminal_answer_at,
};

use crate::hub::OutputTap;

const ENTER_AFTER: Duration = Duration::from_millis(250);
const INTERRUPT: u8 = 0x03;
const KILL_LINE: u8 = 0x15;
const BACKSPACE: u8 = 0x7f;
const CTRL_H: u8 = 0x08;
const ESC: u8 = 0x1b;
const HELD_AT_MOST: usize = 4096;
const KITTY_LOCK_KEYS: std::ops::RangeInclusive<u32> = 57358..=57360;
const KITTY_KEYPAD_TEXT: std::ops::RangeInclusive<u32> = 57399..=57416;
const KITTY_MODIFIER_KEYS: std::ops::RangeInclusive<u32> = 57441..=57454;
const KITTY_PRIVATE_USE: std::ops::RangeInclusive<u32> = 57344..=63743;

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

/// When a second Escape opens the agent's picker, so the agent's input line counts as
/// unfinished: Claude Code's opens within its window, Codex's at any time after an Escape with
/// no other key between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EscapeTwice {
    /// The second Escape opens the picker when it comes within this long of the first, and a
    /// third one closes it.
    Within(Duration),
    /// Every Escape after an Escape, with no other key between, opens or keeps the picker.
    Any,
}

/// The key a read holds, as the Escapes in a row see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Press {
    Escape,
    Escapes,
    Other,
}

/// The Escapes the user pressed in a row, to tell when one opens the agent's picker.
#[derive(Debug)]
struct Escapes {
    rule: EscapeTwice,
    last: Option<Instant>,
}

impl Escapes {
    fn new(rule: EscapeTwice) -> Self {
        Self { rule, last: None }
    }

    /// Takes in a `press` at `now`; returns whether it opens or keeps the agent's picker, as
    /// two Escapes in one read do.
    fn press(&mut self, press: Press, now: Instant) -> bool {
        let opens = match press {
            Press::Other => {
                self.forget();
                return false;
            }
            Press::Escapes => true,
            Press::Escape => self.last.is_some_and(|last| match self.rule {
                EscapeTwice::Within(window) => now.saturating_duration_since(last) <= window,
                EscapeTwice::Any => true,
            }),
        };
        self.last = match self.rule {
            EscapeTwice::Within(_) if opens => None,
            EscapeTwice::Within(_) | EscapeTwice::Any => Some(now),
        };
        opens
    }

    fn forget(&mut self) {
        self.last = None;
    }
}

/// What mahi knows of the user's input line in the agent, from the keys alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line {
    /// Empty, with no key since it emptied that could open a picker or bring text back.
    Clear,
    /// Empty, but a key since may have opened a picker, brought back a past prompt or left a
    /// draft: an arrow, Enter on a line that was not clear, which can send a command that opens
    /// a dialog, Escape, Ctrl-C or Ctrl-U.
    Moved,
    /// Holds this many characters the user typed, each of which a Backspace takes back.
    Typed(usize),
    /// Holds text mahi cannot count.
    Unsure,
}

impl Line {
    fn is_empty(self) -> bool {
        match self {
            Self::Clear | Self::Moved => true,
            Self::Typed(_) | Self::Unsure => false,
        }
    }

    fn typed(self) -> Self {
        match self {
            Self::Clear => Self::Typed(1),
            Self::Typed(count) => Self::Typed(count.saturating_add(1)),
            Self::Moved | Self::Unsure => Self::Unsure,
        }
    }

    fn backspace(self) -> Self {
        match self {
            Self::Typed(1) => Self::Clear,
            Self::Typed(count) => Self::Typed(count - 1),
            Self::Clear | Self::Moved | Self::Unsure => self,
        }
    }

    fn entered(self) -> Self {
        match self {
            Self::Clear => Self::Clear,
            Self::Moved | Self::Typed(_) | Self::Unsure => Self::Moved,
        }
    }

    fn moved(self) -> Self {
        match self {
            Self::Clear | Self::Moved => Self::Moved,
            Self::Typed(_) | Self::Unsure => Self::Unsure,
        }
    }
}

/// What reading the user's keys keeps from one read to the next: the end of a read that can
/// still become a terminal answer, the Escapes in a row, the input line, and whether a bracketed
/// paste is open.
#[derive(Debug)]
struct Reading {
    unfinished: Vec<u8>,
    escapes: Escapes,
    line: Line,
    paste: Option<PasteEnd>,
    paste_start: usize,
}

impl Reading {
    fn new(rule: EscapeTwice) -> Self {
        Self {
            unfinished: Vec::new(),
            escapes: Escapes::new(rule),
            line: Line::Clear,
            paste: None,
            paste_start: 0,
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
    reported: AtomicBool,
    ready_on_output: AtomicBool,
    keyed: AtomicBool,
    asking: AtomicBool,
    reading: Mutex<Reading>,
    last: Mutex<Instant>,
    tap: Option<OutputTap>,
    changing: Mutex<()>,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            turn_open: AtomicBool::new(false),
            turn_ended: AtomicBool::new(true),
            reported: AtomicBool::new(false),
            ready_on_output: AtomicBool::new(false),
            keyed: AtomicBool::new(false),
            asking: AtomicBool::new(false),
            reading: Mutex::new(Reading::new(EscapeTwice::Any)),
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
        escape_twice: EscapeTwice,
    ) -> Self {
        let working = first == Some(TurnState::Working);
        let activity = Self {
            turn_open: AtomicBool::new(working),
            turn_ended: AtomicBool::new(!working),
            ready_on_output: AtomicBool::new(at_launch == AtLaunch::Ready),
            reading: Mutex::new(Reading::new(escape_twice)),
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
            TurnState::Ready => Report::Ready,
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
            self.reported.store(true, Ordering::SeqCst);
        }
    }

    /// Notes output from the agent or keys from the user.
    pub(crate) fn touched(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = Instant::now();
        }
    }

    /// Notes `bytes` the user typed, or the terminal answered, that went to the agent: text, a
    /// paste that holds anything or Ctrl-J leaves the line unfinished; Backspace takes back a
    /// character typed or a Ctrl-J; Enter, Ctrl-C, Ctrl-U or Escape alone empties it, and Ctrl-C
    /// or Escape interrupts a turn; Enter on a clear line keeps it clear, and Shift-Tab leaves
    /// the line as it was; another key, such as an arrow, may open a picker or bring text back,
    /// so it leaves an empty line [`Line::Moved`] and makes typed text [`Line::Unsure`]; the
    /// terminal's answers change nothing. Text or Enter answers the agent's question, if it asked one. An answer that
    /// `bytes` leave unfinished waits for the next `bytes`, unless they are Escape alone. A
    /// second Escape that opens the agent's picker, as [`EscapeTwice`] tells, leaves the line
    /// unfinished.
    pub(crate) fn keys(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.touched();
        let Ok(mut reading) = self.reading.lock() else {
            self.took(&line_effect(LineEffect::on(Line::Unsure), bytes));
            return;
        };
        let Reading {
            unfinished,
            escapes,
            line,
            paste,
            paste_start,
        } = &mut *reading;
        if bytes == [ESC] {
            if unfinished.as_slice() == [ESC] {
                escapes.press(Press::Escape, Instant::now());
            }
            unfinished.clear();
        }
        let joined = !unfinished.is_empty();
        if joined {
            unfinished.extend_from_slice(bytes);
        }
        let read = if joined { unfinished.as_slice() } else { bytes };
        let head = read.get(..unfinished_answer_at(read)).unwrap_or_default();
        let effect = (!is_terminal_answer(head)).then(|| {
            let opens = paste.is_none()
                && press_of(head).is_some_and(|press| escapes.press(press, Instant::now()));
            let mut effect = LineEffect::on(*line);
            effect.paste = *paste;
            effect.paste_start = *paste_start;
            if opens {
                effect.unsure();
            } else {
                effect = line_effect(effect, read);
            }
            if !self.asking.load(Ordering::SeqCst) {
                *line = effect.line;
            }
            *paste = effect.paste;
            *paste_start = effect.paste_start;
            effect
        });
        let finished = head.len();
        if joined {
            unfinished.drain(..finished);
        } else {
            unfinished.extend_from_slice(bytes.get(finished..).unwrap_or_default());
        }
        if unfinished.len() > HELD_AT_MOST {
            unfinished.clear();
        }
        drop(reading);
        if let Some(effect) = effect {
            self.took(&effect);
        }
    }

    fn sent_prompt(&self) {
        if let Ok(mut reading) = self.reading.lock() {
            reading.escapes.forget();
            reading.paste = None;
            reading.paste_start = 0;
            if reading.line == Line::Moved {
                reading.line = Line::Clear;
            }
        }
    }

    fn forget_escapes(&self) {
        if let Ok(mut reading) = self.reading.lock() {
            reading.escapes.forget();
        }
    }

    fn took(&self, effect: &LineEffect) {
        let changing = self.changing.lock();
        self.keyed.store(true, Ordering::SeqCst);
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
        if effect.edits && !effect.interrupts && self.asking.swap(false, Ordering::SeqCst) {
            self.tell(TurnState::Working);
        }
    }

    /// Notes what the agent's hook reported, with the `payload` it read.
    pub(crate) fn saw(&self, kind: HookKind, payload: &[u8]) {
        let Ok(_changing) = self.changing.lock() else {
            return;
        };
        match kind {
            HookKind::Prompt => {
                self.sent_prompt();
                let was_open = self.turn_open.swap(true, Ordering::SeqCst);
                self.turn_ended.store(false, Ordering::SeqCst);
                self.reported.store(false, Ordering::SeqCst);
                let was_asking = self.asking.swap(false, Ordering::SeqCst);
                if !was_open || was_asking {
                    self.tell(TurnState::Working);
                }
            }
            HookKind::TurnEnd => {
                self.turn_open.store(false, Ordering::SeqCst);
                self.turn_ended.store(true, Ordering::SeqCst);
                self.reported.store(true, Ordering::SeqCst);
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
                    self.reported.store(true, Ordering::SeqCst);
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

    fn line(&self) -> Option<Line> {
        self.reading.lock().ok().map(|reading| reading.line)
    }

    fn is_idle(&self, pace: &Pace) -> bool {
        self.line()
            .is_some_and(|line| self.is_idle_with(line, pace))
    }

    fn is_idle_with(&self, line: Line, pace: &Pace) -> bool {
        let Ok(quiet_for) = self.last.lock().map(|last| last.elapsed()) else {
            return false;
        };
        if self.asking.load(Ordering::SeqCst) {
            return false;
        }
        !self.turn_open.load(Ordering::SeqCst) && line.is_empty() && quiet_for >= pace.quiet
    }

    /// Says whether the agent is idle after a turn end or a session start its hooks reported in
    /// this run, with its input line [`Line::Clear`].
    fn is_clear_after_turn_end(&self, pace: &Pace) -> bool {
        self.reported.load(Ordering::SeqCst)
            && self
                .line()
                .is_some_and(|line| line == Line::Clear && self.is_idle_with(line, pace))
    }

    /// Takes in that mahi typed a prompt into the agent, so it types no other until the next
    /// turn end or session start its hooks report.
    pub(crate) fn typed_prompt(&self) {
        self.forget_escapes();
        self.reported.store(false, Ordering::SeqCst);
        self.touched();
    }

    /// Says whether the agent is idle after a turn its turn-end hook reported, or since it
    /// started: an interrupt does not count.
    fn is_idle_after_turn_end(&self, pace: &Pace) -> bool {
        self.turn_ended.load(Ordering::SeqCst) && self.is_idle(pace)
    }
}

/// What keys did to the input line: the line they left, whether they edited it, as text,
/// Enter or an interrupt does, whether they interrupt a turn, the bracketed paste they left
/// open, and how much of the start of a paste they ended with.
#[derive(Debug, PartialEq, Eq)]
struct LineEffect {
    line: Line,
    edits: bool,
    interrupts: bool,
    paste: Option<PasteEnd>,
    paste_start: usize,
}

impl LineEffect {
    fn on(line: Line) -> Self {
        Self {
            line,
            edits: false,
            interrupts: false,
            paste: None,
            paste_start: 0,
        }
    }

    fn enter(&mut self) {
        self.edits = true;
        self.line = self.line.entered();
    }

    fn empties(&mut self, interrupts: bool) {
        self.line = Line::Moved;
        self.edits = true;
        self.interrupts |= interrupts;
    }

    fn types(&mut self) {
        self.line = self.line.typed();
        self.edits = true;
    }

    fn unsure(&mut self) {
        self.line = Line::Unsure;
        self.edits = true;
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

fn line_effect(mut effect: LineEffect, bytes: &[u8]) -> LineEffect {
    if bytes == [ESC] && effect.paste.is_none() {
        effect.empties(true);
        return effect;
    }
    let mut at = 0;
    while let Some(rest @ &[byte, ..]) = bytes.get(at..) {
        if let Some(end) = &mut effect.paste {
            if end.ends(byte) {
                effect.paste = None;
            } else if !end.is_matching() {
                effect.unsure();
            }
            at += 1;
            continue;
        }
        let matched = std::mem::take(&mut effect.paste_start);
        if matched > 0 && PASTE_START.get(matched) == Some(&byte) {
            at += 1;
            if matched + 1 == PASTE_START.len() {
                effect.paste = Some(PasteEnd::default());
            } else {
                effect.paste_start = matched + 1;
            }
            continue;
        }
        if rest.starts_with(PASTE_START) {
            effect.paste = Some(PasteEnd::default());
            at += PASTE_START.len();
            continue;
        }
        if rest == &PASTE_START[..2] {
            effect.paste_start = 2;
        }
        at += 1;
        match byte {
            b'\r' => effect.enter(),
            KILL_LINE => effect.empties(false),
            b'\n' => effect.types(),
            INTERRUPT => effect.empties(true),
            ESC => at = escape(bytes, at, &mut effect),
            BACKSPACE | CTRL_H => effect.line = effect.line.backspace(),
            0x00..=0x1f => effect.line = effect.line.moved(),
            0x20..=0x7e => effect.types(),
            0x80..=0xff => effect.unsure(),
        }
    }
    effect
}

fn escape(bytes: &[u8], at: usize, effect: &mut LineEffect) -> usize {
    if let Some(end) = terminal_answer_at(bytes, at - 1) {
        return end;
    }
    match bytes.get(at) {
        Some(b'[') => {
            let csi = Csi::at(bytes, at + 1);
            if csi.last.is_none() {
                if !starts_answer(bytes.get(at - 1..).unwrap_or_default()) {
                    effect.unsure();
                }
            } else if csi.last == Some(b'u') && csi.intermediates.is_empty() {
                kitty_key(csi.params, effect);
            } else if !csi.is_mouse() && !is_shift_tab(&csi) {
                effect.line = effect.line.moved();
            }
            csi.end + usize::from(csi.last.is_some())
        }
        Some(b'O') => {
            effect.line = effect.line.moved();
            at + 2
        }
        Some(b']' | b'P' | b'_' | b'^' | b'X') => string_end(bytes, at + 1).unwrap_or(bytes.len()),
        Some(_) => {
            effect.unsure();
            at + 1
        }
        None => at,
    }
}

fn is_shift_tab(csi: &Csi<'_>) -> bool {
    csi.last == Some(b'Z') && csi.params.is_empty() && csi.intermediates.is_empty()
}

/// A key the kitty keyboard protocol reported: its code, its modifiers but the lock keys, and
/// whether it was released.
struct KittyKey {
    code: Option<u32>,
    modifiers: u32,
    released: bool,
}

impl KittyKey {
    fn of(params: &[u8]) -> Self {
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
        Self {
            code,
            modifiers,
            released,
        }
    }
}

/// Returns the key `read` holds for the Escapes in a row: Escape, given alone or in the kitty
/// keyboard protocol, two or more of them, another key, or none, when it holds only key
/// releases or mouse reports.
fn press_of(read: &[u8]) -> Option<Press> {
    let mut escapes: usize = 0;
    let mut at = 0;
    while let Some(&byte) = read.get(at) {
        if byte != ESC {
            return Some(Press::Other);
        }
        if let Some(end) = terminal_answer_at(read, at) {
            at = end;
            continue;
        }
        match read.get(at + 1) {
            None | Some(&ESC) => {
                escapes += 1;
                at += 1;
            }
            Some(b'[') => {
                let csi = Csi::at(read, at + 2);
                match (csi.last, csi.intermediates) {
                    (Some(b'u'), b"") => match KittyKey::of(csi.params) {
                        KittyKey { released: true, .. } => {}
                        KittyKey {
                            code: Some(27),
                            modifiers: 0,
                            ..
                        } => escapes += 1,
                        KittyKey { .. } => return Some(Press::Other),
                    },
                    _ if csi.is_mouse() => {}
                    _ => return Some(Press::Other),
                }
                at = csi.end + 1;
            }
            Some(_) => return Some(Press::Other),
        }
    }
    match escapes {
        0 => None,
        1 => Some(Press::Escape),
        _ => Some(Press::Escapes),
    }
}

fn kitty_key(params: &[u8], effect: &mut LineEffect) {
    let KittyKey {
        code,
        modifiers,
        released,
    } = KittyKey::of(params);
    if released {
        return;
    }
    match (code, modifiers) {
        (Some(27), 0) | (Some(99), 4) => effect.empties(true),
        (Some(13), 0) => effect.enter(),
        (Some(117), 4) => effect.empties(false),
        (Some(127), 0) => effect.line = effect.line.backspace(),
        (Some(32..=126), 0 | 1) | (Some(106), 4) => effect.types(),
        (Some(code), 0 | 1) if code > 127 && !KITTY_PRIVATE_USE.contains(&code) => effect.unsure(),
        (Some(code), _) if code == 13 || KITTY_KEYPAD_TEXT.contains(&code) => effect.unsure(),
        (Some(9), 1) => {}
        (Some(code), _)
            if KITTY_MODIFIER_KEYS.contains(&code) || KITTY_LOCK_KEYS.contains(&code) => {}
        _ => effect.line = effect.line.moved(),
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
    /// Be idle after a turn end or a session start its hooks reported, with its input line
    /// clear, so no prompt, dialog or picker the hooks do not report may be open.
    ClearAfterTurnEnd,
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
        Readiness::ClearAfterTurnEnd => activity.is_clear_after_turn_end(&pace),
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
    fn a_second_escape_opens_the_picker_within_claude_codes_window_or_at_any_time_for_codex() {
        let start = Instant::now();
        let at = |millis| start + Duration::from_millis(millis);
        let mut claude = Escapes::new(EscapeTwice::Within(Duration::from_millis(800)));
        assert!(!claude.press(Press::Escape, at(0)));
        assert!(claude.press(Press::Escape, at(800)));
        assert!(!claude.press(Press::Escape, at(900)));
        assert!(!claude.press(Press::Escape, at(1800)));
        assert!(claude.press(Press::Escape, at(2000)));
        assert!(!claude.press(Press::Other, at(2100)));
        assert!(!claude.press(Press::Escape, at(2200)));
        let mut codex = Escapes::new(EscapeTwice::Any);
        assert!(!codex.press(Press::Escape, at(0)));
        assert!(codex.press(Press::Escape, at(60_000)));
        assert!(codex.press(Press::Escape, at(60_100)));
        assert!(!codex.press(Press::Other, at(60_200)));
        assert!(!codex.press(Press::Escape, at(60_300)));
    }

    #[test]
    fn a_second_escape_leaves_the_line_unfinished_and_the_turn_open() {
        let pace = fast();
        let activity = Activity::telling(None, None, AtLaunch::MayAsk, EscapeTwice::Any);
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\x15");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.keys(b"\x1b");
        activity.saw(HookKind::Prompt, b"");
        activity.keys(b"\x1b");
        assert!(!activity.is_turn_open());
        activity.saw(HookKind::Prompt, b"");
        activity.keys(b"\x1b\x1b");
        assert!(activity.is_turn_open());
    }

    #[test]
    fn claude_codes_window_holds_through_activity_and_a_third_escape_empties_the_line() {
        let pace = fast();
        let within = EscapeTwice::Within(Duration::from_secs(60));
        let activity = Activity::telling(None, None, AtLaunch::MayAsk, within);
        activity.keys(b"\x1b");
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        let short = EscapeTwice::Within(Duration::from_millis(1));
        let activity = Activity::telling(None, None, AtLaunch::MayAsk, short);
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn kitty_escapes_count_and_releases_and_mouse_reports_leave_the_escapes_in_a_row() {
        let pace = fast();
        for reads in [
            &[&b"\x1b[27u"[..], b"\x1b[27;1:3u", b"\x1b[27u"][..],
            &[b"\x1b", b"\x1b[<65;10;5M", b"\x1b"],
            &[b"\x1b\x1b", b"\x1b"],
            &[b"\x1b[I\x1b", b"\x1b"],
            &[b"\x1b", b"\x1b\x1b[O", b"\x1b"],
        ] {
            let activity = Activity::telling(None, None, AtLaunch::MayAsk, EscapeTwice::Any);
            for read in reads {
                activity.keys(read);
            }
            thread::sleep(pace.quiet);
            assert!(!activity.is_idle(&pace), "{reads:?}");
        }
        assert_eq!(press_of(b"\x1b"), Some(Press::Escape));
        assert_eq!(press_of(b"\x1b[27u\x1b[27;1:3u"), Some(Press::Escape));
        assert_eq!(press_of(b"\x1b\x1b"), Some(Press::Escapes));
        assert_eq!(press_of(b"\x1b\x1b[O"), Some(Press::Escape));
        assert_eq!(press_of(b"\x1b[27;1:3u"), None);
        assert_eq!(press_of(b"\x1b[<0;3;4m"), None);
        for other in [&b"x"[..], b"\x1b[A", b"\x1bx", b"\x1b[27;5u", b"\x1b[97u"] {
            assert_eq!(press_of(other), Some(Press::Other), "{other:?}");
        }
    }

    #[test]
    fn a_prompt_mahi_typed_forgets_the_escapes_in_a_row() {
        let activity = Activity::telling(None, None, AtLaunch::MayAsk, EscapeTwice::Any);
        activity.keys(b"\x1b");
        activity.typed_prompt();
        activity.saw(HookKind::Prompt, b"");
        activity.keys(b"\x1b");
        assert!(!activity.is_turn_open());
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
    fn only_a_reported_turn_end_with_a_clear_line_lets_a_prompt_in() {
        let pace = fast();
        let activity = Activity::default();
        thread::sleep(pace.quiet);
        assert!(!activity.is_clear_after_turn_end(&pace));
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_clear_after_turn_end(&pace));
        activity.keys(b"/model\r");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        assert!(!activity.is_clear_after_turn_end(&pace));
        activity.saw(HookKind::TurnEnd, b"");
        activity.typed_prompt();
        thread::sleep(pace.quiet);
        assert!(!activity.is_clear_after_turn_end(&pace));
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_clear_after_turn_end(&pace));
    }

    #[test]
    fn a_reported_startup_or_resume_with_a_clear_line_lets_a_prompt_in_before_any_turn() {
        let pace = fast();
        let (startup, resume) = (br#"{"source":"startup"}"#, br#"{"source":"resume"}"#);
        let activity = Activity::default();
        activity.saw(HookKind::SessionStart, startup);
        thread::sleep(pace.quiet);
        assert!(activity.is_clear_after_turn_end(&pace));
        activity.keys(b"/clear\r");
        for source in [
            &br#"{"source":"clear"}"#[..],
            br#"{"source":"compact"}"#,
            b"",
        ] {
            activity.saw(HookKind::SessionStart, source);
        }
        thread::sleep(pace.quiet);
        assert!(!activity.is_clear_after_turn_end(&pace));
        let resumed = Activity::default();
        resumed.saw(HookKind::SessionStart, resume);
        thread::sleep(pace.quiet);
        assert!(resumed.is_clear_after_turn_end(&pace));
        resumed.typed_prompt();
        thread::sleep(pace.quiet);
        assert!(!resumed.is_clear_after_turn_end(&pace));
    }

    #[test]
    fn the_terminals_answers_are_no_key() {
        let answers = [
            &b"\x1b[12;1R"[..],
            b"\x1b]11;rgb:0000/0000/0000\x07",
            b"\x1b[?62;22c",
            b"\x1b[?2026;2$y",
            b"\x1bP1+r544e=787465726d\x1b\\",
            b"\x1b[12;1R\x1b[?0u",
        ];
        let pace = fast();
        let activity = Activity::telling(None, None, AtLaunch::Ready, EscapeTwice::Any);
        activity.wrote();
        for answer in answers {
            activity.keys(answer);
        }
        thread::sleep(pace.quiet);
        assert!(activity.is_clear_after_turn_end(&pace));
        activity.keys(b"\x1b[A");
        thread::sleep(pace.quiet);
        assert!(!activity.is_clear_after_turn_end(&pace));
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
            let activity = Activity::telling(None, None, AtLaunch::Ready, EscapeTwice::Any);
            activity.wrote();
            activity.keys(first);
            activity.keys(rest);
            thread::sleep(pace.quiet);
            assert!(
                activity.is_clear_after_turn_end(&pace),
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
        assert!(!activity.is_clear_after_turn_end(&pace));
    }

    #[test]
    fn a_launch_with_no_dialog_lets_a_prompt_in_once_the_agent_wrote_while_its_line_is_clear() {
        let pace = fast();
        let activity = Activity::telling(None, None, AtLaunch::Ready, EscapeTwice::Any);
        thread::sleep(pace.quiet);
        assert!(!activity.is_clear_after_turn_end(&pace));
        activity.wrote();
        assert!(!activity.is_clear_after_turn_end(&pace));
        thread::sleep(pace.quiet);
        assert!(activity.is_clear_after_turn_end(&pace));
        let keyed_first = Activity::telling(None, None, AtLaunch::Ready, EscapeTwice::Any);
        keyed_first.keys(b"h");
        keyed_first.keys(b"\x15");
        keyed_first.wrote();
        thread::sleep(pace.quiet);
        assert!(!keyed_first.is_clear_after_turn_end(&pace));
        activity.keys(b"h");
        thread::sleep(pace.quiet);
        assert!(!activity.is_clear_after_turn_end(&pace));
        activity.keys(b"\x7f");
        thread::sleep(pace.quiet);
        assert!(activity.is_clear_after_turn_end(&pace));
        activity.keys(b"/review\r");
        thread::sleep(pace.quiet);
        assert!(!activity.is_clear_after_turn_end(&pace));
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
        let activity = Activity::telling(
            None,
            Some(TurnState::Working),
            AtLaunch::MayAsk,
            EscapeTwice::Any,
        );
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        let waiting = Activity::telling(
            None,
            Some(TurnState::Ready),
            AtLaunch::MayAsk,
            EscapeTwice::Any,
        );
        thread::sleep(pace.quiet);
        assert!(waiting.is_idle_after_turn_end(&pace));
    }

    #[test]
    fn the_first_state_reaches_the_workspace_as_later_ones_do() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        crate::report::connect(std::os::fd::IntoRawFd::into_raw_fd(writer));
        let activity = Activity::telling(
            None,
            Some(TurnState::Working),
            AtLaunch::MayAsk,
            EscapeTwice::Any,
        );
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        let mut read = [0_u8; 64];
        let length = rustix::io::read(&reader, &mut read).unwrap();
        let mut reports = Vec::new();
        mahi_term::ReportReader::default().feed(&read[..length], |report| reports.push(report));
        assert_eq!(reports, [Report::Working, Report::Done]);
    }

    #[test]
    fn a_run_that_starts_ready_tells_working_then_done_on_its_first_turn() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        crate::report::connect(std::os::fd::IntoRawFd::into_raw_fd(writer));
        let activity = Activity::telling(
            None,
            Some(TurnState::Ready),
            AtLaunch::MayAsk,
            EscapeTwice::Any,
        );
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        let mut read = [0_u8; 64];
        let length = rustix::io::read(&reader, &mut read).unwrap();
        let mut reports = Vec::new();
        mahi_term::ReportReader::default().feed(&read[..length], |report| reports.push(report));
        assert_eq!(reports, [Report::Ready, Report::Working, Report::Done]);
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
    fn a_newline_in_a_paste_keeps_merges_out_in_one_read_or_several() {
        let pace = fast();
        for reads in [
            &[&b"\x1b[200~fix the parser\n\x1b[201~"[..]][..],
            &[b"\x1b[200~fix the", b" parser\r\n", b"\x1b[201~"],
            &[b"\x1b[200~\n\x1b[201~"],
        ] {
            let activity = Activity::default();
            for read in reads {
                activity.keys(read);
            }
            thread::sleep(pace.quiet);
            assert!(!activity.is_idle(&pace), "{reads:?}");
            activity.keys(b"\x7f");
            thread::sleep(pace.quiet);
            assert!(!activity.is_idle(&pace), "{reads:?}");
            activity.keys(b"\r");
            thread::sleep(pace.quiet);
            assert!(activity.is_idle(&pace), "{reads:?}");
        }
    }

    #[test]
    fn a_paste_split_inside_either_marker_still_opens_and_closes() {
        let pace = fast();
        let whole: &[u8] = b"draft \x1b[200~fix\r\x1b[201~";
        let markers = [6..12, 16..22];
        let cuts = markers
            .into_iter()
            .flat_map(|marker| marker.start + 2..marker.end);
        for cut in cuts {
            let activity = Activity::default();
            activity.keys(&whole[..cut]);
            activity.keys(&whole[cut..]);
            thread::sleep(pace.quiet);
            assert!(!activity.is_idle(&pace), "cut at {cut}");
            activity.keys(b"\r");
            thread::sleep(pace.quiet);
            assert!(activity.is_idle(&pace), "cut at {cut}");
        }
        let activity = Activity::default();
        activity.keys(b"\x1b[200~fix\x1b");
        activity.keys(b"\x1b");
        activity.keys(b"[201~");
        activity.keys(b"\r");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn a_prompt_ends_a_paste_whose_end_mahi_never_saw() {
        let pace = fast();
        let activity = Activity::default();
        activity.keys(b"\x1b[200~fix");
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        activity.keys(b"\r");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn escapes_inside_a_paste_open_no_picker() {
        let pace = fast();
        let activity = Activity::default();
        activity.keys(b"\x1b[200~x");
        activity.keys(b"\x1b\x1b");
        activity.keys(b"[201~");
        activity.keys(b"\r");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn ctrl_j_adds_a_newline_that_backspace_takes_back() {
        let pace = fast();
        let activity = Activity::default();
        activity.keys(b"first line\n");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        let activity = Activity::default();
        activity.keys(b"\n");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\x7f");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn an_escape_before_another_escape_leaves_the_line_unfinished_in_one_read_or_two() {
        let unfinished = LineEffect {
            line: Line::Unsure,
            edits: true,
            interrupts: false,
            paste: None,
            paste_start: 0,
        };
        for bytes in [
            &b"\x1b\x1b"[..],
            b"\x1b\x1b[A",
            b"\x1b\x1b[12;40R",
            b"\x1b[I\x1b\x1b[O",
        ] {
            assert_eq!(
                line_effect(LineEffect::on(Line::Clear), bytes),
                unfinished,
                "{bytes:?}"
            );
        }
        let pace = fast();
        for reads in [
            &[&b"\x1b[I\x1b\x1b[O"[..]][..],
            &[b"\x1b[I\x1b", b"\x1b[O"],
            &[b"\x1b[I\x1b", b"\x1b[12;", b"40R"],
        ] {
            let activity = Activity::default();
            activity.saw(HookKind::Prompt, b"");
            for read in reads {
                activity.keys(read);
            }
            assert!(activity.is_turn_open(), "{reads:?}");
            activity.saw(HookKind::TurnEnd, b"");
            thread::sleep(pace.quiet);
            assert!(!activity.is_idle(&pace), "{reads:?}");
        }
    }

    #[test]
    fn the_line_state_comes_from_keys_not_from_sequences() {
        let effect = |bytes: &[u8]| line_effect(LineEffect::on(Line::Clear), bytes);
        let left = |line: Line, edits: bool, interrupts: bool| LineEffect {
            line,
            edits,
            interrupts,
            paste: None,
            paste_start: 0,
        };
        assert_eq!(effect(b"abc"), left(Line::Typed(3), true, false));
        assert_eq!(effect(b"abc\r"), left(Line::Moved, true, false));
        assert_eq!(effect(b"abc\x03"), left(Line::Moved, true, true));
        assert_eq!(effect(b"\x1b"), left(Line::Moved, true, true));
        assert_eq!(effect(b"\x1b[27u"), left(Line::Moved, true, true));
        assert_eq!(effect(b"\x1b[99;5u"), left(Line::Moved, true, true));
        assert_eq!(effect(b"x\x1b[117;5u"), left(Line::Moved, true, false));
        assert_eq!(effect(b"\x1b[13u"), left(Line::Clear, true, false));
        assert_eq!(effect(b"x\x1b[13u"), left(Line::Moved, true, false));
        assert_eq!(effect(b"\x1b[97u"), left(Line::Typed(1), true, false));
        assert_eq!(effect(b"\x1bx"), left(Line::Unsure, true, false));
        assert_eq!(effect(b"abc\n"), left(Line::Typed(4), true, false));
        assert_eq!(effect(b"\x1b[106;5u"), left(Line::Typed(1), true, false));
        assert_eq!(
            effect(b"\x1b[200~\x1b[201~"),
            left(Line::Clear, false, false)
        );
        assert_eq!(
            effect(b"\x1b[200~a\r"),
            LineEffect {
                paste: Some(PasteEnd::default()),
                ..left(Line::Unsure, true, false)
            }
        );
        for answer in [
            &b"\x1b[12;40R"[..],
            b"\x1b[?62;22c",
            b"\x1b[?1u",
            b"\x1b[I",
            b"\x1b[O",
            b"\x1b]11;rgb:0000/0000/0000\x07",
            b"\x1bP1+r544e\x1b\\",
            b"\x1b[27;1:3u",
            b"\x1b[57441u",
            b"\x1b[<0;10;5M",
            b"\x7f",
        ] {
            assert_eq!(
                effect(answer),
                left(Line::Clear, false, false),
                "{answer:?}"
            );
        }
        for moving in [
            &b"\x1b[A\x1bOB"[..],
            b"\x1b[5~",
            b"\t",
            b"\x1b[9u",
            b"\x01",
            b"\x1b[1;5Z",
            b"\x1b[9;6u",
        ] {
            assert_eq!(
                effect(moving),
                left(Line::Moved, false, false),
                "{moving:?}"
            );
        }
        assert_eq!(effect(b"\r\x1b[12;40R"), left(Line::Clear, true, false));
        assert_eq!(effect(b"\x1b[Z"), left(Line::Clear, false, false));
        assert_eq!(effect(b"\x1b[9;2u"), left(Line::Clear, false, false));
        assert_eq!(effect(b"\x1b[9;66u"), left(Line::Clear, false, false));
        assert_eq!(effect(b"a\x1b[Z"), left(Line::Typed(1), true, false));
    }

    #[test]
    fn backspace_takes_back_each_character_typed_and_any_other_edit_leaves_the_line_unsure() {
        let after = |line: Line, bytes: &[u8]| line_effect(LineEffect::on(line), bytes).line;
        assert_eq!(after(Line::Clear, b"ab\x7f"), Line::Typed(1));
        assert_eq!(after(Line::Clear, b"ab\x7f\x08"), Line::Clear);
        assert_eq!(after(Line::Typed(2), b"\x1b[127u\x1b[127u"), Line::Clear);
        assert_eq!(after(Line::Clear, b"\x7f\x7fa"), Line::Typed(1));
        assert_eq!(after(Line::Moved, b"a\x7f"), Line::Unsure);
        assert_eq!(after(Line::Moved, b"\x7f"), Line::Moved);
        for unsure in [
            &b"ab\x1b[D\x7f\x7f"[..],
            b"ab\x17\x7f\x7f",
            b"ab\x01\x7f\x7f",
            b"\xc3\xa9\x7f",
            b"\x1b[233u\x7f",
            b"\x1bb\x7f",
        ] {
            assert_eq!(after(Line::Clear, unsure), Line::Unsure, "{unsure:?}");
        }
        for emptying in [&b"\x15"[..], b"\x03", b"\x1b[117;5u", b"\r", b"\x1b"] {
            assert_eq!(after(Line::Unsure, emptying), Line::Moved, "{emptying:?}");
        }
    }

    #[test]
    fn a_kitty_chord_or_a_split_sequence_never_counts_a_line_back_to_empty() {
        let after = |line: Line, bytes: &[u8]| line_effect(LineEffect::on(line), bytes).line;
        for unsure in [
            &b"ab\x1b[97;5u\x7f\x7f"[..],
            b"ab\x1b[98;3u\x7f\x7f",
            b"ab\x1b[13;2u\x7f\x7f",
            b"\x1b[57399u\x7f",
            b"a\x1b[121;5u\x7f",
            b"\x1b[",
        ] {
            assert_eq!(after(Line::Clear, unsure), Line::Unsure, "{unsure:?}");
        }
        assert_eq!(after(Line::Clear, b"\x1b[98;3u"), Line::Moved);
        assert_eq!(after(Line::Clear, b"\x1b[57441u\x1b[57358u"), Line::Clear);
        assert_eq!(after(Line::Clear, b"a\x1b[12;"), Line::Typed(1));
    }

    #[test]
    fn keys_that_answer_a_reported_question_leave_the_line_as_it_was() {
        let pace = fast();
        let activity = Activity::default();
        activity.saw(HookKind::Prompt, b"");
        activity.saw(
            HookKind::Asks,
            br#"{"notification_type":"permission_prompt"}"#,
        );
        activity.keys(b"\x1b[B");
        activity.keys(b"\r");
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_clear_after_turn_end(&pace));
    }

    #[test]
    fn a_line_typed_then_erased_lets_merges_and_the_report_in_but_a_moved_one_only_merges() {
        let pace = fast();
        let activity = Activity::telling(None, None, AtLaunch::Ready, EscapeTwice::Any);
        activity.wrote();
        activity.keys(b"hel");
        activity.keys(b"lo");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        for _ in 0..4 {
            activity.keys(b"\x7f");
        }
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\x7f");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        assert!(activity.is_clear_after_turn_end(&pace));
        activity.keys(b"\x1b[A");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        assert!(!activity.is_clear_after_turn_end(&pace));
        activity.keys(b"\x7f");
        thread::sleep(pace.quiet);
        assert!(!activity.is_clear_after_turn_end(&pace));
        activity.keys(b"x\x7f");
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.keys(b"\x15");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle_after_turn_end(&pace));
        assert!(!activity.is_clear_after_turn_end(&pace));
        activity.saw(HookKind::Prompt, b"");
        activity.saw(HookKind::TurnEnd, b"");
        thread::sleep(pace.quiet);
        assert!(activity.is_clear_after_turn_end(&pace));
    }

    #[test]
    fn shift_tab_leaves_the_line_as_it_was_so_a_line_typed_after_it_counts_back_to_empty() {
        let pace = fast();
        for shift_tab in [&b"\x1b[Z"[..], b"\x1b[9;2u"] {
            let activity = Activity::telling(None, None, AtLaunch::Ready, EscapeTwice::Any);
            activity.wrote();
            activity.keys(shift_tab);
            activity.keys(b"hi");
            activity.keys(shift_tab);
            activity.keys(b"\x7f\x7f");
            thread::sleep(pace.quiet);
            assert!(activity.is_clear_after_turn_end(&pace), "{shift_tab:?}");
        }
    }

    #[test]
    fn enter_on_a_clear_line_keeps_it_clear_but_on_a_moved_one_keeps_it_moved() {
        let pace = fast();
        for enter in [&b"\r"[..], b"\x1b[13u"] {
            let activity = Activity::telling(None, None, AtLaunch::Ready, EscapeTwice::Any);
            activity.wrote();
            activity.keys(enter);
            activity.keys(b"hi\x7f\x7f");
            thread::sleep(pace.quiet);
            assert!(activity.is_clear_after_turn_end(&pace), "{enter:?}");
            activity.keys(b"\x1b[A");
            activity.keys(enter);
            thread::sleep(pace.quiet);
            assert!(!activity.is_clear_after_turn_end(&pace), "{enter:?}");
        }
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
