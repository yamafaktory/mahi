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

use mahi_agent::hook::HookKind;
use mahi_core::is_invisible;

use crate::prompts::Prompts;

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";
const INTERRUPT: u8 = 0x03;
const KILL_LINE: u8 = 0x15;
const ESC: u8 = 0x1b;

/// How the injector paces itself: how long the agent and the user must be quiet, how often it
/// looks, how long it waits between the prompt and its Enter, and after how long without
/// output or keys a turn the agent never reported ended counts as over.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pace {
    pub(crate) quiet: Duration,
    pub(crate) look_every: Duration,
    pub(crate) enter_after: Duration,
    pub(crate) stale_turn: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            quiet: Duration::from_secs(2),
            look_every: Duration::from_millis(200),
            enter_after: Duration::from_millis(50),
            stale_turn: Duration::from_secs(60),
        }
    }
}

/// What the agent and the user did last, to tell when the agent is idle: its turn ended, as
/// its hook reports, or was interrupted, the user's own input line is empty, and nothing was
/// written or typed for a while.
#[derive(Debug)]
pub(crate) struct Activity {
    turn_open: AtomicBool,
    line_empty: AtomicBool,
    last: Mutex<Instant>,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            turn_open: AtomicBool::new(false),
            line_empty: AtomicBool::new(true),
            last: Mutex::new(Instant::now()),
        }
    }
}

impl Activity {
    /// Notes output from the agent or keys from the user.
    pub(crate) fn touched(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = Instant::now();
        }
    }

    /// Notes `bytes` the user typed, or the terminal answered, that went to the agent: text
    /// leaves the line unfinished, Enter, Ctrl-C, Ctrl-U or Escape alone empties it, and Ctrl-C
    /// or Escape interrupts a turn; other sequences, such as arrows or the terminal's answers,
    /// change neither.
    pub(crate) fn keys(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.touched();
        let effect = line_effect(bytes);
        if effect.interrupts {
            self.turn_open.store(false, Ordering::SeqCst);
        }
        if let Some(empty) = effect.line_empty {
            self.line_empty.store(empty, Ordering::SeqCst);
        }
    }

    /// Notes what the agent's hook reported.
    pub(crate) fn saw(&self, kind: HookKind) {
        match kind {
            HookKind::Prompt => self.turn_open.store(true, Ordering::SeqCst),
            HookKind::TurnEnd => self.turn_open.store(false, Ordering::SeqCst),
            HookKind::Tool => {}
        }
        self.touched();
    }

    fn typed_prompt(&self) {
        self.line_empty.store(true, Ordering::SeqCst);
        self.touched();
    }

    fn is_idle(&self, pace: &Pace) -> bool {
        let Ok(quiet_for) = self.last.lock().map(|last| last.elapsed()) else {
            return false;
        };
        let turn_over = !self.turn_open.load(Ordering::SeqCst) || quiet_for >= pace.stale_turn;
        turn_over && self.line_empty.load(Ordering::SeqCst) && quiet_for >= pace.quiet
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

/// The agent's side of what the injector needs: whether mahi's palette is open, and whether the
/// agent turned bracketed paste on.
pub(crate) trait AgentInput {
    /// Returns whether the palette is open, when nothing is given to the agent.
    fn palette_open(&self) -> bool;
    /// Returns whether the agent takes pasted text as a bracketed paste.
    fn bracketed_paste(&self) -> bool;
}

/// Gives the agent each accepted prompt when it is idle and the palette closed, while
/// `running` is set: as a bracketed paste when the agent turned that on, then Enter on its
/// own. It holds the agent's input while it looks and types, so neither the user's keys nor
/// the palette come in between.
pub(crate) fn give_accepted(
    prompts: &Prompts,
    activity: &Activity,
    agent: &impl AgentInput,
    writer: &Mutex<impl Write>,
    (running, pace): (&AtomicBool, Pace),
) {
    let mut typed = Vec::new();
    while running.load(Ordering::SeqCst) {
        thread::sleep(pace.look_every);
        let Ok(mut input) = writer.lock() else {
            return;
        };
        if agent.palette_open() || !activity.is_idle(&pace) {
            continue;
        }
        let Some(accepted) = prompts.next_accepted() else {
            continue;
        };
        typed.clear();
        encode(accepted.text.as_str(), agent.bracketed_paste(), &mut typed);
        if type_in(&mut *input, &typed, pace.enter_after).is_err() {
            return;
        }
        activity.typed_prompt();
    }
}

/// Runs `act` once the agent is idle and the palette closed, holding the agent's input while
/// it runs, so neither the user's keys nor an accepted prompt come in between; returns `None`
/// if `running` is cleared first.
pub(crate) fn when_idle<T>(
    activity: &Activity,
    agent: &impl AgentInput,
    writer: &Mutex<impl Write>,
    (running, pace): (&AtomicBool, Pace),
    act: impl FnOnce() -> T,
) -> Option<T> {
    while running.load(Ordering::SeqCst) {
        thread::sleep(pace.look_every);
        let Ok(input) = writer.lock() else {
            return None;
        };
        if agent.palette_open() || !activity.is_idle(&pace) {
            continue;
        }
        let done = act();
        drop(input);
        return Some(done);
    }
    None
}

fn type_in(input: &mut impl Write, typed: &[u8], enter_after: Duration) -> io::Result<()> {
    input.write_all(typed)?;
    input.flush()?;
    thread::sleep(enter_after);
    input.write_all(b"\r")?;
    input.flush()
}

/// Writes `text` as the keys that type it into the agent: control characters other than
/// newlines and tabs, and invisible ones, are left out, so nothing in it can end the paste or
/// act as a key; without bracketed paste, newlines and tabs become spaces, so the prompt is
/// one line the agent takes at once.
fn encode(text: &str, bracketed: bool, out: &mut Vec<u8>) {
    if bracketed {
        out.extend_from_slice(PASTE_START);
    }
    let mut buffer = [0_u8; 4];
    for character in text.chars() {
        let character = match character {
            '\n' if bracketed => '\r',
            '\t' if bracketed => '\t',
            '\n' | '\t' => ' ',
            _ if character.is_control() || is_invisible(character) => continue,
            _ => character,
        };
        out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
    }
    if bracketed {
        out.extend_from_slice(PASTE_END);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mahi_core::ParticipantName;
    use mahi_live::PromptText;

    use super::*;
    use crate::prompts::Decision;

    fn encoded(text: &str, bracketed: bool) -> Vec<u8> {
        let mut out = Vec::new();
        encode(text, bracketed, &mut out);
        out
    }

    fn fast() -> Pace {
        Pace {
            quiet: Duration::from_millis(100),
            look_every: Duration::from_millis(10),
            enter_after: Duration::from_millis(5),
            stale_turn: Duration::from_millis(400),
        }
    }

    #[test]
    fn a_prompt_is_pasted_whole_and_nothing_in_it_can_end_the_paste() {
        assert_eq!(
            encoded("fix it\nthen test\ttoo", true),
            b"\x1b[200~fix it\rthen test\ttoo\x1b[201~"
        );
        assert_eq!(
            encoded("a\x1b[201~\x03b\u{202e}\u{7f}\u{9b}c\r", true),
            b"\x1b[200~a[201~bc\x1b[201~"
        );
        assert_eq!(encoded("two\nlines\tand tab", false), b"two lines and tab");
        assert_eq!(encoded("\x1b\x04x", false), b"x");
    }

    #[test]
    fn a_turn_keeps_the_agent_busy_until_it_ends_is_interrupted_or_goes_stale() {
        let pace = fast();
        let activity = Activity::default();
        assert!(!activity.is_idle(&pace));
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.saw(HookKind::Prompt);
        thread::sleep(pace.quiet);
        assert!(!activity.is_idle(&pace));
        activity.saw(HookKind::TurnEnd);
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.saw(HookKind::Prompt);
        activity.keys(b"\x1b");
        thread::sleep(pace.quiet);
        assert!(activity.is_idle(&pace));
        activity.saw(HookKind::Prompt);
        thread::sleep(pace.stale_turn);
        assert!(activity.is_idle(&pace));
    }

    #[test]
    fn a_line_the_user_left_unfinished_keeps_prompts_out() {
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
        activity.saw(HookKind::TurnEnd);
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

        fn bracketed_paste(&self) -> bool {
            true
        }
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "{what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn accepted_prompts_are_typed_only_while_the_palette_is_closed_and_the_agent_idle() {
        let prompts = Arc::new(Prompts::default());
        let bob = ParticipantName::new("bob").unwrap();
        for (id, text) in [(1, "first"), (2, "second")] {
            prompts.offer(
                bob.clone(),
                [id; 16],
                PromptText::new(text.to_owned()).unwrap(),
            );
            prompts.decide([id; 16], Decision::Accept);
        }
        let activity = Arc::new(Activity::default());
        let agent = Arc::new(FakeAgent {
            palette_open: AtomicBool::new(true),
        });
        let writer = Arc::new(Mutex::new(Vec::new()));
        let running = Arc::new(AtomicBool::new(true));
        let worker = {
            let (prompts, activity, agent, writer, running) = (
                Arc::clone(&prompts),
                Arc::clone(&activity),
                Arc::clone(&agent),
                Arc::clone(&writer),
                Arc::clone(&running),
            );
            thread::spawn(move || {
                give_accepted(&prompts, &activity, &*agent, &writer, (&running, fast()));
            })
        };
        thread::sleep(fast().quiet * 3);
        assert!(writer.lock().unwrap().is_empty());
        activity.keys(b"mine");
        agent.palette_open.store(false, Ordering::SeqCst);
        thread::sleep(fast().quiet * 3);
        assert!(writer.lock().unwrap().is_empty());
        activity.keys(b"\r");
        wait_until("the first prompt was never typed", || {
            writer.lock().unwrap().ends_with(b"\r")
        });
        assert_eq!(
            writer.lock().unwrap().as_slice(),
            b"\x1b[200~first\x1b[201~\r"
        );
        wait_until("the second prompt was never typed", || {
            writer.lock().unwrap().ends_with(b"second\x1b[201~\r")
        });
        running.store(false, Ordering::SeqCst);
        worker.join().unwrap();
    }

    #[test]
    fn work_waits_for_the_idle_agent_and_holds_its_input_or_gives_up_when_the_run_ends() {
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
                when_idle(&activity, &*agent, &writer, (&running, fast()), move || {
                    held.try_lock().is_err()
                })
            })
        };
        thread::sleep(fast().quiet * 3);
        assert!(!worker.is_finished());
        activity.keys(b"\r");
        assert_eq!(worker.join().unwrap(), Some(true));

        agent.palette_open.store(true, Ordering::SeqCst);
        let worker = {
            let (activity, agent, writer, running) = (
                Arc::clone(&activity),
                Arc::clone(&agent),
                Arc::clone(&writer),
                Arc::clone(&running),
            );
            thread::spawn(move || when_idle(&activity, &*agent, &writer, (&running, fast()), || ()))
        };
        thread::sleep(fast().quiet * 3);
        running.store(false, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), None);
    }
}
