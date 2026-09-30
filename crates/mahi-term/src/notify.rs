use mahi_core::is_invisible;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const LONGEST_FIELD: usize = 120;

/// How the user's terminal is asked for a desktop notification: `OSC 9`, which most terminals
/// that raise notifications read, `OSC 777;notify`, for foot and rxvt, or `OSC 99`, for kitty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notifier {
    /// `OSC 9 ; text BEL`.
    Osc9,
    /// `OSC 777 ; notify ; title ; body BEL`.
    Osc777,
    /// `OSC 99 ; ; text ST`.
    Osc99,
}

/// A terminal told of an event: how it raises a notification, if it can, and whether the
/// sequence has to pass through tmux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notice {
    notifier: Option<Notifier>,
    tmux: bool,
}

/// What the environment says of the user's terminal, read once at startup.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TerminalHints<'a> {
    /// `TERM`.
    pub term: Option<&'a str>,
    /// `TERM_PROGRAM`.
    pub term_program: Option<&'a str>,
    /// Whether `KITTY_WINDOW_ID` is set, as kitty sets it, also inside tmux.
    pub kitty: bool,
    /// Whether `VTE_VERSION` is set, as GNOME Terminal and other VTE terminals set it.
    pub vte: bool,
    /// Whether `TMUX` is set.
    pub tmux: bool,
}

impl Notice {
    /// Chooses the notification for the terminal the `hints` name, passed through tmux when it
    /// runs inside it; a terminal known to raise none gets the bell only.
    #[must_use]
    pub fn for_terminal(hints: TerminalHints<'_>) -> Self {
        let term = hints.term.unwrap_or_default();
        let notifier = if hints.kitty || term.contains("kitty") {
            Some(Notifier::Osc99)
        } else if hints.vte || term.starts_with("foot") || term.contains("rxvt") {
            Some(Notifier::Osc777)
        } else if hints.term_program == Some("Apple_Terminal") {
            None
        } else {
            Some(Notifier::Osc9)
        };
        Self {
            notifier,
            tmux: hints.tmux,
        }
    }

    /// Writes the sequence that raises a notification with `title` and `body`, then the bell;
    /// control and invisible characters in them are left out, `;` becomes `,`, and each is cut
    /// to 120 characters, so nothing in them can end the sequence or change what it asks.
    pub fn write(&self, title: &str, body: &str, out: &mut Vec<u8>) {
        if let Some(notifier) = self.notifier {
            let start = out.len();
            match notifier {
                Notifier::Osc9 => {
                    out.extend_from_slice(b"\x1b]9;");
                    push_field(title, out);
                    out.extend_from_slice(b": ");
                    push_field(body, out);
                    out.push(BEL);
                }
                Notifier::Osc777 => {
                    out.extend_from_slice(b"\x1b]777;notify;");
                    push_field(title, out);
                    out.push(b';');
                    push_field(body, out);
                    out.push(BEL);
                }
                Notifier::Osc99 => {
                    out.extend_from_slice(b"\x1b]99;;");
                    push_field(title, out);
                    out.extend_from_slice(b": ");
                    push_field(body, out);
                    out.extend_from_slice(b"\x1b\\");
                }
            }
            if self.tmux {
                wrap_for_tmux(out, start);
            }
        }
        out.push(BEL);
    }
}

fn push_field(text: &str, out: &mut Vec<u8>) {
    let mut buffer = [0_u8; 4];
    let shown = text
        .chars()
        .map(|c| match c {
            ';' => ',',
            c if c.is_whitespace() => ' ',
            c => c,
        })
        .filter(|c| !c.is_control() && !is_invisible(*c))
        .take(LONGEST_FIELD);
    for c in shown {
        out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
    }
}

fn wrap_for_tmux(out: &mut Vec<u8>, start: usize) {
    let sequence = out.split_off(start);
    out.extend_from_slice(b"\x1bPtmux;");
    for &byte in &sequence {
        if byte == ESC {
            out.push(ESC);
        }
        out.push(byte);
    }
    out.extend_from_slice(b"\x1b\\");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OutputTracker;

    fn term(term: &str) -> Notice {
        Notice::for_terminal(TerminalHints {
            term: Some(term),
            ..TerminalHints::default()
        })
    }

    fn written(notice: Notice, title: &str, body: &str) -> Vec<u8> {
        let mut out = Vec::new();
        notice.write(title, body, &mut out);
        out
    }

    #[test]
    fn each_terminal_gets_the_notification_it_reads_then_the_bell() {
        assert_eq!(
            written(term("xterm-256color"), "mahi", "bob sent a prompt"),
            b"\x1b]9;mahi: bob sent a prompt\x07\x07"
        );
        assert_eq!(
            written(term("foot"), "mahi", "hi"),
            b"\x1b]777;notify;mahi;hi\x07\x07"
        );
        assert_eq!(
            written(term("xterm-kitty"), "mahi", "hi"),
            b"\x1b]99;;mahi: hi\x1b\\\x07"
        );
        let apple = Notice::for_terminal(TerminalHints {
            term: Some("xterm-256color"),
            term_program: Some("Apple_Terminal"),
            ..TerminalHints::default()
        });
        assert_eq!(written(apple, "mahi", "hi"), b"\x07");
        let unknown = Notice::for_terminal(TerminalHints::default());
        assert!(written(unknown, "m", "b").starts_with(b"\x1b]9;"));
        let vte = Notice::for_terminal(TerminalHints {
            term: Some("xterm-256color"),
            vte: true,
            ..TerminalHints::default()
        });
        assert!(written(vte, "m", "b").starts_with(b"\x1b]777;notify;"));
    }

    #[test]
    fn inside_tmux_the_sequence_passes_through_with_its_escapes_doubled() {
        let kitty = Notice::for_terminal(TerminalHints {
            term: Some("tmux-256color"),
            term_program: Some("tmux"),
            kitty: true,
            tmux: true,
            ..TerminalHints::default()
        });
        assert_eq!(
            written(kitty, "mahi", "hi"),
            b"\x1bPtmux;\x1b\x1b]99;;mahi: hi\x1b\x1b\\\x1b\\\x07"
        );
    }

    #[test]
    fn a_teammates_text_cannot_end_or_change_the_sequence() {
        let hostile = "a;b\x07c\x1b]0;x\x1b\\d\u{202e}e\u{9c}f\nnext";
        let out = written(term("foot"), "t;itle", hostile);
        assert_eq!(out, b"\x1b]777;notify;t,itle;a,bc]0,x\\def next\x07\x07");
        let mut tracker = OutputTracker::default();
        tracker.feed(&out);
        assert!(tracker.can_draw());
        let long = "x".repeat(500);
        let out = written(term("foot"), &long, &long);
        assert_eq!(out.len(), b"\x1b]777;notify;".len() + 120 + 1 + 120 + 2);
    }
}
