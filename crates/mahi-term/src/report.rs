use std::io::Write as _;

use mahi_core::ThreadId;

const MAX_LINE_BYTES: usize = 511;
const NOTIFY: &str = "notify ";

/// What a mahi the workspace started tells it about its agent, on a pipe of their own: one
/// line each, which the agent cannot write, unlike its terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// The agent's thread.
    Thread(ThreadId),
    /// A turn is open.
    Working,
    /// Its turn ended: it waits for its next prompt.
    Done,
    /// It waits on a question of its own for the user.
    Asks,
    /// How many of the teammates' prompts wait for the user.
    Prompts(u16),
    /// A notification for the user, such as a teammate's prompt that came.
    Notify(String),
}

impl Report {
    /// Writes the report into `out` as its line; a notification's control characters become
    /// spaces, and its text is cut to what a line holds.
    pub fn write(&self, out: &mut Vec<u8>) {
        let _ = match self {
            Self::Notify(text) => {
                out.extend_from_slice(NOTIFY.as_bytes());
                let room = MAX_LINE_BYTES - NOTIFY.len();
                let mut used = 0;
                let mut buffer = [0_u8; 4];
                for c in text.chars() {
                    let c = if c.is_control() { ' ' } else { c };
                    let encoded = c.encode_utf8(&mut buffer);
                    used += encoded.len();
                    if used > room {
                        break;
                    }
                    out.extend_from_slice(encoded.as_bytes());
                }
                writeln!(out)
            }
            Self::Thread(id) => writeln!(out, "thread {id}"),
            Self::Working => writeln!(out, "working"),
            Self::Done => writeln!(out, "done"),
            Self::Asks => writeln!(out, "asks"),
            Self::Prompts(count) => writeln!(out, "prompts {count}"),
        };
    }

    fn parse(line: &[u8]) -> Option<Self> {
        match line {
            b"working" => return Some(Self::Working),
            b"done" => return Some(Self::Done),
            b"asks" => return Some(Self::Asks),
            _ => {}
        }
        if let Some(text) = line.strip_prefix(NOTIFY.as_bytes()) {
            let text = std::str::from_utf8(text).ok()?;
            return (!text.chars().any(char::is_control)).then(|| Self::Notify(text.to_owned()));
        }
        if let Some(id) = line.strip_prefix(b"thread ") {
            return std::str::from_utf8(id).ok()?.parse().ok().map(Self::Thread);
        }
        let count = line.strip_prefix(b"prompts ")?;
        let plain = match count {
            [b'0'] => true,
            [first, ..] => *first != b'0' && count.iter().all(u8::is_ascii_digit),
            [] => false,
        };
        if !plain {
            return None;
        }
        std::str::from_utf8(count)
            .ok()?
            .parse()
            .ok()
            .map(Self::Prompts)
    }
}

/// Reads the reports a mahi writes, from the pieces its pipe gives: a line longer than 511
/// bytes before its newline is skipped to its end, and one that is no report is ignored.
#[derive(Debug)]
pub struct ReportReader {
    line: [u8; MAX_LINE_BYTES],
    length: usize,
    skipping: bool,
}

impl Default for ReportReader {
    fn default() -> Self {
        Self {
            line: [0; MAX_LINE_BYTES],
            length: 0,
            skipping: false,
        }
    }
}

impl ReportReader {
    /// Reads `bytes`, the next piece of the pipe, and gives each report it ends to `report`.
    pub fn feed(&mut self, bytes: &[u8], mut report: impl FnMut(Report)) {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.skipping
                    && let Some(parsed) = self.line.get(..self.length).and_then(Report::parse)
                {
                    report(parsed);
                }
                self.length = 0;
                self.skipping = false;
                continue;
            }
            if self.skipping {
                continue;
            }
            if let Some(slot) = self.line.get_mut(self.length) {
                *slot = byte;
                self.length += 1;
            } else {
                self.length = 0;
                self.skipping = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(pieces: &[&[u8]]) -> Vec<Report> {
        let mut reader = ReportReader::default();
        let mut reports = Vec::new();
        for piece in pieces {
            reader.feed(piece, |report| reports.push(report));
        }
        reports
    }

    #[test]
    fn reports_written_are_read_back_whatever_the_pieces() {
        let id: ThreadId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let written = [
            Report::Thread(id),
            Report::Working,
            Report::Prompts(3),
            Report::Prompts(0),
            Report::Done,
            Report::Asks,
            Report::Notify("bob sent a prompt: fix the parser".to_owned()),
            Report::Notify(String::new()),
        ];
        let mut out = Vec::new();
        for report in &written {
            report.write(&mut out);
        }
        assert_eq!(read(&[&out]), written);
        let pieces: Vec<&[u8]> = out.chunks(3).collect();
        assert_eq!(read(&pieces), written);
    }

    #[test]
    fn a_line_of_up_to_511_bytes_and_its_newline_is_read_and_a_longer_one_skipped_to_its_end() {
        let mut exact = b"notify ".to_vec();
        exact.resize(511, b'x');
        exact.push(b'\n');
        assert_eq!(
            read(&[&exact, b"done\n"]),
            [Report::Notify("x".repeat(504)), Report::Done]
        );
        let mut long = b"notify ".to_vec();
        long.resize(512, b'x');
        long.extend_from_slice(b"\ndone\n");
        assert_eq!(read(&[&long]), [Report::Done]);
    }

    #[test]
    fn a_malformed_line_is_no_report() {
        for line in [
            &b"thread 0123\n"[..],
            b"thread 0123456789ABCDEF0123456789abcdef\n",
            b"prompts\n",
            b"prompts -1\n",
            b"prompts +1\n",
            b"prompts 007\n",
            b"prompts 99999\n",
            b"done\r\n",
            b"sleeping\n",
            b"notify a\tb\n",
            b"notify \xff\n",
            b"notify\n",
            b"done",
        ] {
            assert_eq!(read(&[line]), [], "{line:?}");
        }
    }

    #[test]
    fn a_notification_is_written_on_one_line_cut_to_fit_and_read_back() {
        let mut out = Vec::new();
        Report::Notify("two\nlines\r\x1b]9;x\x07".to_owned()).write(&mut out);
        assert_eq!(out, b"notify two lines  ]9;x \n");
        for (long, kept) in [("é".repeat(400), 252), ("x".repeat(600), 504)] {
            let mut out = Vec::new();
            Report::Notify(long).write(&mut out);
            assert!(out.len() <= 512, "{}", out.len());
            let reports = read(&[&out]);
            let [Report::Notify(text)] = reports.as_slice() else {
                panic!("{reports:?}");
            };
            assert_eq!(text.chars().count(), kept);
        }
    }
}
