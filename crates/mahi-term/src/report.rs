use std::io::Write as _;

use mahi_core::ThreadId;

const MAX_LINE_BYTES: usize = 64;

/// What a mahi the workspace started tells it about its agent, on a pipe of their own: one
/// line each, which the agent cannot write, unlike its terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl Report {
    /// Writes the report into `out` as its line.
    pub fn write(self, out: &mut Vec<u8>) {
        let _ = match self {
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

/// Reads the reports a mahi writes, from the pieces its pipe gives: a line longer than 64
/// bytes is skipped to its end, and one that is no report is ignored.
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
        ];
        let mut out = Vec::new();
        for report in written {
            report.write(&mut out);
        }
        assert_eq!(read(&[&out]), written);
        let pieces: Vec<&[u8]> = out.chunks(3).collect();
        assert_eq!(read(&pieces), written);
    }

    #[test]
    fn a_line_of_up_to_64_bytes_is_read_and_a_longer_one_skipped_to_its_end() {
        let mut fits = b"prompts 1".to_vec();
        fits.resize(64, b' ');
        fits.push(b'\n');
        assert_eq!(read(&[&fits]), []);
        let mut exact = vec![b'0'; 56];
        exact.splice(0..0, b"prompts ".iter().copied());
        assert_eq!(exact.len(), 64);
        exact.push(b'\n');
        assert_eq!(read(&[&exact, b"done\n"]), [Report::Done]);
        let mut long = b"done".to_vec();
        long.resize(65, b'x');
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
            b"done",
        ] {
            assert_eq!(read(&[line]), [], "{line:?}");
        }
    }
}
