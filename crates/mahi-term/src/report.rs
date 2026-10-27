use std::io::Write as _;

use mahi_core::ThreadId;

const MAX_LINE_BYTES: usize = 511;

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
}

impl Report {
    /// Writes the report into `out` as its line.
    pub fn write(&self, out: &mut Vec<u8>) {
        let _ = match self {
            Self::Thread(id) => writeln!(out, "thread {id}"),
            Self::Working => writeln!(out, "working"),
            Self::Done => writeln!(out, "done"),
            Self::Asks => writeln!(out, "asks"),
        };
    }

    fn parse(line: &[u8]) -> Option<Self> {
        match line {
            b"working" => Some(Self::Working),
            b"done" => Some(Self::Done),
            b"asks" => Some(Self::Asks),
            _ => {
                let id = line.strip_prefix(b"thread ")?;
                std::str::from_utf8(id).ok()?.parse().ok().map(Self::Thread)
            }
        }
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
            Report::Done,
            Report::Asks,
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
    fn a_long_line_that_is_no_report_is_skipped_to_its_end_and_the_next_one_is_read() {
        for length in [511, 512, 2000] {
            let mut lines = vec![b'x'; length];
            lines.extend_from_slice(b"\ndone\n");
            assert_eq!(read(&[&lines]), [Report::Done], "{length}");
            let pieces: Vec<&[u8]> = lines.chunks(100).collect();
            assert_eq!(read(&pieces), [Report::Done], "{length}");
        }
    }

    #[test]
    fn a_malformed_line_is_no_report() {
        for line in [
            &b"thread 0123\n"[..],
            b"thread 0123456789ABCDEF0123456789abcdef\n",
            b"prompts 3\n",
            b"notify bob sent a prompt\n",
            b"done\r\n",
            b"sleeping\n",
            b"done",
        ] {
            assert_eq!(read(&[line]), [], "{line:?}");
        }
    }
}
