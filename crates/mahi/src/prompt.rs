use std::{
    fs::{
        File,
        OpenOptions,
    },
    io::{
        self,
        Read,
        Write,
    },
    os::fd::AsFd,
    process,
};

use age::secrecy::SecretString;
use mahi_sandbox::{
    Termination,
    TerminationSignals,
};
use rustix::termios::{
    LocalModes,
    OptionalActions,
    Termios,
};
use zeroize::Zeroizing;

const MAX_ANSWER_BYTES: usize = 1024;

/// Asks the user questions; the real one uses the controlling terminal.
pub(crate) trait Prompt {
    fn say(&mut self, line: &str) -> io::Result<()>;
    fn secret(&mut self, question: &str) -> io::Result<SecretString>;
    fn answer(&mut self, question: &str) -> io::Result<String>;
}

/// Asks through `/dev/tty`, so it works while standard input or output are redirected.
///
/// While it waits for an answer it catches the signals that stop mahi. Echo, if it was
/// turned off for a secret, is turned back on first, then mahi dies of the signal.
#[derive(Debug)]
pub(crate) struct TerminalPrompt {
    terminal: File,
}

struct EchoOff<'a> {
    terminal: &'a File,
    saved: Termios,
}

struct Answer<'a> {
    terminal: &'a File,
    signals: &'a TerminationSignals,
    stopped: Option<Termination>,
}

impl TerminalPrompt {
    pub(crate) fn open() -> io::Result<Self> {
        let terminal = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        Ok(Self { terminal })
    }

    fn read_answer(&self, question: &str, echo: bool) -> io::Result<Zeroizing<Vec<u8>>> {
        let signals = TerminationSignals::listen().map_err(io::Error::other)?;
        let mut answer = Answer {
            terminal: &self.terminal,
            signals: &signals,
            stopped: None,
        };
        let line = {
            let _echo_off = if echo {
                None
            } else {
                Some(EchoOff::new(&self.terminal)?)
            };
            write!(&self.terminal, "{question}")?;
            read_line(&mut answer)
        };
        if let Some(signal) = answer.stopped {
            let _ = writeln!(&self.terminal);
            drop(signals);
            signal.reraise();
            process::exit(128 + signal.number());
        }
        line
    }
}

impl Prompt for TerminalPrompt {
    fn say(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.terminal, "{line}")
    }

    fn secret(&mut self, question: &str) -> io::Result<SecretString> {
        let line = self.read_answer(question, false)?;
        writeln!(self.terminal)?;
        let text = std::str::from_utf8(&line).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "the passphrase is not UTF-8")
        })?;
        Ok(SecretString::from(text.to_owned()))
    }

    fn answer(&mut self, question: &str) -> io::Result<String> {
        let line = self.read_answer(question, true)?;
        Ok(String::from_utf8_lossy(&line).trim().to_owned())
    }
}

impl Read for Answer<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(signal) = self
            .signals
            .wait_for_input(self.terminal.as_fd())
            .map_err(io::Error::other)?
        {
            self.stopped = Some(signal);
            return Err(io::ErrorKind::Interrupted.into());
        }
        (&mut &*self.terminal).read(buffer)
    }
}

fn read_line(mut terminal: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_ANSWER_BYTES));
    let mut byte = Zeroizing::new([0_u8; 1]);
    let mut too_long = false;
    loop {
        if terminal.read(&mut *byte)? == 0 {
            if line.is_empty() && !too_long {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() == MAX_ANSWER_BYTES {
            too_long = true;
        } else if !too_long {
            line.push(byte[0]);
        }
    }
    if too_long {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the answer is too long",
        ));
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(line)
}

impl<'a> EchoOff<'a> {
    fn new(terminal: &'a File) -> io::Result<Self> {
        let saved = rustix::termios::tcgetattr(terminal)?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        rustix::termios::tcsetattr(terminal, OptionalActions::Flush, &quiet)?;
        Ok(Self { terminal, saved })
    }
}

impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(self.terminal, OptionalActions::Now, &self.saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_read_without_its_ending() {
        assert_eq!(&*read_line(&b"secret\r\nnext"[..]).unwrap(), b"secret");
        assert_eq!(&*read_line(&b"last"[..]).unwrap(), b"last");
        assert_eq!(&*read_line(&b"\n"[..]).unwrap(), b"");
    }

    #[test]
    fn end_of_input_on_an_empty_line_cancels() {
        assert_eq!(
            read_line(&b""[..]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn an_answer_that_is_too_long_is_refused_and_read_to_its_end() {
        let mut input = vec![b'x'; MAX_ANSWER_BYTES + 10];
        input.extend_from_slice(b"\nnext line\n");
        let mut reader = &input[..];
        assert_eq!(
            read_line(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(reader, b"next line\n");
    }
}
