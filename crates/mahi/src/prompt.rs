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
    process,
    sync::{
        Arc,
        Mutex,
    },
    thread,
};

use age::secrecy::SecretString;
use mahi_sandbox::TerminationSignals;
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
/// While a secret is typed, echo is off; a signal that stops mahi then restores the terminal
/// before mahi dies of it.
#[derive(Debug)]
pub(crate) struct TerminalPrompt {
    terminal: File,
    echo_saved: Arc<Mutex<Option<Termios>>>,
}

struct EchoOff<'a> {
    terminal: &'a File,
    echo_saved: &'a Mutex<Option<Termios>>,
}

impl TerminalPrompt {
    pub(crate) fn open() -> io::Result<Self> {
        let terminal = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        let echo_saved = Arc::new(Mutex::new(None));
        let signals = TerminationSignals::listen().map_err(io::Error::other)?;
        let restorer = terminal.try_clone()?;
        let saved = Arc::clone(&echo_saved);
        thread::spawn(move || {
            let Ok(signal) = signals.wait() else {
                return;
            };
            let mut guard = saved.lock();
            if let Some(termios) = guard.as_mut().ok().and_then(|saved| saved.take()) {
                let _ = rustix::termios::tcsetattr(&restorer, OptionalActions::Now, &termios);
                let _ = writeln!(&restorer);
            }
            signal.reraise();
            process::exit(128 + signal.number());
        });
        Ok(Self {
            terminal,
            echo_saved,
        })
    }
}

impl Prompt for TerminalPrompt {
    fn say(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.terminal, "{line}")
    }

    fn secret(&mut self, question: &str) -> io::Result<SecretString> {
        let line = {
            let _echo_off = EchoOff::new(&self.terminal, &self.echo_saved)?;
            write!(&self.terminal, "{question}")?;
            read_line(&self.terminal)?
        };
        writeln!(self.terminal)?;
        let text = std::str::from_utf8(&line).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "the passphrase is not UTF-8")
        })?;
        Ok(SecretString::from(text.to_owned()))
    }

    fn answer(&mut self, question: &str) -> io::Result<String> {
        write!(self.terminal, "{question}")?;
        let line = read_line(&self.terminal)?;
        Ok(String::from_utf8_lossy(&line).trim().to_owned())
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
    fn new(terminal: &'a File, echo_saved: &'a Mutex<Option<Termios>>) -> io::Result<Self> {
        let saved = rustix::termios::tcgetattr(terminal)?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        let mut slot = echo_saved
            .lock()
            .map_err(|_| io::Error::other("the terminal state is poisoned"))?;
        rustix::termios::tcsetattr(terminal, OptionalActions::Flush, &quiet)?;
        *slot = Some(saved);
        drop(slot);
        Ok(Self {
            terminal,
            echo_saved,
        })
    }
}

impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.echo_saved.lock()
            && let Some(saved) = slot.take()
        {
            let _ = rustix::termios::tcsetattr(self.terminal, OptionalActions::Now, &saved);
        }
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
