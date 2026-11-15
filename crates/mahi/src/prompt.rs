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
    os::{
        fd::AsFd,
        unix::fs::OpenOptionsExt,
    },
    process,
    thread,
    time::Duration,
};

use age::secrecy::SecretString;
use mahi_sandbox::{
    Termination,
    TerminationSignals,
};
use mahi_term::Preselected;
use rustix::{
    fs::OFlags,
    termios::{
        LocalModes,
        OptionalActions,
        QueueSelector,
        Termios,
    },
};
use zeroize::Zeroizing;

use crate::ui::{
    self,
    DialogPrompt,
};

const MAX_ANSWER_BYTES: usize = 1024;
const NOT_READY_PAUSE: Duration = Duration::from_millis(10);
const TERMINAL: &str = "/dev/tty";

/// Asks the user questions; the real one uses the controlling terminal.
pub(crate) trait Prompt {
    fn say(&mut self, line: &str) -> io::Result<()>;
    fn secret(&mut self, question: &str) -> io::Result<SecretString>;
    fn answer(&mut self, question: &str) -> io::Result<String>;

    /// Asks a yes or no question: on lines, an empty answer takes `preselected`.
    fn confirm(&mut self, question: &str, preselected: Preselected) -> io::Result<bool> {
        confirm_by_answer(|asked| self.answer(asked), question, preselected)
    }

    /// Asks the user to pick one of `options`, each the answer it stands for and its label,
    /// and returns the answer: on lines, the options are listed and the answer typed.
    fn pick(&mut self, question: &str, options: &[(&str, &str)]) -> io::Result<String> {
        for (answer, label) in options {
            self.say(&format!("  {answer}) {label}"))?;
        }
        self.answer(question)
    }
}

/// Asks through `/dev/tty`, so it works while standard input or output are redirected.
///
/// While it waits for an answer it catches the signals that stop mahi. Echo, if it was
/// turned off for a secret, is turned back on first, then mahi dies of the signal.
#[derive(Debug)]
pub(crate) struct TerminalPrompt {
    on: On,
}

/// Where a prompt asks: on the terminal's lines, or in dialogs while a full-screen view owns
/// the terminal.
#[derive(Debug)]
enum On {
    Lines { terminal: File, input: File },
    Dialogs(DialogPrompt),
}

#[derive(Debug, Clone, Copy)]
enum Typing {
    Hidden,
    Shown { after: Duration },
}

struct EchoOff<'a> {
    terminal: &'a File,
    saved: Termios,
}

struct Answer<'a> {
    input: &'a File,
    signals: &'a TerminationSignals,
    stopped: Option<Termination>,
}

impl TerminalPrompt {
    /// Opens the terminal only when standard input is one too, so mahi asks nothing of a user
    /// who runs it from a script or with input piped in.
    pub(crate) fn open_interactive() -> io::Result<Self> {
        if !rustix::termios::isatty(io::stdin()) {
            return Err(io::Error::other("standard input is not a terminal"));
        }
        Self::open()
    }

    pub(crate) fn open() -> io::Result<Self> {
        if ui::is_showing() {
            return Ok(Self {
                on: On::Dialogs(DialogPrompt::default()),
            });
        }
        let terminal = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(OFlags::NOCTTY.bits().cast_signed())
            .open(TERMINAL)?;
        let input = OpenOptions::new()
            .read(true)
            .custom_flags((OFlags::NOCTTY | OFlags::NONBLOCK).bits().cast_signed())
            .open(TERMINAL)?;
        Ok(Self {
            on: On::Lines { terminal, input },
        })
    }

    fn line_answer(files: (&File, &File), question: &str, guard: Duration) -> io::Result<String> {
        let line = Self::read_answer(files, question, Typing::Shown { after: guard })?;
        Ok(String::from_utf8_lossy(&line).trim().to_owned())
    }

    fn read_answer(
        (terminal, input): (&File, &File),
        question: &str,
        typing: Typing,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        let signals = TerminationSignals::listen().map_err(io::Error::other)?;
        let mut answer = Answer {
            input,
            signals: &signals,
            stopped: None,
        };
        rustix::termios::tcflush(terminal, QueueSelector::IFlush)?;
        let line = {
            let quiet = match typing {
                Typing::Shown { after } if after.is_zero() => None,
                Typing::Hidden | Typing::Shown { .. } => Some(EchoOff::new(terminal)?),
            };
            write!(&*terminal, "{question}")?;
            let _quiet = match typing {
                Typing::Shown { after } if !after.is_zero() => {
                    thread::sleep(after);
                    rustix::termios::tcflush(terminal, QueueSelector::IFlush)?;
                    drop(quiet);
                    None
                }
                Typing::Hidden | Typing::Shown { .. } => quiet,
            };
            read_line(&mut answer)
        };
        if let Some(signal) = answer.stopped {
            let _ = writeln!(&*terminal);
            drop(signals);
            signal.reraise();
            process::exit(128 + signal.number());
        }
        line
    }
}

impl<P: Prompt + ?Sized> Prompt for &mut P {
    fn say(&mut self, line: &str) -> io::Result<()> {
        (**self).say(line)
    }

    fn secret(&mut self, question: &str) -> io::Result<SecretString> {
        (**self).secret(question)
    }

    fn answer(&mut self, question: &str) -> io::Result<String> {
        (**self).answer(question)
    }

    fn confirm(&mut self, question: &str, preselected: Preselected) -> io::Result<bool> {
        (**self).confirm(question, preselected)
    }

    fn pick(&mut self, question: &str, options: &[(&str, &str)]) -> io::Result<String> {
        (**self).pick(question, options)
    }
}

impl TerminalPrompt {
    /// Asks for a secret the user may see while typing it, such as a pairing code: shown in a
    /// dialog, which leaves nothing in the scrollback, and read without echo on lines.
    pub(crate) fn shown_secret(&mut self, question: &str) -> io::Result<SecretString> {
        match &mut self.on {
            On::Lines { .. } => self.secret(question),
            On::Dialogs(dialogs) => dialogs.shown_secret(question),
        }
    }
}

impl Prompt for TerminalPrompt {
    fn say(&mut self, line: &str) -> io::Result<()> {
        match &mut self.on {
            On::Lines { terminal, .. } => writeln!(terminal, "{line}"),
            On::Dialogs(dialogs) => {
                dialogs.say(line);
                Ok(())
            }
        }
    }

    fn secret(&mut self, question: &str) -> io::Result<SecretString> {
        match &mut self.on {
            On::Lines { terminal, input } => {
                let line = Self::read_answer((terminal, input), question, Typing::Hidden)?;
                writeln!(terminal)?;
                let text = std::str::from_utf8(&line).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "the answer is not UTF-8")
                })?;
                Ok(SecretString::from(text.to_owned()))
            }
            On::Dialogs(dialogs) => dialogs.secret(question),
        }
    }

    fn answer(&mut self, question: &str) -> io::Result<String> {
        match &mut self.on {
            On::Lines { terminal, input } => {
                Self::line_answer((terminal, input), question, Duration::ZERO)
            }
            On::Dialogs(dialogs) => dialogs.answer(question),
        }
    }

    fn confirm(&mut self, question: &str, preselected: Preselected) -> io::Result<bool> {
        match &mut self.on {
            On::Lines { terminal, input } => confirm_by_answer(
                |asked| Self::line_answer((terminal, input), asked, ui::key_guard(preselected)),
                question,
                preselected,
            ),
            On::Dialogs(dialogs) => dialogs.confirm(question, preselected),
        }
    }

    fn pick(&mut self, question: &str, options: &[(&str, &str)]) -> io::Result<String> {
        if let On::Dialogs(dialogs) = &mut self.on {
            return dialogs.pick(options);
        }
        for (answer, label) in options {
            self.say(&format!("  {answer}) {label}"))?;
        }
        self.answer(question)
    }
}

impl Read for Answer<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(signal) = self
                .signals
                .wait_for_input(self.input.as_fd())
                .map_err(io::Error::other)?
            {
                self.stopped = Some(signal);
                return Err(io::ErrorKind::Interrupted.into());
            }
            match (&mut &*self.input).read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(NOT_READY_PAUSE);
                }
                result => return result,
            }
        }
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

fn confirm_by_answer(
    answer: impl FnOnce(&str) -> io::Result<String>,
    question: &str,
    preselected: Preselected,
) -> io::Result<bool> {
    let hint = match preselected {
        Preselected::Yes => "[Y/n]",
        Preselected::No => "[y/N]",
    };
    let answered = answer(&format!("{question} {hint} "))?;
    let answered = answered.trim();
    Ok(if answered.is_empty() {
        preselected == Preselected::Yes
    } else {
        answered.eq_ignore_ascii_case("y") || answered.eq_ignore_ascii_case("yes")
    })
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
pub(crate) mod tests {
    use std::{
        collections::VecDeque,
        os::fd::OwnedFd,
    };

    use super::*;

    #[derive(Default)]
    pub(crate) struct Script {
        pub(crate) secrets: VecDeque<&'static str>,
        pub(crate) answers: VecDeque<&'static str>,
        pub(crate) said: Vec<String>,
    }

    impl Prompt for Script {
        fn say(&mut self, line: &str) -> io::Result<()> {
            self.said.push(line.to_owned());
            Ok(())
        }

        fn secret(&mut self, _: &str) -> io::Result<SecretString> {
            let secret = self
                .secrets
                .pop_front()
                .expect("an unexpected passphrase question");
            Ok(SecretString::from(secret.to_owned()))
        }

        fn answer(&mut self, _: &str) -> io::Result<String> {
            Ok(self
                .answers
                .pop_front()
                .expect("an unexpected question")
                .to_owned())
        }
    }

    fn lines() -> (OwnedFd, File, File) {
        let (master, slave) = crate::terminal::tests::pty_pair(24, 80);
        let terminal = File::from(slave.try_clone().unwrap());
        rustix::fs::fcntl_setfl(&slave, OFlags::NONBLOCK).unwrap();
        (master, terminal, File::from(slave))
    }

    fn type_once_shown(
        master: OwnedFd,
        question: &'static str,
        typed: Vec<(Duration, &'static [u8])>,
    ) -> thread::JoinHandle<(String, OwnedFd)> {
        thread::spawn(move || {
            let mut shown = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !String::from_utf8_lossy(&shown).contains(question) {
                let read = rustix::io::read(&master, &mut chunk).unwrap();
                shown.extend_from_slice(&chunk[..read]);
            }
            for (wait, bytes) in typed {
                thread::sleep(wait);
                rustix::io::write(&master, bytes).unwrap();
            }
            rustix::fs::fcntl_setfl(&master, OFlags::NONBLOCK).unwrap();
            while let Ok(read) = rustix::io::read(&master, &mut chunk) {
                if read == 0 {
                    break;
                }
                shown.extend_from_slice(&chunk[..read]);
            }
            (String::from_utf8_lossy(&shown).into_owned(), master)
        })
    }

    #[test]
    fn keys_typed_before_a_question_on_lines_answer_nothing() {
        let (master, terminal, input) = lines();
        rustix::io::write(&master, b"y\n").unwrap();
        thread::sleep(Duration::from_millis(100));
        let typist = type_once_shown(master, "Purge? ", vec![(Duration::ZERO, b"n\n")]);
        let answer =
            TerminalPrompt::line_answer((&terminal, &input), "Purge? ", Duration::ZERO).unwrap();
        assert_eq!(answer, "n");
        typist.join().unwrap();
    }

    #[test]
    fn a_guarded_question_on_lines_drops_and_hides_the_keys_typed_while_it_guards() {
        let (master, terminal, input) = lines();
        let typist = type_once_shown(
            master,
            "Add? ",
            vec![
                (Duration::ZERO, b"x\n"),
                (ui::KEY_GUARD + Duration::from_millis(300), b"\n"),
            ],
        );
        let answer =
            TerminalPrompt::line_answer((&terminal, &input), "Add? ", ui::KEY_GUARD).unwrap();
        assert_eq!(answer, "");
        let (shown, _master) = typist.join().unwrap();
        assert!(shown.starts_with("Add? "), "{shown:?}");
        assert!(!shown.contains('x'), "{shown:?}");
    }

    #[test]
    fn only_a_question_that_selects_yes_first_is_guarded() {
        assert_eq!(ui::key_guard(Preselected::Yes), ui::KEY_GUARD);
        assert_eq!(ui::key_guard(Preselected::No), Duration::ZERO);
    }

    #[test]
    fn a_confirmation_on_lines_shows_its_preselected_answer_and_takes_it_when_empty() {
        let confirm = |typed: &'static str, preselected| {
            let mut asked = String::new();
            let confirmed = confirm_by_answer(
                |question| {
                    question.clone_into(&mut asked);
                    Ok(typed.to_owned())
                },
                "Add bob?",
                preselected,
            )
            .unwrap();
            (confirmed, asked)
        };
        assert_eq!(
            confirm("", Preselected::Yes),
            (true, "Add bob? [Y/n] ".to_owned())
        );
        assert_eq!(
            confirm("", Preselected::No),
            (false, "Add bob? [y/N] ".to_owned())
        );
        for typed in ["y", "Y", "yes", "Yes", " YES "] {
            assert!(confirm(typed, Preselected::No).0, "{typed:?}");
        }
        for typed in ["n", "No", "maybe"] {
            assert!(!confirm(typed, Preselected::Yes).0, "{typed:?}");
        }
    }

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
