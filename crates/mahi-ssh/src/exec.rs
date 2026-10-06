use std::{
    fmt,
    io::{
        self,
        Read,
        Write,
    },
    pin::pin,
    sync::{
        Arc,
        Mutex,
        PoisonError,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    time::Duration,
};

use bytes::Bytes;
use thiserror::Error;
use tokio::{
    runtime::Handle,
    sync::{
        mpsc,
        oneshot,
    },
};

use crate::{
    proto::channel::ChannelId,
    session::{
        Command,
        Started,
    },
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const INTERRUPT_POLL: Duration = Duration::from_millis(100);

/// A command running on the remote host.
///
/// Its halves block on the multi-thread runtime the session runs on, so they are used from a
/// thread that is not running async code.
pub struct Exec {
    output: ExecOutput,
    input: ExecInput,
}

/// The caller asked to stop, through the interrupt flag the connection was given.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("interrupted")]
pub struct Interrupted;

/// The command's standard output, read with [`Read`].
pub struct ExecOutput {
    interrupt: Option<Arc<AtomicBool>>,
    runtime: Handle,
    chunks: mpsc::UnboundedReceiver<Bytes>,
    chunk: Bytes,
    ending: Arc<Mutex<Ending>>,
    commands: mpsc::Sender<Command>,
    id: ChannelId,
}

/// The command's standard input, written with [`Write`].
pub struct ExecInput {
    interrupt: Option<Arc<AtomicBool>>,
    runtime: Handle,
    commands: mpsc::Sender<Command>,
    id: ChannelId,
}

/// How a command ended without success.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteFailure {
    /// The command wrote an error and exited with another status than 0, or with none.
    #[error("the remote said: {0}")]
    Said(String),
    /// The command exited with another status than 0 without writing an error.
    #[error("the remote command exited with status {0}")]
    Status(u32),
    /// The command was ended by a signal.
    #[error("the remote command was ended by signal {0}")]
    Signal(String),
    /// The connection ended before the command did.
    #[error("the connection ended before the remote command did")]
    Cut,
}

#[derive(Debug, Default)]
pub(crate) struct Ending {
    pub(crate) closed: bool,
    pub(crate) status: Option<u32>,
    pub(crate) signal: Option<String>,
    pub(crate) errors: Vec<u8>,
}

impl Exec {
    pub(crate) fn start(
        runtime: Handle,
        started: Started,
        commands: mpsc::Sender<Command>,
        interrupt: Option<Arc<AtomicBool>>,
    ) -> Self {
        Self {
            output: ExecOutput {
                interrupt: interrupt.clone(),
                runtime: runtime.clone(),
                chunks: started.output,
                chunk: Bytes::new(),
                ending: started.ending,
                commands: commands.clone(),
                id: started.id,
            },
            input: ExecInput {
                interrupt,
                runtime,
                commands,
                id: started.id,
            },
        }
    }

    /// Returns the command's output and input.
    #[must_use]
    pub fn split(self) -> (ExecOutput, ExecInput) {
        (self.output, self.input)
    }
}

impl ExecInput {
    /// Tells the command that its input has ended.
    ///
    /// Succeeds when the command has already exited, because its input has ended then too.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is gone or the host takes more than 5 minutes.
    ///
    /// # Panics
    ///
    /// Panics if called from async code.
    pub fn finish(&mut self) -> io::Result<()> {
        let (ack, done) = oneshot::channel();
        self.request(Command::Eof { id: self.id, ack }, done)
    }

    fn request(&self, command: Command, done: oneshot::Receiver<io::Result<()>>) -> io::Result<()> {
        let commands = &self.commands;
        let interrupt = self.interrupt.as_deref();
        self.runtime
            .block_on(until_interrupted(interrupt, async {
                tokio::time::timeout(IDLE_TIMEOUT, async {
                    commands
                        .send(command)
                        .await
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                    done.await
                        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
                })
                .await
            }))
            .ok_or_else(|| io::Error::other(Interrupted))?
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}

impl Read for ExecOutput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.chunk.is_empty() {
            let chunks = &mut self.chunks;
            let interrupt = self.interrupt.as_deref();
            let next = self
                .runtime
                .block_on(until_interrupted(interrupt, async {
                    tokio::time::timeout(IDLE_TIMEOUT, chunks.recv()).await
                }))
                .ok_or_else(|| io::Error::other(Interrupted))?
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            match next {
                Some(chunk) => {
                    self.release(chunk.len());
                    self.chunk = chunk;
                }
                None => return self.end().map(|()| 0),
            }
        }
        let count = self.chunk.len().min(buffer.len());
        let chunk = self.chunk.split_to(count);
        buffer
            .get_mut(..count)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
            .copy_from_slice(&chunk);
        Ok(count)
    }
}

impl ExecOutput {
    fn release(&self, count: usize) {
        let commands = &self.commands;
        let id = self.id;
        let _ = self
            .runtime
            .block_on(commands.send(Command::Consumed { id, count }));
    }

    fn end(&self) -> io::Result<()> {
        let ending = self.ending.lock().unwrap_or_else(PoisonError::into_inner);
        let said = printable(&ending.errors);
        let failure = if let Some(signal) = &ending.signal {
            RemoteFailure::Signal(signal.clone())
        } else if !ending.closed {
            RemoteFailure::Cut
        } else {
            match (ending.status, said.is_empty()) {
                (Some(0), _) | (None, true) => return Ok(()),
                (Some(status), true) => RemoteFailure::Status(status),
                (_, false) => RemoteFailure::Said(said),
            }
        };
        Err(io::Error::other(failure))
    }
}

impl Write for ExecInput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let (ack, done) = oneshot::channel();
        let command = Command::Write {
            id: self.id,
            data: Bytes::copy_from_slice(buffer),
            ack,
        };
        self.request(command, done)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs `work` until it finishes, or returns `None` once `interrupt` is set, checking it every
/// 100 ms.
pub(crate) async fn until_interrupted<F: Future>(
    interrupt: Option<&AtomicBool>,
    work: F,
) -> Option<F::Output> {
    let Some(interrupt) = interrupt else {
        return Some(work.await);
    };
    let mut work = pin!(work);
    loop {
        if interrupt.load(Ordering::SeqCst) {
            return None;
        }
        if let Ok(output) = tokio::time::timeout(INTERRUPT_POLL, &mut work).await {
            return Some(output);
        }
    }
}

pub(crate) fn printable(bytes: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| {
            if c == '\n' || c == '\t' || !hidden(c) {
                c
            } else {
                '?'
            }
        })
        .collect();
    text.trim().replace('\n', "\nremote: ")
}

fn hidden(c: char) -> bool {
    c.is_control() || mahi_core::is_invisible(c)
}

impl Drop for ExecOutput {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::Close { id: self.id });
    }
}

impl fmt::Debug for Exec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Exec").finish_non_exhaustive()
    }
}

impl fmt::Debug for ExecOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ExecOutput").finish_non_exhaustive()
    }
}

impl fmt::Debug for ExecInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ExecInput").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_the_remote_says_is_shown_without_control_or_format_characters() {
        assert_eq!(
            printable(b"  fatal: no repo\x1b[31m\r\n\tsee\x07 \n"),
            "fatal: no repo?[31m?\nremote: \tsee?"
        );
        assert_eq!(printable(b"\xff ok"), "\u{fffd} ok");
        assert_eq!(
            printable("a\u{9b}31m b\u{202e}c\u{2066}d\u{200b}e".as_bytes()),
            "a?31m b?c?d?e"
        );
        assert_eq!(
            printable("a\u{2028}b\u{e0041}c\u{3164}d\u{115f}e".as_bytes()),
            "a?b?c?d?e"
        );
    }
}
