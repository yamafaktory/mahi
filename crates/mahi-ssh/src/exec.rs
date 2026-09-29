use std::{
    fmt,
    io::{
        self,
        Read,
        Write,
    },
    sync::{
        Arc,
        Mutex,
        PoisonError,
    },
    time::Duration,
};

use bytes::Bytes;
use russh::{
    ChannelMsg,
    ChannelReadHalf,
    ChannelWriteHalf,
    client::Msg,
};
use thiserror::Error;
use tokio::{
    runtime::Handle,
    sync::mpsc,
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_ERROR_OUTPUT: usize = 4 << 10;
const QUEUED_CHUNKS: usize = 16;
const STDERR: u32 = 1;

/// A command running on the remote host.
///
/// Its halves block on the multi-thread runtime the session runs on, so they are used from a
/// thread that is not running async code.
pub struct Exec {
    output: ExecOutput,
    input: ExecInput,
}

/// The command's standard output, read with [`Read`].
pub struct ExecOutput {
    runtime: Handle,
    chunks: mpsc::Receiver<Bytes>,
    chunk: Bytes,
    ending: Arc<Mutex<Ending>>,
}

/// The command's standard input, written with [`Write`].
pub struct ExecInput {
    runtime: Handle,
    channel: Arc<ChannelWriteHalf<Msg>>,
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
struct Ending {
    closed: bool,
    status: Option<u32>,
    signal: Option<String>,
    errors: Vec<u8>,
}

impl Exec {
    pub(crate) fn start(runtime: Handle, channel: russh::Channel<Msg>, early: Vec<u8>) -> Self {
        let (read, write) = channel.split();
        let write = Arc::new(write);
        let (sender, chunks) = mpsc::channel(QUEUED_CHUNKS);
        let ending = Arc::new(Mutex::new(Ending::default()));
        runtime.spawn(receive(
            read,
            write.clone(),
            Bytes::from(early),
            sender,
            ending.clone(),
        ));
        Self {
            output: ExecOutput {
                runtime: runtime.clone(),
                chunks,
                chunk: Bytes::new(),
                ending,
            },
            input: ExecInput {
                runtime,
                channel: write,
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
    /// # Errors
    ///
    /// Returns an error if the connection is gone or the host takes more than 5 minutes.
    ///
    /// # Panics
    ///
    /// Panics if called from async code.
    pub fn finish(&mut self) -> io::Result<()> {
        let channel = &self.channel;
        self.runtime
            .block_on(async { tokio::time::timeout(IDLE_TIMEOUT, channel.eof()).await })
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::other)
    }
}

impl Read for ExecOutput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.chunk.is_empty() {
            let chunks = &mut self.chunks;
            let next = self
                .runtime
                .block_on(async { tokio::time::timeout(IDLE_TIMEOUT, chunks.recv()).await })
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            match next {
                Some(chunk) => self.chunk = chunk,
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
        let channel = &self.channel;
        let data = Bytes::copy_from_slice(buffer);
        self.runtime
            .block_on(async { tokio::time::timeout(IDLE_TIMEOUT, channel.data_bytes(data)).await })
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::other)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn receive(
    mut channel: ChannelReadHalf,
    write: Arc<ChannelWriteHalf<Msg>>,
    early: Bytes,
    chunks: mpsc::Sender<Bytes>,
    ending: Arc<Mutex<Ending>>,
) {
    let record = |update: &dyn Fn(&mut Ending)| {
        update(&mut ending.lock().unwrap_or_else(PoisonError::into_inner));
    };
    if !early.is_empty() && chunks.send(early).await.is_err() {
        let _ = write.close().await;
        return;
    }
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                if chunks.send(data).await.is_err() {
                    let _ = write.close().await;
                    return;
                }
            }
            ChannelMsg::ExtendedData { data, ext: STDERR } => record(&|ending| {
                let room = MAX_ERROR_OUTPUT.saturating_sub(ending.errors.len());
                ending
                    .errors
                    .extend_from_slice(data.get(..room.min(data.len())).unwrap_or_default());
            }),
            ChannelMsg::ExitStatus { exit_status } => {
                record(&|ending| ending.status = Some(exit_status));
            }
            ChannelMsg::ExitSignal {
                signal_name,
                error_message,
                ..
            } => {
                let signal = printable(format!("{signal_name:?} {error_message}").as_bytes());
                record(&|ending| ending.signal = Some(signal.clone()));
            }
            ChannelMsg::Eof => record(&|ending| ending.closed = true),
            ChannelMsg::Close => {
                record(&|ending| ending.closed = true);
                return;
            }
            _ => {}
        }
    }
}

fn printable(bytes: &[u8]) -> String {
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
    c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
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
    }
}
