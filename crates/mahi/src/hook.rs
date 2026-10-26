use std::{
    io::{
        self,
        Read,
        Write,
    },
    iter,
    net::Shutdown,
    os::unix::net::{
        UnixListener,
        UnixStream,
    },
    path::Path,
    sync::{
        atomic::{
            AtomicBool,
            Ordering,
        },
        mpsc::{
            SyncSender,
            TrySendError,
        },
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mahi_agent::hook::{
    self,
    MAX_MESSAGE_BYTES,
};
pub(crate) use mahi_agent::hook::{
    HookKind,
    HookMessage,
    MAX_PAYLOAD_BYTES,
};
use rustix::event::{
    PollFd,
    PollFlags,
    Timespec,
};

use crate::inject::Activity;

const DEADLINE: Duration = Duration::from_secs(2);
const CONTEXT_WAIT: Duration = Duration::from_secs(1);
const MAX_CONTEXT_BYTES: usize = 1024 * 1024;
const DRAIN_LIMIT: Duration = Duration::from_secs(5);
const ERROR_PAUSE: Duration = Duration::from_millis(50);
const POLL: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 50_000_000,
};

/// What the hook server hands on: a message, or its end once the agent is gone.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    Message(HookMessage),
    End {
        /// How many messages were malformed, too large, too slow, or found the queue full.
        dropped: u64,
    },
}

/// Sends `kind` and up to [`MAX_PAYLOAD_BYTES`] of `input` to the socket at `socket`, as the
/// event's name, a newline, the payload's length as four big-endian bytes, and the payload.
///
/// A payload larger than that is replaced by an empty one, so the event itself still arrives.
pub(crate) fn send(socket: &Path, kind: HookKind, input: impl Read) -> io::Result<()> {
    sent(socket, kind, input)?.shutdown(Shutdown::Write)
}

fn sent(socket: &Path, kind: HookKind, input: impl Read) -> io::Result<UnixStream> {
    let mut payload = Vec::new();
    input
        .take(u64::try_from(MAX_PAYLOAD_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut payload)?;
    let message = hook::encode(kind, &payload)
        .or_else(|| hook::encode(kind, &[]))
        .ok_or_else(|| io::Error::other("cannot encode the hook message"))?;
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(DEADLINE))?;
    stream.write_all(&message)?;
    Ok(stream)
}

/// What mahi adds as context to the user's prompt, when the agent's prompt hook asks.
pub(crate) trait Context: Send + Sync {
    /// Returns the text to add, without giving it away yet.
    fn peek(&self) -> Option<String>;

    /// Gives away `shown`, which the hook read.
    fn taken(&self, shown: &str);
}

/// Sends `kind` and `input` to the socket at `socket` as [`send`] does, then waits at most
/// 1 s, from when it starts, for the context mahi adds to the user's prompt: its length as four
/// big-endian bytes and its text. It hands the text to `print`, and says with one byte that it
/// arrived only once `print` succeeded, so mahi gives the text away only then. Returns whether
/// a text was printed.
pub(crate) fn ask(
    socket: &Path,
    (kind, input): (HookKind, impl Read),
    print: impl FnOnce(&str) -> io::Result<()>,
) -> bool {
    asked(socket, (kind, input), print).is_some()
}

fn asked(
    socket: &Path,
    (kind, input): (HookKind, impl Read),
    print: impl FnOnce(&str) -> io::Result<()>,
) -> Option<()> {
    let deadline = Instant::now() + CONTEXT_WAIT;
    let mut stream = sent(socket, kind, input).ok()?;
    let mut length = [0_u8; 4];
    read_by(&mut stream, &mut length, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(length)).ok()?;
    if length == 0 || length > MAX_CONTEXT_BYTES {
        return None;
    }
    let mut text = vec![0_u8; length];
    read_by(&mut stream, &mut text, deadline)?;
    let text = String::from_utf8(text).ok()?;
    print(&text).ok()?;
    stream.write_all(&[1]).ok()
}

/// Returns `context` as Claude Code's `UserPromptSubmit` hook prints it, to add it to the
/// user's prompt.
pub(crate) fn prompt_context(context: &str) -> String {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }
    })
    .to_string()
}

fn read_by(stream: &mut UnixStream, buffer: &mut [u8], deadline: Instant) -> Option<()> {
    let left = deadline.checked_duration_since(Instant::now())?;
    stream.set_read_timeout(Some(left)).ok()?;
    stream.read_exact(buffer).ok()
}

/// Reads hook connections on `listener` one at a time and queues each valid message on
/// `messages`, until `closing` is set and every connection already made has been read, or a
/// few seconds have passed since. Then queues [`Delivery::End`]. A prompt's hook is answered
/// with what `context` adds to the prompt.
pub(crate) fn serve(
    listener: &UnixListener,
    closing: &AtomicBool,
    messages: &SyncSender<Delivery>,
    (activity, context): (&Activity, Option<&dyn Context>),
) {
    let mut drain_until = None;
    let connections = iter::from_fn(|| {
        loop {
            if closing.load(Ordering::SeqCst) {
                let until = *drain_until.get_or_insert_with(|| Instant::now() + DRAIN_LIMIT);
                if Instant::now() > until {
                    return None;
                }
            }
            match listener.accept() {
                Ok((stream, _)) => return Some(stream.set_nonblocking(false).map(|()| stream)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if closing.load(Ordering::SeqCst) {
                        return None;
                    }
                    wait_for_connection(listener);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    thread::sleep(ERROR_PAUSE);
                    return Some(Err(error));
                }
            }
        }
    });
    let dropped = match listener.set_nonblocking(true) {
        Ok(()) => serve_connections(connections, messages, (activity, context)),
        Err(_) => 0,
    };
    let _ = messages.send(Delivery::End { dropped });
}

fn readable_by(stream: &UnixStream, deadline: Instant) -> bool {
    loop {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        let timeout = Timespec {
            tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(left.subsec_nanos()),
        };
        let mut fds = [PollFd::new(stream, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(ready) => return ready > 0,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return false,
        }
    }
}

fn wait_for_connection(listener: &UnixListener) {
    let mut fds = [PollFd::new(listener, PollFlags::IN)];
    let _ = rustix::event::poll(&mut fds, Some(&POLL));
}

fn serve_connections(
    connections: impl Iterator<Item = io::Result<UnixStream>>,
    messages: &SyncSender<Delivery>,
    (activity, context): (&Activity, Option<&dyn Context>),
) -> u64 {
    let mut dropped = 0;
    for stream in connections {
        let Ok(mut stream) = stream else {
            dropped += 1;
            continue;
        };
        let Some(message) = receive(&mut stream) else {
            dropped += 1;
            continue;
        };
        activity.saw(message.kind, &message.payload);
        if message.kind == HookKind::Prompt
            && let Some(context) = context
        {
            answer(&mut stream, context);
        }
        if message.kind == HookKind::Asks {
            continue;
        }
        match messages.try_send(Delivery::Message(message)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => dropped += 1,
            Err(TrySendError::Disconnected(_)) => break,
        }
    }
    dropped
}

/// Answers a prompt's hook on `stream` with what `context` adds, and gives it away once the
/// hook says it read it, within 1 s; a hook that asks nothing has closed the stream already.
fn answer(stream: &mut UnixStream, context: &dyn Context) {
    let text = context.peek().unwrap_or_default();
    let Ok(length) = u32::try_from(text.len()) else {
        return;
    };
    let mut reply = Vec::with_capacity(4 + text.len());
    reply.extend_from_slice(&length.to_be_bytes());
    reply.extend_from_slice(text.as_bytes());
    if stream.set_write_timeout(Some(CONTEXT_WAIT)).is_err() || stream.write_all(&reply).is_err() {
        return;
    }
    if text.is_empty() || !readable_by(stream, Instant::now() + CONTEXT_WAIT) {
        return;
    }
    let mut read = [0_u8; 1];
    if matches!(stream.read(&mut read), Ok(1)) && read == [1] {
        context.taken(&text);
    }
}

fn receive(stream: &mut UnixStream) -> Option<HookMessage> {
    let deadline = Instant::now() + DEADLINE;
    let mut received = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if !readable_by(stream, deadline) {
            return None;
        }
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        if read == 0 {
            break;
        }
        received.extend_from_slice(buffer.get(..read)?);
        if received.len() > MAX_MESSAGE_BYTES {
            return None;
        }
        if let Some(message) = hook::decode(&received) {
            return Some(message);
        }
    }
    hook::decode(&received)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        Mutex,
        mpsc,
    };

    use super::*;

    struct Server {
        _dir: tempfile::TempDir,
        socket: std::path::PathBuf,
        closing: Arc<AtomicBool>,
        deliveries: mpsc::Receiver<Delivery>,
    }

    fn server() -> Server {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("mahi.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let closing = Arc::new(AtomicBool::new(false));
        let (sender, deliveries) = mpsc::sync_channel(4);
        let flag = Arc::clone(&closing);
        thread::spawn(move || serve(&listener, &flag, &sender, (&Activity::default(), None)));
        Server {
            _dir: dir,
            socket,
            closing,
            deliveries,
        }
    }

    fn raw(socket: &Path, bytes: &[u8]) {
        let mut stream = UnixStream::connect(socket).unwrap();
        let _ = stream.write_all(bytes);
        let _ = stream.shutdown(Shutdown::Write);
    }

    fn framed(name: &[u8], length: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = name.to_vec();
        bytes.push(b'\n');
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn next(server: &Server) -> Delivery {
        server
            .deliveries
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
    }

    fn message(kind: HookKind, payload: &[u8]) -> Delivery {
        Delivery::Message(HookMessage {
            kind,
            payload: payload.to_vec(),
        })
    }

    #[test]
    fn a_sent_event_arrives_with_its_payload() {
        let server = server();
        send(&server.socket, HookKind::Tool, &b"{\"tool\":\"edit\"}"[..]).unwrap();
        send(&server.socket, HookKind::TurnEnd, io::empty()).unwrap();
        assert_eq!(
            next(&server),
            message(HookKind::Tool, b"{\"tool\":\"edit\"}")
        );
        assert_eq!(next(&server), message(HookKind::TurnEnd, b""));
    }

    #[test]
    fn a_question_is_noted_but_never_reaches_the_transcript() {
        let server = server();
        send(
            &server.socket,
            HookKind::Asks,
            &br#"{"notification_type":"permission_prompt"}"#[..],
        )
        .unwrap();
        send(&server.socket, HookKind::TurnEnd, io::empty()).unwrap();
        assert_eq!(next(&server), message(HookKind::TurnEnd, b""));
    }

    #[test]
    fn unknown_names_and_malformed_or_cut_off_messages_are_dropped() {
        let server = server();
        raw(&server.socket, &framed(b"shutdown", 7, b"payload"));
        raw(&server.socket, b"no newline at all");
        raw(&server.socket, b"");
        raw(&server.socket, &[b'x'; 64]);
        raw(&server.socket, b"tool\n");
        raw(&server.socket, &framed(b"tool", 10, b"cut"));
        raw(&server.socket, &framed(b"tool", 2, b"too long"));
        raw(&server.socket, &framed(b"prompt", 5, b"hello"));
        assert_eq!(next(&server), message(HookKind::Prompt, b"hello"));
        server.closing.store(true, Ordering::SeqCst);
        assert_eq!(next(&server), Delivery::End { dropped: 7 });
    }

    #[test]
    fn a_payload_over_the_limit_is_sent_empty_and_cut_off_raw() {
        let server = server();
        let large = vec![b'a'; MAX_MESSAGE_BYTES + 1];
        raw(&server.socket, &framed(b"tool", 0, &large));
        send(&server.socket, HookKind::Prompt, large.as_slice()).unwrap();
        assert_eq!(next(&server), message(HookKind::Prompt, b""));
    }

    #[test]
    fn a_silent_client_is_cut_off_at_the_deadline() {
        let server = server();
        let _silent = UnixStream::connect(&server.socket).unwrap();
        send(&server.socket, HookKind::Tool, io::empty()).unwrap();
        assert_eq!(next(&server), message(HookKind::Tool, b""));
    }

    #[derive(Debug, Default)]
    struct Kept {
        text: Mutex<Option<String>>,
        taken: Mutex<Vec<String>>,
    }

    impl Context for Kept {
        fn peek(&self) -> Option<String> {
            self.text.lock().unwrap().clone()
        }

        fn taken(&self, shown: &str) {
            self.taken.lock().unwrap().push(shown.to_owned());
        }
    }

    fn context_server(kept: &Arc<Kept>) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("mahi.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let closing = Arc::new(AtomicBool::new(false));
        let (sender, deliveries) = mpsc::sync_channel(4);
        let (flag, kept) = (Arc::clone(&closing), Arc::clone(kept));
        thread::spawn(move || {
            serve(
                &listener,
                &flag,
                &sender,
                (&Activity::default(), Some(&*kept as &dyn Context)),
            );
        });
        Server {
            _dir: dir,
            socket,
            closing,
            deliveries,
        }
    }

    #[test]
    fn a_prompt_hook_that_asks_gets_the_context_and_only_then_is_it_taken() {
        let kept = Arc::new(Kept::default());
        let server = context_server(&kept);
        assert!(!ask(
            &server.socket,
            (HookKind::Prompt, &b"fix"[..]),
            |_| Ok(())
        ));
        assert_eq!(next(&server), message(HookKind::Prompt, b"fix"));
        *kept.text.lock().unwrap() = Some("merged bob.claude: ` a.rs `".to_owned());
        send(&server.socket, HookKind::Prompt, &b"plain"[..]).unwrap();
        assert_eq!(next(&server), message(HookKind::Prompt, b"plain"));
        send(&server.socket, HookKind::TurnEnd, io::empty()).unwrap();
        assert_eq!(next(&server), message(HookKind::TurnEnd, b""));
        assert!(kept.taken.lock().unwrap().is_empty());
        let mut printed = String::new();
        let asked = ask(&server.socket, (HookKind::Prompt, &b"go"[..]), |text| {
            printed.push_str(text);
            Ok(())
        });
        assert!(asked);
        assert_eq!(printed, "merged bob.claude: ` a.rs `");
        assert_eq!(next(&server), message(HookKind::Prompt, b"go"));
        send(&server.socket, HookKind::TurnEnd, io::empty()).unwrap();
        assert_eq!(next(&server), message(HookKind::TurnEnd, b""));
        assert_eq!(*kept.taken.lock().unwrap(), ["merged bob.claude: ` a.rs `"]);
        server.closing.store(true, Ordering::SeqCst);
    }

    #[test]
    fn a_context_the_hook_could_not_print_or_did_not_confirm_is_not_taken() {
        let kept = Arc::new(Kept::default());
        *kept.text.lock().unwrap() = Some("merged bob.claude: ` a.rs `".to_owned());
        let server = context_server(&kept);
        let refused = ask(&server.socket, (HookKind::Prompt, &b"a"[..]), |_| {
            Err(io::ErrorKind::BrokenPipe.into())
        });
        assert!(!refused);
        assert_eq!(next(&server), message(HookKind::Prompt, b"a"));
        for reply in [&b""[..], b"\x02"] {
            let mut stream = UnixStream::connect(&server.socket).unwrap();
            stream
                .write_all(&mahi_agent::hook::encode(HookKind::Prompt, b"b").unwrap())
                .unwrap();
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut text = vec![0_u8; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut text).unwrap();
            stream.write_all(reply).unwrap();
            drop(stream);
            assert_eq!(next(&server), message(HookKind::Prompt, b"b"));
        }
        send(&server.socket, HookKind::TurnEnd, io::empty()).unwrap();
        assert_eq!(next(&server), message(HookKind::TurnEnd, b""));
        assert!(kept.taken.lock().unwrap().is_empty());
        server.closing.store(true, Ordering::SeqCst);
    }

    #[test]
    fn the_context_prints_as_claude_codes_prompt_hook_reads_it() {
        let printed: serde_json::Value =
            serde_json::from_str(&prompt_context("a \"quoted\" `note`\n")).unwrap();
        assert_eq!(
            printed["hookSpecificOutput"]["hookEventName"],
            "UserPromptSubmit"
        );
        assert_eq!(
            printed["hookSpecificOutput"]["additionalContext"],
            "a \"quoted\" `note`\n"
        );
    }

    #[test]
    fn closing_reads_every_waiting_connection_before_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("mahi.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        send(&socket, HookKind::TurnEnd, io::empty()).unwrap();
        send(&socket, HookKind::Prompt, &b"last"[..]).unwrap();
        let (sender, deliveries) = mpsc::sync_channel(4);
        serve(
            &listener,
            &AtomicBool::new(true),
            &sender,
            (&Activity::default(), None),
        );
        assert_eq!(
            deliveries.try_recv().unwrap(),
            message(HookKind::TurnEnd, b"")
        );
        assert_eq!(
            deliveries.try_recv().unwrap(),
            message(HookKind::Prompt, b"last")
        );
        assert_eq!(deliveries.try_recv().unwrap(), Delivery::End { dropped: 0 });
    }

    #[test]
    fn a_failed_accept_is_counted_and_serving_goes_on() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&framed(b"prompt", 2, b"ok")).unwrap();
        drop(client);
        let connections = vec![Err(io::Error::from(io::ErrorKind::OutOfMemory)), Ok(server)];
        let (sender, deliveries) = mpsc::sync_channel(4);
        assert_eq!(
            serve_connections(
                connections.into_iter(),
                &sender,
                (&Activity::default(), None)
            ),
            1
        );
        assert_eq!(
            deliveries.try_recv().unwrap(),
            message(HookKind::Prompt, b"ok")
        );
    }

    #[test]
    fn a_full_queue_drops_messages_instead_of_blocking() {
        let connections: Vec<io::Result<UnixStream>> = (0..3)
            .map(|_| {
                let (mut client, server) = UnixStream::pair().unwrap();
                client.write_all(&framed(b"tool", 0, b"")).unwrap();
                Ok(server)
            })
            .collect();
        let (sender, deliveries) = mpsc::sync_channel(1);
        assert_eq!(
            serve_connections(
                connections.into_iter(),
                &sender,
                (&Activity::default(), None)
            ),
            2
        );
        assert_eq!(deliveries.try_recv().unwrap(), message(HookKind::Tool, b""));
    }
}
