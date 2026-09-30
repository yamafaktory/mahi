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
    stream.shutdown(Shutdown::Write)
}

/// Reads hook connections on `listener` one at a time and queues each valid message on
/// `messages`, until `closing` is set and every connection already made has been read, or a
/// few seconds have passed since. Then queues [`Delivery::End`].
pub(crate) fn serve(
    listener: &UnixListener,
    closing: &AtomicBool,
    messages: &SyncSender<Delivery>,
    activity: &Activity,
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
        Ok(()) => serve_connections(connections, messages, activity),
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
    activity: &Activity,
) -> u64 {
    let mut dropped = 0;
    for stream in connections {
        let Ok(stream) = stream else {
            dropped += 1;
            continue;
        };
        let Some(message) = receive(stream) else {
            dropped += 1;
            continue;
        };
        activity.saw(message.kind);
        match messages.try_send(Delivery::Message(message)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => dropped += 1,
            Err(TrySendError::Disconnected(_)) => break,
        }
    }
    dropped
}

fn receive(mut stream: UnixStream) -> Option<HookMessage> {
    let deadline = Instant::now() + DEADLINE;
    let mut received = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if !readable_by(&stream, deadline) {
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
    }
    hook::decode(&received)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
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
        thread::spawn(move || serve(&listener, &flag, &sender, &Activity::default()));
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
            &Activity::default(),
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
            serve_connections(connections.into_iter(), &sender, &Activity::default()),
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
            serve_connections(connections.into_iter(), &sender, &Activity::default()),
            2
        );
        assert_eq!(deliveries.try_recv().unwrap(), message(HookKind::Tool, b""));
    }
}
