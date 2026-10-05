use std::{
    fmt::Write as _,
    io::{
        self,
        BufRead,
        BufReader,
        Read,
        Write,
    },
    os::unix::net::{
        UnixListener,
        UnixStream,
    },
    path::{
        Path,
        PathBuf,
    },
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
    thread,
    time::Duration,
};

use mahi_core::{
    AgentName,
    ThreadId,
};
use mahi_store::ObjectId;
use sha2::{
    Digest,
    Sha256,
};
use thiserror::Error;

use crate::{
    live,
    merge::MergeRequest,
};

const MAX_REQUEST_BYTES: u64 = 512;
const MAX_REPLY_BYTES: u64 = 64 * 1024;
const REQUEST_WAIT: Duration = Duration::from_secs(5);
const ACCEPT_PAUSE: Duration = Duration::from_millis(200);
const VERB: &str = "merge";
const DONE: &str = "done\n";
const FAILED: &str = "failed\n";

#[derive(Debug, Error)]
pub(crate) enum DoorError {
    #[error("cannot reach the mahi running the agent")]
    Unreachable(#[source] io::Error),
    #[error("the mahi running the agent did not merge: {0}")]
    Refused(String),
    #[error("the mahi running the agent gave an answer mahi cannot read")]
    Garbled,
}

/// Returns the socket the mahi running `agent` in `thread` takes merges on, in mahi's private
/// runtime directory, named by a hash of both so the path stays short.
pub(crate) fn door_path(
    runtime: &Path,
    thread: ThreadId,
    agent: &AgentName,
) -> io::Result<PathBuf> {
    let digest = Sha256::new()
        .chain_update(b"mahi merge door\0")
        .chain_update(thread.to_string())
        .chain_update([0])
        .chain_update(agent.as_str())
        .finalize();
    let mut name = String::with_capacity(38);
    for byte in digest.iter().take(16) {
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".merge");
    live::private_socket(runtime, &name)
}

impl MergeRequest {
    fn encode(&self) -> String {
        format!(
            "{VERB} {} {} {}\n",
            self.from, self.commit, self.thread_base
        )
    }

    fn decode(line: &str) -> Option<Self> {
        let mut words = line.strip_suffix('\n')?.split(' ');
        if words.next()? != VERB {
            return None;
        }
        let request = Self {
            from: words.next()?.parse().ok()?,
            commit: ObjectId::from_hex(words.next()?.as_bytes()).ok()?,
            thread_base: ObjectId::from_hex(words.next()?.as_bytes()).ok()?,
        };
        words.next().is_none().then_some(request)
    }
}

/// Where the mahi running an agent takes merges from `mahi merge` while the agent runs; the
/// socket is removed when it is dropped.
#[derive(Debug)]
pub(crate) struct MergeDoor {
    path: PathBuf,
    listener: UnixListener,
}

impl MergeDoor {
    /// Opens the door at `path`, replacing a socket a mahi that ended left there.
    pub(crate) fn open(path: PathBuf) -> io::Result<Self> {
        match std::fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        Ok(Self { path, listener })
    }

    /// Serves requests one at a time until `serving` is cleared, answering each with what
    /// `merge` made of it; `merge` gets the request and a check that its asker still waits.
    pub(crate) fn serve(
        &self,
        serving: &AtomicBool,
        mut merge: impl FnMut(MergeRequest, &dyn Fn() -> bool) -> Result<String, String>,
    ) {
        while serving.load(Ordering::SeqCst) {
            let Ok((stream, _)) = self.listener.accept() else {
                thread::sleep(ACCEPT_PAUSE);
                continue;
            };
            let _ = answer(&stream, &mut merge);
        }
    }
}

impl Drop for MergeDoor {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn answer(
    stream: &UnixStream,
    merge: &mut impl FnMut(MergeRequest, &dyn Fn() -> bool) -> Result<String, String>,
) -> io::Result<()> {
    let timed = stream
        .set_read_timeout(Some(REQUEST_WAIT))
        .and_then(|()| stream.set_write_timeout(Some(REQUEST_WAIT)))
        .is_ok();
    stream.set_nonblocking(!timed)?;
    let mut line = String::new();
    BufReader::new(stream.take(MAX_REQUEST_BYTES)).read_line(&mut line)?;
    let outcome = match MergeRequest::decode(&line) {
        Some(request) => merge(request, &|| still_waiting(stream)),
        None => Err("the request cannot be read".to_owned()),
    };
    let mut writer = stream;
    match outcome {
        Ok(report) => {
            writer.write_all(DONE.as_bytes())?;
            writer.write_all(report.as_bytes())?;
        }
        Err(reason) => {
            writer.write_all(FAILED.as_bytes())?;
            writer.write_all(reason.as_bytes())?;
        }
    }
    writer.flush()
}

fn still_waiting(stream: &UnixStream) -> bool {
    let mut byte = [0_u8; 1];
    match rustix::net::recv(
        stream,
        &mut byte,
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    ) {
        Ok((_, read)) => read > 0,
        Err(error) => error == rustix::io::Errno::AGAIN,
    }
}

/// Asks the mahi at `path` to merge `request`, and returns its report once it merged.
pub(crate) fn ask(path: &Path, request: &MergeRequest) -> Result<String, DoorError> {
    let mut stream = UnixStream::connect(path).map_err(DoorError::Unreachable)?;
    stream
        .write_all(request.encode().as_bytes())
        .map_err(DoorError::Unreachable)?;
    let mut reply = Vec::new();
    stream
        .take(MAX_REPLY_BYTES)
        .read_to_end(&mut reply)
        .map_err(DoorError::Unreachable)?;
    let reply = String::from_utf8_lossy(&reply);
    if let Some(report) = reply.strip_prefix(DONE) {
        Ok(report.to_owned())
    } else if let Some(reason) = reply.strip_prefix(FAILED) {
        Err(DoorError::Refused(reason.to_owned()))
    } else {
        Err(DoorError::Garbled)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn request() -> MergeRequest {
        MergeRequest {
            from: "bob.codex".parse().unwrap(),
            commit: ObjectId::from_hex(b"0123456789abcdef0123456789abcdef01234567").unwrap(),
            thread_base: ObjectId::from_hex(b"89abcdef0123456789abcdef0123456789abcdef").unwrap(),
        }
    }

    fn door() -> (tempfile::TempDir, PathBuf, MergeDoor) {
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let path = door_path(
            dir.path(),
            ThreadId::random().unwrap(),
            &AgentName::new("claude").unwrap(),
        )
        .unwrap();
        let door = MergeDoor::open(path.clone()).unwrap();
        (dir, path, door)
    }

    #[test]
    fn a_request_round_trips_and_anything_else_is_refused() {
        let request = request();
        assert_eq!(
            MergeRequest::decode(&request.encode()),
            Some(request.clone())
        );
        let encoded = request.encode();
        for bad in [
            encoded.trim_end().to_owned(),
            encoded.replacen(VERB, "push", 1),
            encoded.replace('\n', " extra\n"),
            "merge bob 0123 4567\n".to_owned(),
            String::new(),
        ] {
            assert_eq!(MergeRequest::decode(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_door_path_is_short_private_and_differs_by_agent() {
        let dir = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let thread = ThreadId::random().unwrap();
        let claude = door_path(dir.path(), thread, &AgentName::new("claude").unwrap()).unwrap();
        let codex = door_path(dir.path(), thread, &AgentName::new("codex").unwrap()).unwrap();
        assert_ne!(claude, codex);
        assert_eq!(claude.file_name().unwrap().len(), 38);
        assert_eq!(claude.parent(), codex.parent());
    }

    #[test]
    fn the_running_mahi_answers_with_its_report_or_its_reason() {
        let (_dir, path, door) = door();
        let serving = Arc::new(AtomicBool::new(true));
        let server = {
            let serving = Arc::clone(&serving);
            thread::spawn(move || {
                let mut asked = 0;
                door.serve(&serving, |request, waiting| {
                    asked += 1;
                    assert!(waiting());
                    if asked == 1 {
                        Ok(format!("merged {}\n", request.from))
                    } else {
                        Err("the agent ended".to_owned())
                    }
                });
                drop(door);
            })
        };
        assert_eq!(ask(&path, &request()).unwrap(), "merged bob.codex\n");
        assert!(matches!(
            ask(&path, &request()),
            Err(DoorError::Refused(reason)) if reason == "the agent ended"
        ));
        let mut garbage = UnixStream::connect(&path).unwrap();
        garbage.write_all(b"nonsense\n").unwrap();
        let mut reply = String::new();
        garbage.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "failed\nthe request cannot be read");
        serving.store(false, Ordering::SeqCst);
        server.join().unwrap();
        assert!(!path.exists());
        assert!(matches!(
            ask(&path, &request()),
            Err(DoorError::Unreachable(_))
        ));
    }

    #[test]
    fn an_asker_that_left_is_no_longer_waiting() {
        let (_dir, path, door) = door();
        let serving = Arc::new(AtomicBool::new(true));
        let (seen, waiting) = std::sync::mpsc::channel();
        let server = {
            let serving = Arc::clone(&serving);
            thread::spawn(move || {
                door.serve(&serving, |_, still| {
                    thread::sleep(Duration::from_millis(300));
                    seen.send(still()).unwrap();
                    Err("gone".to_owned())
                });
            })
        };
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.write_all(request().encode().as_bytes()).unwrap();
        drop(stream);
        assert!(!waiting.recv_timeout(Duration::from_secs(10)).unwrap());
        serving.store(false, Ordering::SeqCst);
        server.join().unwrap();
    }
}
