use std::{
    fs::File,
    io::{
        self,
        Write as _,
    },
    sync::OnceLock,
};

use mahi_term::Report;
use rustix::fs::OFlags;

static PIPE: OnceLock<File> = OnceLock::new();

/// Takes the pipe on which the workspace that started this mahi reads what it reports, left
/// open at `fd`, and marks it not to wait, so reporting never holds a run up; a pipe that
/// cannot be taken is reported and left, and nothing is reported then.
pub(crate) fn connect(fd: i32) {
    let connected = mahi_sandbox::inherited_pipe(fd).and_then(|pipe| {
        rustix::fs::fcntl_setfl(&pipe, OFlags::NONBLOCK)?;
        PIPE.set(pipe)
            .map_err(|_| io::Error::from(io::ErrorKind::AlreadyExists))
    });
    if let Err(error) = connected {
        crate::report_with("the workspace's report pipe is not usable", &error);
    }
}

/// Returns whether a workspace started this mahi and reads its reports.
pub(crate) fn connected() -> bool {
    PIPE.get().is_some()
}

/// Tells the workspace that started this mahi `report`, if one did; a report the pipe has no
/// room for is dropped.
pub(crate) fn send(report: &Report) {
    let Some(mut pipe) = PIPE.get() else {
        return;
    };
    let mut line = Vec::with_capacity(48);
    report.write(&mut line);
    let _ = pipe.write_all(&line);
}

#[cfg(test)]
mod tests {
    use std::{
        io::Read,
        os::fd::IntoRawFd,
    };

    use mahi_term::ReportReader;

    use super::*;

    #[test]
    fn reports_reach_the_pipe_and_none_waits_once_it_is_full() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        connect(writer.into_raw_fd());
        send(&Report::Working);
        send(&Report::Done);
        let mut reader = File::from(reader);
        let mut read = [0_u8; 64];
        let length = reader.read(&mut read).unwrap();
        let mut reports = Vec::new();
        ReportReader::default().feed(&read[..length], |report| reports.push(report));
        assert_eq!(reports, [Report::Working, Report::Done]);
        let started = std::time::Instant::now();
        for _ in 0..100_000 {
            send(&Report::Working);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
