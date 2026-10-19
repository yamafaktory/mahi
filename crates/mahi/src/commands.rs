use std::{
    fs::File,
    io::{
        self,
        Read as _,
    },
    sync::{
        Mutex,
        OnceLock,
    },
};

/// The byte the workspace sends a child mahi to open its palette.
pub(crate) const OPEN_PALETTE: u8 = b'p';

static PIPE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

/// Takes the pipe on which the workspace that started this mahi tells it to open its palette,
/// left open at `fd`; a pipe that cannot be taken is reported and left, and the palette key is
/// then read from the terminal as outside a workspace.
pub(crate) fn connect(fd: i32) {
    match mahi_sandbox::inherited_pipe(fd) {
        Ok(pipe) => {
            let _ = PIPE.set(Mutex::new(Some(pipe)));
        }
        Err(error) => crate::report_with("the workspace's command pipe is not usable", &error),
    }
}

/// Takes the workspace's command pipe, when a workspace started this mahi and it was not
/// taken yet, dropping the requests that came before, while nothing could open the palette.
pub(crate) fn take() -> Option<File> {
    PIPE.get()?.lock().ok()?.take().map(drained)
}

fn drained(pipe: File) -> File {
    let Ok(flags) = rustix::fs::fcntl_getfl(&pipe) else {
        return pipe;
    };
    if rustix::fs::fcntl_setfl(&pipe, flags | rustix::fs::OFlags::NONBLOCK).is_ok() {
        let mut buffer = [0_u8; 64];
        while matches!((&pipe).read(&mut buffer), Ok(read) if read > 0) {}
        let _ = rustix::fs::fcntl_setfl(&pipe, flags);
    }
    pipe
}

/// Reads `pipe` until the workspace closes it, calling `open` once for each read that asks to
/// open the palette; any other byte is ignored.
pub(crate) fn listen(mut pipe: File, mut open: impl FnMut()) {
    let mut buffer = [0_u8; 64];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => {
                if buffer
                    .get(..read)
                    .unwrap_or_default()
                    .contains(&OPEN_PALETTE)
                {
                    open();
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn requests_that_came_before_the_pipe_was_taken_are_dropped() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut writer = File::from(writer);
        writer.write_all(&[OPEN_PALETTE; 3]).unwrap();
        let reader = drained(File::from(reader));
        writer.write_all(b"x").unwrap();
        drop(writer);
        let mut opened = 0;
        listen(reader, || opened += 1);
        assert_eq!(opened, 0);
    }

    #[test]
    fn a_request_that_comes_after_the_pipe_was_taken_opens_the_palette() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let reader = drained(File::from(reader));
        let late = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            File::from(writer).write_all(&[OPEN_PALETTE]).unwrap();
        });
        let mut opened = 0;
        listen(reader, || opened += 1);
        late.join().unwrap();
        assert_eq!(opened, 1);
    }

    #[test]
    fn the_palette_opens_for_each_request_and_nothing_else_opens_it() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut writer = File::from(writer);
        writer.write_all(b"x\x1b[32;5u").unwrap();
        drop(writer);
        let mut opened = 0;
        listen(File::from(reader), || opened += 1);
        assert_eq!(opened, 0);
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        let mut writer = File::from(writer);
        writer.write_all(&[OPEN_PALETTE]).unwrap();
        drop(writer);
        let mut opened = 0;
        listen(File::from(reader), || opened += 1);
        assert_eq!(opened, 1);
    }
}
