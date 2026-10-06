use std::{
    fs,
    path::PathBuf,
};

use rustix::{
    io::Errno,
    process::{
        Pid,
        test_kill_process,
    },
};

/// Returns an empty directory `<prefix>-<pid>` in the temporary directory for this process,
/// after removing those of earlier fuzz processes that have ended, so runs do not pile up;
/// a directory whose process still runs, or might, is left alone.
pub(super) fn fresh_dir(prefix: &str) -> PathBuf {
    let temp = std::env::temp_dir();
    if let Ok(entries) = fs::read_dir(&temp) {
        for entry in entries.flatten() {
            let ended = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix(prefix)?.strip_prefix('-'))
                .and_then(|pid| pid.parse::<u32>().ok())
                .and_then(|pid| i32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .and_then(Pid::from_raw)
                .is_some_and(|pid| test_kill_process(pid) == Err(Errno::SRCH));
            if ended {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
    let own = temp.join(format!("{prefix}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&own);
    own
}
