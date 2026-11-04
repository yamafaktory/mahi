//! Claude Code: where it keeps an agent's sessions.

use std::path::Path;

const CLAUDE_CODE_LONGEST_PROJECT: usize = 200;

/// Returns whether the file at `path`, relative to Claude Code's session directory, is the log
/// of a session of the main conversation: a `.jsonl` file at its top, as a subagent's log is
/// in a directory of its own.
#[must_use]
pub fn is_session_log(path: &str) -> bool {
    !path.contains('/')
        && Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
}

/// Returns where Claude Code keeps the sessions of an agent working in `worktree`, inside its
/// config directory: `projects/` and the worktree's path with every character other than an
/// ASCII letter or digit replaced by `-`, one for each UTF-16 unit, as Claude Code names it.
/// A name Claude Code would shorten, past 200 characters, gives `None`.
#[must_use]
pub fn session_dir(worktree: &Path) -> Option<String> {
    let mut name = String::new();
    for character in worktree.to_str()?.chars() {
        if character.is_ascii_alphanumeric() {
            name.push(character);
        } else {
            name.extend(std::iter::repeat_n('-', character.len_utf16()));
        }
    }
    (name.len() <= CLAUDE_CODE_LONGEST_PROJECT).then(|| format!("projects/{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_code_sessions_are_found_under_the_worktree_path_it_names() {
        assert_eq!(
            session_dir(Path::new(
                "/home/u/.local/share/mahi/worktrees/app-1f2e/0123abcd"
            ))
            .as_deref(),
            Some("projects/-home-u--local-share-mahi-worktrees-app-1f2e-0123abcd")
        );
        let long = format!("/{}", "a".repeat(199));
        assert!(session_dir(Path::new(&long)).is_some());
        let longer = format!("/{}", "a".repeat(200));
        assert_eq!(session_dir(Path::new(&longer)), None);
        assert_eq!(
            session_dir(Path::new("/tmp/é")).as_deref(),
            Some("projects/-tmp--")
        );
        assert_eq!(
            session_dir(Path::new("/tmp/\u{1f600}")).as_deref(),
            Some("projects/-tmp---")
        );
    }
}
