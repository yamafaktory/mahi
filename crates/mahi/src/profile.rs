use std::{
    ffi::OsStr,
    fs::{
        self,
        File,
    },
    io::{
        self,
        Write,
    },
    os::{
        fd::OwnedFd,
        unix::fs::DirBuilderExt,
    },
    path::Path,
};

use rustix::{
    fs::{
        AtFlags,
        Mode,
        OFlags,
    },
    io::Errno,
};

/// What mahi knows about one agent: the hosts it needs, the variables it may be given, the
/// settings that keep it quiet, and how its hooks report to mahi.
#[derive(Debug)]
pub(crate) struct Profile {
    pub(crate) name: &'static str,
    program: &'static str,
    pub(crate) hosts: &'static [&'static str],
    pub(crate) optional_env: &'static [&'static str],
    pub(crate) env: &'static [(&'static str, &'static str)],
    pub(crate) state_env: &'static str,
    pub(crate) resume_args: &'static [&'static str],
    pub(crate) credential: Option<(&'static str, &'static str)>,
    pub(crate) session_dir: Option<fn(&Path) -> Option<String>>,
    pub(crate) takes_prompt: bool,
    install: fn(&OwnedFd) -> io::Result<()>,
}

const CLAUDE_CODE: Profile = Profile {
    name: "claude-code",
    program: "claude",
    hosts: &["api.anthropic.com"],
    optional_env: &["CLAUDE_CODE_OAUTH_TOKEN"],
    env: &[
        ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
        ("DISABLE_AUTOUPDATER", "1"),
        ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"),
    ],
    state_env: "CLAUDE_CONFIG_DIR",
    resume_args: &["--continue"],
    credential: Some(("claude", "CLAUDE_CODE_OAUTH_TOKEN")),
    session_dir: Some(claude_code_session_dir),
    takes_prompt: true,
    install: install_claude_code,
};

const CLAUDE_CODE_LONGEST_PROJECT: usize = 200;

/// Returns where Claude Code keeps the sessions of an agent working in `worktree`, inside its
/// config directory: `projects/` and the worktree's path with every character other than an
/// ASCII letter or digit replaced by `-`, one for each UTF-16 unit, as Claude Code names it.
/// A name Claude Code would shorten, past 200 characters, gives `None`.
fn claude_code_session_dir(worktree: &Path) -> Option<String> {
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

const PROFILES: [&Profile; 1] = [&CLAUDE_CODE];

const CLAUDE_CODE_SETTINGS: &str = r#"{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "\"$MAHI_BIN\" hook prompt" }] }
    ],
    "PostToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "\"$MAHI_BIN\" hook tool" }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "\"$MAHI_BIN\" hook turn-end" }] }
    ]
  }
}
"#;

const CLAUDE_CODE_STATE: &str = "{\"hasCompletedOnboarding\": true}\n";

impl Profile {
    /// Returns the optional variables of every profile, which mahi reads at startup, before it
    /// knows which profile applies.
    pub(crate) fn optional_env_of_all() -> impl Iterator<Item = &'static str> {
        PROFILES
            .into_iter()
            .flat_map(|profile| profile.optional_env.iter().copied())
    }

    /// Returns the profile for the agent program `program`, found by its file name.
    pub(crate) fn for_agent(program: &OsStr) -> Option<&'static Self> {
        let name = Path::new(program).file_name()?;
        PROFILES
            .into_iter()
            .find(|profile| OsStr::new(profile.program) == name)
    }

    /// Returns the variables the profile sets itself.
    pub(crate) fn set_names(&self) -> Vec<&'static str> {
        self.env
            .iter()
            .map(|(name, _)| *name)
            .chain([self.state_env])
            .collect()
    }

    /// Writes the profile's files into the agent's state directory, open as `state`, replacing
    /// what the agent may have left there without following any symbolic link it planted.
    pub(crate) fn install(&self, state: &OwnedFd) -> io::Result<()> {
        (self.install)(state)
    }
}

fn install_claude_code(state: &OwnedFd) -> io::Result<()> {
    replace(state, "settings.json", CLAUDE_CODE_SETTINGS.as_bytes())?;
    create_if_missing(state, ".claude.json", CLAUDE_CODE_STATE.as_bytes())
}

fn create_if_missing(directory: &OwnedFd, name: &str, contents: &[u8]) -> io::Result<()> {
    let temporary = format!(".{name}.mahi");
    match rustix::fs::unlinkat(directory, temporary.as_str(), AtFlags::empty()) {
        Err(error) if error != Errno::NOENT => return Err(error.into()),
        _ => {}
    }
    let file = rustix::fs::openat(
        directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = File::from(file);
    file.write_all(contents)?;
    file.sync_all()?;
    let linked = rustix::fs::linkat(
        directory,
        temporary.as_str(),
        directory,
        name,
        AtFlags::empty(),
    );
    rustix::fs::unlinkat(directory, temporary.as_str(), AtFlags::empty())?;
    match linked {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    rustix::fs::fsync(directory)?;
    Ok(())
}

/// Replaces the file `name` in `directory` with `contents`, atomically and without following
/// a symbolic link: it is written to a temporary name, synced, then renamed into place.
pub(crate) fn replace(directory: &OwnedFd, name: &str, contents: &[u8]) -> io::Result<()> {
    let temporary = format!(".{name}.mahi");
    match rustix::fs::unlinkat(directory, temporary.as_str(), AtFlags::empty()) {
        Err(error) if error != Errno::NOENT => return Err(error.into()),
        _ => {}
    }
    let file = rustix::fs::openat(
        directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = File::from(file);
    file.write_all(contents)?;
    file.sync_all()?;
    rustix::fs::renameat(directory, temporary.as_str(), directory, name)?;
    rustix::fs::fsync(directory)?;
    Ok(())
}

/// Opens the directory `name` inside `parent`, such as an agent's state directory, creating it
/// if it is missing,
/// without following a symbolic link, and makes sure it is a directory of the user's that only
/// the user can use.
///
/// Returns `Ok(None)` when `name` exists but is not such a directory.
pub(crate) fn open_private_dir(parent: &OwnedFd, name: &str) -> io::Result<Option<OwnedFd>> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Err(error) if error != Errno::EXIST => return Err(error.into()),
        _ => {}
    }
    let directory = match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(Errno::LOOP | Errno::NOTDIR) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let stat = rustix::fs::fstat(&directory)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Ok(None);
    }
    rustix::fs::fchmod(&directory, Mode::from_raw_mode(0o700))?;
    Ok(Some(directory))
}

/// Creates the directory `path` and every missing parent, private to the user.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn open_dir(path: &Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    #[test]
    fn a_state_directory_is_created_private_and_a_planted_link_or_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let parent = open_dir(dir.path());
        assert!(open_private_dir(&parent, "agent").unwrap().is_some());
        let mode = fs::metadata(dir.path().join("agent"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        fs::set_permissions(dir.path().join("agent"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open_private_dir(&parent, "agent").unwrap().is_some());
        let mode = fs::metadata(dir.path().join("agent"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("linked")).unwrap();
        assert!(open_private_dir(&parent, "linked").unwrap().is_none());
        fs::write(dir.path().join("file"), "x").unwrap();
        assert!(open_private_dir(&parent, "file").unwrap().is_none());
    }

    #[test]
    fn the_claude_program_gets_the_claude_code_profile() {
        assert_eq!(
            Profile::for_agent(OsStr::new("claude")).unwrap().name,
            "claude-code"
        );
        assert_eq!(
            Profile::for_agent(OsStr::new("/opt/bin/claude"))
                .unwrap()
                .name,
            "claude-code"
        );
        for other in ["claude-code", "sh", "codex", "/", ""] {
            assert!(Profile::for_agent(OsStr::new(other)).is_none(), "{other}");
        }
    }

    #[test]
    fn claude_code_hooks_report_prompts_tools_and_turn_ends_to_mahi() {
        let dir = tempfile::tempdir().unwrap();
        CLAUDE_CODE.install(&open_dir(dir.path())).unwrap();
        let settings = fs::read_to_string(dir.path().join("settings.json")).unwrap();
        for (event, kind) in [
            ("UserPromptSubmit", "prompt"),
            ("PostToolUse", "tool"),
            ("Stop", "turn-end"),
        ] {
            assert!(settings.contains(event), "{settings}");
            assert!(
                settings.contains(&format!("\\\"$MAHI_BIN\\\" hook {kind}")),
                "{settings}"
            );
        }
        let mode = fs::metadata(dir.path().join("settings.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn claude_code_sessions_are_found_under_the_worktree_path_it_names() {
        assert_eq!(
            claude_code_session_dir(Path::new(
                "/home/u/.local/share/mahi/worktrees/app-1f2e/0123abcd"
            ))
            .as_deref(),
            Some("projects/-home-u--local-share-mahi-worktrees-app-1f2e-0123abcd")
        );
        let long = format!("/{}", "a".repeat(199));
        assert!(claude_code_session_dir(Path::new(&long)).is_some());
        let longer = format!("/{}", "a".repeat(200));
        assert_eq!(claude_code_session_dir(Path::new(&longer)), None);
        assert_eq!(
            claude_code_session_dir(Path::new("/tmp/é")).as_deref(),
            Some("projects/-tmp--")
        );
        assert_eq!(
            claude_code_session_dir(Path::new("/tmp/\u{1f600}")).as_deref(),
            Some("projects/-tmp---")
        );
    }

    #[test]
    fn claude_codes_own_state_is_seeded_once_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        CLAUDE_CODE.install(&open_dir(&state)).unwrap();
        assert_eq!(
            fs::read_to_string(state.join(".claude.json")).unwrap(),
            CLAUDE_CODE_STATE
        );
        let mode = fs::metadata(state.join(".claude.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!state.join(".claude.json.mahi").exists());
        fs::write(state.join(".claude.json"), "{\"kept\": true}").unwrap();
        CLAUDE_CODE.install(&open_dir(&state)).unwrap();
        assert_eq!(
            fs::read_to_string(state.join(".claude.json")).unwrap(),
            "{\"kept\": true}"
        );
        let outside = dir.path().join("outside");
        let linked = dir.path().join("linked");
        fs::create_dir(&linked).unwrap();
        std::os::unix::fs::symlink(&outside, linked.join(".claude.json")).unwrap();
        CLAUDE_CODE.install(&open_dir(&linked)).unwrap();
        assert!(!outside.exists());
        assert!(
            fs::symlink_metadata(linked.join(".claude.json"))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn installing_again_replaces_files_and_planted_links_without_following_them() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "untouched").unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        std::os::unix::fs::symlink(&outside, state.join("settings.json")).unwrap();
        std::os::unix::fs::symlink(&outside, state.join(".settings.json.mahi")).unwrap();
        CLAUDE_CODE.install(&open_dir(&state)).unwrap();
        CLAUDE_CODE.install(&open_dir(&state)).unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "untouched");
        let settings = state.join("settings.json");
        assert!(!fs::symlink_metadata(&settings).unwrap().is_symlink());
        assert_eq!(fs::read_to_string(settings).unwrap(), CLAUDE_CODE_SETTINGS);
        assert!(!state.join(".settings.json.mahi").exists());
    }

    #[test]
    fn no_profile_sets_or_passes_a_variable_mahi_reserves() {
        for profile in PROFILES {
            for name in profile
                .set_names()
                .into_iter()
                .chain(profile.optional_env.iter().copied())
            {
                assert!(
                    name.parse::<crate::environment::EnvName>().is_ok(),
                    "{}: {name}",
                    profile.name
                );
            }
        }
    }

    #[test]
    fn claude_code_needs_only_the_api_host_and_passes_only_the_subscription_token() {
        assert_eq!(CLAUDE_CODE.hosts, ["api.anthropic.com"]);
        assert_eq!(CLAUDE_CODE.optional_env, ["CLAUDE_CODE_OAUTH_TOKEN"]);
        for (name, _) in CLAUDE_CODE.env {
            assert!(!name.contains("API_KEY") && !name.contains("AUTH_TOKEN"));
        }
    }
}
