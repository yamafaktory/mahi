use std::{
    ffi::OsStr,
    fs::{
        self,
        OpenOptions,
    },
    io::{
        self,
        Write,
    },
    os::unix::fs::{
        DirBuilderExt,
        OpenOptionsExt,
    },
    path::Path,
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
    install: fn(&Path) -> io::Result<()>,
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
    install: install_claude_code,
};

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

impl Profile {
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

    /// Prepares the agent's state directory `state`, which must exist and be empty.
    pub(crate) fn install(&self, state: &Path) -> io::Result<()> {
        (self.install)(state)
    }
}

fn install_claude_code(state: &Path) -> io::Result<()> {
    write_new(
        &state.join("settings.json"),
        CLAUDE_CODE_SETTINGS.as_bytes(),
    )
}

fn write_new(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
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
        CLAUDE_CODE.install(dir.path()).unwrap();
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
        assert!(CLAUDE_CODE.install(dir.path()).is_err());
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
