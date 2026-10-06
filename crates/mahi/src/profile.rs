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
    path::{
        Path,
        PathBuf,
    },
    sync::OnceLock,
};

use mahi_agent::{
    claude_code::{
        self,
        LogLine,
    },
    profile::{
        MAX_PROFILE_BYTES,
        Placeholder,
        ProfileError,
        Reader,
        StateFile,
        Template,
        UserProfile,
        When,
        Write as Writing,
        template,
    },
};
use mahi_identity::{
    ConfigDir,
    CredentialName,
    IdentityError,
    check_owned_dir,
    read_owned_file,
};
use mahi_proxy::HostName;
use rustix::{
    fs::{
        AtFlags,
        Mode,
        OFlags,
    },
    io::Errno,
};
use thiserror::Error;

use crate::environment::{
    EnvName,
    EnvNameError,
    PASSED_ON,
};

/// Reads one line of an agent's own session log.
pub(crate) type ReadLogLine = fn(&[u8]) -> Option<LogLine>;

/// Finds where an agent keeps its sessions for a worktree.
pub(crate) type SessionDir = fn(&Path) -> Option<String>;

/// How mahi tells the agent where its tools are.
#[derive(Debug)]
pub(crate) enum Tools {
    /// It does not.
    None,
    /// With this flag before the file in the state directory that names `mahi mcp`.
    McpFlag(&'static str),
    /// With these arguments, filled in.
    Args(Vec<Template>),
}

#[derive(Debug)]
enum Install {
    ClaudeCode,
    Codex,
    Files(Vec<StateFile>),
}

/// What mahi knows about one agent: the hosts it needs, the variables it may be given, the
/// settings that keep it quiet, and how its hooks and tools reach mahi; built in, or read
/// from a user's profile file.
#[derive(Debug)]
pub(crate) struct Profile {
    pub(crate) name: String,
    program: String,
    pub(crate) source: Option<PathBuf>,
    pub(crate) hosts: Vec<HostName>,
    pub(crate) optional_env: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) state_env: Option<String>,
    pub(crate) resume_args: Vec<String>,
    pub(crate) args: Vec<String>,
    pub(crate) credential: Option<(CredentialName, String)>,
    reader: Option<Reader>,
    pub(crate) takes_prompt: bool,
    pub(crate) tools: Tools,
    install: Install,
}

/// The file in the agent's state directory that tells it where `mahi mcp` is.
pub(crate) const MCP_CONFIG: &str = "mcp.json";

/// A user's profile file that mahi cannot use.
#[derive(Debug, Error)]
pub(crate) enum LoadError {
    #[error("cannot read the profile {}", .0.display())]
    Read(PathBuf, #[source] IdentityError),
    #[error("the profile {} is not UTF-8", .0.display())]
    NotUtf8(PathBuf),
    #[error("the profile {}", .0.display())]
    Invalid(PathBuf, #[source] ProfileError),
    #[error("the profile {}", .0.display())]
    Variable(PathBuf, #[source] EnvNameError),
    #[error("the profile {} sets {}, which mahi already passes on", .0.display(), .1)]
    PassedOn(PathBuf, String),
    #[error("the profiles {} and {} are both for {}", .0.display(), .1.display(), .2)]
    Twice(PathBuf, PathBuf, String),
    #[error("the profiles {} and {} are both named {}", .0.display(), .1.display(), .2)]
    SameName(PathBuf, PathBuf, String),
    #[error("the profile {} is named {}, as mahi's built-in profile for another program", .0.display(), .1)]
    BuiltInName(PathBuf, String),
    #[error("cannot list the profiles in {}", .0.display())]
    List(PathBuf, #[source] io::Error),
}

fn claude_code_profile() -> Profile {
    Profile {
        name: "claude-code".to_owned(),
        program: "claude".to_owned(),
        source: None,
        hosts: ["api.anthropic.com"]
            .iter()
            .filter_map(|host| host.parse().ok())
            .collect(),
        optional_env: vec!["CLAUDE_CODE_OAUTH_TOKEN".to_owned()],
        env: [
            ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
            ("DISABLE_AUTOUPDATER", "1"),
            ("ENABLE_CLAUDEAI_MCP_SERVERS", "false"),
        ]
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect(),
        state_env: Some("CLAUDE_CONFIG_DIR".to_owned()),
        resume_args: vec!["--continue".to_owned()],
        args: Vec::new(),
        credential: "claude"
            .parse()
            .ok()
            .map(|name| (name, "CLAUDE_CODE_OAUTH_TOKEN".to_owned())),
        reader: Some(Reader::ClaudeCode),
        takes_prompt: true,
        tools: Tools::McpFlag("--mcp-config"),
        install: Install::ClaudeCode,
    }
}

const CODEX_ARGS: [&str; 8] = [
    "-c",
    "sandbox_mode=\"danger-full-access\"",
    "-c",
    "cli_auth_credentials_store=\"file\"",
    "-c",
    "check_for_update_on_startup=false",
    "-c",
    "analytics.enabled=false",
];

const CODEX_TOOL_ARGS: [&str; 8] = [
    "-c",
    "mcp_servers.mahi.command=\"{mahi_bin}\"",
    "-c",
    "mcp_servers.mahi.args=[\"mcp\"]",
    "-c",
    "mcp_servers.mahi.env.MAHI_MCP_SOCKET=\"{mcp_socket}\"",
    "-c",
    "mcp_servers.mahi.default_tools_approval_mode=\"approve\"",
];

fn codex_profile() -> Profile {
    Profile {
        name: "codex".to_owned(),
        program: "codex".to_owned(),
        source: None,
        hosts: ["api.openai.com", "chatgpt.com", "auth.openai.com"]
            .iter()
            .filter_map(|host| host.parse().ok())
            .collect(),
        optional_env: Vec::new(),
        env: Vec::new(),
        state_env: Some("CODEX_HOME".to_owned()),
        resume_args: ["resume", "--last", "--all"]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect(),
        args: CODEX_ARGS.iter().map(|arg| (*arg).to_owned()).collect(),
        credential: None,
        reader: None,
        takes_prompt: true,
        tools: Tools::Args(
            CODEX_TOOL_ARGS
                .iter()
                .map(|arg| {
                    template("codex", arg).expect("built-in templates hold only known placeholders")
                })
                .collect(),
        ),
        install: Install::Codex,
    }
}

fn builtin_profiles() -> [Profile; 2] {
    [claude_code_profile(), codex_profile()]
}

static PROFILES: OnceLock<Vec<Profile>> = OnceLock::new();

fn profiles() -> &'static [Profile] {
    PROFILES.get_or_init(|| builtin_profiles().into())
}

/// Reads the user's profiles from `profiles/*.toml` in `config`, before any profile is
/// looked up; each replaces the built-in profile for the same program. A missing directory
/// means none.
///
/// # Errors
///
/// Returns a [`LoadError`] naming the file when one cannot be read, is invalid, sets or
/// passes a variable mahi reserves or passes on itself, or is for the same program or has
/// the same name as another.
pub(crate) fn load(config: &ConfigDir) -> Result<(), LoadError> {
    let loaded = with_builtin(read_profiles(&config.profiles_dir())?)?;
    let fresh = PROFILES.set(loaded).is_ok();
    debug_assert!(fresh, "profiles are loaded before any is looked up");
    Ok(())
}

fn with_builtin(mut loaded: Vec<Profile>) -> Result<Vec<Profile>, LoadError> {
    for builtin in builtin_profiles() {
        if let Some(clash) = loaded
            .iter()
            .find(|profile| profile.name == builtin.name && profile.program != builtin.program)
        {
            return Err(LoadError::BuiltInName(
                clash.source.clone().unwrap_or_default(),
                clash.name.clone(),
            ));
        }
        if !loaded
            .iter()
            .any(|profile| profile.program == builtin.program)
        {
            loaded.push(builtin);
        }
    }
    Ok(loaded)
}

fn read_profiles(dir: &Path) -> Result<Vec<Profile>, LoadError> {
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(LoadError::List(dir.to_path_buf(), error)),
        Ok(metadata) if metadata.is_symlink() => {
            return Err(LoadError::Read(
                dir.to_path_buf(),
                IdentityError::WritableByOthers(dir.to_path_buf()),
            ));
        }
        Ok(_) => {}
    }
    check_owned_dir(dir).map_err(|error| LoadError::Read(dir.to_path_buf(), error))?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir).map_err(|error| LoadError::List(dir.to_path_buf(), error))? {
        let path = entry
            .map_err(|error| LoadError::List(dir.to_path_buf(), error))?
            .path();
        let shown = path
            .file_name()
            .is_some_and(|name| !name.as_encoded_bytes().starts_with(b"."));
        if shown
            && path
                .extension()
                .is_some_and(|extension| extension == "toml")
        {
            paths.push(path);
        }
    }
    paths.sort();
    let mut loaded: Vec<Profile> = Vec::with_capacity(paths.len());
    for path in paths {
        let profile = read_profile(&path)?;
        if let Some(other) = loaded.iter().find(|other| other.program == profile.program) {
            return Err(LoadError::Twice(
                other.source.clone().unwrap_or_default(),
                path,
                profile.program,
            ));
        }
        if let Some(other) = loaded.iter().find(|other| other.name == profile.name) {
            return Err(LoadError::SameName(
                other.source.clone().unwrap_or_default(),
                path,
                profile.name,
            ));
        }
        loaded.push(profile);
    }
    Ok(loaded)
}

fn read_profile(path: &Path) -> Result<Profile, LoadError> {
    let bytes = read_owned_file(path, MAX_PROFILE_BYTES as u64)
        .map_err(|error| LoadError::Read(path.to_path_buf(), error))?;
    let text = String::from_utf8(bytes).map_err(|_| LoadError::NotUtf8(path.to_path_buf()))?;
    let user =
        UserProfile::parse(&text).map_err(|error| LoadError::Invalid(path.to_path_buf(), error))?;
    let names = user
        .pass_env
        .iter()
        .chain(user.env.iter().map(|(name, _)| name))
        .chain(user.state_env.iter())
        .chain(
            user.credential
                .iter()
                .map(|credential| &credential.variable),
        );
    for name in names {
        name.parse::<EnvName>()
            .map_err(|error| LoadError::Variable(path.to_path_buf(), error))?;
        if PASSED_ON.contains(&name.as_str()) {
            return Err(LoadError::PassedOn(path.to_path_buf(), name.clone()));
        }
    }
    Ok(Profile {
        name: user.name.as_str().to_owned(),
        program: user.program,
        source: Some(path.to_path_buf()),
        hosts: user.hosts,
        optional_env: user.pass_env,
        env: user.env,
        state_env: user.state_env,
        resume_args: user.resume_args,
        args: user.args,
        credential: user
            .credential
            .map(|credential| (credential.name, credential.variable)),
        reader: user.reader,
        takes_prompt: user.first_prompt_arg,
        tools: if user.tool_args.is_empty() {
            Tools::None
        } else {
            Tools::Args(user.tool_args)
        },
        install: Install::Files(user.files),
    })
}

impl Profile {
    /// Returns the optional variables of every profile, which mahi reads at startup, before it
    /// knows which profile applies.
    pub(crate) fn optional_env_of_all() -> impl Iterator<Item = &'static str> {
        profiles()
            .iter()
            .flat_map(|profile| profile.optional_env.iter().map(String::as_str))
    }

    /// Returns the profile for the agent program `program`, found by its file name.
    pub(crate) fn for_agent(program: &OsStr) -> Option<&'static Self> {
        let name = Path::new(program).file_name()?;
        profiles()
            .iter()
            .find(|profile| OsStr::new(&profile.program) == name)
    }

    /// Returns the variables the profile sets itself.
    pub(crate) fn set_names(&self) -> Vec<&str> {
        self.env
            .iter()
            .map(|(name, _)| name.as_str())
            .chain(self.state_env.as_deref())
            .collect()
    }

    /// Returns where the agent keeps its sessions, when mahi has a reader for them.
    pub(crate) fn session_dir(&self) -> Option<SessionDir> {
        self.reader
            .map(|Reader::ClaudeCode| claude_code::session_dir as SessionDir)
    }

    /// Returns how one line of the agent's session log reads, when mahi has a reader for it.
    pub(crate) fn log_line(&self) -> Option<ReadLogLine> {
        self.reader
            .map(|Reader::ClaudeCode| claude_code::log_line as ReadLogLine)
    }

    /// Writes the profile's files into the agent's state directory, open as `state` and found
    /// at `state_path`, replacing what the agent may have left there without following any
    /// symbolic link it planted; with `tools`, the mahi binary and the socket its tools are
    /// served at, they also tell the agent to start `mahi mcp`.
    ///
    /// # Errors
    ///
    /// Returns an error if a file cannot be written, or a value a file needs holds a quote, a
    /// backslash or a control character.
    pub(crate) fn install(
        &self,
        state: &OwnedFd,
        state_path: &Path,
        tools: Option<(&str, &str)>,
    ) -> io::Result<()> {
        match &self.install {
            Install::ClaudeCode => install_claude_code(state, tools),
            Install::Codex => replace(state, "hooks.json", CODEX_HOOKS.as_bytes()),
            Install::Files(files) => install_files(files, state, state_path, tools),
        }
    }

    /// Returns the arguments the profile adds when mahi serves the agent its tools, filled in
    /// with the state directory and `tools`; `None` when a value is not safe to put there.
    pub(crate) fn tool_args(&self, state_path: &Path, tools: (&str, &str)) -> Option<Vec<String>> {
        let Tools::Args(templates) = &self.tools else {
            return Some(Vec::new());
        };
        templates
            .iter()
            .map(|template| render(template, state_path, Some(tools)))
            .collect()
    }
}

fn safe(value: &str) -> bool {
    !value.contains(['"', '\\']) && !value.chars().any(char::is_control)
}

fn render(template: &Template, state_path: &Path, tools: Option<(&str, &str)>) -> Option<String> {
    let state = state_path.to_str().filter(|state| safe(state));
    let (mahi, socket) = tools
        .filter(|(mahi, socket)| safe(mahi) && safe(socket))
        .unzip();
    let mut missing = false;
    let mut out = String::new();
    template.render(
        |placeholder| {
            let value = match placeholder {
                Placeholder::StateDir => state,
                Placeholder::MahiBin => mahi,
                Placeholder::McpSocket => socket,
            };
            value.map_or_else(
                || {
                    missing = true;
                    String::new()
                },
                str::to_owned,
            )
        },
        &mut out,
    );
    (!missing).then_some(out)
}

fn install_files(
    files: &[StateFile],
    state: &OwnedFd,
    state_path: &Path,
    tools: Option<(&str, &str)>,
) -> io::Result<()> {
    for file in files {
        if file.when == When::Tools && tools.is_none() {
            continue;
        }
        let contents = render(&file.content, state_path, tools).ok_or_else(|| {
            io::Error::other(
                "a value the profile's file needs holds a quote, a backslash or a control \
                 character, or is not UTF-8",
            )
        })?;
        let Some((name, parents)) = file.path.split_last() else {
            continue;
        };
        let mut directory = None;
        for component in parents {
            let parent = directory.as_ref().unwrap_or(state);
            directory = Some(open_private_dir(parent, component)?.ok_or_else(|| {
                io::Error::other(format!(
                    "{component:?} in the state directory is not a directory"
                ))
            })?);
        }
        let directory = directory.as_ref().unwrap_or(state);
        match file.write {
            Writing::Replace => replace(directory, name, contents.as_bytes())?,
            Writing::Create => create_if_missing(directory, name, contents.as_bytes())?,
        }
    }
    Ok(())
}

const CLAUDE_CODE_SETTINGS: &str = r#"{
  "permissions": { "allow": ["mcp__mahi"] },
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

const CODEX_HOOKS: &str = r#"{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "\"$MAHI_BIN\" hook prompt" }] }
    ],
    "PostToolUse": [
      { "hooks": [{ "type": "command", "command": "\"$MAHI_BIN\" hook tool" }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "\"$MAHI_BIN\" hook turn-end" }] }
    ]
  }
}
"#;

const CLAUDE_CODE_STATE: &str = "{\"hasCompletedOnboarding\": true}\n";

fn install_claude_code(state: &OwnedFd, tools: Option<(&str, &str)>) -> io::Result<()> {
    replace(state, "settings.json", CLAUDE_CODE_SETTINGS.as_bytes())?;
    if let Some((mahi, socket)) = tools {
        let config = serde_json::json!({
            "mcpServers": {
                "mahi": {
                    "type": "stdio",
                    "command": mahi,
                    "args": ["mcp"],
                    "env": { "MAHI_MCP_SOCKET": socket }
                }
            }
        });
        let mut bytes = serde_json::to_vec_pretty(&config).map_err(io::Error::other)?;
        bytes.push(b'\n');
        replace(state, MCP_CONFIG, &bytes)?;
    }
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

    fn profiles_dir(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        for (name, text) in files {
            fs::write(dir.path().join(name), text).unwrap();
            fs::set_permissions(dir.path().join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        dir
    }

    const CODEX: &str = r#"
name = "codex"
program = "codex"
hosts = ["api.openai.com"]
pass-env = ["OPENAI_API_KEY"]
env = { CODEX_QUIET = "1" }
state-env = "CODEX_HOME"
resume-args = ["resume", "--last"]
first-prompt-arg = true

[tools]
args = ["--mcp", "{state_dir}/mcp.json"]

[[file]]
path = "hooks/notify.toml"
content = "command = [\"$MAHI_BIN\", \"hook\", \"turn-end\"]\n"

[[file]]
path = "mcp.json"
when = "tools"
content = '{{"command": "{mahi_bin}", "socket": "{mcp_socket}"}}'

[[file]]
path = "seen.txt"
write = "create"
content = "first\n"
"#;

    #[test]
    fn user_profiles_are_read_from_their_directory_and_checked() {
        let dir = profiles_dir(&[("codex.toml", CODEX), ("notes.md", "not a profile")]);
        let loaded = read_profiles(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        let codex = &loaded[0];
        assert_eq!(
            (codex.name.as_str(), codex.program.as_str()),
            ("codex", "codex")
        );
        assert_eq!(
            codex.source.as_deref(),
            Some(dir.path().join("codex.toml").as_path())
        );
        assert_eq!(codex.state_env.as_deref(), Some("CODEX_HOME"));
        assert_eq!(codex.set_names(), ["CODEX_QUIET", "CODEX_HOME"]);
        assert!(codex.takes_prompt && codex.session_dir().is_none());
        assert!(
            read_profiles(&dir.path().join("missing"))
                .unwrap()
                .is_empty()
        );

        let twice = profiles_dir(&[
            ("a.toml", "name = \"a\"\nprogram = \"codex\"\n"),
            ("b.toml", "name = \"b\"\nprogram = \"codex\"\n"),
        ]);
        assert!(matches!(
            read_profiles(twice.path()),
            Err(LoadError::Twice(..))
        ));
        for (text, wanted) in [
            ("env = { HTTPS_PROXY = \"x\" }", "Variable"),
            ("pass-env = [\"MAHI_BIN\"]", "Variable"),
            ("env = { PATH = \"/x\" }", "PassedOn"),
            ("hosts = [\"-bad\"]", "Invalid"),
        ] {
            let bad = profiles_dir(&[(
                "bad.toml",
                &format!("name = \"bad\"\nprogram = \"bad\"\n{text}\n"),
            )]);
            let error = read_profiles(bad.path()).unwrap_err();
            assert!(
                format!("{error:?}").starts_with(wanted),
                "{text}: {error:?}"
            );
        }
        let shared = profiles_dir(&[("codex.toml", CODEX)]);
        fs::set_permissions(
            shared.path().join("codex.toml"),
            fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        assert!(matches!(
            read_profiles(shared.path()),
            Err(LoadError::Read(..))
        ));
    }

    #[test]
    fn hidden_files_are_skipped_and_clashes_and_linked_directories_refused() {
        let dir = profiles_dir(&[("codex.toml", CODEX)]);
        std::os::unix::fs::symlink("gone", dir.path().join(".#codex.toml")).unwrap();
        assert_eq!(read_profiles(dir.path()).unwrap().len(), 1);

        let same_name = profiles_dir(&[
            ("a.toml", "name = \"same\"\nprogram = \"a\"\n"),
            ("b.toml", "name = \"same\"\nprogram = \"b\"\n"),
        ]);
        let error = read_profiles(same_name.path()).unwrap_err();
        assert!(error.to_string().contains("both named same"), "{error}");

        let linked = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path(), linked.path().join("profiles")).unwrap();
        assert!(matches!(
            read_profiles(&linked.path().join("profiles")),
            Err(LoadError::Read(..))
        ));

        let handoff = profiles_dir(&[(
            "h.toml",
            "name = \"h\"\nprogram = \"h\"\nenv = { MAHI_HANDOFF = \"/x\" }\n",
        )]);
        assert!(matches!(
            read_profiles(handoff.path()),
            Err(LoadError::Variable(..))
        ));

        let builtin_name =
            profiles_dir(&[("c.toml", "name = \"claude-code\"\nprogram = \"cc\"\n")]);
        let clash = with_builtin(read_profiles(builtin_name.path()).unwrap()).unwrap_err();
        assert!(matches!(clash, LoadError::BuiltInName(..)), "{clash}");
        let replacing = profiles_dir(&[("c.toml", "name = \"mine\"\nprogram = \"claude\"\n")]);
        let profiles = with_builtin(read_profiles(replacing.path()).unwrap()).unwrap();
        let names: Vec<&str> = profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect();
        assert_eq!(names, ["mine", "codex"]);
        let none = with_builtin(Vec::new()).unwrap();
        let names: Vec<&str> = none.iter().map(|profile| profile.name.as_str()).collect();
        assert_eq!(names, ["claude-code", "codex"]);
        let codex_name = profiles_dir(&[("c.toml", "name = \"codex\"\nprogram = \"cx\"\n")]);
        let clash = with_builtin(read_profiles(codex_name.path()).unwrap()).unwrap_err();
        assert!(matches!(clash, LoadError::BuiltInName(..)), "{clash}");
    }

    #[test]
    fn a_user_profiles_files_and_tool_arguments_are_filled_in_and_written() {
        let dir = profiles_dir(&[("codex.toml", CODEX)]);
        let codex = read_profiles(dir.path()).unwrap().remove(0);
        let state_dir = tempfile::tempdir().unwrap();
        let state = state_dir.path();
        codex.install(&open_dir(state), state, None).unwrap();
        assert_eq!(
            fs::read_to_string(state.join("hooks/notify.toml")).unwrap(),
            "command = [\"$MAHI_BIN\", \"hook\", \"turn-end\"]\n"
        );
        assert!(!state.join("mcp.json").exists());
        fs::write(state.join("seen.txt"), "kept\n").unwrap();
        let tools = ("/usr/bin/mahi", "/tmp/m/mcp.sock");
        codex.install(&open_dir(state), state, Some(tools)).unwrap();
        assert_eq!(
            fs::read_to_string(state.join("seen.txt")).unwrap(),
            "kept\n"
        );
        assert_eq!(
            fs::read_to_string(state.join("mcp.json")).unwrap(),
            r#"{"command": "/usr/bin/mahi", "socket": "/tmp/m/mcp.sock"}"#
        );
        assert_eq!(
            codex.tool_args(state, tools).unwrap(),
            ["--mcp".to_owned(), format!("{}/mcp.json", state.display())]
        );
        let quoted = state.join("a\"b");
        fs::create_dir(&quoted).unwrap();
        assert!(codex.tool_args(&quoted, tools).is_none());
        let unsafe_mahi = ("/opt/\"x\"/mahi", "/tmp/s");
        assert!(
            codex
                .install(&open_dir(state), state, Some(unsafe_mahi))
                .is_err()
        );

        let outside = tempfile::tempdir().unwrap();
        let planted = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), planted.path().join("hooks")).unwrap();
        assert!(
            codex
                .install(&open_dir(planted.path()), planted.path(), None)
                .is_err()
        );
        assert!(!outside.path().join("notify.toml").exists());
    }

    #[test]
    fn the_claude_and_codex_programs_get_their_built_in_profiles() {
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
        assert_eq!(
            Profile::for_agent(OsStr::new("/usr/local/bin/codex"))
                .unwrap()
                .name,
            "codex"
        );
        for other in ["claude-code", "sh", "codex-cli", "/", ""] {
            assert!(Profile::for_agent(OsStr::new(other)).is_none(), "{other}");
        }
    }

    #[test]
    fn claude_code_hooks_report_prompts_tools_and_turn_ends_to_mahi() {
        let dir = tempfile::tempdir().unwrap();
        claude_code_profile()
            .install(&open_dir(dir.path()), Path::new(""), None)
            .unwrap();
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
    fn claude_codes_own_state_is_seeded_once_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        claude_code_profile()
            .install(&open_dir(&state), Path::new(""), None)
            .unwrap();
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
        claude_code_profile()
            .install(&open_dir(&state), Path::new(""), None)
            .unwrap();
        assert_eq!(
            fs::read_to_string(state.join(".claude.json")).unwrap(),
            "{\"kept\": true}"
        );
        let outside = dir.path().join("outside");
        let linked = dir.path().join("linked");
        fs::create_dir(&linked).unwrap();
        std::os::unix::fs::symlink(&outside, linked.join(".claude.json")).unwrap();
        claude_code_profile()
            .install(&open_dir(&linked), Path::new(""), None)
            .unwrap();
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
        claude_code_profile()
            .install(&open_dir(&state), Path::new(""), None)
            .unwrap();
        claude_code_profile()
            .install(&open_dir(&state), Path::new(""), None)
            .unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "untouched");
        let settings = state.join("settings.json");
        assert!(!fs::symlink_metadata(&settings).unwrap().is_symlink());
        assert_eq!(fs::read_to_string(settings).unwrap(), CLAUDE_CODE_SETTINGS);
        assert!(!state.join(".settings.json.mahi").exists());
    }

    #[test]
    fn no_profile_sets_or_passes_a_variable_mahi_reserves() {
        for profile in profiles() {
            for name in profile
                .set_names()
                .into_iter()
                .chain(profile.optional_env.iter().map(String::as_str))
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
        let claude = claude_code_profile();
        assert_eq!(
            claude.hosts,
            ["api.anthropic.com".parse::<HostName>().unwrap()]
        );
        assert_eq!(claude.optional_env, ["CLAUDE_CODE_OAUTH_TOKEN"]);
        for (name, _) in &claude.env {
            assert!(!name.contains("API_KEY") && !name.contains("AUTH_TOKEN"));
        }
    }

    #[test]
    fn claude_code_is_told_where_mahi_mcp_is_and_may_use_its_tools() {
        let dir = tempfile::tempdir().unwrap();
        claude_code_profile()
            .install(
                &open_dir(dir.path()),
                Path::new(""),
                Some(("/opt/mahi \"x\"/mahi", "/tmp/s/mcp.sock")),
            )
            .unwrap();
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join(MCP_CONFIG)).unwrap()).unwrap();
        assert_eq!(
            config["mcpServers"]["mahi"]["command"],
            "/opt/mahi \"x\"/mahi"
        );
        assert_eq!(config["mcpServers"]["mahi"]["args"][0], "mcp");
        assert_eq!(
            config["mcpServers"]["mahi"]["env"]["MAHI_MCP_SOCKET"],
            "/tmp/s/mcp.sock"
        );
        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join("settings.json")).unwrap()).unwrap();
        assert_eq!(settings["permissions"]["allow"][0], "mcp__mahi");
        assert!(matches!(
            claude_code_profile().tools,
            Tools::McpFlag("--mcp-config")
        ));
    }

    #[test]
    fn codex_hooks_report_prompts_tools_and_turn_ends_to_mahi() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "untouched").unwrap();
        std::os::unix::fs::symlink(&outside, state.join("hooks.json")).unwrap();
        codex_profile()
            .install(&open_dir(&state), Path::new(""), None)
            .unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "untouched");
        let hooks: serde_json::Value =
            serde_json::from_slice(&fs::read(state.join("hooks.json")).unwrap()).unwrap();
        for (event, kind) in [
            ("UserPromptSubmit", "prompt"),
            ("PostToolUse", "tool"),
            ("Stop", "turn-end"),
        ] {
            let hook = &hooks["hooks"][event][0]["hooks"][0];
            assert_eq!(hook["type"], "command");
            assert_eq!(hook["command"], format!("\"$MAHI_BIN\" hook {kind}"));
        }
        let mode = fs::metadata(state.join("hooks.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn codex_runs_in_mahis_sandbox_and_is_told_where_mahi_mcp_is() {
        let codex = codex_profile();
        assert_eq!(codex.state_env.as_deref(), Some("CODEX_HOME"));
        assert_eq!(codex.resume_args, ["resume", "--last", "--all"]);
        assert!(codex.takes_prompt && codex.credential.is_none() && codex.optional_env.is_empty());
        let hosts: Vec<String> = codex.hosts.iter().map(ToString::to_string).collect();
        assert_eq!(hosts, ["api.openai.com", "chatgpt.com", "auth.openai.com"]);
        assert_eq!(codex.args, CODEX_ARGS);
        let tools = ("/usr/bin/mahi", "/tmp/m/mcp.sock");
        assert_eq!(
            codex.tool_args(Path::new("/state"), tools).unwrap(),
            [
                "-c",
                "mcp_servers.mahi.command=\"/usr/bin/mahi\"",
                "-c",
                "mcp_servers.mahi.args=[\"mcp\"]",
                "-c",
                "mcp_servers.mahi.env.MAHI_MCP_SOCKET=\"/tmp/m/mcp.sock\"",
                "-c",
                "mcp_servers.mahi.default_tools_approval_mode=\"approve\"",
            ]
        );
        assert!(
            codex
                .tool_args(Path::new("/state"), ("/opt/\"x\"/mahi", "/tmp/s"))
                .is_none()
        );
    }
}
