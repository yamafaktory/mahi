//! A user-written agent profile, read from a TOML file in mahi's configuration directory: the
//! hosts, variables, credential and resume arguments an agent needs, and the files mahi writes
//! into its state directory, such as the configuration that wires up its hooks and tools.

use std::{
    collections::{
        BTreeMap,
        HashSet,
    },
    fmt,
    str::FromStr,
};

use mahi_identity::CredentialName;
use mahi_proxy::HostName;
use serde::Deserialize;
use thiserror::Error;

/// The largest profile file mahi reads.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
const MAX_NAME_BYTES: usize = 32;
const MAX_PROGRAM_BYTES: usize = 255;
const MAX_LIST: usize = 32;
const MAX_TOOL_ARGS: usize = 16;
const MAX_FILES: usize = 16;
const MAX_VALUE_BYTES: usize = 4096;
const MAX_ENV_NAME_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 1024;
const MAX_COMPONENT_BYTES: usize = 200;
const MAX_DEPTH: usize = 8;

/// A profile's name: 1 to 32 lowercase letters, digits and dashes, not starting or ending
/// with a dash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileName(String);

impl ProfileName {
    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A reader mahi has built in for one agent: where it keeps its sessions and how its session
/// log reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    /// Claude Code's session directories and log lines.
    ClaudeCode,
    /// Codex's session directory and log lines.
    Codex,
}

/// When mahi writes a file into the agent's state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// On every start.
    Always,
    /// Only when mahi serves the agent its tools.
    Tools,
}

/// How mahi writes a file into the agent's state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Write {
    /// Replacing what is there.
    Replace,
    /// Only when nothing is there, so the agent keeps what it wrote.
    Create,
}

/// A value a template can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholder {
    /// `{state_dir}`: the agent's state directory.
    StateDir,
    /// `{mahi_bin}`: the mahi binary, as the agent sees it.
    MahiBin,
    /// `{mcp_socket}`: the socket the agent's tools are served at.
    McpSocket,
}

impl Placeholder {
    fn needs_tools(self) -> bool {
        matches!(self, Self::MahiBin | Self::McpSocket)
    }
}

/// One piece of a template: text, or a value filled in when mahi writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    /// Text kept as it is.
    Text(String),
    /// A value mahi fills in.
    Value(Placeholder),
}

/// Text in which `{state_dir}`, `{mahi_bin}` and `{mcp_socket}` are filled in, and `{{` and
/// `}}` stand for braces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template(Vec<Piece>);

impl Template {
    /// Returns the template's pieces, in order.
    #[must_use]
    pub fn pieces(&self) -> &[Piece] {
        &self.0
    }

    /// Writes the template into `out`, filling each value in with `value`.
    pub fn render(&self, mut value: impl FnMut(Placeholder) -> String, out: &mut String) {
        for piece in &self.0 {
            match piece {
                Piece::Text(text) => out.push_str(text),
                Piece::Value(placeholder) => out.push_str(&value(*placeholder)),
            }
        }
    }

    fn uses(&self, test: impl Fn(Placeholder) -> bool) -> bool {
        self.0
            .iter()
            .any(|piece| matches!(piece, Piece::Value(placeholder) if test(*placeholder)))
    }
}

/// A file mahi writes into the agent's state directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateFile {
    /// The path's components, relative to the state directory.
    pub path: Vec<String>,
    /// When it is written.
    pub when: When,
    /// How it is written.
    pub write: Write,
    /// What it holds.
    pub content: Template,
}

/// A stored credential handed to the agent as a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCredential {
    /// The credential's name in mahi's store.
    pub name: CredentialName,
    /// The variable the agent gets it as.
    pub variable: String,
}

/// A user-written agent profile, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile {
    /// The profile's name.
    pub name: ProfileName,
    /// The file name of the agent program it applies to.
    pub program: String,
    /// The hosts it lets the agent reach.
    pub hosts: Vec<HostName>,
    /// The variables passed on when they are set.
    pub pass_env: Vec<String>,
    /// The variables it sets, with their values.
    pub env: Vec<(String, String)>,
    /// The variable that points the agent at its state directory.
    pub state_env: Option<String>,
    /// The arguments `mahi resume` runs the program with.
    pub resume_args: Vec<String>,
    /// The arguments added after the user's own, before any `--`, every time the agent runs.
    pub args: Vec<String>,
    /// The stored credential the agent gets.
    pub credential: Option<ProfileCredential>,
    /// Whether a handoff's first prompt is given as the agent's last argument, after `--`.
    pub first_prompt_arg: bool,
    /// The reader mahi has built in for the agent's sessions.
    pub reader: Option<Reader>,
    /// The arguments added before the user's when mahi serves the agent its tools.
    pub tool_args: Vec<Template>,
    /// The files written into the state directory.
    pub files: Vec<StateFile>,
}

/// A profile file that mahi refuses.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileError {
    /// The file is larger than [`MAX_PROFILE_BYTES`].
    #[error("the profile is larger than 64 KiB")]
    TooLarge,
    /// The file is not TOML of the profile's form, at the line given when known.
    #[error("the profile is not valid{}: {message}", line.map(|line| format!(" at line {line}")).unwrap_or_default())]
    Syntax {
        /// The line, from 1, when known.
        line: Option<usize>,
        /// What is wrong.
        message: String,
    },
    /// A value is not of its field's form.
    #[error("{field} is not valid: {value:?}")]
    Invalid {
        /// The field.
        field: &'static str,
        /// The value refused.
        value: String,
    },
    /// A list holds more than its field allows.
    #[error("{0} lists too many entries")]
    TooMany(&'static str),
    /// A variable is named twice among `env`, `pass-env`, `state-env` and `credential`.
    #[error("the variable {0} is named twice")]
    Twice(String),
    /// Two files have the same path once ASCII case is folded, or one is a directory of the
    /// other.
    #[error("the file {0:?} is listed twice or is also a directory of another")]
    DuplicateFile(String),
    /// Files are listed, `{state_dir}` used or a reader named without a `state-env`.
    #[error("files, {{state_dir}} and a reader need a state-env")]
    NoStateDir,
    /// A file written on every start uses a value only known when tools are served.
    #[error("the file {0:?} uses {{mahi_bin}} or {{mcp_socket}}, so it needs when = \"tools\"")]
    ToolsOnly(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawProfile {
    name: String,
    program: String,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    pass_env: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    state_env: Option<String>,
    #[serde(default)]
    resume_args: Vec<String>,
    #[serde(default)]
    args: Vec<String>,
    credential: Option<RawCredential>,
    #[serde(default)]
    first_prompt_arg: bool,
    reader: Option<String>,
    tools: Option<RawTools>,
    #[serde(default)]
    file: Vec<RawFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredential {
    name: String,
    variable: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTools {
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    path: String,
    content: String,
    when: Option<String>,
    write: Option<String>,
}

fn invalid(field: &'static str, value: &str) -> ProfileError {
    ProfileError::Invalid {
        field,
        value: value.chars().take(64).collect(),
    }
}

fn at_most<T>(list: Vec<T>, most: usize, field: &'static str) -> Result<Vec<T>, ProfileError> {
    if list.len() > most {
        Err(ProfileError::TooMany(field))
    } else {
        Ok(list)
    }
}

fn env_name(field: &'static str, name: &str) -> Result<String, ProfileError> {
    let mut bytes = name.bytes();
    let valid = name.len() <= MAX_ENV_NAME_BYTES
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if valid {
        Ok(name.to_owned())
    } else {
        Err(invalid(field, name))
    }
}

fn value(field: &'static str, text: &str) -> Result<String, ProfileError> {
    if text.len() <= MAX_VALUE_BYTES && !text.contains('\0') {
        Ok(text.to_owned())
    } else {
        Err(invalid(field, text))
    }
}

impl FromStr for ProfileName {
    type Err = ProfileError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let valid = !text.is_empty()
            && text.len() <= MAX_NAME_BYTES
            && !text.starts_with('-')
            && !text.ends_with('-')
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(invalid("name", text))
        }
    }
}

fn program(text: &str) -> Result<String, ProfileError> {
    let valid = !text.is_empty()
        && text.len() <= MAX_PROGRAM_BYTES
        && text != "."
        && text != ".."
        && !text.contains(['/', '\0']);
    if valid {
        Ok(text.to_owned())
    } else {
        Err(invalid("program", text))
    }
}

/// Parses `text` as a template, refusing unknown values and lone braces. Values are inserted
/// as they are, so mahi refuses to write a file or an argument when a value holds a quote, a
/// backslash or a control character, which could change what the agent reads.
///
/// # Errors
///
/// Returns [`ProfileError::Invalid`] naming `field` if a brace is not part of `{{`, `}}` or a
/// known value, or the text is longer than a profile file may be.
pub fn template(field: &'static str, text: &str) -> Result<Template, ProfileError> {
    if text.len() > MAX_PROFILE_BYTES || text.contains('\0') {
        return Err(invalid(field, text));
    }
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(['{', '}']) {
        literal.push_str(&rest[..at]);
        let tail = &rest[at..];
        if let Some(after) = tail.strip_prefix("{{") {
            literal.push('{');
            rest = after;
        } else if let Some(after) = tail.strip_prefix("}}") {
            literal.push('}');
            rest = after;
        } else if tail.starts_with('}') {
            return Err(invalid(field, text));
        } else {
            let end = tail.find('}').ok_or_else(|| invalid(field, text))?;
            let placeholder = match &tail[1..end] {
                "state_dir" => Placeholder::StateDir,
                "mahi_bin" => Placeholder::MahiBin,
                "mcp_socket" => Placeholder::McpSocket,
                _ => return Err(invalid(field, text)),
            };
            if !literal.is_empty() {
                pieces.push(Piece::Text(std::mem::take(&mut literal)));
            }
            pieces.push(Piece::Value(placeholder));
            rest = &tail[end + 1..];
        }
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        pieces.push(Piece::Text(literal));
    }
    Ok(Template(pieces))
}

fn file_path(text: &str) -> Result<Vec<String>, ProfileError> {
    let components: Vec<&str> = text.split('/').collect();
    let valid = text.len() <= MAX_PATH_BYTES
        && components.len() <= MAX_DEPTH
        && components.iter().all(|component| {
            !component.is_empty()
                && *component != "."
                && *component != ".."
                && component.len() <= MAX_COMPONENT_BYTES
                && !(component.starts_with('.')
                    && component
                        .len()
                        .checked_sub(5)
                        .and_then(|at| component.get(at..))
                        .is_some_and(|end| end.eq_ignore_ascii_case(".mahi")))
                && component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b'@')
                })
        });
    if valid {
        Ok(components.into_iter().map(str::to_owned).collect())
    } else {
        Err(invalid("file.path", text))
    }
}

fn state_file(raw: RawFile) -> Result<StateFile, ProfileError> {
    let path = file_path(&raw.path)?;
    let when = match raw.when.as_deref() {
        None | Some("always") => When::Always,
        Some("tools") => When::Tools,
        Some(other) => return Err(invalid("file.when", other)),
    };
    let write = match raw.write.as_deref() {
        None | Some("replace") => Write::Replace,
        Some("create") => Write::Create,
        Some(other) => return Err(invalid("file.write", other)),
    };
    let content = template("file.content", &raw.content)?;
    if when == When::Always && content.uses(Placeholder::needs_tools) {
        return Err(ProfileError::ToolsOnly(raw.path));
    }
    Ok(StateFile {
        path,
        when,
        write,
        content,
    })
}

fn state_files(raw: Vec<RawFile>) -> Result<Vec<StateFile>, ProfileError> {
    let files: Vec<StateFile> = at_most(raw, MAX_FILES, "file")?
        .into_iter()
        .map(state_file)
        .collect::<Result<_, _>>()?;
    let mut paths = HashSet::new();
    let mut directories = HashSet::new();
    for file in &files {
        let folded: Vec<String> = file
            .path
            .iter()
            .map(|component| component.to_ascii_lowercase())
            .collect();
        for depth in 1..folded.len() {
            directories.insert(folded[..depth].join("/"));
        }
        if !paths.insert(folded.join("/")) {
            return Err(ProfileError::DuplicateFile(file.path.join("/")));
        }
    }
    if let Some(both) = paths.iter().find(|path| directories.contains(*path)) {
        return Err(ProfileError::DuplicateFile(both.clone()));
    }
    Ok(files)
}

fn names_once(
    pass_env: &[String],
    env: &[(String, String)],
    state_env: Option<&String>,
    credential: Option<&ProfileCredential>,
) -> Result<(), ProfileError> {
    let mut named = HashSet::new();
    let all_names = pass_env
        .iter()
        .chain(env.iter().map(|(name, _)| name))
        .chain(state_env)
        .chain(credential.map(|credential| &credential.variable));
    for name in all_names {
        if !named.insert(name.as_str()) {
            return Err(ProfileError::Twice(name.clone()));
        }
    }
    Ok(())
}

impl UserProfile {
    /// Reads and checks a profile file's text.
    ///
    /// # Errors
    ///
    /// Returns a [`ProfileError`] if the text is too large, is not TOML of the profile's form
    /// (unknown fields included), or a value or list breaks its rule.
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        if text.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::TooLarge);
        }
        let raw: RawProfile = toml::from_str(text).map_err(|error| ProfileError::Syntax {
            line: error
                .span()
                .and_then(|span| text.get(..span.start))
                .map(|before| before.matches('\n').count() + 1),
            message: error.message().to_owned(),
        })?;
        let hosts = at_most(raw.hosts, MAX_LIST, "hosts")?
            .iter()
            .map(|host| host.parse().map_err(|_| invalid("hosts", host)))
            .collect::<Result<_, _>>()?;
        let pass_env: Vec<String> = at_most(raw.pass_env, MAX_LIST, "pass-env")?
            .iter()
            .map(|name| env_name("pass-env", name))
            .collect::<Result<_, _>>()?;
        if raw.env.len() > MAX_LIST {
            return Err(ProfileError::TooMany("env"));
        }
        let env: Vec<(String, String)> = raw
            .env
            .iter()
            .map(|(name, text)| Ok((env_name("env", name)?, value("env", text)?)))
            .collect::<Result<_, ProfileError>>()?;
        let state_env = raw
            .state_env
            .as_deref()
            .map(|name| env_name("state-env", name))
            .transpose()?;
        let credential = raw
            .credential
            .map(|raw| {
                Ok::<_, ProfileError>(ProfileCredential {
                    name: raw
                        .name
                        .parse()
                        .map_err(|_| invalid("credential.name", &raw.name))?,
                    variable: env_name("credential.variable", &raw.variable)?,
                })
            })
            .transpose()?;
        names_once(&pass_env, &env, state_env.as_ref(), credential.as_ref())?;
        let resume_args = at_most(raw.resume_args, MAX_LIST, "resume-args")?
            .iter()
            .map(|argument| value("resume-args", argument))
            .collect::<Result<_, _>>()?;
        let args = at_most(raw.args, MAX_LIST, "args")?
            .iter()
            .map(|argument| value("args", argument))
            .collect::<Result<_, _>>()?;
        let reader = match raw.reader.as_deref() {
            None => None,
            Some("claude-code") => Some(Reader::ClaudeCode),
            Some("codex") => Some(Reader::Codex),
            Some(other) => return Err(invalid("reader", other)),
        };
        let tool_args: Vec<Template> = at_most(
            raw.tools.map_or_else(Vec::new, |tools| tools.args),
            MAX_TOOL_ARGS,
            "tools.args",
        )?
        .iter()
        .map(|argument| {
            value("tools.args", argument)?;
            template("tools.args", argument)
        })
        .collect::<Result<_, _>>()?;
        let files = state_files(raw.file)?;
        let uses_state_dir = tool_args
            .iter()
            .chain(files.iter().map(|file| &file.content))
            .any(|template| template.uses(|placeholder| placeholder == Placeholder::StateDir));
        if state_env.is_none() && (!files.is_empty() || uses_state_dir || reader.is_some()) {
            return Err(ProfileError::NoStateDir);
        }
        Ok(Self {
            name: raw.name.parse()?,
            program: program(&raw.program)?,
            hosts,
            pass_env,
            env,
            state_env,
            resume_args,
            args,
            credential,
            first_prompt_arg: raw.first_prompt_arg,
            reader,
            tool_args,
            files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
name = "codex"
program = "codex"
hosts = ["api.openai.com"]
pass-env = ["OPENAI_API_KEY"]
env = { CODEX_QUIET = "1" }
state-env = "CODEX_HOME"
resume-args = ["resume", "--last"]
args = ["-c", "sandbox_mode=\"danger-full-access\""]
credential = { name = "openai", variable = "OPENAI_TOKEN" }
first-prompt-arg = true
reader = "claude-code"

[tools]
args = ["--config", "{state_dir}/mcp.json"]

[[file]]
path = "hooks/config.toml"
content = "notify = [\"$MAHI_BIN\", \"hook\", \"turn-end\"]\n"

[[file]]
path = "mcp.json"
when = "tools"
write = "create"
content = '{{"command": "{mahi_bin}", "socket": "{mcp_socket}"}}'
"#;

    #[test]
    fn a_full_profile_is_read_with_every_field_checked() {
        let profile = UserProfile::parse(FULL).unwrap();
        assert_eq!(profile.name.as_str(), "codex");
        assert_eq!(profile.program, "codex");
        assert_eq!(profile.hosts.len(), 1);
        assert_eq!(profile.pass_env, ["OPENAI_API_KEY"]);
        assert_eq!(profile.env, [("CODEX_QUIET".to_owned(), "1".to_owned())]);
        assert_eq!(profile.state_env.as_deref(), Some("CODEX_HOME"));
        assert_eq!(profile.resume_args, ["resume", "--last"]);
        assert_eq!(profile.args, ["-c", "sandbox_mode=\"danger-full-access\""]);
        assert_eq!(profile.credential.unwrap().variable, "OPENAI_TOKEN");
        assert!(profile.first_prompt_arg);
        assert_eq!(profile.reader, Some(Reader::ClaudeCode));
        let codex = UserProfile::parse(&FULL.replace("\"claude-code\"", "\"codex\"")).unwrap();
        assert_eq!(codex.reader, Some(Reader::Codex));
        assert_eq!(profile.files.len(), 2);
        assert_eq!(profile.files[0].path, ["hooks", "config.toml"]);
        assert_eq!(profile.files[1].when, When::Tools);
        assert_eq!(profile.files[1].write, Write::Create);
        let mut rendered = String::new();
        profile.files[1].content.render(
            |placeholder| match placeholder {
                Placeholder::MahiBin => "/usr/bin/mahi".to_owned(),
                Placeholder::McpSocket => "/tmp/s".to_owned(),
                Placeholder::StateDir => "/state".to_owned(),
            },
            &mut rendered,
        );
        assert_eq!(
            rendered,
            r#"{"command": "/usr/bin/mahi", "socket": "/tmp/s"}"#
        );
    }

    #[test]
    fn a_minimal_profile_names_its_program() {
        let profile = UserProfile::parse("name = \"aider\"\nprogram = \"aider\"\n").unwrap();
        assert!(profile.hosts.is_empty() && profile.files.is_empty());
        assert!(!profile.first_prompt_arg);
    }

    #[test]
    fn templates_take_known_values_and_doubled_braces_only() {
        assert!(template("t", "{state_dir}/x {{y}}").is_ok());
        assert_eq!(
            template("t", "é{{state_dir}}").unwrap().pieces(),
            [Piece::Text("é{state_dir}".to_owned())]
        );
        for bad in [
            "{home}",
            "{state_dir",
            "}",
            "a } b",
            "{}",
            "{ state_dir }",
            "{a{b}",
            "{state_dir}}",
            "a\0b",
        ] {
            assert!(template("t", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bad_profiles_are_refused_with_what_is_wrong() {
        let base = "name = \"x\"\nprogram = \"x\"\n";
        let cases = [
            ("name = \"X\"\nprogram = \"x\"\n", "name"),
            ("name = \"x\"\nprogram = \"a/b\"\n", "program"),
            (&format!("{base}surprise = 1\n") as &str, "not valid"),
            (&format!("{base}hosts = [\"127.0.0.1\"]\n"), "hosts"),
            (&format!("{base}pass-env = [\"1BAD\"]\n"), "pass-env"),
            (
                &format!("{base}pass-env = [\"A\"]\nenv = {{ A = \"1\" }}\n"),
                "twice",
            ),
            (&format!("{base}reader = \"aider\"\n"), "reader"),
            (&format!("{base}args = [\"a\\u0000b\"]\n"), "args"),
            (
                &format!("{base}[[file]]\npath = \"f\"\ncontent = \"x\"\n"),
                "state-env",
            ),
            (
                &format!("{base}state-env = \"S\"\n[[file]]\npath = \"../f\"\ncontent = \"x\"\n"),
                "file.path",
            ),
            (
                &format!(
                    "{base}state-env = \"S\"\n[[file]]\npath = \"f\"\ncontent = \"{{mahi_bin}}\"\n"
                ),
                "when",
            ),
            (
                &format!(
                    "{base}state-env = \"S\"\n[[file]]\npath = \"F\"\ncontent = \"\"\n\
                     [[file]]\npath = \"f\"\ncontent = \"\"\n"
                ),
                "twice",
            ),
            (
                &format!("{base}[tools]\nargs = [\"{{state_dir}}\"]\n"),
                "state-env",
            ),
            (&format!("{base}env = {{ A = \"a\\u0000b\" }}\n"), "env"),
            (
                &format!("{base}hosts = [{}]\n", ["\"a.example\""; 33].join(",")),
                "too many",
            ),
            (
                &format!(
                    "{base}state-env = \"S\"\n[[file]]\npath = \"a/b\"\ncontent = \"\"\n\
                     [[file]]\npath = \"A\"\ncontent = \"\"\n"
                ),
                "directory of another",
            ),
            (
                &format!(
                    "{base}state-env = \"S\"\n[[file]]\npath = \"{}\"\ncontent = \"\"\n",
                    ["d"; 9].join("/")
                ),
                "file.path",
            ),
            (
                &format!(
                    "{base}state-env = \"S\"\n[[file]]\npath = \"{}\"\ncontent = \"\"\n",
                    "x".repeat(201)
                ),
                "file.path",
            ),
            (
                &format!("{base}state-env = \"S\"\n[[file]]\npath = \".x.MAHI\"\ncontent = \"\"\n"),
                "file.path",
            ),
            (
                &format!(
                    "{base}state-env = \"S\"\n[[file]]\npath = \"a\\u001b\"\ncontent = \"\"\n"
                ),
                "file.path",
            ),
            (&format!("{base}\nhosts = 3\n"), "line 4"),
            (&format!("{base}reader = \"claude-code\"\n"), "state-env"),
        ];
        for (text, expected) in cases {
            let error = UserProfile::parse(text).unwrap_err().to_string();
            assert!(error.contains(expected), "{text:?}: {error}");
        }
        assert_eq!(
            UserProfile::parse(&" ".repeat(MAX_PROFILE_BYTES + 1)),
            Err(ProfileError::TooLarge)
        );
        let long = format!("name = \"{}\"\nprogram = \"x\"\n", "y".repeat(100));
        let refused = UserProfile::parse(&long).unwrap_err().to_string();
        assert!(refused.len() < 100, "{refused}");
    }
}
