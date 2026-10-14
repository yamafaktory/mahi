use std::{
    collections::BTreeSet,
    fmt::Write as _,
};

use gix::config::{
    File,
    Source,
    file::{
        Metadata,
        init::Options,
    },
};

use crate::StoreError;

const CORE_KEYS: [&str; 13] = [
    "repositoryformatversion",
    "bare",
    "filemode",
    "symlinks",
    "ignorecase",
    "precomposeunicode",
    "logallrefupdates",
    "autocrlf",
    "eol",
    "safecrlf",
    "checkstat",
    "trustctime",
    "quotepath",
];
const MAX_VALUE_BYTES: usize = 64;

/// Returns the settings of a repository's own git configuration `bytes` that git needs to read
/// the repository, as a configuration of their own: the `core` settings that describe its
/// files (format version, case, links, line endings) and every `extensions` setting, each kept
/// only when its value is a plain word. Remotes, credentials, includes, programs and paths are
/// left out.
pub(crate) fn agent_config(mut bytes: Vec<u8>) -> Result<String, StoreError> {
    let file = File::from_bytes_owned(
        &mut bytes,
        Metadata::from(Source::Local),
        Options::default(),
    )
    .map_err(|_| StoreError::UnreadableConfig)?;
    let mut config = String::new();
    write_section(&mut config, &file, "core", CORE_KEYS.iter().copied());
    let extensions: BTreeSet<String> = file
        .sections_by_name("extensions")
        .into_iter()
        .flatten()
        .filter(|section| section.header().subsection_name().is_none())
        .flat_map(|section| {
            section
                .value_names()
                .map(|name| name.to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|name| is_plain(name.as_bytes()))
        .collect();
    write_section(
        &mut config,
        &file,
        "extensions",
        extensions.iter().map(String::as_str),
    );
    Ok(config)
}

fn write_section<'a>(
    config: &mut String,
    file: &File,
    section: &str,
    keys: impl Iterator<Item = &'a str>,
) {
    let mut started = false;
    for key in keys {
        let value = match file.string_by(section, None, key) {
            Some(value) if !value.is_empty() => value,
            _ => match file.boolean_by(section, None, key) {
                Ok(Some(flag)) => if flag { "true" } else { "false" }.into(),
                _ => continue,
            },
        };
        if !is_plain(&value) {
            continue;
        }
        if !started {
            let _ = writeln!(config, "[{section}]");
            started = true;
        }
        let _ = writeln!(config, "\t{key} = {value}");
    }
}

fn is_plain(value: &[u8]) -> bool {
    (1..=MAX_VALUE_BYTES).contains(&value.len())
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_what_describes_the_repository_is_kept() {
        let config = agent_config(
            b"[core]\n\trepositoryformatversion = 1\n\tbare = false\n\tfilemode = true\n\
              \thooksPath = /tmp/hooks\n\tfsmonitor = rm -rf\n\tsshCommand = ssh -i key\n\
              [extensions]\n\tobjectFormat = sha256\n\tworktreeConfig = true\n\
              [remote \"origin\"]\n\turl = https://user:token@example.com/r.git\n\
              [http]\n\textraHeader = Authorization: Bearer token\n\
              [url \"https://user:token@example.com/\"]\n\tinsteadOf = https://example.com/\n\
              [credential]\n\thelper = store\n\
              [include]\n\tpath = /etc/elsewhere\n\
              [user]\n\temail = someone@example.com\n"
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            config,
            "[core]\n\trepositoryformatversion = 1\n\tbare = false\n\tfilemode = true\n\
             [extensions]\n\tobjectformat = sha256\n\tworktreeconfig = true\n"
        );
        assert!(!config.contains("token"));
    }

    #[test]
    fn a_value_that_is_not_a_plain_word_is_left_out() {
        let config = agent_config(
            b"[core]\n\teol = lf\n\tautocrlf = \"in put\"\n\tsymlinks\n\
              [extensions]\n\tnoop = a\\\"b\n\tpartialClone = origin\n"
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            config,
            "[core]\n\tsymlinks = true\n\teol = lf\n[extensions]\n\tpartialclone = origin\n"
        );
    }

    #[test]
    fn an_empty_or_unreadable_configuration_gives_nothing_or_an_error() {
        assert_eq!(agent_config(Vec::new()).unwrap(), "");
        assert!(matches!(
            agent_config(b"[core\n".to_vec()),
            Err(StoreError::UnreadableConfig)
        ));
    }
}
