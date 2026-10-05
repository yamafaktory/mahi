use std::{
    fs::File,
    io::{
        self,
        Read,
    },
    path::{
        Path,
        PathBuf,
    },
};

use mahi_identity::ConfigDir;
use mahi_term::{
    PaletteKey,
    PaletteKeyError,
};
use serde::Deserialize;
use thiserror::Error;

const MAX_SETTINGS_BYTES: u64 = 64 * 1024;
/// How much one fetch reads, or one push sends, when `config.toml` does not say.
pub(crate) const DEFAULT_TRANSFER_LIMIT: u64 = 1 << 30;
const UNITS: [(&str, u64); 5] = [
    ("TiB", 1 << 40),
    ("GiB", 1 << 30),
    ("MiB", 1 << 20),
    ("KiB", 1 << 10),
    ("B", 1),
];

/// What the user set in `config.toml`, in mahi's configuration directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) palette_key: PaletteKey,
    pub(crate) fetch_limit: u64,
    pub(crate) push_limit: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            palette_key: PaletteKey::default(),
            fetch_limit: DEFAULT_TRANSFER_LIMIT,
            push_limit: DEFAULT_TRANSFER_LIMIT,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SettingsFile {
    palette_key: Option<String>,
    fetch_limit: Option<Size>,
    push_limit: Option<Size>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Size {
    Bytes(u64),
    Text(String),
}

/// `config.toml` cannot be used.
#[derive(Debug, Error)]
pub(crate) enum SettingsError {
    #[error("cannot read {0}: {1}")]
    Read(PathBuf, #[source] io::Error),
    #[error("{0} is larger than 64 KiB")]
    TooLarge(PathBuf),
    #[error("{0} is not valid: {1}")]
    Invalid(PathBuf, String),
    #[error("palette-key in {0}: {1}")]
    PaletteKey(PathBuf, #[source] PaletteKeyError),
    #[error("{1} in {0} is not a size such as 1073741824 or \"1 GiB\"")]
    Size(PathBuf, &'static str),
}

impl Settings {
    /// Reads `config.toml` in `config`; a missing file gives the defaults.
    pub(crate) fn load(config: &ConfigDir) -> Result<Self, SettingsError> {
        Self::read(&config.settings_file())
    }

    fn read(path: &Path) -> Result<Self, SettingsError> {
        let failed = |error| SettingsError::Read(path.to_path_buf(), error);
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(failed(error)),
        };
        let mut text = String::new();
        file.take(MAX_SETTINGS_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(failed)?;
        if u64::try_from(text.len()).map_or(true, |length| length > MAX_SETTINGS_BYTES) {
            return Err(SettingsError::TooLarge(path.to_path_buf()));
        }
        let file: SettingsFile = toml::from_str(&text).map_err(|error| {
            SettingsError::Invalid(path.to_path_buf(), error.message().to_owned())
        })?;
        let palette_key = file
            .palette_key
            .map(|name| name.parse())
            .transpose()
            .map_err(|error| SettingsError::PaletteKey(path.to_path_buf(), error))?
            .unwrap_or_default();
        let limit = |size: Option<Size>, name: &'static str| {
            size.map_or(Ok(DEFAULT_TRANSFER_LIMIT), |size| {
                size.bytes()
                    .ok_or_else(|| SettingsError::Size(path.to_path_buf(), name))
            })
        };
        Ok(Self {
            palette_key,
            fetch_limit: limit(file.fetch_limit, "fetch-limit")?,
            push_limit: limit(file.push_limit, "push-limit")?,
        })
    }
}

impl Size {
    fn bytes(&self) -> Option<u64> {
        let bytes = match self {
            Self::Bytes(bytes) => *bytes,
            Self::Text(text) => {
                let text = text.trim();
                let (number, unit) = UNITS.iter().find_map(|(name, unit)| {
                    text.strip_suffix(name)
                        .map(|number| (number.trim_end(), *unit))
                })?;
                number.parse::<u64>().ok()?.checked_mul(unit)?
            }
        };
        (bytes > 0).then_some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn a_missing_or_empty_file_gives_ctrl_space() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Settings::read(&dir.path().join("config.toml")).unwrap(),
            Settings::default()
        );
        let (_dir, path) = written("");
        assert_eq!(
            Settings::read(&path).unwrap().palette_key,
            PaletteKey::CTRL_SPACE
        );
    }

    #[test]
    fn palette_key_chooses_the_key() {
        let (_dir, path) = written("palette-key = \"f5\"\n");
        assert_eq!(
            Settings::read(&path).unwrap().palette_key,
            "f5".parse().unwrap()
        );
    }

    #[test]
    fn transfer_limits_take_bytes_or_sizes_and_default_to_one_gib() {
        let (_dir, path) = written("");
        let defaults = Settings::read(&path).unwrap();
        assert_eq!(
            (defaults.fetch_limit, defaults.push_limit),
            (1 << 30, 1 << 30)
        );
        let (_dir, path) = written("fetch-limit = \"2 GiB\"\npush-limit = 4096\n");
        let set = Settings::read(&path).unwrap();
        assert_eq!((set.fetch_limit, set.push_limit), (2 << 30, 4096));
        for (text, bytes) in [
            ("\"512MiB\"", 512 << 20),
            ("\" 3 KiB \"", 3 << 10),
            ("\"7 B\"", 7),
            ("\"1 TiB\"", 1 << 40),
        ] {
            let (_dir, path) = written(&format!("fetch-limit = {text}\n"));
            assert_eq!(Settings::read(&path).unwrap().fetch_limit, bytes, "{text}");
        }
        for text in [
            "0",
            "\"0 GiB\"",
            "\"1 GB\"",
            "\"lots\"",
            "\"99999999999 TiB\"",
            "-1",
        ] {
            let (_dir, path) = written(&format!("push-limit = {text}\n"));
            let error = Settings::read(&path).unwrap_err();
            assert!(
                matches!(
                    error,
                    SettingsError::Size(_, "push-limit") | SettingsError::Invalid(..)
                ),
                "{text}: {error:?}"
            );
        }
    }

    #[test]
    fn unknown_settings_bad_keys_bad_toml_and_huge_files_are_refused() {
        for (text, wanted) in [
            ("palette_key = \"f5\"\n", "Invalid"),
            ("palette-key = 5\n", "Invalid"),
            ("palette-key = \"ctrl-m\"\n", "PaletteKey"),
            ("palette-key = ", "Invalid"),
            ("colour = \"red\"\n", "Invalid"),
        ] {
            let (_dir, path) = written(text);
            let error = Settings::read(&path).unwrap_err();
            assert!(
                format!("{error:?}").starts_with(wanted),
                "{text:?}: {error:?}"
            );
            assert!(error.to_string().contains("config.toml"), "{error}");
        }
        let huge = format!("# {}\n", "x".repeat(64 * 1024));
        let (_dir, path) = written(&huge);
        assert!(matches!(
            Settings::read(&path),
            Err(SettingsError::TooLarge(_))
        ));
    }
}
